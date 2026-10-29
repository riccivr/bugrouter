package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/riccivr/bugrouter/internal/adapter"
	"github.com/riccivr/bugrouter/internal/cache"
	"github.com/riccivr/bugrouter/internal/cloud"
	"github.com/riccivr/bugrouter/internal/dedup"
	"github.com/riccivr/bugrouter/internal/httpx"
	"github.com/riccivr/bugrouter/internal/introspector"
	"github.com/riccivr/bugrouter/internal/mcp"
	"github.com/riccivr/bugrouter/internal/resolver"
	"github.com/riccivr/bugrouter/internal/scrubber"
	"github.com/riccivr/bugrouter/internal/version"
)

func resolveTarget(ctx context.Context, httpClient *httpx.Client, query string, noCache bool) (*resolver.Target, error) {
	if httpClient == nil {
		httpClient = httpx.NewClient(0)
	}
	wf := resolver.NewWaterfall(
		0,
		resolver.NewOrgCloudProbe(),
		resolver.NewDirectProbe(),
		resolver.NewWorkspaceProbe("."),
		resolver.NewOSPackageProbe(),
		resolver.NewRegistryProbe(httpClient, resolver.DefaultRegistryEndpoints()),
		resolver.NewWebDomainProbe(httpClient),
	)
	if !noCache {
		wf.WithCache(cache.NewStore("", 0))
	}
	return wf.Resolve(ctx, query)
}

func parseMarkdownBodyFile(raw string) (summary, steps, logs string) {
	lines := strings.Split(raw, "\n")
	type sectionType int
	const (
		secNone sectionType = iota
		secSummary
		secSteps
		secLogs
	)
	var currentSection sectionType
	var summaryLines, stepsLines, logsLines []string
	hasAnyRecognizedHeading := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			heading := strings.TrimSpace(strings.TrimLeft(trimmed, "#"))
			lower := strings.ToLower(heading)
			switch {
			case lower == "summary":
				currentSection = secSummary
				hasAnyRecognizedHeading = true
				continue
			case lower == "steps to reproduce" || lower == "steps":
				currentSection = secSteps
				hasAnyRecognizedHeading = true
				continue
			case lower == "logs" || lower == "logs & output" || lower == "logs and output":
				currentSection = secLogs
				hasAnyRecognizedHeading = true
				continue
			default:
				if strings.HasPrefix(trimmed, "## ") {
					currentSection = secNone
					continue
				}
			}
		}

		switch currentSection {
		case secSummary:
			summaryLines = append(summaryLines, line)
		case secSteps:
			stepsLines = append(stepsLines, line)
		case secLogs:
			logsLines = append(logsLines, line)
		}
	}

	if !hasAnyRecognizedHeading {
		return strings.TrimSpace(raw), "", ""
	}

	summary = strings.TrimSpace(strings.Join(summaryLines, "\n"))
	steps = strings.TrimSpace(strings.Join(stepsLines, "\n"))
	logs = strings.TrimSpace(strings.Join(logsLines, "\n"))
	return summary, steps, logs
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "version", "--version", "-version", "-v":
		fmt.Printf("bugrouter %s\n", version.Version)
		return

	case "mcp":
		httpClient := httpx.NewClient(0)
		cacheStore := cache.NewStore("", 0)
		wf := resolver.NewWaterfall(
			0,
			resolver.NewOrgCloudProbe(),
			resolver.NewDirectProbe(),
			resolver.NewWorkspaceProbe("."),
			resolver.NewOSPackageProbe(),
			resolver.NewRegistryProbe(httpClient, resolver.DefaultRegistryEndpoints()),
			resolver.NewWebDomainProbe(httpClient),
		).WithCache(cacheStore)
		store := adapter.NewDraftStore("")
		intro := introspector.New(httpClient).WithCache(cacheStore)
		srv := mcp.NewServer(wf, store).WithIntrospector(intro)
		if err := srv.Run(context.Background(), os.Stdin, os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "mcp server error: %v\n", err)
			os.Exit(1)
		}
		return

	case "resolve":
		fs := flag.NewFlagSet("resolve", flag.ContinueOnError)
		jsonOut := fs.Bool("json", false, "output structured JSON")
		noCache := fs.Bool("no-cache", false, "disable disk cache")
		timeout := fs.Duration("timeout", 15*time.Second, "request and probe timeout duration")
		if err := fs.Parse(os.Args[2:]); err != nil {
			os.Exit(1)
		}

		args := fs.Args()
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "error: resolve requires a target query")
			os.Exit(1)
		}

		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()

		httpClient := httpx.NewClient(0)
		target, err := resolveTarget(ctx, httpClient, args[0], *noCache)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(target); err != nil {
				fmt.Fprintf(os.Stderr, "encode json: %v\n", err)
				os.Exit(1)
			}
			return
		}

		fmt.Printf("Canonical Name: %s\n", target.CanonicalName)
		if target.LocalVersion != "" {
			fmt.Printf("Local Version:  %s\n", target.LocalVersion)
		}
		fmt.Printf("Layer:          %s\n", target.Layer)
		fmt.Printf("Protocol:       %s\n", target.Tracker.Protocol)
		if target.Tracker.URL != "" {
			fmt.Printf("Tracker URL:    %s\n", target.Tracker.URL)
		}
		if target.Tracker.Email != "" {
			fmt.Printf("Tracker Email:  %s\n", target.Tracker.Email)
		}

	case "draft":
		fs := flag.NewFlagSet("draft", flag.ContinueOnError)
		title := fs.String("title", "", "bug report title")
		summary := fs.String("summary", "", "summary of the issue")
		steps := fs.String("steps", "", "steps to reproduce")
		logs := fs.String("logs", "", "error logs or console output")
		bodyFile := fs.String("body-file", "", "path to markdown body file or '-' for stdin")
		timeout := fs.Duration("timeout", 15*time.Second, "request and probe timeout duration")
		jsonOut := fs.Bool("json", false, "output structured JSON")
		noCache := fs.Bool("no-cache", false, "disable disk cache")
		if err := fs.Parse(os.Args[2:]); err != nil {
			os.Exit(1)
		}

		args := fs.Args()
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "error: draft requires a target query")
			os.Exit(1)
		}
		if strings.TrimSpace(*title) == "" {
			fmt.Fprintln(os.Stderr, "error: --title is required")
			os.Exit(1)
		}

		if *bodyFile != "" {
			var r io.Reader
			if *bodyFile == "-" {
				r = os.Stdin
			} else {
				f, err := os.Open(*bodyFile)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error: open body file %s: %v\n", *bodyFile, err)
					os.Exit(1)
				}
				defer f.Close()
				r = f
			}
			const maxBodyBytes = 512 * 1024
			data, err := io.ReadAll(io.LimitReader(r, maxBodyBytes))
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: read body file: %v\n", err)
				os.Exit(1)
			}
			fSummary, fSteps, fLogs := parseMarkdownBodyFile(string(data))
			if *summary == "" {
				*summary = fSummary
			}
			if *steps == "" {
				*steps = fSteps
			}
			if *logs == "" {
				*logs = fLogs
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()

		httpClient := httpx.NewClient(0)
		target, err := resolveTarget(ctx, httpClient, args[0], *noCache)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		intro := introspector.New(httpClient)
		if !*noCache {
			intro.WithCache(cache.NewStore("", 0))
		}
		schema, err := intro.Introspect(ctx, *target)
		if err != nil {
			// Non-fatal; fallback to generic drafting if offline or no template found.
			schema = nil
		}

		finder := dedup.NewFinder(httpClient)
		dups, err := finder.FindDuplicates(ctx, *target, scrubber.Scrub(*title))
		if err != nil {
			// Non-fatal; proceed if duplicate search encounters network/rate errors.
			dups = nil
		}

		draft, err := adapter.BuildDraft(adapter.DraftInput{
			Target:           *target,
			Title:            *title,
			Summary:          *summary,
			StepsToReproduce: *steps,
			Logs:             *logs,
			Template:         schema,
			Duplicates:       dups,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: build draft: %v\n", err)
			os.Exit(1)
		}

		draftStore := adapter.NewDraftStore("")
		savedPath, err := draftStore.Save(draft)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: save draft: %v\n", err)
			os.Exit(1)
		}

		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(draft); err != nil {
				fmt.Fprintf(os.Stderr, "encode json: %v\n", err)
				os.Exit(1)
			}
			return
		}

		fmt.Printf("Draft ID:       %s\n", draft.ID)
		fmt.Printf("Staged Path:    %s\n", savedPath)
		fmt.Printf("Target:         %s\n", draft.Target.CanonicalName)
		fmt.Printf("Title:          %s\n", draft.Title)
		if draft.SubmissionURL != "" {
			fmt.Printf("Submission URL: %s\n", draft.SubmissionURL)
		}
		if len(draft.PotentialDuplicates) > 0 {
			fmt.Printf("\nPotential Upstream Duplicates (%d found):\n", len(draft.PotentialDuplicates))
			for _, d := range draft.PotentialDuplicates {
				fmt.Printf("  - [%s] (%.0f%% match) %s\n    %s\n", d.State, d.Score*100, d.Title, d.URL)
			}
		}
		if draft.DebbugsEmail != "" {
			fmt.Printf("\n--- Debbugs Email ---\n%s\n", draft.DebbugsEmail)
		}

	case "serve":
		fs := flag.NewFlagSet("serve", flag.ContinueOnError)
		addr := fs.String("addr", ":8080", "HTTP server listen address")
		draftsDir := fs.String("drafts-dir", "", "drafts storage directory")
		authToken := fs.String("auth-token", "", "Bearer auth token (falls back to BUGROUTER_CLOUD_TOKEN)")
		auditLog := fs.String("audit-log", "", "audit log path (default: XDG state path)")
		webhookURL := fs.String("webhook-url", "", "webhook delivery URL (falls back to BUGROUTER_WEBHOOK_URL)")
		if err := fs.Parse(os.Args[2:]); err != nil {
			os.Exit(1)
		}

		store := adapter.NewDraftStore(*draftsDir)
		httpClient := httpx.NewClient(0)
		forge := cloud.NewForgeClient(httpClient)
		srv := cloud.NewServer(*addr, store, forge)
		if *authToken != "" {
			srv.WithAuthToken(*authToken)
		}
		srv.WithAuditLogger(cloud.NewAuditLogger(*auditLog))
		srv.WithWebhookNotifier(cloud.NewWebhookNotifier(httpClient, *webhookURL, ""))

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if shutdownErr := srv.Shutdown(shutdownCtx); shutdownErr != nil {
				fmt.Fprintf(os.Stderr, "server shutdown error: %v\n", shutdownErr)
			}
		}()

		fmt.Printf("bugrouter cloud control plane listening on %s\n", *addr)
		if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "server error: %v\n", err)
			os.Exit(1)
		}
		return

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: bugrouter <command> [arguments]")
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  version                     Print version information")
	fmt.Fprintln(os.Stderr, "  resolve [--json] [--no-cache] [--timeout <dur>] <q>")
	fmt.Fprintln(os.Stderr, "                              Resolve software target to bug tracker")
	fmt.Fprintln(os.Stderr, "  draft [--title <t>] [--summary <s>] [--steps <st>] [--logs <l>]")
	fmt.Fprintln(os.Stderr, "        [--body-file <path>] [--timeout <dur>] [--json] [--no-cache] <q>")
	fmt.Fprintln(os.Stderr, "                              Stage bug report draft and generate submission URLs")
	fmt.Fprintln(os.Stderr, "  serve [--addr <addr>] [--drafts-dir <dir>] [--auth-token <tok>] [--audit-log <path>] [--webhook-url <url>]")
	fmt.Fprintln(os.Stderr, "                              Start Cloud Control Plane HTTP daemon and Web UI")
	fmt.Fprintln(os.Stderr, "  mcp                         Start Model Context Protocol (MCP) stdio server")
}
