package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

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

func resolveTarget(query string, noCache bool) (*resolver.Target, error) {
	httpClient := httpx.NewClient(0)
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
	return wf.Resolve(context.Background(), query)
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
		if err := fs.Parse(os.Args[2:]); err != nil {
			os.Exit(1)
		}

		args := fs.Args()
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "error: resolve requires a target query")
			os.Exit(1)
		}

		target, err := resolveTarget(args[0], *noCache)
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

		target, err := resolveTarget(args[0], *noCache)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		httpClient := httpx.NewClient(0)
		intro := introspector.New(httpClient)
		if !*noCache {
			intro.WithCache(cache.NewStore("", 0))
		}
		schema, err := intro.Introspect(context.Background(), *target)
		if err != nil {
			// Non-fatal; fallback to generic drafting if offline or no template found.
			schema = nil
		}

		finder := dedup.NewFinder(httpClient)
		dups, err := finder.FindDuplicates(context.Background(), *target, scrubber.Scrub(*title))
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
		if err := fs.Parse(os.Args[2:]); err != nil {
			os.Exit(1)
		}

		store := adapter.NewDraftStore(*draftsDir)
		httpClient := httpx.NewClient(0)
		forge := cloud.NewForgeClient(httpClient)
		srv := cloud.NewServer(*addr, store, forge)

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
	fmt.Fprintln(os.Stderr, "  resolve [--json] [--no-cache] <q> Resolve software target to bug tracker")
	fmt.Fprintln(os.Stderr, "  draft [--title <t>] [--summary <s>] [--steps <st>] [--logs <l>] [--json] <q>")
	fmt.Fprintln(os.Stderr, "                              Stage bug report draft and generate submission URLs")
	fmt.Fprintln(os.Stderr, "  serve [--addr <addr>] [--drafts-dir <dir>]")
	fmt.Fprintln(os.Stderr, "                              Start Cloud Control Plane HTTP daemon and Web UI")
	fmt.Fprintln(os.Stderr, "  mcp                         Start Model Context Protocol (MCP) stdio server")
}
