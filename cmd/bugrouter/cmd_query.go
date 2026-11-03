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
)

func runIntrospect(ctx context.Context, httpClient *httpx.Client, out io.Writer, errOut io.Writer, args []string) int {
	fs := flag.NewFlagSet("introspect", flag.ContinueOnError)
	fs.SetOutput(errOut)
	jsonOut := fs.Bool("json", false, "output structured JSON")
	noCache := fs.Bool("no-cache", false, "disable disk cache")
	timeout := fs.Duration("timeout", 15*time.Second, "request and probe timeout duration")

	flagArgs, posArgs := splitInterleavedFlags(args, map[string]bool{
		"timeout": true,
	})

	if err := fs.Parse(flagArgs); err != nil {
		return 1
	}

	if len(posArgs) < 1 {
		fmt.Fprintln(errOut, "error: introspect requires a target query")
		fmt.Fprintln(errOut, "Usage: bugrouter introspect [--json] [--no-cache] [--timeout <dur>] <target>")
		return 1
	}

	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	if httpClient == nil {
		httpClient = httpx.NewClient(0)
	}

	target, err := resolveTarget(ctx, httpClient, posArgs[0], *noCache)
	if err != nil {
		fmt.Fprintf(errOut, "error: resolve target: %v\n", err)
		return 1
	}

	intro := introspector.New(httpClient)
	if !*noCache {
		intro = intro.WithCache(cache.NewStore("", 0))
	}
	schema, err := intro.Introspect(ctx, *target)
	if err != nil {
		fmt.Fprintf(errOut, "error: introspect template: %v\n", err)
		return 1
	}

	if *jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(schema); err != nil {
			fmt.Fprintf(errOut, "error: encode json: %v\n", err)
			return 1
		}
		return 0
	}

	fmt.Fprintf(out, "Template Name:  %s\n", schema.Name)
	fmt.Fprintf(out, "Format:         %s\n", schema.Format)
	fmt.Fprintf(out, "Protocol:       %s\n", schema.Protocol)
	if schema.TitlePrefix != "" {
		fmt.Fprintf(out, "Title Prefix:   %s\n", schema.TitlePrefix)
	}
	if len(schema.Labels) > 0 {
		fmt.Fprintf(out, "Labels:         %s\n", strings.Join(schema.Labels, ", "))
	}
	fmt.Fprintf(out, "Fields (%d):\n", len(schema.Fields))
	for _, f := range schema.Fields {
		reqStr := ""
		if f.Required {
			reqStr = " (required)"
		}
		fmt.Fprintf(out, "  - [%s] %s%s\n", f.Type, f.Label, reqStr)
	}
	if schema.Policy != nil {
		fmt.Fprintf(out, "Maintainer Policy:\n")
		fmt.Fprintf(out, "  AI Opt-Out:   %t\n", schema.Policy.AIOptOut)
		if schema.Policy.OptOutReason != "" {
			fmt.Fprintf(out, "  Reason:       %s\n", schema.Policy.OptOutReason)
		}
		if len(schema.Policy.ChecklistRules) > 0 {
			fmt.Fprintf(out, "  Checklist Rules:\n")
			for _, r := range schema.Policy.ChecklistRules {
				fmt.Fprintf(out, "    * %s\n", r)
			}
		}
	}
	return 0
}

func runDedup(ctx context.Context, httpClient *httpx.Client, out io.Writer, errOut io.Writer, args []string) int {
	fs := flag.NewFlagSet("dedup", flag.ContinueOnError)
	fs.SetOutput(errOut)
	jsonOut := fs.Bool("json", false, "output structured JSON")
	noCache := fs.Bool("no-cache", false, "disable disk cache")
	timeout := fs.Duration("timeout", 15*time.Second, "request and probe timeout duration")

	flagArgs, posArgs := splitInterleavedFlags(args, map[string]bool{
		"timeout": true,
	})

	if err := fs.Parse(flagArgs); err != nil {
		return 1
	}

	if len(posArgs) < 2 {
		fmt.Fprintln(errOut, "error: dedup requires <target> and <title> arguments")
		fmt.Fprintln(errOut, "Usage: bugrouter dedup [--json] [--no-cache] [--timeout <dur>] <target> <title>")
		return 1
	}

	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	if httpClient == nil {
		httpClient = httpx.NewClient(0)
	}

	target, err := resolveTarget(ctx, httpClient, posArgs[0], *noCache)
	if err != nil {
		fmt.Fprintf(errOut, "error: resolve target: %v\n", err)
		return 1
	}

	finder := dedup.NewFinder(httpClient)
	dups, err := finder.FindDuplicates(ctx, *target, scrubber.Scrub(posArgs[1]))
	if err != nil {
		fmt.Fprintf(errOut, "error: find duplicates: %v\n", err)
		return 1
	}
	if dups == nil {
		dups = []dedup.ExistingIssue{}
	}

	if *jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(dups); err != nil {
			fmt.Fprintf(errOut, "error: encode json: %v\n", err)
			return 1
		}
		return 0
	}

	if len(dups) == 0 {
		fmt.Fprintln(out, "No potential upstream duplicates found.")
		return 0
	}

	for _, d := range dups {
		fmt.Fprintf(out, "[#%s] (%.0f%%) %s - %s (%s)\n", d.ID, d.Score*100, d.State, d.Title, d.URL)
	}
	return 0
}

func runScrub(in io.Reader, out io.Writer, errOut io.Writer, args []string) int {
	fs := flag.NewFlagSet("scrub", flag.ContinueOnError)
	fs.SetOutput(errOut)
	input := fs.String("input", "", "input text to scrub")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	var text string
	if *input != "" {
		text = *input
	} else {
		const maxBytes = 512 * 1024
		data, err := io.ReadAll(io.LimitReader(in, maxBytes))
		if err != nil {
			fmt.Fprintf(errOut, "error: read stdin: %v\n", err)
			return 1
		}
		text = string(data)
	}

	scrubbed := scrubber.Scrub(text)
	if strings.HasSuffix(string(scrubbed), "\n") {
		fmt.Fprint(out, scrubbed)
	} else {
		fmt.Fprintln(out, scrubbed)
	}
	return 0
}

func cmdResolve(args []string) {
	fs := flag.NewFlagSet("resolve", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "output structured JSON")
	noCache := fs.Bool("no-cache", false, "disable disk cache")
	timeout := fs.Duration("timeout", 15*time.Second, "request and probe timeout duration")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	posArgs := fs.Args()
	if len(posArgs) < 1 {
		fmt.Fprintln(os.Stderr, "error: resolve requires a target query")
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	httpClient := httpx.NewClient(0)
	target, err := resolveTarget(ctx, httpClient, posArgs[0], *noCache)
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
}

func cmdIntrospect(args []string) {
	if code := runIntrospect(context.Background(), nil, os.Stdout, os.Stderr, args); code != 0 {
		os.Exit(code)
	}
}

func cmdDedup(args []string) {
	if code := runDedup(context.Background(), nil, os.Stdout, os.Stderr, args); code != 0 {
		os.Exit(code)
	}
}

func cmdScrub(args []string) {
	if code := runScrub(os.Stdin, os.Stdout, os.Stderr, args); code != 0 {
		os.Exit(code)
	}
}

func cmdStack(args []string) {
	fs := flag.NewFlagSet("stack", flag.ContinueOnError)
	dir := fs.String("dir", ".", "workspace directory to scan")
	checkUpstream := fs.Bool("check-upstream", false, "query upstream trackers for active bugs matching dependencies")
	jsonOut := fs.Bool("json", false, "output structured JSON")
	noCache := fs.Bool("no-cache", false, "disable disk cache")
	timeout := fs.Duration("timeout", 30*time.Second, "request and scan timeout duration")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	httpClient := httpx.NewClient(0)
	wf := resolver.NewWaterfall(
		0,
		resolver.NewOrgCloudProbe(),
		resolver.NewDirectProbe(),
		resolver.NewWorkspaceProbe(*dir),
		resolver.NewOSPackageProbe(),
		resolver.NewRegistryProbe(httpClient, resolver.DefaultRegistryEndpoints()),
		resolver.NewWebDomainProbe(httpClient),
	)
	if !*noCache {
		wf.WithCache(cache.NewStore("", 0))
	}

	finder := dedup.NewFinder(httpClient)
	report, err := dedup.BuildStackRadar(ctx, wf, finder, *dir, *checkUpstream)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: scan stack: %v\n", err)
		os.Exit(1)
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "error: encode json: %v\n", err)
			os.Exit(1)
		}
		return
	}

	fmt.Printf("Workspace Stack Inventory (%s): %d dependencies (%d resolved)\n", report.RootDir, report.Total, report.Resolved)
	for _, entry := range report.Entries {
		dep := entry.Dependency
		verStr := ""
		if dep.Version != "" {
			verStr = fmt.Sprintf(" (%s)", dep.Version)
		}
		if dep.Target != nil {
			trackerInfo := ""
			if dep.Target.Tracker.URL != "" {
				trackerInfo = fmt.Sprintf(" -> %s: %s", dep.Target.Tracker.Protocol, dep.Target.Tracker.URL)
			} else if dep.Target.Tracker.Email != "" {
				trackerInfo = fmt.Sprintf(" -> %s: %s", dep.Target.Tracker.Protocol, dep.Target.Tracker.Email)
			}
			fmt.Printf("- [%s] %s%s%s\n", dep.Ecosystem, dep.Name, verStr, trackerInfo)
		} else {
			errInfo := ""
			if dep.ResolutionErr != "" {
				errInfo = fmt.Sprintf(" (error: %s)", dep.ResolutionErr)
			}
			fmt.Printf("- [%s] %s%s [unresolved%s]\n", dep.Ecosystem, dep.Name, verStr, errInfo)
		}

		if len(entry.UpstreamBugs) > 0 {
			for _, bug := range entry.UpstreamBugs {
				fmt.Printf("    * [#%s] %s (%s)\n", bug.ID, bug.Title, bug.URL)
			}
		}
	}
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", ":8080", "HTTP server listen address")
	draftsDir := fs.String("drafts-dir", "", "drafts storage directory")
	authToken := fs.String("auth-token", "", "Bearer auth token (falls back to BUGROUTER_CLOUD_TOKEN)")
	auditLog := fs.String("audit-log", "", "audit log path (default: XDG state path)")
	webhookURL := fs.String("webhook-url", "", "webhook delivery URL (falls back to BUGROUTER_WEBHOOK_URL)")
	webhookSecret := fs.String("webhook-secret", "", "HMAC secret for webhook delivery (falls back to BUGROUTER_WEBHOOK_SECRET)")
	if err := fs.Parse(args); err != nil {
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
	srv.WithWebhookNotifier(cloud.NewWebhookNotifier(httpClient, *webhookURL, *webhookSecret))

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
	finder := dedup.NewFinder(httpClient)
	srv.WithStackScanner(wf, finder, ".")
	srv.WithIntrospector(introspector.New(httpClient).WithCache(cacheStore))

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
}

func cmdMCP(args []string) {
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
}
