package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
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
	"github.com/riccivr/bugrouter/internal/telemetry"
	"github.com/riccivr/bugrouter/internal/verifier"
	"github.com/riccivr/bugrouter/internal/version"
)

// AgentTriageResult represents the structured JSON envelope returned by agent triage.
type AgentTriageResult struct {
	Candidates          []resolver.TraceCandidate    `json:"candidates"`
	ResolvedTarget      *resolver.Target             `json:"resolved_target,omitempty"`
	TemplateSchema      *introspector.TemplateSchema `json:"template_schema,omitempty"`
	PotentialDuplicates []dedup.ExistingIssue        `json:"potential_duplicates,omitempty"`
	ScrubbedLog         scrubber.ScrubbedText        `json:"scrubbed_log,omitempty"`
	NextActions         []string                     `json:"next_actions"`
}

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

// ReportOptions contains configuration flags for the interactive guided bug report wizard.
type ReportOptions struct {
	Query            string
	Title            string
	Summary          string
	StepsToReproduce string
	ExpectedBehavior string
	ActualBehavior   string
	Logs             string
	WithTelemetry    bool
	NoTelemetry      bool
	JSON             bool
	NoCache          bool
	Timeout          time.Duration
}

func runGuidedReport(ctx context.Context, in io.Reader, out io.Writer, httpClient *httpx.Client, opts ReportOptions) (*adapter.StagedDraft, string, error) {
	if httpClient == nil {
		httpClient = httpx.NewClient(0)
	}

	if opts.Query == "" {
		return nil, "", errors.New("report requires a target query")
	}

	// Step 1: Resolve target via resolveTarget
	if !opts.JSON {
		fmt.Fprintf(out, "==> Resolving software target %q...\n", opts.Query)
	}
	target, err := resolveTarget(ctx, httpClient, opts.Query, opts.NoCache)
	if err != nil {
		return nil, "", fmt.Errorf("resolve target %q: %w", opts.Query, err)
	}
	if !opts.JSON {
		fmt.Fprintf(out, "    Resolved: %s (tracker: %s [%s])\n", target.CanonicalName, target.Tracker.URL, target.Tracker.Protocol)
	}

	// Step 2: Introspect upstream issue template (non-fatal fallback)
	intro := introspector.New(httpClient)
	if !opts.NoCache {
		intro = intro.WithCache(cache.NewStore("", 0))
	}
	schema, introErr := intro.Introspect(ctx, *target)
	if introErr != nil {
		schema = nil
	}

	// Step 3: Collect hardware/OS telemetry by default (unless --no-telemetry is set)
	var sysTelemetry *telemetry.SystemTelemetry
	if !opts.NoTelemetry {
		if !opts.JSON {
			fmt.Fprintf(out, "==> Collecting hardware and OS telemetry...\n")
		}
		t := telemetry.Collect(ctx)
		sysTelemetry = &t
	}

	// Step 4: For any core field not supplied via flags, prompt interactively line-by-line
	scanner := bufio.NewScanner(in)

	if strings.TrimSpace(opts.Title) == "" {
		if !opts.JSON {
			fmt.Fprintf(out, "\nEnter bug report title: ")
		}
		if scanner.Scan() {
			opts.Title = strings.TrimSpace(scanner.Text())
		}
	}

	if strings.TrimSpace(opts.Summary) == "" {
		if !opts.JSON {
			fmt.Fprintf(out, "Enter summary (describe the issue): ")
		}
		if scanner.Scan() {
			opts.Summary = strings.TrimSpace(scanner.Text())
		}
	}

	if strings.TrimSpace(opts.StepsToReproduce) == "" {
		if !opts.JSON {
			fmt.Fprintf(out, "Enter steps to reproduce: ")
		}
		if scanner.Scan() {
			opts.StepsToReproduce = strings.TrimSpace(scanner.Text())
		}
	}

	if strings.TrimSpace(opts.ExpectedBehavior) == "" {
		if !opts.JSON {
			fmt.Fprintf(out, "Enter expected behavior (optional, press Enter to skip): ")
		}
		if scanner.Scan() {
			opts.ExpectedBehavior = strings.TrimSpace(scanner.Text())
		}
	}

	if strings.TrimSpace(opts.ActualBehavior) == "" {
		if !opts.JSON {
			fmt.Fprintf(out, "Enter actual behavior (optional, press Enter to skip): ")
		}
		if scanner.Scan() {
			opts.ActualBehavior = strings.TrimSpace(scanner.Text())
		}
	}

	if strings.TrimSpace(opts.Logs) == "" {
		if !opts.JSON {
			fmt.Fprintf(out, "Enter error logs or console output (optional, press Enter to skip): ")
		}
		if scanner.Scan() {
			opts.Logs = strings.TrimSpace(scanner.Text())
		}
	}

	if scanErr := scanner.Err(); scanErr != nil {
		return nil, "", fmt.Errorf("read interactive input: %w", scanErr)
	}

	if strings.TrimSpace(opts.Title) == "" {
		return nil, "", errors.New("report title cannot be empty")
	}

	// Step 5: Check upstream duplicates via dedup.NewFinder(httpClient).FindDuplicates
	finder := dedup.NewFinder(httpClient)
	var dups []dedup.ExistingIssue
	if d, dupErr := finder.FindDuplicates(ctx, *target, scrubber.Scrub(opts.Title)); dupErr == nil {
		dups = d
	}
	if !opts.JSON && len(dups) > 0 {
		fmt.Fprintf(out, "\nPotential Upstream Duplicates (%d found):\n", len(dups))
		for _, d := range dups {
			fmt.Fprintf(out, "  - [%s] (%.0f%% match) %s\n    %s\n", d.State, d.Score*100, d.Title, d.URL)
		}
	}

	// Step 6: Build draft via adapter.BuildDraft and display QualityReport + SubmissionURL + staged file path
	draft, err := adapter.BuildDraft(adapter.DraftInput{
		Target:           *target,
		Title:            opts.Title,
		Summary:          opts.Summary,
		StepsToReproduce: opts.StepsToReproduce,
		ExpectedBehavior: opts.ExpectedBehavior,
		ActualBehavior:   opts.ActualBehavior,
		Logs:             opts.Logs,
		Template:         schema,
		Duplicates:       dups,
		Telemetry:        sysTelemetry,
	})
	if err != nil {
		return nil, "", fmt.Errorf("build draft: %w", err)
	}

	store := adapter.NewDraftStore("")
	stagedPath, err := store.Save(draft)
	if err != nil {
		return nil, "", fmt.Errorf("stage draft: %w", err)
	}

	if !opts.JSON {
		fmt.Fprintf(out, "\n--- Bug Report Staged ---\n")
		fmt.Fprintf(out, "Draft ID:       %s\n", draft.ID)
		fmt.Fprintf(out, "Staged File:    %s\n", stagedPath)
		fmt.Fprintf(out, "Canonical Name: %s\n", target.CanonicalName)
		fmt.Fprintf(out, "Tracker:        %s (%s)\n", target.Tracker.URL, target.Tracker.Protocol)
		if draft.SubmissionURL != "" {
			fmt.Fprintf(out, "Submission URL: %s\n", draft.SubmissionURL)
		}
		fmt.Fprintf(out, "\nQuality Assessment:\n")
		fmt.Fprintf(out, "  Score: %d/100 (Grade: %s, Passed: %t)\n", draft.Quality.Score, draft.Quality.Grade, draft.Quality.Passed)
		if len(draft.Quality.Issues) > 0 {
			fmt.Fprintf(out, "  Suggestions:\n")
			for _, issue := range draft.Quality.Issues {
				fmt.Fprintf(out, "    - %s\n", issue)
			}
		}
	}

	return draft, stagedPath, nil
}

// recoverAndParkSelfBug records internal bugrouter panic diagnostics into the parked store.
func recoverAndParkSelfBug(r any, stack []byte, storeDir string) (*adapter.ParkedBug, error) {
	if r == nil {
		return nil, nil
	}
	parkStore := adapter.NewParkedStore(storeDir)
	title := fmt.Sprintf("internal panic in bugrouter %s: %v", version.Version, r)
	snippet := string(stack)
	workaround := fmt.Sprintf("os=%s arch=%s", runtime.GOOS, runtime.GOARCH)
	bug, _, err := parkStore.Park("bugrouter", title, snippet, workaround, "")
	if err != nil {
		return nil, fmt.Errorf("park self bug: %w", err)
	}
	return bug, nil
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			bug, parkErr := recoverAndParkSelfBug(r, stack, "")
			if parkErr != nil {
				fmt.Fprintf(os.Stderr, "internal panic: %v\n%s\nfailed to park self bug: %v\n", r, string(stack), parkErr)
			} else if bug != nil {
				fmt.Fprintf(os.Stderr, "internal panic: %v\n%s\nParked breadcrumb bug %s.\nTo draft an upstream ticket, run:\n  bugrouter draft --from-parked %s\n", r, string(stack), bug.ID, bug.ID)
			}
			os.Exit(1)
		}
	}()

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "version", "--version", "-version", "-v":
		fmt.Printf("bugrouter %s (%s/%s)\n", version.Version, runtime.GOOS, runtime.GOARCH)
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

	case "park":
		fs := flag.NewFlagSet("park", flag.ContinueOnError)
		snippet := fs.String("snippet", "", "error snippet or stack trace")
		workaround := fs.String("workaround", "", "how the anomaly was mitigated or worked around")
		file := fs.String("file", "", "workspace file path where anomaly was discovered")
		relatedDep := fs.String("related-dep", "", "secondary/related dependency causing interaction anomaly")
		jsonOut := fs.Bool("json", false, "output JSON handoff payload")

		// Reorder flags and positional args so flags can precede or follow dependency and title
		var flagArgs []string
		var posArgs []string
		for i := 2; i < len(os.Args); i++ {
			arg := os.Args[i]
			if strings.HasPrefix(arg, "-") {
				flagArgs = append(flagArgs, arg)
				if (arg == "--snippet" || arg == "-snippet" || arg == "--workaround" || arg == "-workaround" || arg == "--file" || arg == "-file" || arg == "--related-dep" || arg == "-related-dep") && i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "-") {
					i++
					flagArgs = append(flagArgs, os.Args[i])
				}
			} else {
				posArgs = append(posArgs, arg)
			}
		}

		if err := fs.Parse(flagArgs); err != nil {
			os.Exit(1)
		}

		if len(posArgs) < 2 {
			fmt.Fprintln(os.Stderr, "error: park requires <dependency> and <title> arguments")
			fmt.Fprintln(os.Stderr, "Usage: bugrouter park [--snippet <s>] [--workaround <w>] [--file <f>] [--related-dep <pkg>] [--json] <dependency> <title>")
			os.Exit(1)
		}

		dep := posArgs[0]
		title := posArgs[1]

		parkStore := adapter.NewParkedStore("")
		bug, handoff, err := parkStore.Park(dep, title, *snippet, *workaround, *file, *relatedDep)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: park bug: %v\n", err)
			os.Exit(1)
		}

		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(map[string]any{
				"parked_bug": bug,
				"handoff":    handoff,
			}); err != nil {
				fmt.Fprintf(os.Stderr, "error: encode json: %v\n", err)
				os.Exit(1)
			}
			return
		}

		fmt.Printf("Bug parked successfully in <5ms!\n")
		fmt.Printf("Parked ID:       %s\n", bug.ID)
		fmt.Printf("Dependency:      %s\n", bug.Dependency)
		if bug.RelatedDependency != "" {
			fmt.Printf("Related Dep:     %s\n", bug.RelatedDependency)
		}
		fmt.Printf("Title:           %s\n", bug.Title)
		fmt.Printf("Resource URI:    %s\n", handoff.ResourceURI)
		fmt.Printf("CLI Command:     %s\n\n", handoff.CLICommand)
		fmt.Printf("Spawn Instruction:\n  %s\n\n", handoff.SpawnSessionPrompt)
		fmt.Printf("Patch Instructions:\n  %s\n\n", handoff.PatchInstructions)
		fmt.Println("User Options:")
		for _, opt := range handoff.UserOptions {
			fmt.Printf("  %s\n", opt)
		}
		fmt.Printf("\nDirective:\n  %s\n", handoff.AgentDirective)
		return

	case "patch":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: bugrouter patch <list|add|rm> [arguments...]")
			os.Exit(1)
		}
		patchStore := adapter.NewPatchStore("")
		switch os.Args[2] {
		case "list":
			fs := flag.NewFlagSet("patch list", flag.ContinueOnError)
			jsonOut := fs.Bool("json", false, "output JSON array")
			if err := fs.Parse(os.Args[3:]); err != nil {
				os.Exit(1)
			}
			patches, err := patchStore.List()
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: list patches: %v\n", err)
				os.Exit(1)
			}
			if *jsonOut {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(patches); err != nil {
					fmt.Fprintf(os.Stderr, "error: encode json: %v\n", err)
					os.Exit(1)
				}
				return
			}
			if len(patches) == 0 {
				fmt.Println("No active dependency patches tracked in ledger.")
				return
			}
			fmt.Printf("%-10s %-25s %-10s %-30s %s\n", "ID", "DEPENDENCY", "ECOSYSTEM", "TARGET", "REASON")
			fmt.Println(strings.Repeat("-", 90))
			for _, p := range patches {
				fmt.Printf("%-10s %-25s %-10s %-30s %s\n", p.ID, p.Dependency, p.Ecosystem, p.PatchTarget, p.Reason)
			}
			return

		case "add":
			fs := flag.NewFlagSet("patch add", flag.ContinueOnError)
			dep := fs.String("dep", "", "dependency name (required)")
			target := fs.String("target", "", "fork repository URL, branch, or patch file (required)")
			ecosystem := fs.String("ecosystem", "", "ecosystem identifier (go, npm, cargo, python, custom)")
			manifest := fs.String("manifest", "", "manifest file (e.g. go.mod, package.json)")
			issue := fs.String("issue", "", "upstream issue URL being tracked")
			reason := fs.String("reason", "", "reason for patching locally")
			if err := fs.Parse(os.Args[3:]); err != nil {
				os.Exit(1)
			}
			if strings.TrimSpace(*dep) == "" || strings.TrimSpace(*target) == "" {
				fmt.Fprintln(os.Stderr, "error: patch add requires --dep and --target")
				fmt.Fprintln(os.Stderr, "Usage: bugrouter patch add --dep <d> --target <fork> [--ecosystem <e>] [--issue <url>] [--manifest <m>] [--reason <r>]")
				os.Exit(1)
			}
			r := strings.TrimSpace(*reason)
			if r == "" {
				r = "Local patch tracked in bugrouter ledger"
			}
			patch, err := patchStore.Record(*dep, *ecosystem, *target, *manifest, *issue, r)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: record patch: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Recorded dependency patch %s for %s (%s) in patch ledger.\n", patch.ID, patch.Dependency, patch.PatchTarget)
			return

		case "rm":
			if len(os.Args) < 4 {
				fmt.Fprintln(os.Stderr, "error: patch rm requires <id-or-dep>")
				fmt.Fprintln(os.Stderr, "Usage: bugrouter patch rm <id-or-dep>")
				os.Exit(1)
			}
			target := os.Args[3]
			if err := patchStore.Remove(target); err != nil {
				fmt.Fprintf(os.Stderr, "error: remove patch: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Removed patch %q from patch ledger.\n", target)
			return

		default:
			fmt.Fprintf(os.Stderr, "error: unknown patch subcommand %q\n", os.Args[2])
			fmt.Fprintln(os.Stderr, "Usage: bugrouter patch <list|add|rm> [arguments...]")
			os.Exit(1)
		}

	case "draft":
		fs := flag.NewFlagSet("draft", flag.ContinueOnError)
		title := fs.String("title", "", "bug report title")
		summary := fs.String("summary", "", "summary of the issue")
		steps := fs.String("steps", "", "steps to reproduce")
		logs := fs.String("logs", "", "error logs or console output")
		bodyFile := fs.String("body-file", "", "path to markdown body file or '-' for stdin")
		fromParked := fs.String("from-parked", "", "hydrate draft from previously parked bug ID")
		relatedDep := fs.String("related-dep", "", "secondary/related dependency to query for correlated stack evidence")
		timeout := fs.Duration("timeout", 15*time.Second, "request and probe timeout duration")
		strictQuality := fs.Bool("strict-quality", false, "reject draft if quality checks fail")
		verifyCmd := fs.String("verify-cmd", "", "run bounded command to verify reproduction and attach proof")
		withTelemetry := fs.Bool("with-telemetry", false, "collect and attach local hardware/OS telemetry")
		jsonOut := fs.Bool("json", false, "output structured JSON")
		noCache := fs.Bool("no-cache", false, "disable disk cache")
		if err := fs.Parse(os.Args[2:]); err != nil {
			os.Exit(1)
		}

		var parkedBug *adapter.ParkedBug
		if *fromParked != "" {
			parkStore := adapter.NewParkedStore("")
			p, err := parkStore.Get(*fromParked)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: load parked bug %s: %v\n", *fromParked, err)
				os.Exit(1)
			}
			parkedBug = p
			if *title == "" {
				*title = parkedBug.Title
			}
			if *logs == "" && string(parkedBug.ErrorSnippet) != "" {
				*logs = string(parkedBug.ErrorSnippet)
			}
			if *summary == "" {
				if string(parkedBug.WorkaroundNote) != "" {
					*summary = fmt.Sprintf("Discovered anomaly in %s: %s\n\nWorkaround/Notes: %s", parkedBug.Dependency, parkedBug.Title, string(parkedBug.WorkaroundNote))
				} else {
					*summary = fmt.Sprintf("Discovered anomaly in %s: %s", parkedBug.Dependency, parkedBug.Title)
				}
			}
			if *steps == "" && parkedBug.WorkspaceFile != "" {
				*steps = fmt.Sprintf("Observed in %s", parkedBug.WorkspaceFile)
			}
			if *relatedDep == "" && parkedBug.RelatedDependency != "" {
				*relatedDep = parkedBug.RelatedDependency
			}
		}

		args := fs.Args()
		var targetQuery string
		if len(args) > 0 {
			targetQuery = args[0]
		} else if parkedBug != nil {
			targetQuery = parkedBug.Dependency
		} else {
			fmt.Fprintln(os.Stderr, "error: draft requires a target query or --from-parked <id>")
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
		target, err := resolveTarget(ctx, httpClient, targetQuery, *noCache)
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

		var proof *verifier.VerificationProof
		if *verifyCmd != "" {
			p, err := verifier.Verify(ctx, verifier.VerifyOptions{
				Command: *verifyCmd,
				Timeout: *timeout,
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: verify reproduction: %v\n", err)
				os.Exit(1)
			}
			proof = p
			if *logs == "" && proof.ScrubbedOutput != "" {
				*logs = string(proof.ScrubbedOutput)
			}
		}

		var sysTelemetry *telemetry.SystemTelemetry
		if *withTelemetry {
			t := telemetry.Collect(ctx)
			sysTelemetry = &t
		}

		var relatedIssues []dedup.ExistingIssue
		if *relatedDep != "" {
			relTarget, relErr := resolveTarget(ctx, httpClient, *relatedDep, *noCache)
			if relErr == nil && relTarget != nil {
				searchQuery := scrubber.Scrub(*title + " " + *summary)
				relDups, err := finder.FindDuplicates(ctx, *relTarget, searchQuery)
				if err == nil {
					relatedIssues = relDups
				}
			}
		}

		draft, err := adapter.BuildDraft(adapter.DraftInput{
			Target:            *target,
			Title:             *title,
			Summary:           *summary,
			StepsToReproduce:  *steps,
			Logs:              *logs,
			Template:          schema,
			Duplicates:        dups,
			Verification:      proof,
			Telemetry:         sysTelemetry,
			RelatedDependency: *relatedDep,
			RelatedIssues:     relatedIssues,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: build draft: %v\n", err)
			os.Exit(1)
		}

		if *strictQuality && !draft.Quality.Passed {
			if *jsonOut {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(draft.Quality); err != nil {
					fmt.Fprintf(os.Stderr, "encode json: %v\n", err)
				}
			} else {
				fmt.Fprintf(os.Stderr, "error: strict quality gate failed (Score: %d/100, Grade: %s):\n", draft.Quality.Score, draft.Quality.Grade)
				for _, issue := range draft.Quality.Issues {
					fmt.Fprintf(os.Stderr, "  - %s\n", issue)
				}
			}
			os.Exit(2)
		}

		draftStore := adapter.NewDraftStore("")
		savedPath, err := draftStore.Save(draft)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: save draft: %v\n", err)
			os.Exit(1)
		}

		if parkedBug != nil {
			parkedBug.Status = "triaged"
			parkStore := adapter.NewParkedStore("")
			if parkSaveErr := parkStore.Save(parkedBug); parkSaveErr != nil {
				// Non-fatal status update failure
			}
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

	case "report":
		fs := flag.NewFlagSet("report", flag.ContinueOnError)
		title := fs.String("title", "", "bug report title")
		summary := fs.String("summary", "", "summary of the issue")
		steps := fs.String("steps", "", "steps to reproduce")
		expected := fs.String("expected", "", "expected behavior")
		actual := fs.String("actual", "", "actual behavior")
		logs := fs.String("logs", "", "error logs or console output")
		withTelemetry := fs.Bool("with-telemetry", false, "collect hardware/OS telemetry (default enabled)")
		noTelemetry := fs.Bool("no-telemetry", false, "disable hardware/OS telemetry collection")
		jsonOut := fs.Bool("json", false, "output structured JSON")
		noCache := fs.Bool("no-cache", false, "disable disk cache")
		timeout := fs.Duration("timeout", 20*time.Second, "request and probe timeout duration")
		if err := fs.Parse(os.Args[2:]); err != nil {
			os.Exit(1)
		}

		args := fs.Args()
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "error: report requires a target query")
			os.Exit(1)
		}

		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()

		opts := ReportOptions{
			Query:            args[0],
			Title:            *title,
			Summary:          *summary,
			StepsToReproduce: *steps,
			ExpectedBehavior: *expected,
			ActualBehavior:   *actual,
			Logs:             *logs,
			WithTelemetry:    *withTelemetry,
			NoTelemetry:      *noTelemetry,
			JSON:             *jsonOut,
			NoCache:          *noCache,
			Timeout:          *timeout,
		}

		draft, stagedPath, err := runGuidedReport(ctx, os.Stdin, os.Stdout, nil, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if encErr := enc.Encode(map[string]any{
				"draft":       draft,
				"staged_path": stagedPath,
			}); encErr != nil {
				fmt.Fprintf(os.Stderr, "error: encode json: %v\n", encErr)
				os.Exit(1)
			}
		}
		return

	case "agent":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: bugrouter agent <triage|verify|telemetry> [arguments]")
			os.Exit(1)
		}

		if os.Args[2] == "telemetry" {
			fs := flag.NewFlagSet("agent telemetry", flag.ContinueOnError)
			fs.Bool("json", false, "output structured JSON")
			timeout := fs.Duration("timeout", 5*time.Second, "telemetry collection timeout duration")
			if err := fs.Parse(os.Args[3:]); err != nil {
				os.Exit(1)
			}

			ctx, cancel := context.WithTimeout(context.Background(), *timeout)
			defer cancel()

			t := telemetry.Collect(ctx)
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(t); err != nil {
				fmt.Fprintf(os.Stderr, "error: encode json: %v\n", err)
				os.Exit(1)
			}
			return
		}

		if os.Args[2] == "verify" {
			fs := flag.NewFlagSet("agent verify", flag.ContinueOnError)
			cmd := fs.String("cmd", "", "reproduction command to execute")
			timeout := fs.Duration("timeout", 15*time.Second, "execution timeout duration")
			expectExit := fs.Int("expect-exit", 0, "expected exit code (0 means any non-zero exit code is considered reproduced)")
			workDir := fs.String("work-dir", "", "working directory for reproduction command")
			if err := fs.Parse(os.Args[3:]); err != nil {
				os.Exit(1)
			}

			if strings.TrimSpace(*cmd) == "" {
				fmt.Fprintln(os.Stderr, "error: --cmd is required")
				os.Exit(1)
			}

			ctx := context.Background()
			proof, err := verifier.Verify(ctx, verifier.VerifyOptions{
				Command:    *cmd,
				Timeout:    *timeout,
				ExpectExit: *expectExit,
				WorkDir:    *workDir,
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: verify: %v\n", err)
				os.Exit(1)
			}

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(proof); err != nil {
				fmt.Fprintf(os.Stderr, "error: encode json: %v\n", err)
				os.Exit(1)
			}
			return
		}

		var agentArgs []string
		if os.Args[2] == "triage" {
			agentArgs = os.Args[3:]
		} else if strings.HasPrefix(os.Args[2], "-") {
			agentArgs = os.Args[2:]
		} else {
			fmt.Fprintln(os.Stderr, "Usage: bugrouter agent <triage|verify> [arguments]")
			os.Exit(1)
		}

		fs := flag.NewFlagSet("agent triage", flag.ContinueOnError)
		logFile := fs.String("log-file", "", "path to crash log file or '-' for stdin")
		query := fs.String("query", "", "target package name, binary name, or repo query override")
		title := fs.String("title", "", "bug report title override for duplicate search")
		timeout := fs.Duration("timeout", 15*time.Second, "request and probe timeout duration")
		noCache := fs.Bool("no-cache", false, "disable disk cache")
		if err := fs.Parse(agentArgs); err != nil {
			os.Exit(1)
		}

		var rawLog string
		if *logFile != "" {
			var r io.Reader
			if *logFile == "-" {
				r = os.Stdin
			} else {
				f, err := os.Open(*logFile)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error: open log file %s: %v\n", *logFile, err)
					os.Exit(1)
				}
				defer f.Close()
				r = f
			}
			const maxLogBytes = 512 * 1024
			data, err := io.ReadAll(io.LimitReader(r, maxLogBytes))
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: read log file: %v\n", err)
				os.Exit(1)
			}
			rawLog = string(data)
		} else if *query == "" {
			const maxLogBytes = 512 * 1024
			data, err := io.ReadAll(io.LimitReader(os.Stdin, maxLogBytes))
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: read stdin: %v\n", err)
				os.Exit(1)
			}
			rawLog = string(data)
		}

		candidates := resolver.ExtractTargetsFromLog(rawLog)
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()

		httpClient := httpx.NewClient(0)
		var resolvedTarget *resolver.Target

		if *query != "" {
			t, err := resolveTarget(ctx, httpClient, *query, *noCache)
			if err == nil {
				resolvedTarget = t
			}
		} else {
			for _, c := range candidates {
				t, err := resolveTarget(ctx, httpClient, c.Query, *noCache)
				if err == nil && t != nil {
					resolvedTarget = t
					break
				}
			}
		}

		var schema *introspector.TemplateSchema
		var dups []dedup.ExistingIssue

		if resolvedTarget != nil {
			intro := introspector.New(httpClient)
			if !*noCache {
				intro.WithCache(cache.NewStore("", 0))
			}
			s, err := intro.Introspect(ctx, *resolvedTarget)
			if err == nil {
				schema = s
			}

			searchTitle := *title
			if searchTitle == "" && len(candidates) > 0 {
				searchTitle = candidates[0].Evidence
			}
			if searchTitle != "" {
				finder := dedup.NewFinder(httpClient)
				d, err := finder.FindDuplicates(ctx, *resolvedTarget, scrubber.Scrub(searchTitle))
				if err == nil {
					dups = d
				}
			}
		}

		var nextActions []string
		if resolvedTarget != nil {
			nextActions = append(nextActions, fmt.Sprintf("Run 'bugrouter draft --title <title> --steps <steps> %s' to stage a verified bug ticket", resolvedTarget.CanonicalName))
			if len(dups) > 0 {
				nextActions = append(nextActions, "Review potential upstream duplicates before submitting")
			}
			if schema != nil && schema.Name != "" {
				nextActions = append(nextActions, fmt.Sprintf("Fill required fields defined in upstream issue template: %s", schema.Name))
			}
		} else {
			nextActions = append(nextActions, "No candidates could be automatically resolved to an upstream tracker. Specify target manually via '--query <target>'")
		}

		if dups == nil {
			dups = []dedup.ExistingIssue{}
		}
		if candidates == nil {
			candidates = []resolver.TraceCandidate{}
		}

		result := AgentTriageResult{
			Candidates:          candidates,
			ResolvedTarget:      resolvedTarget,
			TemplateSchema:      schema,
			PotentialDuplicates: dups,
			ScrubbedLog:         scrubber.Scrub(rawLog),
			NextActions:         nextActions,
		}

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			fmt.Fprintf(os.Stderr, "error: encode json: %v\n", err)
			os.Exit(1)
		}
		return

	case "crash-log":
		fs := flag.NewFlagSet("crash-log", flag.ContinueOnError)
		jsonOut := fs.Bool("json", false, "output structured JSON")
		query := fs.String("query", "", "target package name, binary name, or repo query override")
		title := fs.String("title", "", "bug report title override for duplicate search")
		timeout := fs.Duration("timeout", 15*time.Second, "request and probe timeout duration")
		noCache := fs.Bool("no-cache", false, "disable disk cache")
		if err := fs.Parse(os.Args[2:]); err != nil {
			os.Exit(1)
		}

		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()

		rawLog, suspect, err := resolver.ReadLatestCrash(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: read system crash log: %v\n", err)
			os.Exit(1)
		}

		candidates := resolver.ExtractTargetsFromLog(rawLog)
		if suspect != "" {
			found := false
			for _, c := range candidates {
				if strings.EqualFold(c.Query, suspect) {
					found = true
					break
				}
			}
			if !found {
				candidates = append([]resolver.TraceCandidate{{
					Query:    suspect,
					Source:   "os_crash_suspect",
					Evidence: "OS post-mortem crash log suspect binary: " + suspect,
				}}, candidates...)
			}
		}

		httpClient := httpx.NewClient(0)
		var resolvedTarget *resolver.Target

		if *query != "" {
			t, err := resolveTarget(ctx, httpClient, *query, *noCache)
			if err == nil {
				resolvedTarget = t
			}
		} else if suspect != "" {
			t, err := resolveTarget(ctx, httpClient, suspect, *noCache)
			if err == nil {
				resolvedTarget = t
			}
		}

		if resolvedTarget == nil {
			for _, c := range candidates {
				t, err := resolveTarget(ctx, httpClient, c.Query, *noCache)
				if err == nil && t != nil {
					resolvedTarget = t
					break
				}
			}
		}

		var schema *introspector.TemplateSchema
		var dups []dedup.ExistingIssue

		if resolvedTarget != nil {
			intro := introspector.New(httpClient)
			if !*noCache {
				intro.WithCache(cache.NewStore("", 0))
			}
			s, err := intro.Introspect(ctx, *resolvedTarget)
			if err == nil {
				schema = s
			}

			searchTitle := *title
			if searchTitle == "" && suspect != "" {
				searchTitle = fmt.Sprintf("crash in %s", suspect)
			} else if searchTitle == "" && len(candidates) > 0 {
				searchTitle = candidates[0].Evidence
			}
			if searchTitle != "" {
				finder := dedup.NewFinder(httpClient)
				d, err := finder.FindDuplicates(ctx, *resolvedTarget, scrubber.Scrub(searchTitle))
				if err == nil {
					dups = d
				}
			}
		}

		var nextActions []string
		if resolvedTarget != nil {
			nextActions = append(nextActions, fmt.Sprintf("Run 'bugrouter draft --title <title> --steps <steps> %s' to stage a verified bug ticket", resolvedTarget.CanonicalName))
			if len(dups) > 0 {
				nextActions = append(nextActions, "Review potential upstream duplicates before submitting")
			}
			if schema != nil && schema.Name != "" {
				nextActions = append(nextActions, fmt.Sprintf("Fill required fields defined in upstream issue template: %s", schema.Name))
			}
		} else {
			nextActions = append(nextActions, "No candidates could be automatically resolved to an upstream tracker. Specify target manually via '--query <target>'")
		}

		if dups == nil {
			dups = []dedup.ExistingIssue{}
		}
		if candidates == nil {
			candidates = []resolver.TraceCandidate{}
		}

		scrubbed := scrubber.Scrub(rawLog)

		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(map[string]any{
				"suspect":              suspect,
				"candidates":           candidates,
				"resolved_target":      resolvedTarget,
				"template_schema":      schema,
				"potential_duplicates": dups,
				"scrubbed_log":         scrubbed,
				"next_actions":         nextActions,
			}); err != nil {
				fmt.Fprintf(os.Stderr, "error: encode json: %v\n", err)
				os.Exit(1)
			}
			return
		}

		fmt.Println("=== Latest System Crash Log ===")
		if suspect != "" {
			fmt.Printf("Suspect Binary / Package: %s\n", suspect)
		}
		if resolvedTarget != nil {
			fmt.Printf("Resolved Upstream Target: %s (%s [%s])\n", resolvedTarget.CanonicalName, resolvedTarget.Tracker.URL, resolvedTarget.Tracker.Protocol)
		} else {
			fmt.Println("Resolved Upstream Target: (none)")
		}
		if len(candidates) > 0 {
			fmt.Printf("\nExtracted Trace Candidates (%d found):\n", len(candidates))
			for _, c := range candidates {
				fmt.Printf("  - [%s] %s - %s\n", c.Source, c.Query, c.Evidence)
			}
		}
		if len(dups) > 0 {
			fmt.Printf("\nPotential Upstream Duplicates (%d found):\n", len(dups))
			for _, d := range dups {
				fmt.Printf("  - [%s] (%.0f%% match) %s\n    %s\n", d.State, d.Score*100, d.Title, d.URL)
			}
		}
		if len(nextActions) > 0 {
			fmt.Println("\nRecommended Next Actions:")
			for _, a := range nextActions {
				fmt.Printf("  * %s\n", a)
			}
		}
		fmt.Printf("\nScrubbed Crash Log Sample:\n%s\n", scrubbed)
		return

	case "telemetry":
		fs := flag.NewFlagSet("telemetry", flag.ContinueOnError)
		jsonOut := fs.Bool("json", false, "output structured JSON")
		timeout := fs.Duration("timeout", 5*time.Second, "telemetry collection timeout duration")
		if err := fs.Parse(os.Args[2:]); err != nil {
			os.Exit(1)
		}

		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()

		t := telemetry.Collect(ctx)
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(t); err != nil {
				fmt.Fprintf(os.Stderr, "error: encode json: %v\n", err)
				os.Exit(1)
			}
			return
		}

		fmt.Println(telemetry.FormatMarkdown(t))
		return

	case "stack":
		fs := flag.NewFlagSet("stack", flag.ContinueOnError)
		dir := fs.String("dir", ".", "workspace directory to scan")
		checkUpstream := fs.Bool("check-upstream", false, "query upstream trackers for active bugs matching dependencies")
		jsonOut := fs.Bool("json", false, "output structured JSON")
		noCache := fs.Bool("no-cache", false, "disable disk cache")
		timeout := fs.Duration("timeout", 30*time.Second, "request and scan timeout duration")
		if err := fs.Parse(os.Args[2:]); err != nil {
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
		return

	case "serve":
		fs := flag.NewFlagSet("serve", flag.ContinueOnError)
		addr := fs.String("addr", ":8080", "HTTP server listen address")
		draftsDir := fs.String("drafts-dir", "", "drafts storage directory")
		authToken := fs.String("auth-token", "", "Bearer auth token (falls back to BUGROUTER_CLOUD_TOKEN)")
		auditLog := fs.String("audit-log", "", "audit log path (default: XDG state path)")
		webhookURL := fs.String("webhook-url", "", "webhook delivery URL (falls back to BUGROUTER_WEBHOOK_URL)")
		webhookSecret := fs.String("webhook-secret", "", "HMAC secret for webhook delivery (falls back to BUGROUTER_WEBHOOK_SECRET)")
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
	fmt.Fprintln(os.Stderr, "  park [--snippet <s>] [--workaround <w>] [--file <f>] [--related-dep <pkg>] [--json] <dependency> <title>")
	fmt.Fprintln(os.Stderr, "                              Instantly park a 3rd-party anomaly in <5ms without hijacking session")
	fmt.Fprintln(os.Stderr, "  patch list [--json]         List tracked dependency patches and temporary forks")
	fmt.Fprintln(os.Stderr, "  patch add --dep <d> --target <fork> [--ecosystem <e>] [--issue <url>] [--manifest <m>] [--reason <r>]")
	fmt.Fprintln(os.Stderr, "                              Record a temporary dependency fork/patch in the ledger")
	fmt.Fprintln(os.Stderr, "  patch rm <id-or-dep>        Remove a dependency patch from the ledger")
	fmt.Fprintln(os.Stderr, "  draft [--title <t>] [--summary <s>] [--steps <st>] [--logs <l>] [--from-parked <id>] [--related-dep <pkg>]")
	fmt.Fprintln(os.Stderr, "        [--verify-cmd <cmd>] [--with-telemetry] [--body-file <path>] [--strict-quality] [--timeout <dur>] [--json] [--no-cache] [<q>]")
	fmt.Fprintln(os.Stderr, "                              Stage bug report draft and generate submission URLs")
	fmt.Fprintln(os.Stderr, "  report [--title <t>] [--summary <s>] [--steps <st>] [--expected <ex>] [--actual <ac>] [--logs <l>]")
	fmt.Fprintln(os.Stderr, "         [--with-telemetry] [--no-telemetry] [--json] [--no-cache] [--timeout <dur>] <q>")
	fmt.Fprintln(os.Stderr, "                              Interactive guided bug reporting wizard with live anti-slop quality linting")
	fmt.Fprintln(os.Stderr, "  telemetry [--json] [--timeout <dur>]")
	fmt.Fprintln(os.Stderr, "                              Inspect local operating system and hardware telemetry")
	fmt.Fprintln(os.Stderr, "  crash-log [--json] [--query <target>] [--no-cache] [--timeout <dur>]")
	fmt.Fprintln(os.Stderr, "                              Inspect and triage the latest native OS post-mortem crash log")
	fmt.Fprintln(os.Stderr, "  agent triage [--log-file <path>] [--query <target>] [--title <t>] [--timeout <dur>]")
	fmt.Fprintln(os.Stderr, "                              Autonomous triage of crash logs outputting machine-parseable JSON")
	fmt.Fprintln(os.Stderr, "  agent verify --cmd <command> [--timeout <dur>] [--expect-exit <code>] [--work-dir <dir>]")
	fmt.Fprintln(os.Stderr, "                              Bounded reproduction execution and deterministic proof generation")
	fmt.Fprintln(os.Stderr, "  agent telemetry [--json] [--timeout <dur>]")
	fmt.Fprintln(os.Stderr, "                              Inspect local telemetry as machine-parseable JSON")
	fmt.Fprintln(os.Stderr, "  stack [--dir <dir>] [--check-upstream] [--json] [--no-cache] [--timeout <dur>]")
	fmt.Fprintln(os.Stderr, "                              Scan workspace dependency manifests and downstream bug radar")
	fmt.Fprintln(os.Stderr, "  serve [--addr <addr>] [--drafts-dir <dir>] [--auth-token <tok>] [--audit-log <path>] [--webhook-url <url>] [--webhook-secret <sec>]")
	fmt.Fprintln(os.Stderr, "                              Start Cloud Control Plane HTTP daemon and Web UI")
	fmt.Fprintln(os.Stderr, "  mcp                         Start Model Context Protocol (MCP) stdio server")
}
