package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/riccivr/bugrouter/internal/cache"
	"github.com/riccivr/bugrouter/internal/dedup"
	"github.com/riccivr/bugrouter/internal/httpx"
	"github.com/riccivr/bugrouter/internal/introspector"
	"github.com/riccivr/bugrouter/internal/resolver"
	"github.com/riccivr/bugrouter/internal/scrubber"
	"github.com/riccivr/bugrouter/internal/telemetry"
	"github.com/riccivr/bugrouter/internal/verifier"
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

func runVerify(ctx context.Context, out io.Writer, errOut io.Writer, args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(errOut)
	cmd := fs.String("cmd", "", "reproduction command to execute")
	timeout := fs.Duration("timeout", 15*time.Second, "execution timeout duration")
	expectExit := fs.Int("expect-exit", 0, "expected exit code (0 means any non-zero exit code is considered reproduced)")
	workDir := fs.String("work-dir", "", "working directory for reproduction command")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	if strings.TrimSpace(*cmd) == "" {
		fmt.Fprintln(errOut, "error: --cmd is required")
		return 1
	}

	if ctx == nil {
		ctx = context.Background()
	}
	proof, err := verifier.Verify(ctx, verifier.VerifyOptions{
		Command:    *cmd,
		Timeout:    *timeout,
		ExpectExit: *expectExit,
		WorkDir:    *workDir,
	})
	if err != nil {
		fmt.Fprintf(errOut, "error: verify: %v\n", err)
		return 1
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(proof); err != nil {
		fmt.Fprintf(errOut, "error: encode json: %v\n", err)
		return 1
	}
	return 0
}

func runTriage(ctx context.Context, httpClient *httpx.Client, in io.Reader, out io.Writer, errOut io.Writer, args []string) int {
	fs := flag.NewFlagSet("triage", flag.ContinueOnError)
	fs.SetOutput(errOut)
	logFile := fs.String("log-file", "", "path to crash log file or '-' for stdin")
	query := fs.String("query", "", "target package name, binary name, or repo query override")
	title := fs.String("title", "", "bug report title override for duplicate search")
	summaryMD := fs.Bool("summary-md", false, "output GitHub-Flavored Markdown summary")
	timeout := fs.Duration("timeout", 15*time.Second, "request and probe timeout duration")
	noCache := fs.Bool("no-cache", false, "disable disk cache")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	var rawLog string
	if *logFile != "" {
		var r io.Reader
		if *logFile == "-" {
			r = in
		} else {
			f, err := os.Open(*logFile)
			if err != nil {
				fmt.Fprintf(errOut, "error: open log file %s: %v\n", *logFile, err)
				return 1
			}
			defer f.Close()
			r = f
		}
		const maxLogBytes = 512 * 1024
		data, err := io.ReadAll(io.LimitReader(r, maxLogBytes))
		if err != nil {
			fmt.Fprintf(errOut, "error: read log file: %v\n", err)
			return 1
		}
		rawLog = string(data)
	} else if *query == "" {
		const maxLogBytes = 512 * 1024
		data, err := io.ReadAll(io.LimitReader(in, maxLogBytes))
		if err != nil {
			fmt.Fprintf(errOut, "error: read stdin: %v\n", err)
			return 1
		}
		rawLog = string(data)
	}

	candidates := resolver.ExtractTargetsFromLog(rawLog)
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	if httpClient == nil {
		httpClient = httpx.NewClient(0)
	}
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

	if *summaryMD {
		var sb strings.Builder
		sb.WriteString("### 🔍 bugrouter Crash Log Triage Summary\n\n")

		if result.ResolvedTarget != nil {
			sb.WriteString(fmt.Sprintf("**Resolved Upstream Target:** `%s` (%s [%s])\n\n",
				result.ResolvedTarget.CanonicalName, result.ResolvedTarget.Tracker.URL, result.ResolvedTarget.Tracker.Protocol))
		} else {
			sb.WriteString("**Resolved Upstream Target:** _None automatically resolved_\n\n")
		}

		if len(result.Candidates) > 0 {
			sb.WriteString("#### Extracted Trace Candidates\n\n")
			sb.WriteString("| Source | Candidate Query | Evidence |\n")
			sb.WriteString("| :--- | :--- | :--- |\n")
			for _, c := range result.Candidates {
				sb.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` |\n", c.Source, c.Query, c.Evidence))
			}
			sb.WriteString("\n")
		}

		if len(result.PotentialDuplicates) > 0 {
			sb.WriteString(fmt.Sprintf("#### Potential Upstream Duplicates (%d found)\n\n", len(result.PotentialDuplicates)))
			for _, d := range result.PotentialDuplicates {
				sb.WriteString(fmt.Sprintf("- [%s] (%.0f%% match) [%s](%s)\n", d.State, d.Score*100, d.Title, d.URL))
			}
			sb.WriteString("\n")
		}

		if len(result.NextActions) > 0 {
			sb.WriteString("#### Recommended Next Actions\n\n")
			for _, action := range result.NextActions {
				sb.WriteString(fmt.Sprintf("- %s\n", action))
			}
			sb.WriteString("\n")
		}

		fmt.Fprint(out, sb.String())
		return 0
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintf(errOut, "error: encode json: %v\n", err)
		return 1
	}
	return 0
}

func cmdTriage(args []string) {
	if code := runTriage(context.Background(), nil, os.Stdin, os.Stdout, os.Stderr, args); code != 0 {
		os.Exit(code)
	}
}

func cmdVerify(args []string) {
	if code := runVerify(context.Background(), os.Stdout, os.Stderr, args); code != 0 {
		os.Exit(code)
	}
}

func cmdAgent(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: bugrouter agent <triage|verify|telemetry> [arguments]")
		os.Exit(1)
	}

	if args[0] == "telemetry" {
		fs := flag.NewFlagSet("agent telemetry", flag.ContinueOnError)
		fs.Bool("json", false, "output structured JSON")
		timeout := fs.Duration("timeout", 5*time.Second, "telemetry collection timeout duration")
		if err := fs.Parse(args[1:]); err != nil {
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

	if args[0] == "verify" {
		if code := runVerify(context.Background(), os.Stdout, os.Stderr, args[1:]); code != 0 {
			os.Exit(code)
		}
		return
	}

	if args[0] == "triage" {
		if code := runTriage(context.Background(), nil, os.Stdin, os.Stdout, os.Stderr, args[1:]); code != 0 {
			os.Exit(code)
		}
		return
	}

	if strings.HasPrefix(args[0], "-") {
		if code := runTriage(context.Background(), nil, os.Stdin, os.Stdout, os.Stderr, args); code != 0 {
			os.Exit(code)
		}
		return
	}

	fmt.Fprintln(os.Stderr, "Usage: bugrouter agent <triage|verify|telemetry> [arguments]")
	os.Exit(1)
}

func cmdCrashLog(args []string) {
	fs := flag.NewFlagSet("crash-log", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "output structured JSON")
	query := fs.String("query", "", "target package name, binary name, or repo query override")
	title := fs.String("title", "", "bug report title override for duplicate search")
	timeout := fs.Duration("timeout", 15*time.Second, "request and probe timeout duration")
	noCache := fs.Bool("no-cache", false, "disable disk cache")
	if err := fs.Parse(args); err != nil {
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
}

func cmdTelemetry(args []string) {
	fs := flag.NewFlagSet("telemetry", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "output structured JSON")
	timeout := fs.Duration("timeout", 5*time.Second, "telemetry collection timeout duration")
	if err := fs.Parse(args); err != nil {
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
}
