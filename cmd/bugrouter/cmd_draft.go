package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/riccivr/bugrouter/internal/adapter"
	"github.com/riccivr/bugrouter/internal/cache"
	"github.com/riccivr/bugrouter/internal/dedup"
	"github.com/riccivr/bugrouter/internal/httpx"
	"github.com/riccivr/bugrouter/internal/introspector"
	"github.com/riccivr/bugrouter/internal/scrubber"
	"github.com/riccivr/bugrouter/internal/telemetry"
	"github.com/riccivr/bugrouter/internal/verifier"
)

// ReportOptions contains configuration flags for the interactive guided bug report wizard.
type ReportOptions struct {
	Query            string
	Title            string
	Summary          string
	StepsToReproduce string
	ExpectedBehavior string
	ActualBehavior   string
	Logs             string
	NoTelemetry      bool
	JSON             bool
	NoCache          bool
	Timeout          time.Duration
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

func runGuidedReport(ctx context.Context, in io.Reader, out io.Writer, httpClient *httpx.Client, opts ReportOptions) (*adapter.StagedDraft, string, error) {
	if httpClient == nil {
		httpClient = httpx.NewClient(0)
	}

	if opts.Query == "" {
		return nil, "", errors.New("report requires a target query")
	}

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

	intro := introspector.New(httpClient)
	if !opts.NoCache {
		intro = intro.WithCache(cache.NewStore("", 0))
	}
	schema, introErr := intro.Introspect(ctx, *target)
	if introErr != nil {
		schema = nil
	}

	var sysTelemetry *telemetry.SystemTelemetry
	if !opts.NoTelemetry {
		if !opts.JSON {
			fmt.Fprintf(out, "==> Collecting hardware and OS telemetry...\n")
		}
		t := telemetry.Collect(ctx)
		sysTelemetry = &t
	}

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

func cmdDraft(args []string) {
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
	if err := fs.Parse(args); err != nil {
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

	posArgs := fs.Args()
	var targetQuery string
	if len(posArgs) > 0 {
		targetQuery = posArgs[0]
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
		intro = intro.WithCache(cache.NewStore("", 0))
	}
	schema, err := intro.Introspect(ctx, *target)
	if err != nil {
		schema = nil
	}

	finder := dedup.NewFinder(httpClient)
	dups, err := finder.FindDuplicates(ctx, *target, scrubber.Scrub(*title))
	if err != nil {
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
			fmt.Fprintf(os.Stderr, "warning: update parked bug %s status: %v\n", parkedBug.ID, parkSaveErr)
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
}

func cmdReport(args []string) {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	title := fs.String("title", "", "bug report title")
	summary := fs.String("summary", "", "summary of the issue")
	steps := fs.String("steps", "", "steps to reproduce")
	expected := fs.String("expected", "", "expected behavior")
	actual := fs.String("actual", "", "actual behavior")
	logs := fs.String("logs", "", "error logs or console output")
	fs.Bool("with-telemetry", false, "collect hardware/OS telemetry (default enabled)")
	noTelemetry := fs.Bool("no-telemetry", false, "disable hardware/OS telemetry collection")
	jsonOut := fs.Bool("json", false, "output structured JSON")
	noCache := fs.Bool("no-cache", false, "disable disk cache")
	timeout := fs.Duration("timeout", 20*time.Second, "request and probe timeout duration")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	posArgs := fs.Args()
	if len(posArgs) < 1 {
		fmt.Fprintln(os.Stderr, "error: report requires a target query")
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	opts := ReportOptions{
		Query:            posArgs[0],
		Title:            *title,
		Summary:          *summary,
		StepsToReproduce: *steps,
		ExpectedBehavior: *expected,
		ActualBehavior:   *actual,
		Logs:             *logs,
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
}
