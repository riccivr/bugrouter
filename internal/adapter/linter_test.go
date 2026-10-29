package adapter

import (
	"strings"
	"testing"
)

func TestLintDraftHighSignal(t *testing.T) {
	in := DraftInput{
		Title:            "Null pointer dereference during connection pool initialization",
		Summary:          "When initializing the connection pool with zero max connections, a panic occurs.",
		StepsToReproduce: "1. Instantiate pool with MaxConns=0\n2. Call pool.Acquire()\n3. Observe panic",
		Logs:             "panic: runtime error: invalid memory address or nil pointer dereference",
	}

	report := LintDraft(in)
	if report.Score != 100 {
		t.Errorf("expected Score=100, got %d", report.Score)
	}
	if report.Grade != "ready" {
		t.Errorf("expected Grade=ready, got %s", report.Grade)
	}
	if !report.Passed {
		t.Errorf("expected Passed=true, got false (issues: %v)", report.Issues)
	}
	if len(report.Issues) != 0 {
		t.Errorf("expected 0 issues, got: %v", report.Issues)
	}
}

func TestLintDraftAISlop(t *testing.T) {
	slopPhrases := []string{
		"as an ai",
		"as a large language model",
		"i hope this message finds you",
		"certainly!",
		"here is the bug report",
		"delve into",
		"it is important to note",
	}

	for _, phrase := range slopPhrases {
		in := DraftInput{
			Title:            "Memory leak in worker connection pool",
			Summary:          "Detailed summary explaining the issue: " + phrase + " we observed high memory usage.",
			StepsToReproduce: "1. Start worker daemon\n2. Stream 100k records\n3. Observe OOM kill",
			Logs:             "FATAL: out of memory",
		}

		report := LintDraft(in)
		if report.Passed {
			t.Errorf("expected Passed=false for slop phrase %q, got true", phrase)
		}
		if report.Score != 65 {
			t.Errorf("expected Score=65 (-35 deduction), got %d", report.Score)
		}
		found := false
		for _, issue := range report.Issues {
			if strings.Contains(issue, "conversational AI filler") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected conversational AI filler issue for %q, got %v", phrase, report.Issues)
		}
	}
}

func TestLintDraftIncomplete(t *testing.T) {
	// 1. Ultra-short title
	inShortTitle := DraftInput{
		Title:            "crash bug",
		Summary:          "Detailed summary explaining the issue context thoroughly.",
		StepsToReproduce: "1. Run command with flag --verbose\n2. Check exit code",
		Logs:             "exit status 1",
	}
	rep1 := LintDraft(inShortTitle)
	if rep1.Score != 75 {
		t.Errorf("expected Score=75 (-25 for short title), got %d", rep1.Score)
	}

	// 2. Missing reproduction steps
	inMissingSteps := DraftInput{
		Title:            "Crash on network timeout in auth service",
		Summary:          "Detailed summary explaining the issue context thoroughly.",
		StepsToReproduce: "repro steps", // < 15 chars
		Logs:             "timeout error",
	}
	rep2 := LintDraft(inMissingSteps)
	if rep2.Score != 80 {
		t.Errorf("expected Score=80 (-20 for missing steps), got %d", rep2.Score)
	}

	// 3. Missing summary
	inMissingSummary := DraftInput{
		Title:            "Crash on network timeout in auth service",
		Summary:          "too short", // < 20 chars
		StepsToReproduce: "1. Run command with flag --verbose\n2. Check exit code",
		Logs:             "timeout error",
	}
	rep3 := LintDraft(inMissingSummary)
	if rep3.Score != 85 {
		t.Errorf("expected Score=85 (-15 for short summary), got %d", rep3.Score)
	}

	// 4. Missing diagnostic evidence
	inMissingLogs := DraftInput{
		Title:            "Crash on network timeout in auth service",
		Summary:          "Detailed summary explaining the issue context thoroughly.",
		StepsToReproduce: "1. Run command with flag --verbose\n2. Check exit code",
		Logs:             "",
		ActualBehavior:   "",
	}
	rep4 := LintDraft(inMissingLogs)
	if rep4.Score != 85 {
		t.Errorf("expected Score=85 (-15 for missing evidence), got %d", rep4.Score)
	}

	// 5. Cumulative low-signal draft
	inLowSignal := DraftInput{
		Title:            "bug",
		Summary:          "",
		StepsToReproduce: "",
	}
	rep5 := LintDraft(inLowSignal)
	// 100 - 25 (title) - 20 (steps) - 15 (summary) - 15 (evidence) = 25
	if rep5.Score != 25 {
		t.Errorf("expected Score=25, got %d", rep5.Score)
	}
	if rep5.Grade != "low_signal" {
		t.Errorf("expected Grade=low_signal, got %s", rep5.Grade)
	}
	if rep5.Passed {
		t.Errorf("expected Passed=false for low-signal draft, got true")
	}
}
