package adapter

import (
	"strings"
	"testing"

	"github.com/riccivr/bugrouter/internal/resolver"
)

func TestLintInputClean(t *testing.T) {
	in := DraftInput{
		Target: resolver.Target{
			CanonicalName: "requests",
		},
		Title:            "SSL connection reset during streaming download",
		Summary:          "Encountered SSLEOFError when reading chunks from large file streams over TLS 1.3.",
		StepsToReproduce: "1. Open requests.get with stream=True.\n2. Read chunks until EOF.\n3. Observe protocol reset error.",
	}

	rep := LintInput(in)
	if rep == nil {
		t.Fatalf("expected non-nil report")
	}
	if !rep.Passed {
		t.Errorf("clean draft failed linting: %v", rep.Violations)
	}
	if rep.Score != 1.0 {
		t.Errorf("Score = %.2f, want 1.0", rep.Score)
	}
}

func TestLintInputViolations(t *testing.T) {
	tests := []struct {
		name     string
		input    DraftInput
		wantRule string
	}{
		{
			name: "banned buzzword in summary",
			input: DraftInput{
				Title:            "Crash on network timeout",
				Summary:          "We must delve into the intricate landscape of our backend.",
				StepsToReproduce: "1. Run the test suite.\n2. Observe timeout error.",
			},
			wantRule: "banned_buzzword",
		},
		{
			name: "chatbot phrase in summary",
			input: DraftInput{
				Title:            "Crash on network timeout",
				Summary:          "I hope this helps! As an AI, I observed an error during connection setup.",
				StepsToReproduce: "1. Run the test suite.\n2. Observe timeout error.",
			},
			wantRule: "chatbot_phrase",
		},
		{
			name: "em dash in title",
			input: DraftInput{
				Title:            "Crash on network timeout — connection refused",
				Summary:          "Observed connection refused error during health checks.",
				StepsToReproduce: "1. Run health check.\n2. Read response.",
			},
			wantRule: "em_dash",
		},
		{
			name: "curly quotes in steps",
			input: DraftInput{
				Title:            "Crash on network timeout",
				Summary:          "Observed connection refused error during health checks.",
				StepsToReproduce: "1. Run “curl -v” on server.\n2. Read response.",
			},
			wantRule: "curly_quote",
		},
		{
			name: "decorative emoji in title",
			input: DraftInput{
				Title:            "Crash on network timeout 🚀",
				Summary:          "Observed connection refused error during health checks.",
				StepsToReproduce: "1. Run health check.\n2. Read response.",
			},
			wantRule: "decorative_emoji",
		},
		{
			name: "placeholder in steps",
			input: DraftInput{
				Title:            "Crash on network timeout",
				Summary:          "Observed connection refused error during health checks.",
				StepsToReproduce: "1. TODO: add reproduction steps here.",
			},
			wantRule: "placeholder",
		},
		{
			name: "vague title",
			input: DraftInput{
				Title:            "bug",
				Summary:          "Observed connection refused error during health checks.",
				StepsToReproduce: "1. Run health check.\n2. Read response.",
			},
			wantRule: "vague_title",
		},
		{
			name: "empty summary",
			input: DraftInput{
				Title:            "Crash on network timeout",
				Summary:          "",
				StepsToReproduce: "1. Run health check.\n2. Read response.",
			},
			wantRule: "empty_summary",
		},
		{
			name: "empty steps",
			input: DraftInput{
				Title:            "Crash on network timeout",
				Summary:          "Observed connection refused error during health checks.",
				StepsToReproduce: "1.",
			},
			wantRule: "empty_steps",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rep := LintInput(tc.input)
			if rep.Passed {
				t.Fatalf("expected failure for %s, but passed", tc.name)
			}
			found := false
			for _, v := range rep.Violations {
				if v.Rule == tc.wantRule {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected rule %q in violations, got: %v", tc.wantRule, rep.Violations)
			}
			if rep.Score >= 1.0 {
				t.Errorf("Score = %.2f, want < 1.0", rep.Score)
			}
		})
	}
}

func TestStripCodeBlocksPreservesProse(t *testing.T) {
	body := `## Summary
This is real prose explaining the bug.

## Logs
` + "```" + `
// The word robust and delve appear inside code
func delveIntoCode() {
    log.Println("robust system")
}
` + "```" + `

## Steps
1. Execute binary.
`

	prose := stripCodeBlocks(body)
	if strings.Contains(prose, "delveIntoCode") {
		t.Errorf("stripCodeBlocks did not remove code block content: %s", prose)
	}
	if !strings.Contains(prose, "This is real prose explaining the bug.") {
		t.Errorf("stripCodeBlocks stripped prose: %s", prose)
	}
}

func TestFormatViolations(t *testing.T) {
	rep := &QualityReport{
		Passed: false,
		Score:  0.75,
		Violations: []QualityViolation{
			{
				Field:   "title",
				Rule:    "em_dash",
				Message: "contains em dash",
			},
		},
	}

	formatted := FormatViolations(rep)
	if !strings.Contains(formatted, "Anti-Slop Quality Check Failed") {
		t.Errorf("formatted report unexpected: %s", formatted)
	}
	if !strings.Contains(formatted, "[title] em_dash: contains em dash") {
		t.Errorf("formatted report missing violation details: %s", formatted)
	}
}
