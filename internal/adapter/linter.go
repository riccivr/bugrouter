package adapter

import (
	"strings"
)

// QualityReport encapsulates the deterministic quality evaluation of a bug draft.
type QualityReport struct {
	Score  int      `json:"score"`
	Grade  string   `json:"grade"`
	Passed bool     `json:"passed"`
	Issues []string `json:"issues,omitempty"`
}

var aiSlopPhrases = []string{
	"as an ai",
	"as a large language model",
	"i hope this message finds you",
	"certainly!",
	"here is the bug report",
	"delve into",
	"it is important to note",
}

// LintDraft evaluates draft input against quality rules, returning a scored report.
func LintDraft(in DraftInput) QualityReport {
	score := 100
	var issues []string
	hasAISlop := false

	// 1. AI Slop / Conversational Filler (-35 pts, forces Passed = false)
	lowerFields := strings.ToLower(strings.Join([]string{
		in.Title,
		in.Summary,
		in.StepsToReproduce,
	}, " "))

	for _, phrase := range aiSlopPhrases {
		if strings.Contains(lowerFields, phrase) {
			hasAISlop = true
			score -= 35
			issues = append(issues, "contains conversational AI filler; rewrite with direct technical facts only")
			break
		}
	}

	// 2. Vague or Ultra-Short Title (-25 pts)
	cleanTitle := sanitizeTitle(in.Title)
	if len(strings.Fields(cleanTitle)) < 3 {
		score -= 25
		issues = append(issues, "title must contain at least 3 words specifying the component and failure symptom")
	}

	// 3. Missing Reproduction Steps (-20 pts)
	if len(strings.TrimSpace(in.StepsToReproduce)) < 15 {
		score -= 20
		issues = append(issues, "steps_to_reproduce is missing or too brief (< 15 chars); provide exact commands or steps")
	}

	// 4. Missing Summary (-15 pts)
	if len(strings.TrimSpace(in.Summary)) < 20 {
		score -= 15
		issues = append(issues, "summary is missing or too brief (< 20 chars); explain the failure context")
	}

	// 5. Missing Diagnostic Evidence (-15 pts)
	if strings.TrimSpace(in.Logs) == "" && strings.TrimSpace(in.ActualBehavior) == "" {
		score -= 15
		issues = append(issues, "include error logs, stack traces, or actual_behavior output")
	}

	// Clamp Score to [0, 100]
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	var grade string
	switch {
	case score >= 80:
		grade = "ready"
	case score >= 50:
		grade = "needs_detail"
	default:
		grade = "low_signal"
	}

	passed := score >= 70 && !hasAISlop

	return QualityReport{
		Score:  score,
		Grade:  grade,
		Passed: passed,
		Issues: issues,
	}
}
