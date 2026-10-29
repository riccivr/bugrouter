package adapter

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// QualityViolation details an anti-slop or hygiene rule failure in a draft.
type QualityViolation struct {
	Field   string `json:"field"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
	Offense string `json:"offense,omitempty"`
}

// QualityReport summarizes the results of the anti-slop linter.
type QualityReport struct {
	Passed     bool               `json:"passed"`
	Score      float64            `json:"score"`
	Violations []QualityViolation `json:"violations,omitempty"`
}

var (
	// Banned buzzwords representing classic LLM filler patterns ("unslop" guidelines)
	bannedBuzzwordsRegex = regexp.MustCompile(`(?i)\b(delve|delving|pivotal|testament|landscape|tapestry|enduring|foster|fostering|interplay|intricate|showcase|showcasing|underscore|underscores|underscoring|vibrant|crucial|leverage|leveraging|groundbreaking|breathtaking|game-changer|seamlessly|holistic|synergy|bespoke)\b`)

	// Chatbot conversational phrases that clutter issue trackers
	chatbotPhrasesRegex = regexp.MustCompile(`(?i)\b(as an ai|i hope this helps|let me know if|feel free to|certainly[,!]|found the smoking gun|in order to|due to the fact that|it is important to note|serves as a|stands as a)\b`)

	// Placeholders indicating unfinished drafts
	placeholderRegex = regexp.MustCompile(`(?i)\b(TODO|TBD|FIXME|XXX|REPLACE_ME|INSERT_HERE|LOREM\s+IPSUM)\b|<insert[^>]*>|\[insert[^\]]*\]`)

	// Vague titles that hinder upstream triage
	vagueTitleRegex = regexp.MustCompile(`(?i)^(bug|error|crash|issue|something broken|failure|broken|fix needed|problem|test)$`)
)

// LintText checks an isolated prose text string for buzzwords, punctuation tells, and placeholders.
func LintText(field, text string) []QualityViolation {
	var violations []QualityViolation
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return violations
	}

	// 1. Banned buzzwords
	if matches := bannedBuzzwordsRegex.FindAllString(trimmed, -1); len(matches) > 0 {
		seen := make(map[string]bool)
		for _, m := range matches {
			lower := strings.ToLower(m)
			if seen[lower] {
				continue
			}
			seen[lower] = true
			violations = append(violations, QualityViolation{
				Field:   field,
				Rule:    "banned_buzzword",
				Message: fmt.Sprintf("contains banned LLM buzzword %q", lower),
				Offense: lower,
			})
		}
	}

	// 2. Chatbot conversational phrases
	if matches := chatbotPhrasesRegex.FindAllString(trimmed, -1); len(matches) > 0 {
		seen := make(map[string]bool)
		for _, m := range matches {
			lower := strings.ToLower(m)
			if seen[lower] {
				continue
			}
			seen[lower] = true
			violations = append(violations, QualityViolation{
				Field:   field,
				Rule:    "chatbot_phrase",
				Message: fmt.Sprintf("contains conversational chatbot phrase %q", lower),
				Offense: lower,
			})
		}
	}

	// 3. Em dashes and en dashes
	if strings.Contains(trimmed, "\u2014") || strings.Contains(trimmed, "\u2013") {
		violations = append(violations, QualityViolation{
			Field:   field,
			Rule:    "em_dash",
			Message: "contains em dash or en dash; use commas or periods instead",
			Offense: "—",
		})
	}

	// 4. Curly quotes
	if strings.ContainsAny(trimmed, "“”‘’") {
		violations = append(violations, QualityViolation{
			Field:   field,
			Rule:    "curly_quote",
			Message: "contains typographic curly quotes; use straight quotes instead",
			Offense: "“",
		})
	}

	// 5. Decorative emojis
	for _, r := range trimmed {
		if isDecorativeEmoji(r) {
			violations = append(violations, QualityViolation{
				Field:   field,
				Rule:    "decorative_emoji",
				Message: fmt.Sprintf("contains decorative emoji %q (%U)", string(r), r),
				Offense: string(r),
			})
			break // Record once per field to avoid flooding
		}
	}

	// 6. Placeholders
	if matches := placeholderRegex.FindAllString(trimmed, -1); len(matches) > 0 {
		seen := make(map[string]bool)
		for _, m := range matches {
			upper := strings.ToUpper(m)
			if seen[upper] {
				continue
			}
			seen[upper] = true
			violations = append(violations, QualityViolation{
				Field:   field,
				Rule:    "placeholder",
				Message: fmt.Sprintf("contains unresolved placeholder %q", m),
				Offense: m,
			})
		}
	}

	return violations
}

// LintInput validates all human and agent prose fields of a DraftInput.
func LintInput(in DraftInput) *QualityReport {
	var violations []QualityViolation

	// Title quality checks
	title := strings.TrimSpace(in.Title)
	if len(title) < 10 {
		violations = append(violations, QualityViolation{
			Field:   "title",
			Rule:    "title_too_short",
			Message: "title is too short (minimum 10 characters required)",
			Offense: title,
		})
	}
	if vagueTitleRegex.MatchString(title) {
		violations = append(violations, QualityViolation{
			Field:   "title",
			Rule:    "vague_title",
			Message: "title is too generic; provide specific failure details",
			Offense: title,
		})
	}
	violations = append(violations, LintText("title", title)...)

	// Summary quality checks
	summary := strings.TrimSpace(in.Summary)
	if summary == "" || strings.EqualFold(summary, "No summary provided.") || len(summary) < 10 {
		violations = append(violations, QualityViolation{
			Field:   "summary",
			Rule:    "empty_summary",
			Message: "summary is empty or lacks substantive technical explanation",
			Offense: summary,
		})
	} else {
		violations = append(violations, LintText("summary", summary)...)
	}

	// Steps quality checks
	steps := strings.TrimSpace(in.StepsToReproduce)
	if steps == "" || steps == "1." || strings.EqualFold(steps, "none") || strings.EqualFold(steps, "n/a") || len(steps) < 10 {
		violations = append(violations, QualityViolation{
			Field:   "steps",
			Rule:    "empty_steps",
			Message: "steps to reproduce are empty or uninformative",
			Offense: steps,
		})
	} else {
		violations = append(violations, LintText("steps", steps)...)
	}

	// Optional prose fields
	if in.ExpectedBehavior != "" {
		violations = append(violations, LintText("expected", in.ExpectedBehavior)...)
	}
	if in.ActualBehavior != "" {
		violations = append(violations, LintText("actual", in.ActualBehavior)...)
	}

	// Compute final score
	score := 1.0
	for _, v := range violations {
		switch v.Rule {
		case "placeholder", "vague_title", "empty_steps", "empty_summary":
			score -= 0.25
		case "chatbot_phrase":
			score -= 0.15
		case "banned_buzzword":
			score -= 0.10
		case "em_dash", "curly_quote", "decorative_emoji":
			score -= 0.05
		default:
			score -= 0.10
		}
	}
	if score < 0.0 {
		score = 0.0
	}
	if len(violations) == 0 {
		score = 1.0
	}

	return &QualityReport{
		Passed:     len(violations) == 0,
		Score:      score,
		Violations: violations,
	}
}

// LintDraft runs quality analysis on the staged draft's fields and body.
func LintDraft(draft *StagedDraft) *QualityReport {
	if draft == nil {
		return &QualityReport{Passed: false, Score: 0.0}
	}

	// Extract markdown sections outside code blocks to prevent false alarms on code symbols
	body := string(draft.MarkdownBody)
	proseOnly := stripCodeBlocks(body)

	title := string(draft.Title)
	var violations []QualityViolation

	if len(title) < 10 {
		violations = append(violations, QualityViolation{
			Field:   "title",
			Rule:    "title_too_short",
			Message: "title is too short (minimum 10 characters required)",
			Offense: title,
		})
	}
	violations = append(violations, LintText("title", title)...)
	violations = append(violations, LintText("body", proseOnly)...)

	score := 1.0
	for _, v := range violations {
		switch v.Rule {
		case "placeholder", "vague_title", "empty_steps", "empty_summary":
			score -= 0.25
		case "chatbot_phrase":
			score -= 0.15
		case "banned_buzzword":
			score -= 0.10
		case "em_dash", "curly_quote", "decorative_emoji":
			score -= 0.05
		default:
			score -= 0.10
		}
	}
	if score < 0.0 {
		score = 0.0
	}
	if len(violations) == 0 {
		score = 1.0
	}

	return &QualityReport{
		Passed:     len(violations) == 0,
		Score:      score,
		Violations: violations,
	}
}

// FormatViolations converts quality violations into human-readable bullet points.
func FormatViolations(rep *QualityReport) string {
	if rep == nil || len(rep.Violations) == 0 {
		return "No quality violations found."
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Anti-Slop Quality Check Failed (Score: %.2f/1.00):\n", rep.Score))
	for _, v := range rep.Violations {
		sb.WriteString(fmt.Sprintf("  - [%s] %s: %s\n", v.Field, v.Rule, v.Message))
	}
	return strings.TrimSpace(sb.String())
}

func stripCodeBlocks(raw string) string {
	lines := strings.Split(raw, "\n")
	var prose []string
	inCode := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			inCode = !inCode
			continue
		}
		if !inCode {
			prose = append(prose, line)
		}
	}
	return strings.Join(prose, "\n")
}

func isDecorativeEmoji(r rune) bool {
	// Standard pictographic and symbol emoji ranges
	if r >= 0x1F300 && r <= 0x1FAFF {
		return true
	}
	// Dingbats and miscellaneous symbols
	if (r >= 0x2700 && r <= 0x27BF) || (r >= 0x2600 && r <= 0x26FF) {
		return true
	}
	return unicode.Is(unicode.So, r) && r > 0x00FF
}
