package scrubber

import (
	"regexp"
	"runtime"
)

// ScrubbedText represents sanitized text that has passed through credential and PII redaction.
type ScrubbedText string

var (
	// Multiline PEM private keys.
	pemRegex = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)

	// HTTP Authorization headers and Bearer tokens.
	bearerRegex = regexp.MustCompile(`(?i)(authorization\s*[:=]\s*bearer\s+|bearer\s+)[a-zA-Z0-9_\-\.~=+/]+`)

	// Known API key prefixes.
	awsKeyRegex  = regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`)
	githubRegex  = regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b`)
	apiKeysRegex = regexp.MustCompile(`\b(sk-[a-zA-Z0-9_\-]{20,}|rk_live_[a-zA-Z0-9]{20,}|sk_live_[a-zA-Z0-9]{20,})\b`)
	slackRegex   = regexp.MustCompile(`\bxox[baprs]-[0-9a-zA-Z\-]{10,}\b`)

	// Generic assignment statements in configuration files and command invocations.
	genericSecretRegex = regexp.MustCompile(`(?i)\b([a-zA-Z0-9_-]*(?:api[_-]?key|secret|password|passwd|token|client[_-]?secret|access[_-]?key))\b(\s*[:=]\s*["']?)([^"'\s,;\[][^"'\s,;]*)`)

	// Database and service URIs containing inline credentials.
	connStringRegex = regexp.MustCompile(`([a-zA-Z0-9+.-]+://[^:/\s]+:)([^@\s]+)(@)`)

	// Linux and macOS user home directory paths.
	homePathRegex = regexp.MustCompile(`(/home/[a-zA-Z0-9._-]+|/Users/[a-zA-Z0-9._-]+)`)
)

// Scrub deterministically redacts secrets, tokens, connection strings, and local username paths.
func Scrub(raw string) ScrubbedText {
	s := raw

	// 1. PEM private keys
	s = pemRegex.ReplaceAllString(s, "[REDACTED_PRIVATE_KEY]")

	// 2. Authorization / Bearer tokens
	s = bearerRegex.ReplaceAllString(s, "${1}[REDACTED_TOKEN]")

	// 3. Known API key patterns
	s = awsKeyRegex.ReplaceAllString(s, "[REDACTED_AWS_KEY]")
	s = githubRegex.ReplaceAllString(s, "[REDACTED_GITHUB_TOKEN]")
	s = apiKeysRegex.ReplaceAllString(s, "[REDACTED_API_KEY]")
	s = slackRegex.ReplaceAllString(s, "[REDACTED_SLACK_TOKEN]")

	// 4. Generic key/secret assignments
	s = genericSecretRegex.ReplaceAllString(s, "${1}${2}[REDACTED_SECRET]")

	// 5. Connection string credentials
	s = connStringRegex.ReplaceAllString(s, "${1}[REDACTED_PASSWORD]${3}")

	// 6. User home directory prefixes
	s = homePathRegex.ReplaceAllString(s, "~")

	return ScrubbedText(s)
}

// CollectEnvSummary returns non-sensitive system environment metadata.
func CollectEnvSummary() map[string]string {
	return map[string]string{
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
		"go_version": runtime.Version(),
	}
}
