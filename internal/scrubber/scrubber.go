package scrubber

import (
	"regexp"
	"runtime"
	"strings"
)

// ScrubbedText represents sanitized text that has passed through credential and PII redaction.
type ScrubbedText string

var (
	// Multiline PEM private keys.
	pemRegex = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)

	// HTTP Authorization headers and Bearer tokens.
	bearerRegex = regexp.MustCompile(`(?i)(authorization\s*[:=]\s*bearer\s+|bearer\s+)[a-zA-Z0-9_\-\.~=+/]+`)

	// Known API key prefixes.
	awsKeyRegex   = regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`)
	githubRegex   = regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b`)
	apiKeysRegex  = regexp.MustCompile(`\b(sk-[a-zA-Z0-9_\-]{20,}|rk_live_[a-zA-Z0-9]{20,}|sk_live_[a-zA-Z0-9]{20,})\b`)
	slackRegex    = regexp.MustCompile(`\bxox[baprs]-[0-9a-zA-Z\-]{10,}\b`)
	gcpKeyRegex   = regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)
	jwtRegex      = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
	azureKeyRegex = regexp.MustCompile(`(?i)(AccountKey=|SharedAccessKey=|SharedAccessSignature=)[A-Za-z0-9%+/=]{30,}`)
	azureSasRegex = regexp.MustCompile(`(?i)([\?&]sig=)[A-Za-z0-9%+/=]{30,}`)

	// Generic assignment statements in configuration files and command invocations.
	genericSecretRegex = regexp.MustCompile(`(?i)\b([a-zA-Z0-9_-]*(?:api[_-]?key|secret|password|passwd|token|client[_-]?secret|access[_-]?key))\b(\s*[:=]\s*["']?)([^"'\s,;\[][^\s,;]*)`)

	// Common non-secret literals to preserve.
	nonSecretLiterals = map[string]bool{
		"true":      true,
		"false":     true,
		"null":      true,
		"nil":       true,
		"none":      true,
		"undefined": true,
		"yes":       true,
		"no":        true,
	}

	// Database and service URIs containing inline credentials.
	connStringRegex = regexp.MustCompile(`([a-zA-Z0-9+.-]+://[^:/\s]+:)([^@\s]+)(@)`)

	// Linux and macOS user home directory paths.
	homePathRegex    = regexp.MustCompile(`(/home/[a-zA-Z0-9._-]+|/Users/[a-zA-Z0-9._-]+)`)
	winHomePathRegex = regexp.MustCompile(`(?i)[a-zA-Z]:[/\\]Users[/\\][a-zA-Z0-9._-]+`)
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
	s = gcpKeyRegex.ReplaceAllString(s, "[REDACTED_GCP_KEY]")
	s = jwtRegex.ReplaceAllString(s, "[REDACTED_JWT]")
	s = azureKeyRegex.ReplaceAllString(s, "${1}[REDACTED_AZURE_KEY]")
	s = azureSasRegex.ReplaceAllString(s, "${1}[REDACTED_AZURE_KEY]")

	// 4. Generic key/secret assignments
	s = genericSecretRegex.ReplaceAllStringFunc(s, func(match string) string {
		subs := genericSecretRegex.FindStringSubmatch(match)
		if len(subs) < 4 {
			return match
		}
		rawVal := subs[3]
		var trailingQuote string
		if strings.HasSuffix(rawVal, "\"") {
			trailingQuote = "\""
			rawVal = strings.TrimSuffix(rawVal, "\"")
		} else if strings.HasSuffix(rawVal, "'") {
			trailingQuote = "'"
			rawVal = strings.TrimSuffix(rawVal, "'")
		}
		cleanVal := strings.Trim(strings.TrimSpace(rawVal), "\"'")
		if len(cleanVal) < 6 || nonSecretLiterals[strings.ToLower(cleanVal)] {
			return match
		}
		if trailingQuote == "" {
			if strings.HasSuffix(subs[2], "\"") {
				trailingQuote = "\""
			} else if strings.HasSuffix(subs[2], "'") {
				trailingQuote = "'"
			}
		}
		return subs[1] + subs[2] + "[REDACTED_SECRET]" + trailingQuote
	})

	// 5. Connection string credentials
	s = connStringRegex.ReplaceAllString(s, "${1}[REDACTED_PASSWORD]${3}")

	// 6. User home directory prefixes
	s = winHomePathRegex.ReplaceAllString(s, "~")
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
