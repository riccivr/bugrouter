package scrubber

import (
	"strings"
	"testing"
)

func TestScrub(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "pem private key block",
			in:   "Config dump:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y123456\n-----END RSA PRIVATE KEY-----\nDone",
			want: "Config dump:\n[REDACTED_PRIVATE_KEY]\nDone",
		},
		{
			name: "authorization header bearer token",
			in:   "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz",
			want: "Authorization: Bearer [REDACTED_TOKEN]",
		},
		{
			name: "lowercase bearer token",
			in:   "curl -H 'bearer secret_token_value.123' https://api.com",
			want: "curl -H 'bearer [REDACTED_TOKEN]' https://api.com",
		},
		{
			name: "aws access key id",
			in:   "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
			want: "AWS_ACCESS_KEY_ID=[REDACTED_AWS_KEY]",
		},
		{
			name: "github personal access token",
			in:   "export GITHUB_TOKEN=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345",
			want: "export GITHUB_TOKEN=[REDACTED_GITHUB_TOKEN]",
		},
		{
			name: "github fine grained pat",
			in:   "git remote set-url origin https://github_pat_11AAAAAAA0123456789012@github.com/repo",
			want: "git remote set-url origin https://[REDACTED_GITHUB_TOKEN]@github.com/repo",
		},
		{
			name: "openai api key",
			in:   "OPENAI_API_KEY=sk-proj-1234567890abcdef123456",
			want: "OPENAI_API_KEY=[REDACTED_API_KEY]",
		},
		{
			name: "stripe live key",
			in:   "stripe_secret = rk_live_12345678901234567890",
			want: "stripe_secret = [REDACTED_API_KEY]",
		},
		{
			name: "slack bot token",
			in:   "xoxb-1234567890-abcdefghij",
			want: "[REDACTED_SLACK_TOKEN]",
		},
		{
			name: "generic secret assignment in dotenv",
			in:   "DATABASE_PASSWORD=supersecretpass123\nCLIENT_SECRET=\"topsecretvalue\"",
			want: "DATABASE_PASSWORD=[REDACTED_SECRET]\nCLIENT_SECRET=\"[REDACTED_SECRET]\"",
		},
		{
			name: "postgres connection string",
			in:   "postgres://admin:mypassword123@localhost:5432/mydb",
			want: "postgres://admin:[REDACTED_PASSWORD]@localhost:5432/mydb",
		},
		{
			name: "linux home path",
			in:   "Error reading file at /home/alice/project/src/index.js",
			want: "Error reading file at ~/project/src/index.js",
		},
		{
			name: "macos home path",
			in:   "Stack trace: /Users/bob/workspace/app.go:42",
			want: "Stack trace: ~/workspace/app.go:42",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := string(Scrub(tc.in))
			if got != tc.want {
				t.Errorf("\ngot:  %q\nwant: %q", got, tc.want)
			}
		})
	}
}

func TestCollectEnvSummary(t *testing.T) {
	summary := CollectEnvSummary()
	if summary["os"] == "" {
		t.Error("expected non-empty os")
	}
	if summary["arch"] == "" {
		t.Error("expected non-empty arch")
	}
	if !strings.HasPrefix(summary["go_version"], "go") {
		t.Errorf("unexpected go_version: %s", summary["go_version"])
	}
}
