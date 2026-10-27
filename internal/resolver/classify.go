package resolver

import (
	"fmt"
	"strings"
)

// NormalizeRepoURL sanitizes repository URLs across protocols into canonical HTTPS targets.
func NormalizeRepoURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	for {
		if strings.HasPrefix(raw, "scm:git:") {
			raw = strings.TrimPrefix(raw, "scm:git:")
		} else if strings.HasPrefix(raw, "scm:") {
			raw = strings.TrimPrefix(raw, "scm:")
		} else if strings.HasPrefix(raw, "git+") {
			raw = strings.TrimPrefix(raw, "git+")
		} else {
			break
		}
	}

	if strings.HasPrefix(raw, "ssh://") {
		trimmed := strings.TrimPrefix(raw, "ssh://")
		if strings.HasPrefix(trimmed, "git@") {
			trimmed = strings.TrimPrefix(trimmed, "git@")
		}
		raw = "https://" + trimmed
	} else if strings.HasPrefix(raw, "git@") {
		trimmed := strings.TrimPrefix(raw, "git@")
		host, path, found := strings.Cut(trimmed, ":")
		if found && !strings.Contains(host, "/") {
			raw = "https://" + host + "/" + strings.TrimPrefix(path, "/")
		} else {
			raw = "https://" + trimmed
		}
	} else if strings.HasPrefix(raw, "git://") {
		raw = "https://" + strings.TrimPrefix(raw, "git://")
	}

	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		if strings.Contains(raw, ".") && strings.Contains(raw, "/") {
			raw = "https://" + raw
		}
	}

	raw = strings.TrimRight(raw, "/")
	if strings.HasSuffix(raw, ".git") {
		raw = strings.TrimSuffix(raw, ".git")
		raw = strings.TrimRight(raw, "/")
	}

	return raw
}

// ClassifyTracker identifies the bug tracker protocol and endpoints from metadata.
func ClassifyTracker(bugsURL, bugsEmail, repoURL string) (TrackerInfo, string) {
	normRepo := NormalizeRepoURL(repoURL)
	bugsURL = strings.TrimSpace(bugsURL)
	bugsEmail = strings.TrimSpace(bugsEmail)

	if strings.HasPrefix(bugsURL, "mailto:") {
		extracted := strings.TrimSpace(strings.TrimPrefix(bugsURL, "mailto:"))
		bugsURL = ""
		if bugsEmail == "" {
			bugsEmail = extracted
		}
	}

	if strings.Contains(bugsEmail, "@gnu.org") || strings.Contains(bugsEmail, "@bugs.debian.org") {
		return TrackerInfo{
			Protocol: ProtocolDebbugs,
			URL:      bugsURL,
			Email:    bugsEmail,
		}, normRepo
	}

	targetURL := bugsURL
	if targetURL == "" {
		targetURL = normRepo
	}
	targetURL = strings.TrimRight(targetURL, "/")

	if strings.Contains(targetURL, "github.com/") {
		idx := strings.Index(targetURL, "github.com/")
		path := targetURL[idx+len("github.com/"):]
		parts := strings.Split(path, "/")
		if len(parts) >= 2 {
			owner := parts[0]
			repo := strings.TrimSuffix(parts[1], ".git")
			return TrackerInfo{
				Protocol: ProtocolGitHub,
				URL:      fmt.Sprintf("https://github.com/%s/%s/issues", owner, repo),
				Email:    bugsEmail,
			}, normRepo
		}
	}

	if strings.Contains(targetURL, "gitlab.") || strings.Contains(targetURL, "/gitlab/") {
		if bugsURL != "" && (strings.Contains(bugsURL, "/-/issues") || strings.HasSuffix(bugsURL, "/issues")) {
			return TrackerInfo{
				Protocol: ProtocolGitLab,
				URL:      bugsURL,
				Email:    bugsEmail,
			}, normRepo
		}

		base := normRepo
		if base == "" {
			base = targetURL
		}
		base = strings.TrimSuffix(base, ".git")
		base = strings.TrimRight(base, "/")
		if !strings.HasSuffix(base, "/issues") {
			base = base + "/issues"
		}
		return TrackerInfo{
			Protocol: ProtocolGitLab,
			URL:      base,
			Email:    bugsEmail,
		}, normRepo
	}

	if strings.Contains(targetURL, "codeberg.org/") {
		idx := strings.Index(targetURL, "codeberg.org/")
		path := targetURL[idx+len("codeberg.org/"):]
		parts := strings.Split(path, "/")
		if len(parts) >= 2 {
			owner := parts[0]
			repo := strings.TrimSuffix(parts[1], ".git")
			return TrackerInfo{
				Protocol: ProtocolCodeberg,
				URL:      fmt.Sprintf("https://codeberg.org/%s/%s/issues", owner, repo),
				Email:    bugsEmail,
			}, normRepo
		}
	}

	if strings.Contains(targetURL, "sr.ht/") {
		return TrackerInfo{
			Protocol: ProtocolSourceHut,
			URL:      targetURL,
			Email:    bugsEmail,
		}, normRepo
	}

	if strings.Contains(targetURL, "bugzilla.") || strings.Contains(targetURL, "show_bug.cgi") || strings.Contains(targetURL, "enter_bug.cgi") {
		return TrackerInfo{
			Protocol: ProtocolBugzilla,
			URL:      targetURL,
			Email:    bugsEmail,
		}, normRepo
	}

	if strings.Contains(targetURL, "bugs.debian.org") || strings.Contains(targetURL, "debbugs.gnu.org") {
		return TrackerInfo{
			Protocol: ProtocolDebbugs,
			URL:      targetURL,
			Email:    bugsEmail,
		}, normRepo
	}

	if bugsEmail != "" {
		return TrackerInfo{
			Protocol: ProtocolDebbugs,
			URL:      bugsURL,
			Email:    bugsEmail,
		}, normRepo
	}

	if bugsURL != "" {
		return TrackerInfo{
			Protocol: ProtocolWebURL,
			URL:      bugsURL,
		}, normRepo
	}

	if targetURL != "" {
		return TrackerInfo{
			Protocol: ProtocolWebURL,
			URL:      targetURL,
		}, normRepo
	}

	return TrackerInfo{}, normRepo
}
