package adapter

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/riccivr/bugrouter/internal/resolver"
	"github.com/riccivr/bugrouter/internal/scrubber"
	"github.com/riccivr/bugrouter/internal/version"
)

// DraftInput holds raw issue details provided by users or agent processes.
type DraftInput struct {
	Target           resolver.Target
	Title            string
	Summary          string
	StepsToReproduce string
	ExpectedBehavior string
	ActualBehavior   string
	Logs             string
	Severity         string
}

// StagedDraft represents a redacted and formatted issue ready for review or submission.
type StagedDraft struct {
	ID            string                `json:"id"`
	CreatedAt     time.Time             `json:"created_at"`
	Status        string                `json:"status"`
	Target        resolver.Target       `json:"target"`
	Title         scrubber.ScrubbedText `json:"title"`
	MarkdownBody  scrubber.ScrubbedText `json:"markdown_body"`
	SubmissionURL string                `json:"submission_url,omitempty"`
	DebbugsEmail  string                `json:"debbugs_email,omitempty"`
}

func generateDraftID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate draft id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// BuildDraft constructs a staged ticket with scrubbed markdown content and submission endpoints.
func BuildDraft(in DraftInput) (*StagedDraft, error) {
	if strings.TrimSpace(in.Title) == "" {
		return nil, errors.New("draft title cannot be empty")
	}

	id, err := generateDraftID()
	if err != nil {
		return nil, err
	}

	scrubbedTitle := scrubber.Scrub(strings.TrimSpace(in.Title))
	scrubbedSummary := scrubber.Scrub(strings.TrimSpace(in.Summary))
	scrubbedSteps := scrubber.Scrub(strings.TrimSpace(in.StepsToReproduce))
	scrubbedExpected := scrubber.Scrub(strings.TrimSpace(in.ExpectedBehavior))
	scrubbedActual := scrubber.Scrub(strings.TrimSpace(in.ActualBehavior))
	scrubbedLogs := scrubber.Scrub(strings.TrimSpace(in.Logs))

	localVersion := in.Target.LocalVersion
	if localVersion == "" {
		localVersion = "unknown"
	}
	canonicalName := in.Target.CanonicalName
	if canonicalName == "" {
		canonicalName = in.Target.Query
	}

	severity := strings.TrimSpace(in.Severity)
	if severity == "" {
		severity = "normal"
	}

	var sb strings.Builder
	sb.WriteString("## Summary\n\n")
	if scrubbedSummary != "" {
		sb.WriteString(string(scrubbedSummary))
	} else {
		sb.WriteString("No summary provided.")
	}
	sb.WriteString("\n\n## Steps to Reproduce\n\n")
	if scrubbedSteps != "" {
		sb.WriteString(string(scrubbedSteps))
	} else {
		sb.WriteString("1. ")
	}
	sb.WriteString("\n\n## Expected vs Actual Behavior\n\n")
	if scrubbedExpected != "" {
		sb.WriteString("**Expected:**\n")
		sb.WriteString(string(scrubbedExpected))
		sb.WriteString("\n\n")
	}
	if scrubbedActual != "" {
		sb.WriteString("**Actual:**\n")
		sb.WriteString(string(scrubbedActual))
		sb.WriteString("\n\n")
	}
	if scrubbedExpected == "" && scrubbedActual == "" {
		sb.WriteString("Not specified.\n\n")
	}
	sb.WriteString("## Logs & Output\n\n")
	if scrubbedLogs != "" {
		sb.WriteString("```\n")
		sb.WriteString(string(scrubbedLogs))
		sb.WriteString("\n```\n\n")
	} else {
		sb.WriteString("None provided.\n\n")
	}
	sb.WriteString("## Environment\n\n")
	sb.WriteString(fmt.Sprintf("- **Target:** %s\n", canonicalName))
	sb.WriteString(fmt.Sprintf("- **Version:** %s\n", localVersion))
	sb.WriteString(fmt.Sprintf("- **Platform:** %s/%s\n\n", runtime.GOOS, runtime.GOARCH))
	sb.WriteString(fmt.Sprintf("*Staged via bugrouter/%s*\n", version.Version))

	markdownBody := scrubber.ScrubbedText(sb.String())

	var submissionURL string
	var debbugsEmail string

	trackerURL := in.Target.Tracker.URL
	trackerEmail := in.Target.Tracker.Email
	protocol := in.Target.Tracker.Protocol

	switch protocol {
	case resolver.ProtocolGitHub, resolver.ProtocolCodeberg:
		base := strings.TrimRight(trackerURL, "/")
		if !strings.HasSuffix(base, "/new") {
			base = base + "/new"
		}
		submissionURL = fmt.Sprintf("%s?title=%s&body=%s", base, url.QueryEscape(string(scrubbedTitle)), url.QueryEscape(string(markdownBody)))

	case resolver.ProtocolGitLab:
		base := strings.TrimRight(trackerURL, "/")
		if !strings.HasSuffix(base, "/new") {
			base = base + "/new"
		}
		submissionURL = fmt.Sprintf("%s?issue[title]=%s&issue[description]=%s", base, url.QueryEscape(string(scrubbedTitle)), url.QueryEscape(string(markdownBody)))

	case resolver.ProtocolDebbugs:
		emailTo := trackerEmail
		if emailTo == "" {
			emailTo = "submit@bugs.debian.org"
		}

		debbugsEmail = fmt.Sprintf("To: %s\nSubject: %s\n\nPackage: %s\nVersion: %s\nSeverity: %s\n\n%s",
			emailTo,
			string(scrubbedTitle),
			canonicalName,
			localVersion,
			severity,
			string(markdownBody),
		)

		mailBody := fmt.Sprintf("Package: %s\nVersion: %s\nSeverity: %s\n\n%s",
			canonicalName,
			localVersion,
			severity,
			string(markdownBody),
		)
		submissionURL = fmt.Sprintf("mailto:%s?subject=%s&body=%s",
			emailTo,
			url.QueryEscape(string(scrubbedTitle)),
			url.QueryEscape(mailBody),
		)

	default:
		submissionURL = trackerURL
	}

	return &StagedDraft{
		ID:            id,
		CreatedAt:     time.Now().UTC(),
		Status:        "pending_review",
		Target:        in.Target,
		Title:         scrubbedTitle,
		MarkdownBody:  markdownBody,
		SubmissionURL: submissionURL,
		DebbugsEmail:  debbugsEmail,
	}, nil
}

// DraftStore manages local file staging for reviewed and pending bug tickets.
type DraftStore struct {
	dir string
}

// NewDraftStore initializes a local draft store with XDG data fallback.
func NewDraftStore(dir string) *DraftStore {
	if dir == "" {
		if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
			dir = filepath.Join(xdg, "bugrouter", "drafts")
		} else if home, err := os.UserHomeDir(); err == nil && home != "" {
			dir = filepath.Join(home, ".local", "share", "bugrouter", "drafts")
		} else {
			dir = filepath.Join(os.TempDir(), "bugrouter", "drafts")
		}
	}
	return &DraftStore{dir: dir}
}

// Save writes the staged draft atomically to disk with restricted user-only permissions.
func (s *DraftStore) Save(d *StagedDraft) (string, error) {
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return "", fmt.Errorf("create draft directory %s: %w", s.dir, err)
	}

	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal staged draft %s: %w", d.ID, err)
	}

	targetPath := filepath.Join(s.dir, d.ID+".json")

	tmpFile, err := os.CreateTemp(s.dir, "draft-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create temp draft file in %s: %w", s.dir, err)
	}
	tmpName := tmpFile.Name()

	// Enforce 0600 permissions so draft credentials and logs are restricted to the local user.
	if err := tmpFile.Chmod(0600); err != nil {
		closeErr := tmpFile.Close()
		cleanupErr := os.Remove(tmpName)
		if cleanupErr != nil && !os.IsNotExist(cleanupErr) {
			return "", fmt.Errorf("chmod draft file %s: %w (close: %v, cleanup: %v)", tmpName, err, closeErr, cleanupErr)
		}
		if closeErr != nil {
			return "", fmt.Errorf("chmod draft file %s: %w (close: %v)", tmpName, err, closeErr)
		}
		return "", fmt.Errorf("chmod draft file %s: %w", tmpName, err)
	}

	if _, err := tmpFile.Write(data); err != nil {
		closeErr := tmpFile.Close()
		cleanupErr := os.Remove(tmpName)
		if cleanupErr != nil && !os.IsNotExist(cleanupErr) {
			return "", fmt.Errorf("write draft file %s: %w (close: %v, cleanup: %v)", tmpName, err, closeErr, cleanupErr)
		}
		if closeErr != nil {
			return "", fmt.Errorf("write draft file %s: %w (close: %v)", tmpName, err, closeErr)
		}
		return "", fmt.Errorf("write draft file %s: %w", tmpName, err)
	}

	if err := tmpFile.Close(); err != nil {
		cleanupErr := os.Remove(tmpName)
		if cleanupErr != nil && !os.IsNotExist(cleanupErr) {
			return "", fmt.Errorf("close draft file %s: %w (cleanup: %v)", tmpName, err, cleanupErr)
		}
		return "", fmt.Errorf("close draft file %s: %w", tmpName, err)
	}

	if err := os.Rename(tmpName, targetPath); err != nil {
		cleanupErr := os.Remove(tmpName)
		if cleanupErr != nil && !os.IsNotExist(cleanupErr) {
			return "", fmt.Errorf("rename draft file to %s: %w (cleanup: %v)", targetPath, err, cleanupErr)
		}
		return "", fmt.Errorf("rename draft file to %s: %w", targetPath, err)
	}

	return targetPath, nil
}
