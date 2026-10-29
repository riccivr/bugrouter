package cloud

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/riccivr/bugrouter/internal/resolver"
)

// AuditEvent records a Human-in-the-Loop review mutation or submission event.
type AuditEvent struct {
	Timestamp time.Time         `json:"timestamp"`
	Action    string            `json:"action"` // "draft.approved" | "draft.discarded" | "draft.submit_failed"
	DraftID   string            `json:"draft_id"`
	Target    string            `json:"target"`
	Protocol  resolver.Protocol `json:"protocol"`
	IssueURL  string            `json:"issue_url,omitempty"`
	RemoteIP  string            `json:"remote_ip,omitempty"`
	Error     string            `json:"error,omitempty"`
}

// AuditLogger manages an append-only JSONL audit trail on disk.
type AuditLogger struct {
	mu   sync.Mutex
	path string
}

// NewAuditLogger initializes an audit logger writing to path, or standard XDG state paths.
func NewAuditLogger(path string) *AuditLogger {
	if path == "" {
		if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
			path = filepath.Join(xdg, "bugrouter", "audit.log")
		} else if home, err := os.UserHomeDir(); err == nil && home != "" {
			path = filepath.Join(home, ".local", "state", "bugrouter", "audit.log")
		} else {
			path = filepath.Join(os.TempDir(), "bugrouter", "audit.log")
		}
	}
	return &AuditLogger{path: path}
}

// Path returns the configured file path of the audit log.
func (l *AuditLogger) Path() string {
	return l.path
}

// Record appends a single JSONL event to the audit log with 0600 permissions.
func (l *AuditLogger) Record(ev AuditEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	dir := filepath.Dir(l.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create audit log directory %s: %w", dir, err)
	}

	data, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}
	data = append(data, '\n')

	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("open audit log %s: %w", l.path, err)
	}
	defer f.Close()

	if err := f.Chmod(0600); err != nil {
		return fmt.Errorf("chmod audit log %s: %w", l.path, err)
	}

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write audit event: %w", err)
	}
	return nil
}

// ListRecent retrieves the newest events up to limit (capped to 1 MiB read).
func (l *AuditLogger) ListRecent(limit int) ([]AuditEvent, error) {
	if limit <= 0 {
		limit = 50
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return []AuditEvent{}, nil
		}
		return nil, fmt.Errorf("open audit log %s: %w", l.path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat audit log %s: %w", l.path, err)
	}

	size := info.Size()
	if size == 0 {
		return []AuditEvent{}, nil
	}

	const maxRead = 1024 * 1024 // 1 MiB cap
	offset := int64(0)
	readSize := size
	if size > maxRead {
		offset = size - maxRead
		readSize = maxRead
	}

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek audit log: %w", err)
	}

	buf := make([]byte, readSize)
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}

	// If read was sliced mid-file, discard the potentially partial first line
	if offset > 0 {
		if idx := bytes.IndexByte(buf, '\n'); idx != -1 {
			buf = buf[idx+1:]
		}
	}

	lines := bytes.Split(buf, []byte("\n"))
	var all []AuditEvent
	for _, line := range lines {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		var ev AuditEvent
		if err := json.Unmarshal(trimmed, &ev); err != nil {
			continue
		}
		all = append(all, ev)
	}

	// Reverse chronological order (newest first)
	var recent []AuditEvent
	for i := len(all) - 1; i >= 0; i-- {
		recent = append(recent, all[i])
		if len(recent) >= limit {
			break
		}
	}
	if recent == nil {
		recent = []AuditEvent{}
	}
	return recent, nil
}
