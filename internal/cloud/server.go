package cloud

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/riccivr/bugrouter/internal/adapter"
	"github.com/riccivr/bugrouter/internal/version"
)

// ForgeSubmitter submits a staged draft to an authenticated upstream forge.
type ForgeSubmitter = adapter.ForgeSubmitter

// Server provides the Cloud Control Plane HTTP daemon and review queue UI.
type Server struct {
	mux             *http.ServeMux
	draftStore      *adapter.DraftStore
	addr            string
	submitter       ForgeSubmitter
	authToken       string
	auditLogger     *AuditLogger
	webhookNotifier *WebhookNotifier
	httpServer      *http.Server
}

// NewServer initializes a Cloud Control Plane server with routes registered.
func NewServer(addr string, store *adapter.DraftStore, submitter ForgeSubmitter) *Server {
	if addr == "" {
		addr = ":8080"
	}
	s := &Server{
		mux:        http.NewServeMux(),
		draftStore: store,
		addr:       addr,
		submitter:  submitter,
		authToken:  os.Getenv("BUGROUTER_CLOUD_TOKEN"),
	}
	s.registerRoutes()
	return s
}

// WithAuthToken configures a Bearer token requirement for API endpoints.
func (s *Server) WithAuthToken(token string) *Server {
	s.authToken = token
	return s
}

// WithAuditLogger attaches an append-only JSONL audit logger.
func (s *Server) WithAuditLogger(logger *AuditLogger) *Server {
	s.auditLogger = logger
	return s
}

// WithWebhookNotifier attaches a webhook notification dispatcher.
func (s *Server) WithWebhookNotifier(notifier *WebhookNotifier) *Server {
	s.webhookNotifier = notifier
	return s
}

// Handler returns the underlying http.Handler with security middleware applied.
func (s *Server) Handler() http.Handler {
	return s.securityMiddleware(s.mux)
}

func (s *Server) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Bearer Token Auth (when s.authToken != "")
		if s.authToken != "" {
			isPublic := r.Method == http.MethodGet && (r.URL.Path == "/" || r.URL.Path == "/api/v1/health")
			if !isPublic {
				authHeader := r.Header.Get("Authorization")
				if !strings.HasPrefix(authHeader, "Bearer ") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					if err := json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"}); err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
					}
					return
				}
				tokenProvided := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
				hProvided := sha256.Sum256([]byte(tokenProvided))
				hExpected := sha256.Sum256([]byte(s.authToken))
				if subtle.ConstantTimeCompare(hProvided[:], hExpected[:]) != 1 {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					if err := json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"}); err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
					}
					return
				}
			}
		}

		// 2. CSRF / Cross-Origin Mutation Guard on POST /api/v1/... routes
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/") {
			if origin := r.Header.Get("Origin"); origin != "" {
				u, err := url.Parse(origin)
				if err != nil || u.Host == "" || !strings.EqualFold(u.Host, r.Host) {
					http.Error(w, "forbidden: cross-origin mutation rejected", http.StatusForbidden)
					return
				}
			}

			hasCustomHeader := r.Header.Get("X-Bugrouter-Request") == "1"
			hasValidAuth := false
			if s.authToken != "" {
				authHeader := r.Header.Get("Authorization")
				if strings.HasPrefix(authHeader, "Bearer ") {
					tokenProvided := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
					hProvided := sha256.Sum256([]byte(tokenProvided))
					hExpected := sha256.Sum256([]byte(s.authToken))
					if subtle.ConstantTimeCompare(hProvided[:], hExpected[:]) == 1 {
						hasValidAuth = true
					}
				}
			}

			if !hasCustomHeader && !hasValidAuth {
				http.Error(w, "forbidden: missing CSRF guard header", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/v1/drafts", s.handleListDrafts)
	s.mux.HandleFunc("POST /api/v1/drafts/{id}/approve", s.handleApproveDraft)
	s.mux.HandleFunc("POST /api/v1/drafts/{id}/discard", s.handleDiscardDraft)
	s.mux.HandleFunc("GET /api/v1/audit", s.handleAuditLog)
	s.mux.HandleFunc("GET /", s.handleIndex)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"version": version.Version,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleListDrafts(w http.ResponseWriter, r *http.Request) {
	if s.draftStore == nil {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte("[]")); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	drafts, err := s.draftStore.List()
	if err != nil {
		http.Error(w, fmt.Sprintf("list drafts: %v", err), http.StatusInternalServerError)
		return
	}
	if drafts == nil {
		drafts = []*adapter.StagedDraft{}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(drafts); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func extractDraftID(r *http.Request) string {
	id := r.PathValue("id")
	if id == "" {
		trimmed := strings.TrimPrefix(r.URL.Path, "/api/v1/drafts/")
		trimmed = strings.TrimSuffix(trimmed, "/approve")
		trimmed = strings.TrimSuffix(trimmed, "/discard")
		id = strings.Trim(trimmed, "/")
	}
	if !adapter.IsValidDraftID(id) {
		return ""
	}
	return id
}

func (s *Server) handleApproveDraft(w http.ResponseWriter, r *http.Request) {
	id := extractDraftID(r)
	if id == "" {
		http.Error(w, "missing draft id in path", http.StatusBadRequest)
		return
	}

	if s.draftStore == nil {
		http.Error(w, "draft store unconfigured", http.StatusInternalServerError)
		return
	}

	draft, err := s.draftStore.Get(id)
	if err != nil {
		http.Error(w, fmt.Sprintf("get draft %s: %v", id, err), http.StatusNotFound)
		return
	}

	remoteIP, _, ipErr := net.SplitHostPort(r.RemoteAddr)
	if ipErr != nil {
		remoteIP = r.RemoteAddr
	}

	var issueURL string
	if s.submitter != nil {
		issueURL, err = s.submitter.Submit(r.Context(), draft)
		if err != nil {
			if s.auditLogger != nil {
				failEv := AuditEvent{
					Timestamp: time.Now().UTC(),
					Action:    "draft.submit_failed",
					DraftID:   id,
					Target:    draft.Target.CanonicalName,
					Protocol:  draft.Target.Tracker.Protocol,
					RemoteIP:  remoteIP,
					Error:     err.Error(),
				}
				if logErr := s.auditLogger.Record(failEv); logErr != nil {
					fmt.Fprintf(os.Stderr, "audit log record error: %v\n", logErr)
				}
				if s.webhookNotifier != nil {
					if notifyErr := s.webhookNotifier.Notify(r.Context(), failEv); notifyErr != nil {
						fmt.Fprintf(os.Stderr, "webhook notify error: %v\n", notifyErr)
					}
				}
			}
			http.Error(w, fmt.Sprintf("submit draft to upstream tracker: %v", err), http.StatusInternalServerError)
			return
		}
	} else if draft.SubmissionURL != "" {
		issueURL = draft.SubmissionURL
	}

	draft.Status = "submitted"
	if issueURL != "" {
		draft.SubmissionURL = issueURL
	}

	if _, err := s.draftStore.Save(draft); err != nil {
		http.Error(w, fmt.Sprintf("save updated draft %s: %v", id, err), http.StatusInternalServerError)
		return
	}

	ev := AuditEvent{
		Timestamp: time.Now().UTC(),
		Action:    "draft.approved",
		DraftID:   id,
		Target:    draft.Target.CanonicalName,
		Protocol:  draft.Target.Tracker.Protocol,
		IssueURL:  issueURL,
		RemoteIP:  remoteIP,
	}
	if s.auditLogger != nil {
		if logErr := s.auditLogger.Record(ev); logErr != nil {
			fmt.Fprintf(os.Stderr, "audit log record error: %v\n", logErr)
		}
	}
	if s.webhookNotifier != nil {
		if notifyErr := s.webhookNotifier.Notify(r.Context(), ev); notifyErr != nil {
			fmt.Fprintf(os.Stderr, "webhook notify error: %v\n", notifyErr)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"status":    "submitted",
		"issue_url": issueURL,
		"draft":     draft,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleDiscardDraft(w http.ResponseWriter, r *http.Request) {
	id := extractDraftID(r)
	if id == "" {
		http.Error(w, "missing draft id in path", http.StatusBadRequest)
		return
	}

	if s.draftStore == nil {
		http.Error(w, "draft store unconfigured", http.StatusInternalServerError)
		return
	}

	draft, err := s.draftStore.Get(id)
	if err != nil {
		http.Error(w, fmt.Sprintf("get draft %s: %v", id, err), http.StatusNotFound)
		return
	}

	remoteIP, _, ipErr := net.SplitHostPort(r.RemoteAddr)
	if ipErr != nil {
		remoteIP = r.RemoteAddr
	}

	draft.Status = "discarded"
	if _, err := s.draftStore.Save(draft); err != nil {
		http.Error(w, fmt.Sprintf("save discarded draft %s: %v", id, err), http.StatusInternalServerError)
		return
	}

	ev := AuditEvent{
		Timestamp: time.Now().UTC(),
		Action:    "draft.discarded",
		DraftID:   id,
		Target:    draft.Target.CanonicalName,
		Protocol:  draft.Target.Tracker.Protocol,
		RemoteIP:  remoteIP,
	}
	if s.auditLogger != nil {
		if logErr := s.auditLogger.Record(ev); logErr != nil {
			fmt.Fprintf(os.Stderr, "audit log record error: %v\n", logErr)
		}
	}
	if s.webhookNotifier != nil {
		if notifyErr := s.webhookNotifier.Notify(r.Context(), ev); notifyErr != nil {
			fmt.Fprintf(os.Stderr, "webhook notify error: %v\n", notifyErr)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"status": "discarded",
		"id":     id,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	var events []AuditEvent
	var err error
	if s.auditLogger != nil {
		events, err = s.auditLogger.ListRecent(50)
		if err != nil {
			http.Error(w, fmt.Sprintf("list audit log: %v", err), http.StatusInternalServerError)
			return
		}
	} else {
		events = []AuditEvent{}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(events); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write([]byte(indexHTML)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Start launches the HTTP server listening on the configured address.
func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.addr, err)
	}
	s.httpServer = &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return s.httpServer.Serve(listener)
}

// Shutdown terminates the running HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	return s.httpServer.Shutdown(ctx)
}

const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>bugrouter — Cloud Control Plane</title>
  <style>
    :root {
      --bg: #0d1117;
      --card: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --heading: #f0f6fc;
      --accent: #58a6ff;
      --success: #238636;
      --danger: #da3633;
      --warning: #d29922;
      --muted: #8b949e;
    }
    body {
      margin: 0;
      padding: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
    }
    header {
      background: var(--card);
      border-bottom: 1px solid var(--border);
      padding: 16px 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    header h1 {
      margin: 0;
      font-size: 1.25rem;
      color: var(--heading);
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .badge {
      font-size: 0.75rem;
      padding: 2px 8px;
      border-radius: 12px;
      background: var(--border);
      color: var(--accent);
    }
    main {
      max-width: 1200px;
      margin: 24px auto;
      padding: 0 16px;
    }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 6px;
      overflow: hidden;
      margin-bottom: 24px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
    }
    th, td {
      padding: 12px 16px;
      border-bottom: 1px solid var(--border);
      font-size: 0.9rem;
    }
    th {
      background: #090d13;
      color: var(--muted);
      font-weight: 600;
    }
    tr:last-child td {
      border-bottom: none;
    }
    .btn {
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 0.8rem;
      font-weight: 600;
      cursor: pointer;
      border: 1px solid transparent;
      margin-right: 6px;
    }
    .btn-approve {
      background: var(--success);
      color: white;
    }
    .btn-discard {
      background: var(--card);
      border-color: var(--border);
      color: var(--danger);
    }
    .btn-inspect {
      background: var(--card);
      border-color: var(--border);
      color: var(--accent);
    }
    .btn:hover {
      opacity: 0.9;
    }
    .status-tag {
      padding: 2px 8px;
      border-radius: 10px;
      font-size: 0.75rem;
      font-weight: 600;
    }
    .status-pending { background: rgba(210, 153, 34, 0.2); color: var(--warning); }
    .status-submitted { background: rgba(35, 134, 54, 0.2); color: #3fb950; }
    .status-discarded { background: rgba(218, 54, 51, 0.2); color: var(--danger); }
    #modal {
      display: none;
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0,0,0,0.7);
      align-items: center;
      justify-content: center;
    }
    #modal-box {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      max-width: 800px;
      width: 90%;
      max-height: 85vh;
      overflow-y: auto;
      padding: 24px;
    }
    pre {
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 12px;
      overflow-x: auto;
      font-size: 0.85rem;
      color: #79c0ff;
    }
  </style>
</head>
<body>
  <header>
    <h1>bugrouter <span>Cloud Control Plane</span> <span class="badge">CalVer 2026.10.0</span></h1>
    <div style="display: flex; gap: 8px; align-items: center;">
      <input type="password" id="auth-token" placeholder="Auth Token" style="padding: 6px 10px; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; color: var(--text); font-size: 0.85rem;" onchange="saveToken(this.value)">
      <button class="btn btn-inspect" onclick="refreshQueue()">Refresh Queue</button>
    </div>
  </header>
  <main>
    <h2>Human-in-the-Loop Review Queue</h2>
    <div class="card">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Title</th>
            <th>Target</th>
            <th>Protocol</th>
            <th>Status</th>
            <th>Created</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="drafts-table">
          <tr><td colspan="7" style="text-align:center; color: var(--muted);">Loading staged drafts...</td></tr>
        </tbody>
      </table>
    </div>

    <h2>Recent Audit Trail</h2>
    <div class="card" id="audit-container">
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Action</th>
            <th>Draft ID</th>
            <th>Target</th>
            <th>Protocol</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody id="audit-table">
          <tr><td colspan="6" style="text-align:center; color: var(--muted);">Loading audit log...</td></tr>
        </tbody>
      </table>
    </div>
  </main>

  <div id="modal" onclick="closeModal(event)">
    <div id="modal-box" onclick="event.stopPropagation()">
      <h3 id="modal-title">Draft Inspection</h3>
      <div id="modal-content"></div>
      <div style="text-align: right; margin-top: 16px;">
        <button class="btn btn-discard" onclick="closeModal()">Close</button>
      </div>
    </div>
  </div>

  <script>
    let currentDrafts = [];

    function getToken() {
      return sessionStorage.getItem('bugrouter_token') || '';
    }

    function saveToken(val) {
      sessionStorage.setItem('bugrouter_token', val.trim());
    }

    const storedToken = getToken();
    if (storedToken) {
      const tokenInput = document.getElementById('auth-token');
      if (tokenInput) tokenInput.value = storedToken;
    }

    function getHeaders() {
      const headers = { 'X-Bugrouter-Request': '1' };
      const tok = getToken();
      if (tok) {
        headers['Authorization'] = 'Bearer ' + tok;
      }
      return headers;
    }

    async function fetchDrafts() {
      try {
        const res = await fetch('/api/v1/drafts', { headers: getHeaders() });
        currentDrafts = await res.json();
        renderTable();
      } catch (err) {
        document.getElementById('drafts-table').innerHTML =
          '<tr><td colspan="7" style="color:var(--danger); text-align:center;">Failed to load drafts: ' + err.message + '</td></tr>';
      }
    }

    function renderTable() {
      const tbody = document.getElementById('drafts-table');
      if (!currentDrafts || currentDrafts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color: var(--muted);">No staged drafts pending review.</td></tr>';
        return;
      }
      tbody.innerHTML = currentDrafts.map(d => {
        const statusClass = d.status === 'submitted' ? 'status-submitted' : (d.status === 'discarded' ? 'status-discarded' : 'status-pending');
        const targetName = (d.target && d.target.canonical_name) || 'unknown';
        const protocol = (d.target && d.target.tracker && d.target.tracker.protocol) || 'none';
        return '<tr>' +
          '<td><code>' + d.id + '</code></td>' +
          '<td>' + escapeHTML(d.title || '') + '</td>' +
          '<td>' + escapeHTML(targetName) + '</td>' +
          '<td><span class="badge">' + protocol + '</span></td>' +
          '<td><span class="status-tag ' + statusClass + '">' + d.status + '</span></td>' +
          '<td>' + new Date(d.created_at).toLocaleString() + '</td>' +
          '<td>' +
            '<button class="btn btn-inspect" onclick="inspectDraft(\'' + d.id + '\')">Inspect</button>' +
            (d.status !== 'submitted' ? '<button class="btn btn-approve" onclick="approveDraft(\'' + d.id + '\')">Approve</button>' : '') +
            (d.status !== 'discarded' ? '<button class="btn btn-discard" onclick="discardDraft(\'' + d.id + '\')">Discard</button>' : '') +
          '</td>' +
        '</tr>';
      }).join('');
    }

    function inspectDraft(id) {
      const d = currentDrafts.find(x => x.id === id);
      if (!d) return;
      document.getElementById('modal-title').textContent = 'Draft: ' + d.title;
      let bodyHtml = '<h4>Target Metadata</h4><p>Target: <b>' + (d.target.canonical_name || '') + '</b> | Protocol: <b>' + (d.target.tracker.protocol || '') + '</b></p>';
      if (d.submission_url) {
        const u = d.submission_url;
        if (u.startsWith('https://') || u.startsWith('http://') || u.startsWith('mailto:')) {
          bodyHtml += '<p>Submission URL: <a href="' + escapeHTML(u) + '" target="_blank" style="color:var(--accent);">' + escapeHTML(u) + '</a></p>';
        } else {
          bodyHtml += '<p>Submission URL: <span>' + escapeHTML(u) + '</span></p>';
        }
      }
      if (d.template) {
        bodyHtml += '<h4>Template Schema</h4><p>Name: ' + escapeHTML(d.template.name || '') + ' (' + d.template.format + ')</p>';
      }
      if (d.potential_duplicates && d.potential_duplicates.length > 0) {
        bodyHtml += '<div style="margin-top:12px; padding:12px; background:rgba(210,153,34,0.15); border:1px solid var(--warning); border-radius:6px;">';
        bodyHtml += '<h4 style="margin:0 0 8px 0; color:var(--warning);">Potential Upstream Duplicates</h4><ul style="margin:0; padding-left:20px;">';
        for (const dup of d.potential_duplicates) {
          const scorePct = (dup.score * 100).toFixed(0) + '%';
          const link = (dup.url && (dup.url.startsWith('https://') || dup.url.startsWith('http://'))) ?
            '<a href="' + escapeHTML(dup.url) + '" target="_blank" style="color:var(--accent);">' + escapeHTML(dup.title || dup.id) + '</a>' :
            escapeHTML(dup.title || dup.id);
          bodyHtml += '<li>[' + escapeHTML(dup.state || 'unknown') + '] ' + link + ' <span class="badge">' + scorePct + ' match</span></li>';
        }
        bodyHtml += '</ul></div>';
      }
      bodyHtml += '<h4>Scrubbed Markdown Body</h4><pre>' + escapeHTML(d.markdown_body || '') + '</pre>';
      document.getElementById('modal-content').innerHTML = bodyHtml;
      document.getElementById('modal').style.display = 'flex';
    }

    function closeModal() {
      document.getElementById('modal').style.display = 'none';
    }

    function refreshQueue() {
      fetchDrafts();
      fetchAudit();
    }

    async function fetchAudit() {
      try {
        const res = await fetch('/api/v1/audit', { headers: getHeaders() });
        const events = await res.json();
        renderAudit(events);
      } catch (err) {
        document.getElementById('audit-table').innerHTML =
          '<tr><td colspan="6" style="color:var(--danger); text-align:center;">Failed to load audit log: ' + err.message + '</td></tr>';
      }
    }

    function renderAudit(events) {
      const tbody = document.getElementById('audit-table');
      if (!events || events.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color: var(--muted);">No recent audit events recorded.</td></tr>';
        return;
      }
      tbody.innerHTML = events.map(e => {
        let details = '-';
        if (e.issue_url) {
          const u = e.issue_url;
          if (u.startsWith('https://') || u.startsWith('http://')) {
            details = '<a href="' + escapeHTML(u) + '" target="_blank" style="color:var(--accent);">' + escapeHTML(u) + '</a>';
          } else {
            details = escapeHTML(u);
          }
        } else if (e.error) {
          details = '<span style="color:var(--danger);">' + escapeHTML(e.error) + '</span>';
        }
        return '<tr>' +
          '<td>' + new Date(e.timestamp).toLocaleString() + '</td>' +
          '<td><span class="badge">' + escapeHTML(e.action || '') + '</span></td>' +
          '<td><code>' + escapeHTML(e.draft_id || '') + '</code></td>' +
          '<td>' + escapeHTML(e.target || '') + '</td>' +
          '<td>' + escapeHTML(e.protocol || '') + '</td>' +
          '<td>' + details + '</td>' +
        '</tr>';
      }).join('');
    }

    async function approveDraft(id) {
      if (!confirm('Approve and submit draft ' + id + ' to upstream tracker?')) return;
      try {
        const res = await fetch('/api/v1/drafts/' + id + '/approve', {
          method: 'POST',
          headers: getHeaders()
        });
        if (!res.ok) {
          const errText = await res.text();
          alert('Approval failed: ' + errText);
        } else {
          await fetchDrafts();
          await fetchAudit();
        }
      } catch (err) {
        alert('Network error: ' + err.message);
      }
    }

    async function discardDraft(id) {
      if (!confirm('Discard staged draft ' + id + '?')) return;
      try {
        const res = await fetch('/api/v1/drafts/' + id + '/discard', {
          method: 'POST',
          headers: getHeaders()
        });
        if (!res.ok) {
          const errText = await res.text();
          alert('Discard failed: ' + errText);
        } else {
          await fetchDrafts();
          await fetchAudit();
        }
      } catch (err) {
        alert('Network error: ' + err.message);
      }
    }

    function escapeHTML(str) {
      return str.replace(/[&<>'"]/g, tag => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
      }[tag] || tag));
    }

    fetchDrafts();
    fetchAudit();
  </script>
</body>
</html>
`
