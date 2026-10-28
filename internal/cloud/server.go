package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/riccivr/bugrouter/internal/adapter"
	"github.com/riccivr/bugrouter/internal/version"
)

// ForgeSubmitter submits a staged draft to an authenticated upstream forge.
type ForgeSubmitter = adapter.ForgeSubmitter

// Server provides the Cloud Control Plane HTTP daemon and review queue UI.
type Server struct {
	mux        *http.ServeMux
	draftStore *adapter.DraftStore
	addr       string
	submitter  ForgeSubmitter
	httpServer *http.Server
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
	}
	s.registerRoutes()
	return s
}

// Handler returns the underlying http.Handler for testing or custom wrapping.
func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/v1/drafts", s.handleListDrafts)
	s.mux.HandleFunc("POST /api/v1/drafts/{id}/approve", s.handleApproveDraft)
	s.mux.HandleFunc("POST /api/v1/drafts/{id}/discard", s.handleDiscardDraft)
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

	var issueURL string
	if s.submitter != nil {
		issueURL, err = s.submitter.Submit(r.Context(), draft)
		if err != nil {
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

	draft.Status = "discarded"
	if _, err := s.draftStore.Save(draft); err != nil {
		http.Error(w, fmt.Sprintf("save discarded draft %s: %v", id, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"status": "discarded",
		"id":     id,
	}); err != nil {
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
		Handler:           s.mux,
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
    <div>
      <button class="btn btn-inspect" onclick="fetchDrafts()">Refresh Queue</button>
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

    async function fetchDrafts() {
      try {
        const res = await fetch('/api/v1/drafts');
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
      bodyHtml += '<h4>Scrubbed Markdown Body</h4><pre>' + escapeHTML(d.markdown_body || '') + '</pre>';
      document.getElementById('modal-content').innerHTML = bodyHtml;
      document.getElementById('modal').style.display = 'flex';
    }

    function closeModal() {
      document.getElementById('modal').style.display = 'none';
    }

    async function approveDraft(id) {
      if (!confirm('Approve and submit draft ' + id + ' to upstream tracker?')) return;
      try {
        const res = await fetch('/api/v1/drafts/' + id + '/approve', { method: 'POST' });
        if (!res.ok) {
          const errText = await res.text();
          alert('Approval failed: ' + errText);
        } else {
          await fetchDrafts();
        }
      } catch (err) {
        alert('Network error: ' + err.message);
      }
    }

    async function discardDraft(id) {
      if (!confirm('Discard staged draft ' + id + '?')) return;
      try {
        const res = await fetch('/api/v1/drafts/' + id + '/discard', { method: 'POST' });
        if (!res.ok) {
          const errText = await res.text();
          alert('Discard failed: ' + errText);
        } else {
          await fetchDrafts();
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
  </script>
</body>
</html>
`
