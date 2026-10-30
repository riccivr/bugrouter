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
	"path/filepath"
	"strings"
	"time"

	"github.com/riccivr/bugrouter/internal/adapter"
	"github.com/riccivr/bugrouter/internal/dedup"
	"github.com/riccivr/bugrouter/internal/httpx"
	"github.com/riccivr/bugrouter/internal/introspector"
	"github.com/riccivr/bugrouter/internal/resolver"
	"github.com/riccivr/bugrouter/internal/scrubber"
	"github.com/riccivr/bugrouter/internal/telemetry"
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
	resolver        *resolver.Waterfall
	dedupFinder     *dedup.Finder
	introspector    *introspector.Introspector
	httpClient      *httpx.Client
	stackDir        string
	servicesPath    string
	patchStore      *adapter.PatchStore
}

// NewServer initializes a Cloud Control Plane server with routes registered.
func NewServer(addr string, store *adapter.DraftStore, submitter ForgeSubmitter) *Server {
	if addr == "" {
		addr = ":8080"
	}
	hc := httpx.NewClient(0)
	s := &Server{
		mux:          http.NewServeMux(),
		draftStore:   store,
		addr:         addr,
		submitter:    submitter,
		authToken:    os.Getenv("BUGROUTER_CLOUD_TOKEN"),
		stackDir:     ".",
		servicesPath: resolver.ResolveOrgCloudConfigPath(),
		patchStore:   adapter.NewPatchStore(""),
		introspector: introspector.New(hc),
		httpClient:   hc,
	}
	s.registerRoutes()
	return s
}

// WithIntrospector configures an issue template introspector.
func (s *Server) WithIntrospector(intro *introspector.Introspector) *Server {
	if intro != nil {
		s.introspector = intro
	}
	return s
}

// WithHTTPClient overrides the default HTTP client (e.g. for testing with private/loopback hosts permitted).
func (s *Server) WithHTTPClient(client *httpx.Client) *Server {
	if client != nil {
		s.httpClient = client
	}
	return s
}

// WithServicesFile sets the services.json file path for the plug-and-play dependency catalog.
func (s *Server) WithServicesFile(path string) *Server {
	s.servicesPath = path
	return s
}

// WithPatchStore overrides the default dependency patch store for testing or custom configuration.
func (s *Server) WithPatchStore(store *adapter.PatchStore) *Server {
	if store != nil {
		s.patchStore = store
	}
	return s
}

// WithStackScanner configures the resolver waterfall and duplicate finder for the stack radar API.
func (s *Server) WithStackScanner(wf *resolver.Waterfall, finder *dedup.Finder, rootDir string) *Server {
	s.resolver = wf
	s.dedupFinder = finder
	if strings.TrimSpace(rootDir) != "" {
		s.stackDir = rootDir
	} else {
		s.stackDir = "."
	}
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

		// 2. CSRF / Cross-Origin Mutation Guard on mutating /api/v1/... routes
		if (r.Method == http.MethodPost || r.Method == http.MethodDelete || r.Method == http.MethodPut) && strings.HasPrefix(r.URL.Path, "/api/v1/") {
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
	s.mux.HandleFunc("GET /api/v1/services", s.handleListServices)
	s.mux.HandleFunc("POST /api/v1/services", s.handleUpsertService)
	s.mux.HandleFunc("DELETE /api/v1/services/{name}", s.handleDeleteService)
	s.mux.HandleFunc("GET /api/v1/patches", s.handleListPatches)
	s.mux.HandleFunc("POST /api/v1/patches/check", s.handleCheckPatches)
	s.mux.HandleFunc("POST /api/v1/patches", s.handleRecordPatch)
	s.mux.HandleFunc("DELETE /api/v1/patches/{id}", s.handleDeletePatch)
	s.mux.HandleFunc("GET /api/v1/drafts", s.handleListDrafts)
	s.mux.HandleFunc("POST /api/v1/drafts", s.handleCreateDraft)
	s.mux.HandleFunc("POST /api/v1/drafts/{id}/approve", s.handleApproveDraft)
	s.mux.HandleFunc("POST /api/v1/drafts/{id}/discard", s.handleDiscardDraft)
	s.mux.HandleFunc("GET /api/v1/audit", s.handleAuditLog)
	s.mux.HandleFunc("GET /api/v1/stack", s.handleStack)
	s.mux.HandleFunc("GET /", s.handleIndex)
}

func (s *Server) handleStack(w http.ResponseWriter, r *http.Request) {
	checkUpstream := r.URL.Query().Get("check_upstream") == "1" || r.URL.Query().Get("check_upstream") == "true"
	if s.resolver == nil {
		report := dedup.StackRadarReport{
			RootDir:   s.stackDir,
			ScannedAt: time.Now().UTC(),
			Entries:   []dedup.StackRadarEntry{},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(report); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()

	report, err := dedup.BuildStackRadar(ctx, s.resolver, s.dedupFinder, s.stackDir, checkUpstream)
	if err != nil {
		http.Error(w, fmt.Sprintf("build stack radar: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(report); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
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

func (s *Server) handleListServices(w http.ResponseWriter, r *http.Request) {
	if s.servicesPath == "" {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte("[]")); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	data, err := os.ReadFile(s.servicesPath)
	if err != nil {
		if os.IsNotExist(err) {
			w.Header().Set("Content-Type", "application/json")
			if _, writeErr := w.Write([]byte("[]")); writeErr != nil {
				http.Error(w, writeErr.Error(), http.StatusInternalServerError)
			}
			return
		}
		http.Error(w, fmt.Sprintf("read services file: %v", err), http.StatusInternalServerError)
		return
	}

	var reg resolver.OrgCloudRegistry
	if err := json.Unmarshal(data, &reg); err != nil {
		http.Error(w, fmt.Sprintf("unmarshal services: %v", err), http.StatusInternalServerError)
		return
	}

	if reg.Services == nil {
		reg.Services = []resolver.ServiceEntry{}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(reg.Services); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleUpsertService(w http.ResponseWriter, r *http.Request) {
	var entry resolver.ServiceEntry
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024*1024)).Decode(&entry); err != nil {
		http.Error(w, fmt.Sprintf("invalid json payload: %v", err), http.StatusBadRequest)
		return
	}

	entry.Name = strings.TrimSpace(entry.Name)
	if entry.Name == "" {
		http.Error(w, "service name is required", http.StatusBadRequest)
		return
	}

	// Normalize tracker if URL is omitted or protocol is missing
	if entry.Tracker.URL == "" || entry.Tracker.Protocol == "" {
		derivedTracker, normRepo := resolver.ClassifyTracker(entry.Tracker.URL, entry.Tracker.Email, entry.RepositoryURL)
		if entry.Tracker.Protocol == "" {
			entry.Tracker.Protocol = derivedTracker.Protocol
		}
		if entry.Tracker.URL == "" {
			entry.Tracker.URL = derivedTracker.URL
		}
		if entry.Tracker.Email == "" {
			entry.Tracker.Email = derivedTracker.Email
		}
		if normRepo != "" && entry.RepositoryURL == "" {
			entry.RepositoryURL = normRepo
		}
	}

	if s.servicesPath == "" {
		http.Error(w, "services configuration path not set", http.StatusInternalServerError)
		return
	}

	// Load existing registry or initialize empty
	var reg resolver.OrgCloudRegistry
	if data, err := os.ReadFile(s.servicesPath); err == nil {
		if unmarshalErr := json.Unmarshal(data, &reg); unmarshalErr != nil {
			http.Error(w, fmt.Sprintf("read existing services file: %v", unmarshalErr), http.StatusInternalServerError)
			return
		}
	}

	// Upsert entry by name (case-insensitive)
	found := false
	for i, existing := range reg.Services {
		if strings.EqualFold(existing.Name, entry.Name) {
			reg.Services[i] = entry
			found = true
			break
		}
	}
	if !found {
		reg.Services = append(reg.Services, entry)
	}

	// Write atomically with 0600 permissions
	if err := writeRegistryAtomic(s.servicesPath, &reg); err != nil {
		http.Error(w, fmt.Sprintf("save services: %v", err), http.StatusInternalServerError)
		return
	}

	// Record audit event
	remoteIP := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		remoteIP = strings.TrimSpace(strings.Split(fwd, ",")[0])
	}
	ev := AuditEvent{
		Timestamp: time.Now().UTC(),
		Action:    "service.upserted",
		Target:    entry.Name,
		Protocol:  entry.Tracker.Protocol,
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
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(entry); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleDeleteService(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		trimmed := strings.TrimPrefix(r.URL.Path, "/api/v1/services/")
		name = strings.Trim(trimmed, "/")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		http.Error(w, "missing service name in path", http.StatusBadRequest)
		return
	}

	if s.servicesPath == "" {
		http.Error(w, "services configuration path not set", http.StatusInternalServerError)
		return
	}

	data, err := os.ReadFile(s.servicesPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, fmt.Sprintf("service %q not found", name), http.StatusNotFound)
			return
		}
		http.Error(w, fmt.Sprintf("read services file: %v", err), http.StatusInternalServerError)
		return
	}

	var reg resolver.OrgCloudRegistry
	if err := json.Unmarshal(data, &reg); err != nil {
		http.Error(w, fmt.Sprintf("unmarshal services: %v", err), http.StatusInternalServerError)
		return
	}

	found := false
	var updated []resolver.ServiceEntry
	for _, existing := range reg.Services {
		if strings.EqualFold(existing.Name, name) {
			found = true
			continue
		}
		updated = append(updated, existing)
	}
	if !found {
		http.Error(w, fmt.Sprintf("service %q not found", name), http.StatusNotFound)
		return
	}

	reg.Services = updated
	if err := writeRegistryAtomic(s.servicesPath, &reg); err != nil {
		http.Error(w, fmt.Sprintf("save services: %v", err), http.StatusInternalServerError)
		return
	}

	// Record audit event
	remoteIP := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		remoteIP = strings.TrimSpace(strings.Split(fwd, ",")[0])
	}
	ev := AuditEvent{
		Timestamp: time.Now().UTC(),
		Action:    "service.deleted",
		Target:    name,
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
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "name": name}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func writeRegistryAtomic(path string, reg *resolver.OrgCloudRegistry) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create config dir %s: %w", dir, err)
	}

	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal registry: %w", err)
	}

	tmpFile, err := os.CreateTemp(dir, "services-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp services file in %s: %w", dir, err)
	}
	tmpName := tmpFile.Name()

	if err := tmpFile.Chmod(0600); err != nil {
		closeErr := tmpFile.Close()
		cleanupErr := os.Remove(tmpName)
		if cleanupErr != nil && !os.IsNotExist(cleanupErr) {
			return fmt.Errorf("chmod %s: %w (close: %v, cleanup: %v)", tmpName, err, closeErr, cleanupErr)
		}
		if closeErr != nil {
			return fmt.Errorf("chmod %s: %w (close: %v)", tmpName, err, closeErr)
		}
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}

	if _, err := tmpFile.Write(data); err != nil {
		closeErr := tmpFile.Close()
		cleanupErr := os.Remove(tmpName)
		if cleanupErr != nil && !os.IsNotExist(cleanupErr) {
			return fmt.Errorf("write %s: %w (close: %v, cleanup: %v)", tmpName, err, closeErr, cleanupErr)
		}
		if closeErr != nil {
			return fmt.Errorf("write %s: %w (close: %v)", tmpName, err, closeErr)
		}
		return fmt.Errorf("write %s: %w", tmpName, err)
	}

	if err := tmpFile.Close(); err != nil {
		cleanupErr := os.Remove(tmpName)
		if cleanupErr != nil && !os.IsNotExist(cleanupErr) {
			return fmt.Errorf("close %s: %w (cleanup: %v)", tmpName, err, cleanupErr)
		}
		return fmt.Errorf("close %s: %w", tmpName, err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		cleanupErr := os.Remove(tmpName)
		if cleanupErr != nil && !os.IsNotExist(cleanupErr) {
			return fmt.Errorf("rename to %s: %w (cleanup: %v)", path, err, cleanupErr)
		}
		return fmt.Errorf("rename to %s: %w", path, err)
	}

	return nil
}

func (s *Server) handleListPatches(w http.ResponseWriter, r *http.Request) {
	if s.patchStore == nil {
		http.Error(w, "patch store not configured", http.StatusInternalServerError)
		return
	}
	if r.URL.Query().Get("check_upstream") == "1" || r.URL.Query().Get("check_upstream") == "true" {
		s.handleCheckPatches(w, r)
		return
	}
	patches, err := s.patchStore.List()
	if err != nil {
		http.Error(w, fmt.Sprintf("list patches: %v", err), http.StatusInternalServerError)
		return
	}
	if patches == nil {
		patches = []adapter.DependencyPatch{}
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(patches); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleCheckPatches(w http.ResponseWriter, r *http.Request) {
	if s.patchStore == nil {
		http.Error(w, "patch store not configured", http.StatusInternalServerError)
		return
	}
	patches, err := s.patchStore.List()
	if err != nil {
		http.Error(w, fmt.Sprintf("list patches: %v", err), http.StatusInternalServerError)
		return
	}
	if patches == nil {
		patches = []adapter.DependencyPatch{}
	}

	results, err := adapter.CheckPatchUpstreamStatus(r.Context(), s.httpClient, patches)
	if err != nil {
		http.Error(w, fmt.Sprintf("check patch upstream status: %v", err), http.StatusInternalServerError)
		return
	}
	if results == nil {
		results = []adapter.PatchStatusResult{}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(results); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type RecordPatchRequest struct {
	Dependency       string `json:"dependency"`
	Ecosystem        string `json:"ecosystem"`
	PatchTarget      string `json:"patch_target"`
	ManifestFile     string `json:"manifest_file"`
	UpstreamIssueURL string `json:"upstream_issue_url"`
	Reason           string `json:"reason"`
}

func (s *Server) handleRecordPatch(w http.ResponseWriter, r *http.Request) {
	if s.patchStore == nil {
		http.Error(w, "patch store not configured", http.StatusInternalServerError)
		return
	}
	var req RecordPatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid json payload: %v", err), http.StatusBadRequest)
		return
	}

	req.Dependency = strings.TrimSpace(req.Dependency)
	req.PatchTarget = strings.TrimSpace(req.PatchTarget)
	req.Reason = strings.TrimSpace(req.Reason)

	if req.Dependency == "" {
		http.Error(w, "dependency is required", http.StatusBadRequest)
		return
	}
	if req.PatchTarget == "" {
		http.Error(w, "patch_target is required", http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		http.Error(w, "reason is required", http.StatusBadRequest)
		return
	}

	patch, err := s.patchStore.Record(req.Dependency, req.Ecosystem, req.PatchTarget, req.ManifestFile, req.UpstreamIssueURL, req.Reason)
	if err != nil {
		http.Error(w, fmt.Sprintf("record patch: %v", err), http.StatusInternalServerError)
		return
	}

	// Record audit event
	remoteIP := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		remoteIP = strings.TrimSpace(strings.Split(fwd, ",")[0])
	}
	ev := AuditEvent{
		Timestamp: time.Now().UTC(),
		Action:    "patch.recorded",
		DraftID:   patch.ID,
		Target:    patch.Dependency,
		Protocol:  resolver.Protocol(patch.Ecosystem),
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
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(patch); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleDeletePatch(w http.ResponseWriter, r *http.Request) {
	if s.patchStore == nil {
		http.Error(w, "patch store not configured", http.StatusInternalServerError)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		trimmed := strings.TrimPrefix(r.URL.Path, "/api/v1/patches/")
		id = strings.Trim(trimmed, "/")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		http.Error(w, "missing patch id in path", http.StatusBadRequest)
		return
	}

	if err := s.patchStore.Remove(id); err != nil {
		http.Error(w, fmt.Sprintf("patch %q not found: %v", id, err), http.StatusNotFound)
		return
	}

	// Record audit event
	remoteIP := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		remoteIP = strings.TrimSpace(strings.Split(fwd, ",")[0])
	}
	ev := AuditEvent{
		Timestamp: time.Now().UTC(),
		Action:    "patch.removed",
		DraftID:   id,
		Target:    id,
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
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"status": "deleted",
		"id":     id,
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

// CreateDraftRequest defines the payload for creating a staged bug report draft.
type CreateDraftRequest struct {
	Query            string `json:"query"`
	Title            string `json:"title"`
	Summary          string `json:"summary"`
	StepsToReproduce string `json:"steps_to_reproduce"`
	ExpectedBehavior string `json:"expected_behavior,omitempty"`
	ActualBehavior   string `json:"actual_behavior,omitempty"`
	Logs             string `json:"logs,omitempty"`
	IncludeTelemetry bool   `json:"include_telemetry"`
	StrictQuality    bool   `json:"strict_quality"`
}

func (s *Server) handleCreateDraft(w http.ResponseWriter, r *http.Request) {
	var req CreateDraftRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024*1024)).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid json payload: %v", err), http.StatusBadRequest)
		return
	}

	req.Query = strings.TrimSpace(req.Query)
	req.Title = strings.TrimSpace(req.Title)
	if req.Query == "" {
		http.Error(w, "query is required", http.StatusBadRequest)
		return
	}
	if req.Title == "" {
		http.Error(w, "title is required", http.StatusBadRequest)
		return
	}

	// Resolve target
	var target *resolver.Target
	if s.resolver != nil {
		t, err := s.resolver.Resolve(r.Context(), req.Query)
		if err != nil {
			http.Error(w, fmt.Sprintf("resolve query %q: %v", req.Query, err), http.StatusBadRequest)
			return
		}
		target = t
	} else {
		directProbe := resolver.NewDirectProbe()
		t, probeErr := directProbe.Resolve(r.Context(), req.Query)
		if probeErr == nil && t != nil {
			target = t
		} else {
			target = &resolver.Target{
				CanonicalName: req.Query,
				RepositoryURL: req.Query,
				Tracker: resolver.TrackerInfo{
					Protocol: resolver.ProtocolGitHub,
					URL:      req.Query,
				},
			}
		}
	}

	// Collect hardware telemetry if requested
	var sysTelemetry *telemetry.SystemTelemetry
	if req.IncludeTelemetry {
		telem := telemetry.Collect(r.Context())
		sysTelemetry = &telem
	}

	// Query potential duplicates
	var dups []dedup.ExistingIssue
	if s.dedupFinder != nil && target != nil {
		if d, dupErr := s.dedupFinder.FindDuplicates(r.Context(), *target, scrubber.Scrub(req.Title)); dupErr == nil {
			dups = d
		}
	}

	// Introspect issue template and maintainer policy if available
	var schema *introspector.TemplateSchema
	if s.introspector != nil && target != nil {
		if sch, introErr := s.introspector.Introspect(r.Context(), *target); introErr == nil {
			schema = sch
		}
	}

	// Build staged draft
	draft, err := adapter.BuildDraft(adapter.DraftInput{
		Target:           *target,
		Template:         schema,
		Title:            req.Title,
		Summary:          req.Summary,
		StepsToReproduce: req.StepsToReproduce,
		ExpectedBehavior: req.ExpectedBehavior,
		ActualBehavior:   req.ActualBehavior,
		Logs:             req.Logs,
		Duplicates:       dups,
		Telemetry:        sysTelemetry,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("build draft: %v", err), http.StatusBadRequest)
		return
	}

	// Strict quality check
	if req.StrictQuality && !draft.Quality.Passed {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		if encErr := json.NewEncoder(w).Encode(draft.Quality); encErr != nil {
			http.Error(w, encErr.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Save to draftStore
	if s.draftStore != nil {
		if savedPath, saveErr := s.draftStore.Save(draft); saveErr != nil {
			http.Error(w, fmt.Sprintf("save draft: %v", saveErr), http.StatusInternalServerError)
			return
		} else if savedPath == "" {
			// Non-fatal
		}
	}

	// Record audit event
	remoteIP := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		remoteIP = strings.TrimSpace(strings.Split(fwd, ",")[0])
	}
	ev := AuditEvent{
		Timestamp: time.Now().UTC(),
		Action:    "draft.created",
		DraftID:   draft.ID,
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
	w.WriteHeader(http.StatusCreated)
	if encErr := json.NewEncoder(w).Encode(draft); encErr != nil {
		http.Error(w, encErr.Error(), http.StatusInternalServerError)
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

	if draft.Status == "submitted" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		if encErr := json.NewEncoder(w).Encode(map[string]string{
			"error":     "draft already submitted",
			"issue_url": draft.SubmissionURL,
		}); encErr != nil {
			http.Error(w, fmt.Sprintf("encode json: %v", encErr), http.StatusInternalServerError)
		}
		return
	}

	if draft.Status == "companion_only" || (draft.Template != nil && draft.Template.Policy != nil && draft.Template.Policy.AIOptOut) {
		reason := "upstream restrictions"
		if draft.Template != nil && draft.Template.Policy != nil && draft.Template.Policy.OptOutReason != "" {
			reason = draft.Template.Policy.OptOutReason
		}
		http.Error(w, fmt.Sprintf("maintainer policy opt-out: upstream repository restricts automated/AI submissions (%s); use draft as a local human companion only", reason), http.StatusForbidden)
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

	if draft.Status == "submitted" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		if encErr := json.NewEncoder(w).Encode(map[string]string{
			"error":     "draft already submitted",
			"issue_url": draft.SubmissionURL,
		}); encErr != nil {
			http.Error(w, fmt.Sprintf("encode json: %v", encErr), http.StatusInternalServerError)
		}
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
		WriteTimeout:      60 * time.Second,
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
    .status-companion { background: rgba(88, 166, 255, 0.2); color: var(--accent); }
    .badge-revert { background: rgba(35, 134, 54, 0.2); color: #3fb950; font-weight: bold; border: 1px solid rgba(35, 134, 54, 0.4); }
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
    .service-tile {
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 12px;
      cursor: pointer;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      min-height: 75px;
      transition: all 0.15s ease;
    }
    .service-tile:hover {
      border-color: var(--accent);
      transform: translateY(-1px);
    }
    .service-tile.connected {
      border-color: rgba(35, 134, 54, 0.6);
      background: rgba(35, 134, 54, 0.08);
    }
  </style>
</head>
<body>
  <header>
    <h1>bugrouter <span>Cloud Control Plane</span> <span class="badge">CalVer 2026.10.0</span></h1>
    <div style="display: flex; gap: 8px; align-items: center;">
      <input type="password" id="auth-token" placeholder="Auth Token" style="padding: 6px 10px; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; color: var(--text); font-size: 0.85rem;" onchange="saveToken(this.value)">
      <button class="btn btn-approve" onclick="openComposerModal()">New Guided Report</button>
      <button class="btn btn-inspect" onclick="refreshQueue()">Refresh Queue</button>
    </div>
  </header>
  <main>
    <!-- Active Dependency Patches (Temporary Forks) Banner -->
    <div id="patches-container" style="display: none; margin-bottom: 24px;">
      <div class="card" style="border-left: 4px solid #f59e0b; background: rgba(245, 158, 11, 0.06); padding: 16px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 1.1rem;">⚠️</span>
            <h3 style="margin: 0; color: #f59e0b; font-size: 1rem;">Active Dependency Patches (Temporary Forks)</h3>
            <span id="patches-badge" style="background: #f59e0b; color: #000; font-weight: bold; font-size: 0.75rem; padding: 2px 8px; border-radius: 12px;">0 Active</span>
          </div>
          <div style="display: flex; gap: 8px;">
            <button class="btn btn-inspect" style="font-size: 0.8rem; padding: 4px 10px;" onclick="checkPatchesStatus()">Check Upstream Status</button>
            <button class="btn btn-inspect" style="font-size: 0.8rem; padding: 4px 10px;" onclick="openAddPatchModal()">+ Track Local Patch</button>
          </div>
        </div>
        <p style="margin: 0 0 12px 0; color: var(--muted); font-size: 0.85rem;">
          These 3rd-party dependencies are currently running on local forks or vendor patches. Keep them close to your eyes so temporary workarounds do not become permanent tech debt.
        </p>
        <div id="patches-table-wrapper" style="overflow-x: auto;">
          <table style="width: 100%; border-collapse: collapse; font-size: 0.85rem;">
            <thead>
              <tr style="text-align: left; border-bottom: 1px solid rgba(245, 158, 11, 0.2);">
                <th style="padding: 6px 8px;">Dependency</th>
                <th style="padding: 6px 8px;">Ecosystem</th>
                <th style="padding: 6px 8px;">Patch Target (Fork / Branch / File)</th>
                <th style="padding: 6px 8px;">Upstream Issue</th>
                <th style="padding: 6px 8px;">Reason</th>
                <th style="padding: 6px 8px; text-align: right;">Action</th>
              </tr>
            </thead>
            <tbody id="patches-tbody">
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
      <div>
        <h2 style="margin: 0;">Connected Dependencies &amp; Downstream Services</h2>
        <p style="margin: 4px 0 0 0; color: var(--muted); font-size: 0.85rem;">WorkOS-style plug-and-play catalog. Configure downstream dependencies so agents instantly resolve trackers and park bugs without context hijacking.</p>
      </div>
      <button class="btn btn-inspect" onclick="openAddServiceModal()">+ Add Custom Service</button>
    </div>
    <div class="card" style="padding: 16px; margin-bottom: 24px;">
      <div id="services-grid" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px;">
        <div style="color: var(--muted); font-size: 0.85rem;">Loading connected services...</div>
      </div>
    </div>

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

    <div style="display: flex; justify-content: space-between; align-items: center;">
      <h2>Connected Tech Stack &amp; Downstream Radar</h2>
      <button class="btn btn-inspect" onclick="fetchStack(true)">Scan Upstream Bugs</button>
    </div>
    <div class="card" id="stack-container">
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Version</th>
            <th>Ecosystem</th>
            <th>Manifest</th>
            <th>Protocol</th>
            <th>Upstream Tracker URL</th>
            <th>Downstream Radar / Open Issues</th>
          </tr>
        </thead>
        <tbody id="stack-table">
          <tr><td colspan="7" style="text-align:center; color: var(--muted);">Loading workspace stack radar...</td></tr>
        </tbody>
      </table>
    </div>
  <!-- Add Patch Modal -->
  <div id="add-patch-modal" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); align-items: center; justify-content: center; z-index: 1000;" onclick="closeAddPatchModal(event)">
    <div style="background: var(--card); border: 1px solid var(--border); border-radius: 8px; max-width: 600px; width: 90%; max-height: 85vh; overflow-y: auto; padding: 24px;" onclick="event.stopPropagation()">
      <h3 style="margin-top:0; color:var(--heading);">Track Dependency Patch (Temporary Fork)</h3>
      <p style="margin: 0 0 12px 0; color: var(--muted); font-size: 0.85rem;">
        Track a temporary local fork, branch, or patch so your team never forgets to revert it when upstream releases a fix.
      </p>
      <div id="add-patch-error" style="display:none; color:var(--danger); margin-bottom:12px; font-size:0.85rem;"></div>
      <div style="display:flex; flex-direction:column; gap:12px;">
        <div>
          <label style="font-size:0.8rem; color:var(--muted);">Dependency Name *</label>
          <input type="text" id="patch-dep" placeholder="e.g. sharp or github.com/gin-gonic/gin" style="width:100%; box-sizing:border-box; background:var(--input-bg); border:1px solid var(--border); color:var(--text); padding:8px; border-radius:4px;" />
        </div>
        <div>
          <label style="font-size:0.8rem; color:var(--muted);">Patch Target (Fork URL / Branch / File) *</label>
          <input type="text" id="patch-target" placeholder="e.g. github.com/myorg/sharp@fix-segfault or patches/sharp+0.33.patch" style="width:100%; box-sizing:border-box; background:var(--input-bg); border:1px solid var(--border); color:var(--text); padding:8px; border-radius:4px;" />
        </div>
        <div>
          <label style="font-size:0.8rem; color:var(--muted);">Ecosystem (optional, e.g. go, npm, cargo, python, custom)</label>
          <input type="text" id="patch-eco" placeholder="e.g. npm" style="width:100%; box-sizing:border-box; background:var(--input-bg); border:1px solid var(--border); color:var(--text); padding:8px; border-radius:4px;" />
        </div>
        <div>
          <label style="font-size:0.8rem; color:var(--muted);">Manifest File (optional)</label>
          <input type="text" id="patch-manifest" placeholder="e.g. package.json, go.mod, Cargo.toml" style="width:100%; box-sizing:border-box; background:var(--input-bg); border:1px solid var(--border); color:var(--text); padding:8px; border-radius:4px;" />
        </div>
        <div>
          <label style="font-size:0.8rem; color:var(--muted);">Upstream Issue URL (optional)</label>
          <input type="text" id="patch-upstream" placeholder="e.g. https://github.com/lovell/sharp/issues/1234" style="width:100%; box-sizing:border-box; background:var(--input-bg); border:1px solid var(--border); color:var(--text); padding:8px; border-radius:4px;" />
        </div>
        <div>
          <label style="font-size:0.8rem; color:var(--muted);">Reason *</label>
          <textarea id="patch-reason" rows="2" placeholder="Explain why the dependency was temporarily patched..." style="width:100%; box-sizing:border-box; background:var(--input-bg); border:1px solid var(--border); color:var(--text); padding:8px; border-radius:4px; font-family:inherit;"></textarea>
        </div>
        <div style="display:flex; justify-content:flex-end; gap:8px; margin-top:8px;">
          <button class="btn btn-discard" onclick="closeAddPatchModal()">Cancel</button>
          <button class="btn btn-approve" id="btn-save-patch" onclick="submitAddPatch()">Track in Ledger</button>
        </div>
      </div>
    </div>
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

  <div id="composer-modal" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); align-items: center; justify-content: center; z-index: 1000;" onclick="closeComposerModal(event)">
    <div style="background: var(--card); border: 1px solid var(--border); border-radius: 8px; max-width: 700px; width: 90%; max-height: 85vh; overflow-y: auto; padding: 24px;" onclick="event.stopPropagation()">
      <h3 style="margin-top:0; color:var(--heading);">New Guided Bug Report</h3>
      <div id="composer-error" style="display:none; color:var(--danger); margin-bottom:12px; font-size:0.85rem;"></div>
      <div style="display:flex; flex-direction:column; gap:12px;">
        <div>
          <label style="display:block; font-size:0.8rem; color:var(--muted); margin-bottom:4px;">Target Query (e.g. org/repo, command, URL) *</label>
          <input type="text" id="comp-query" placeholder="github.com/myorg/myapp" style="width:100%; box-sizing:border-box; padding:8px; background:var(--bg); border:1px solid var(--border); border-radius:6px; color:var(--text); font-size:0.85rem;">
        </div>
        <div>
          <label style="display:block; font-size:0.8rem; color:var(--muted); margin-bottom:4px;">Bug Title *</label>
          <input type="text" id="comp-title" placeholder="Panic during connection initialization" style="width:100%; box-sizing:border-box; padding:8px; background:var(--bg); border:1px solid var(--border); border-radius:6px; color:var(--text); font-size:0.85rem;">
        </div>
        <div>
          <label style="display:block; font-size:0.8rem; color:var(--muted); margin-bottom:4px;">Summary *</label>
          <textarea id="comp-summary" rows="3" placeholder="Explain the context and failure..." style="width:100%; box-sizing:border-box; padding:8px; background:var(--bg); border:1px solid var(--border); border-radius:6px; color:var(--text); font-size:0.85rem; font-family:inherit;"></textarea>
        </div>
        <div>
          <label style="display:block; font-size:0.8rem; color:var(--muted); margin-bottom:4px;">Steps to Reproduce *</label>
          <textarea id="comp-steps" rows="3" placeholder="1. Step one&#10;2. Step two" style="width:100%; box-sizing:border-box; padding:8px; background:var(--bg); border:1px solid var(--border); border-radius:6px; color:var(--text); font-size:0.85rem; font-family:inherit;"></textarea>
        </div>
        <div style="display:flex; gap:12px;">
          <div style="flex:1;">
            <label style="display:block; font-size:0.8rem; color:var(--muted); margin-bottom:4px;">Expected Behavior</label>
            <input type="text" id="comp-expected" placeholder="Returns clean error" style="width:100%; box-sizing:border-box; padding:8px; background:var(--bg); border:1px solid var(--border); border-radius:6px; color:var(--text); font-size:0.85rem;">
          </div>
          <div style="flex:1;">
            <label style="display:block; font-size:0.8rem; color:var(--muted); margin-bottom:4px;">Actual Behavior</label>
            <input type="text" id="comp-actual" placeholder="Panics with SIGSEGV" style="width:100%; box-sizing:border-box; padding:8px; background:var(--bg); border:1px solid var(--border); border-radius:6px; color:var(--text); font-size:0.85rem;">
          </div>
        </div>
        <div>
          <label style="display:block; font-size:0.8rem; color:var(--muted); margin-bottom:4px;">Logs / Stack Trace</label>
          <textarea id="comp-logs" rows="3" placeholder="Paste error logs here..." style="width:100%; box-sizing:border-box; padding:8px; background:var(--bg); border:1px solid var(--border); border-radius:6px; color:var(--text); font-size:0.85rem; font-family:inherit;"></textarea>
        </div>
        <div style="display:flex; align-items:center; gap:8px;">
          <input type="checkbox" id="comp-telemetry" checked>
          <label for="comp-telemetry" style="font-size:0.85rem; color:var(--text);">Attach Hardware &amp; OS Telemetry</label>
        </div>
        <div style="display:flex; align-items:center; gap:8px;">
          <input type="checkbox" id="comp-strict">
          <label for="comp-strict" style="font-size:0.85rem; color:var(--text);">Strict Quality Check (fail on AI slop / low signal)</label>
        </div>
      </div>
      <div style="display:flex; justify-content:flex-end; gap:8px; margin-top:20px;">
        <button class="btn btn-discard" onclick="closeComposerModal()">Cancel</button>
        <button class="btn btn-approve" id="btn-submit-draft" onclick="submitGuidedDraft()">Stage Draft</button>
      </div>
    </div>
  </div>

  <div id="service-detail-modal" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); align-items: center; justify-content: center; z-index: 1000;" onclick="closeServiceDetailModal(event)">
    <div style="background: var(--card); border: 1px solid var(--border); border-radius: 8px; max-width: 600px; width: 90%; max-height: 85vh; overflow-y: auto; padding: 24px;" onclick="event.stopPropagation()">
      <h3 id="service-detail-title" style="margin-top:0; color:var(--heading);">Service Details</h3>
      <div id="service-detail-content"></div>
      <div style="text-align: right; margin-top: 16px;">
        <button class="btn btn-discard" onclick="closeServiceDetailModal()">Close</button>
      </div>
    </div>
  </div>

  <div id="add-service-modal" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); align-items: center; justify-content: center; z-index: 1000;" onclick="closeAddServiceModal(event)">
    <div style="background: var(--card); border: 1px solid var(--border); border-radius: 8px; max-width: 600px; width: 90%; max-height: 85vh; overflow-y: auto; padding: 24px;" onclick="event.stopPropagation()">
      <h3 style="margin-top:0; color:var(--heading);">Connect Custom Dependency / Service</h3>
      <div id="add-service-error" style="display:none; color:var(--danger); margin-bottom:12px; font-size:0.85rem;"></div>
      <div style="display:flex; flex-direction:column; gap:12px;">
        <div>
          <label style="display:block; font-size:0.8rem; color:var(--muted); margin-bottom:4px;">Service or Dependency Name *</label>
          <input type="text" id="svc-name" placeholder="e.g. sharp, billing-api, ffmpeg" style="width:100%; box-sizing:border-box; padding:8px; background:var(--bg); border:1px solid var(--border); border-radius:6px; color:var(--text); font-size:0.85rem;">
        </div>
        <div>
          <label style="display:block; font-size:0.8rem; color:var(--muted); margin-bottom:4px;">Repository URL</label>
          <input type="text" id="svc-repo" placeholder="https://github.com/myorg/myservice" style="width:100%; box-sizing:border-box; padding:8px; background:var(--bg); border:1px solid var(--border); border-radius:6px; color:var(--text); font-size:0.85rem;">
        </div>
        <div>
          <label style="display:block; font-size:0.8rem; color:var(--muted); margin-bottom:4px;">Tracker / Issues URL (optional if inferrable)</label>
          <input type="text" id="svc-tracker" placeholder="https://github.com/myorg/myservice/issues" style="width:100%; box-sizing:border-box; padding:8px; background:var(--bg); border:1px solid var(--border); border-radius:6px; color:var(--text); font-size:0.85rem;">
        </div>
        <div>
          <label style="display:block; font-size:0.8rem; color:var(--muted); margin-bottom:4px;">Protocol</label>
          <select id="svc-protocol" style="width:100%; box-sizing:border-box; padding:8px; background:var(--bg); border:1px solid var(--border); border-radius:6px; color:var(--text); font-size:0.85rem;">
            <option value="">Auto-detect from URL</option>
            <option value="github">GitHub</option>
            <option value="gitlab">GitLab</option>
            <option value="jira">Jira</option>
            <option value="linear">Linear</option>
            <option value="gitea">Gitea / Forgejo</option>
            <option value="bugzilla">Bugzilla</option>
            <option value="custom">Custom Tracker</option>
          </select>
        </div>
      </div>
      <div style="display:flex; justify-content:flex-end; gap:8px; margin-top:20px;">
        <button class="btn btn-discard" onclick="closeAddServiceModal()">Cancel</button>
        <button class="btn btn-approve" id="btn-add-service" onclick="submitCustomService()">Connect Service</button>
      </div>
    </div>
  </div>

  <script>
    const PRESETS = [
      { name: 'stripe', title: 'Stripe', repo: 'https://github.com/stripe/stripe-node', tracker: 'https://github.com/stripe/stripe-node/issues', protocol: 'github' },
      { name: 'supabase', title: 'Supabase', repo: 'https://github.com/supabase/supabase', tracker: 'https://github.com/supabase/supabase/issues', protocol: 'github' },
      { name: 'auth0', title: 'Auth0', repo: 'https://github.com/auth0/node-auth0', tracker: 'https://github.com/auth0/node-auth0/issues', protocol: 'github' },
      { name: 'prisma', title: 'Prisma', repo: 'https://github.com/prisma/prisma', tracker: 'https://github.com/prisma/prisma/issues', protocol: 'github' },
      { name: 'nextjs', title: 'Next.js', repo: 'https://github.com/vercel/next.js', tracker: 'https://github.com/vercel/next.js/issues', protocol: 'github' },
      { name: 'remix', title: 'Remix', repo: 'https://github.com/remix-run/remix', tracker: 'https://github.com/remix-run/remix/issues', protocol: 'github' },
      { name: 'redis', title: 'Redis', repo: 'https://github.com/redis/redis', tracker: 'https://github.com/redis/redis/issues', protocol: 'github' },
      { name: 'postgres', title: 'Postgres', repo: 'https://github.com/postgres/postgres', tracker: 'https://github.com/postgres/postgres/issues', protocol: 'github' },
      { name: 'ffmpeg', title: 'FFmpeg', repo: 'https://git.ffmpeg.org/ffmpeg.git', tracker: 'https://trac.ffmpeg.org', protocol: 'custom' },
      { name: 'blender', title: 'Blender', repo: 'https://projects.blender.org/blender/blender', tracker: 'https://projects.blender.org/blender/blender/issues', protocol: 'gitea' }
    ];

    let currentDrafts = [];
    let currentServices = [];
    let currentPatches = [];

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

    async function fetchPatches() {
      try {
        const res = await fetch('/api/v1/patches', { headers: getHeaders() });
        if (res.ok) {
          currentPatches = await res.json();
          renderPatches();
        }
      } catch (err) {
        console.error('fetch patches error', err);
      }
    }

    async function checkPatchesStatus() {
      try {
        const res = await fetch('/api/v1/patches/check', {
          method: 'POST',
          headers: getHeaders()
        });
        if (res.ok) {
          const results = await res.json();
          renderPatches(results);
        } else {
          const err = await res.text();
          alert('Check upstream patches failed: ' + err);
        }
      } catch (err) {
        alert('Network error: ' + err.message);
      }
    }

    function renderPatches(statusResults) {
      const container = document.getElementById('patches-container');
      const tbody = document.getElementById('patches-tbody');
      const badge = document.getElementById('patches-badge');
      if (!container || !tbody) return;

      const items = statusResults || (currentPatches ? currentPatches.map(p => ({ patch: p })) : []);
      if (!items || items.length === 0) {
        container.style.display = 'none';
        return;
      }

      container.style.display = 'block';
      let readyCount = 0;
      items.forEach(r => { if (r.can_revert) readyCount++; });
      if (badge) badge.textContent = items.length + ' Active' + (readyCount > 0 ? ' (' + readyCount + ' Ready to Revert)' : '');

      tbody.innerHTML = items.map(item => {
        const p = item.patch || item;
        const canRevert = !!item.can_revert;
        const upstreamState = item.upstream_state;
        let issueLink = '<span style="color: var(--muted);">-</span>';
        if (p.upstream_issue_url) {
          issueLink = '<a href="' + escapeHTML(p.upstream_issue_url) + '" target="_blank" style="color: var(--accent);">' + escapeHTML(p.upstream_issue_url) + '</a>';
        }
        let stateBadge = '';
        if (canRevert) {
          stateBadge = ' <span class="badge badge-revert">Ready to Revert</span>';
        } else if (upstreamState && upstreamState !== 'no_url') {
          stateBadge = ' <span class="badge">[' + escapeHTML(upstreamState) + ']</span>';
        }

        return '<tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">' +
          '<td style="padding: 8px;"><strong>' + escapeHTML(p.dependency) + '</strong></td>' +
          '<td style="padding: 8px;"><span class="badge">' + escapeHTML(p.ecosystem || 'custom') + '</span></td>' +
          '<td style="padding: 8px;"><code>' + escapeHTML(p.patch_target) + '</code></td>' +
          '<td style="padding: 8px;">' + issueLink + stateBadge + '</td>' +
          '<td style="padding: 8px; color: var(--muted);">' + escapeHTML(p.reason || '') + '</td>' +
          '<td style="padding: 8px; text-align: right;">' +
            '<button class="btn btn-discard" style="padding: 3px 8px; font-size: 0.75rem;" onclick="removePatch(\'' + escapeHTML(p.id) + '\')">Remove</button>' +
          '</td>' +
        '</tr>';
      }).join('');
    }

    function openAddPatchModal() {
      const errEl = document.getElementById('add-patch-error');
      if (errEl) errEl.style.display = 'none';
      document.getElementById('patch-dep').value = '';
      document.getElementById('patch-target').value = '';
      document.getElementById('patch-eco').value = '';
      document.getElementById('patch-manifest').value = '';
      document.getElementById('patch-upstream').value = '';
      document.getElementById('patch-reason').value = '';
      document.getElementById('add-patch-modal').style.display = 'flex';
    }

    function closeAddPatchModal(e) {
      if (e && e.target !== document.getElementById('add-patch-modal')) return;
      document.getElementById('add-patch-modal').style.display = 'none';
    }

    async function submitAddPatch() {
      const dep = document.getElementById('patch-dep').value.trim();
      const target = document.getElementById('patch-target').value.trim();
      const eco = document.getElementById('patch-eco').value.trim();
      const manifest = document.getElementById('patch-manifest').value.trim();
      const upstream = document.getElementById('patch-upstream').value.trim();
      const reason = document.getElementById('patch-reason').value.trim();

      if (!dep || !target || !reason) {
        alert('Dependency, Patch Target, and Reason are required.');
        return;
      }

      try {
        const res = await fetch('/api/v1/patches', {
          method: 'POST',
          headers: { ...getHeaders(), 'Content-Type': 'application/json' },
          body: JSON.stringify({
            dependency: dep,
            patch_target: target,
            ecosystem: eco,
            manifest_file: manifest,
            upstream_issue_url: upstream,
            reason: reason
          })
        });
        if (!res.ok) {
          const err = await res.text();
          alert('Failed to record patch: ' + err);
          return;
        }
        closeAddPatchModal();
        await fetchPatches();
        await fetchAudit();
      } catch (err) {
        alert('Network error: ' + err.message);
      }
    }

    async function removePatch(id) {
      if (!confirm('Remove tracked dependency patch from ledger?')) return;
      try {
        const res = await fetch('/api/v1/patches/' + encodeURIComponent(id), {
          method: 'DELETE',
          headers: getHeaders()
        });
        if (!res.ok) {
          const err = await res.text();
          alert('Failed to remove patch: ' + err);
          return;
        }
        await fetchPatches();
        await fetchAudit();
      } catch (err) {
        alert('Network error: ' + err.message);
      }
    }

    async function fetchServices() {
      try {
        const res = await fetch('/api/v1/services', { headers: getHeaders() });
        currentServices = await res.json();
        renderServices();
      } catch (err) {
        const grid = document.getElementById('services-grid');
        if (grid) {
          grid.innerHTML = '<div style="color:var(--danger);">Failed to load services: ' + escapeHTML(err.message) + '</div>';
        }
      }
    }

    function renderServices() {
      const grid = document.getElementById('services-grid');
      if (!grid) return;
      let html = '';

      for (const p of PRESETS) {
        const connected = currentServices.find(s => s.name.toLowerCase() === p.name.toLowerCase());
        const isConn = !!connected;
        const badge = isConn ? '<span class="status-tag status-submitted" style="font-size:0.7rem;">Connected</span>' : '<span class="badge" style="font-size:0.7rem;">+ Connect</span>';
        html += '<div class="service-tile ' + (isConn ? 'connected' : '') + '" onclick="clickPresetTile(\'' + p.name + '\')">' +
          '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">' +
            '<span style="font-weight:600; color:var(--heading);">' + escapeHTML(p.title) + '</span>' +
            badge +
          '</div>' +
          '<div style="font-size:0.75rem; color:var(--muted); word-break:break-all;">' + escapeHTML(p.protocol) + ' &bull; ' + escapeHTML(p.name) + '</div>' +
        '</div>';
      }

      for (const s of currentServices) {
        if (!PRESETS.some(p => p.name.toLowerCase() === s.name.toLowerCase())) {
          const proto = (s.tracker && s.tracker.protocol) || 'custom';
          html += '<div class="service-tile connected" onclick="openServiceDetailModal(\'' + escapeHTML(s.name) + '\')">' +
            '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">' +
              '<span style="font-weight:600; color:var(--heading);">' + escapeHTML(s.name) + '</span>' +
              '<span class="status-tag status-submitted" style="font-size:0.7rem;">Connected</span>' +
            '</div>' +
            '<div style="font-size:0.75rem; color:var(--muted); word-break:break-all;">' + escapeHTML(proto) + ' &bull; Custom Service</div>' +
          '</div>';
        }
      }

      grid.innerHTML = html;
    }

    async function clickPresetTile(name) {
      const existing = currentServices.find(s => s.name.toLowerCase() === name.toLowerCase());
      if (existing) {
        openServiceDetailModal(existing.name);
        return;
      }
      const p = PRESETS.find(x => x.name.toLowerCase() === name.toLowerCase());
      if (!p) return;
      try {
        const res = await fetch('/api/v1/services', {
          method: 'POST',
          headers: { ...getHeaders(), 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: p.name,
            repository_url: p.repo,
            tracker: { protocol: p.protocol, url: p.tracker }
          })
        });
        if (!res.ok) {
          const errText = await res.text();
          alert('Failed to connect ' + p.title + ': ' + errText);
          return;
        }
        await fetchServices();
        await fetchAudit();
      } catch (err) {
        alert('Network error: ' + err.message);
      }
    }

    function openServiceDetailModal(name) {
      const s = currentServices.find(x => x.name.toLowerCase() === name.toLowerCase());
      if (!s) return;
      document.getElementById('service-detail-title').textContent = 'Service: ' + s.name;
      const proto = (s.tracker && s.tracker.protocol) || 'none';
      const trackerURL = (s.tracker && (s.tracker.url || s.tracker.email)) || s.repository_url || '-';
      const parkSnippet = 'bugrouter park ' + s.name + ' "Anomaly description here"';

      let html = '<div style="display:flex; flex-direction:column; gap:12px;">' +
        '<div><label style="color:var(--muted); font-size:0.8rem;">Protocol</label><br><span class="badge">' + escapeHTML(proto) + '</span></div>' +
        '<div><label style="color:var(--muted); font-size:0.8rem;">Repository URL</label><br><code>' + escapeHTML(s.repository_url || '-') + '</code></div>' +
        '<div><label style="color:var(--muted); font-size:0.8rem;">Tracker URL</label><br><code>' + escapeHTML(trackerURL) + '</code></div>' +
        '<div><label style="color:var(--muted); font-size:0.8rem;">1-Click Copyable CLI Park Snippet</label><pre style="cursor:pointer;" title="Click to copy" onclick="copyToClipboard(\'' + escapeHTML(parkSnippet) + '\')">' + escapeHTML(parkSnippet) + '</pre></div>' +
        '<div style="text-align:right; margin-top:8px;">' +
          '<button class="btn btn-discard" onclick="disconnectService(\'' + escapeHTML(s.name) + '\')">Disconnect Service</button>' +
        '</div>' +
      '</div>';

      document.getElementById('service-detail-content').innerHTML = html;
      document.getElementById('service-detail-modal').style.display = 'flex';
    }

    function closeServiceDetailModal(e) {
      if (e && e.target !== document.getElementById('service-detail-modal')) return;
      document.getElementById('service-detail-modal').style.display = 'none';
    }

    async function disconnectService(name) {
      if (!confirm('Disconnect ' + name + ' from org services?')) return;
      try {
        const res = await fetch('/api/v1/services/' + encodeURIComponent(name), {
          method: 'DELETE',
          headers: getHeaders()
        });
        if (!res.ok) {
          const errText = await res.text();
          alert('Disconnect failed: ' + errText);
          return;
        }
        closeServiceDetailModal();
        await fetchServices();
        await fetchAudit();
      } catch (err) {
        alert('Network error: ' + err.message);
      }
    }

    function openAddServiceModal() {
      const errEl = document.getElementById('add-service-error');
      if (errEl) errEl.style.display = 'none';
      document.getElementById('svc-name').value = '';
      document.getElementById('svc-repo').value = '';
      document.getElementById('svc-tracker').value = '';
      document.getElementById('svc-protocol').value = '';
      document.getElementById('add-service-modal').style.display = 'flex';
    }

    function closeAddServiceModal(e) {
      if (e && e.target !== document.getElementById('add-service-modal')) return;
      document.getElementById('add-service-modal').style.display = 'none';
    }

    async function submitCustomService() {
      const name = document.getElementById('svc-name').value.trim();
      const repo = document.getElementById('svc-repo').value.trim();
      const tracker = document.getElementById('svc-tracker').value.trim();
      const protocol = document.getElementById('svc-protocol').value.trim();

      const errEl = document.getElementById('add-service-error');
      if (!name) {
        errEl.textContent = 'Service name is required.';
        errEl.style.display = 'block';
        return;
      }

      const btn = document.getElementById('btn-add-service');
      btn.disabled = true;
      btn.textContent = 'Connecting...';
      errEl.style.display = 'none';

      try {
        const res = await fetch('/api/v1/services', {
          method: 'POST',
          headers: { ...getHeaders(), 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: name,
            repository_url: repo,
            tracker: { protocol: protocol, url: tracker }
          })
        });

        if (!res.ok) {
          const errText = await res.text();
          errEl.textContent = 'Failed to connect service: ' + errText;
          errEl.style.display = 'block';
          return;
        }

        closeAddServiceModal();
        await fetchServices();
        await fetchAudit();
      } catch (err) {
        errEl.textContent = 'Network error: ' + err.message;
        errEl.style.display = 'block';
      } finally {
        btn.disabled = false;
        btn.textContent = 'Connect Service';
      }
    }

    function copyToClipboard(text) {
      navigator.clipboard.writeText(text).then(() => {
        alert('Copied to clipboard: ' + text);
      }).catch(() => {});
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
        const isCompanion = d.status === 'companion_only';
        const statusClass = d.status === 'submitted' ? 'status-submitted' : (d.status === 'discarded' ? 'status-discarded' : (isCompanion ? 'status-companion' : 'status-pending'));
        const targetName = (d.target && d.target.canonical_name) || 'unknown';
        const protocol = (d.target && d.target.tracker && d.target.tracker.protocol) || 'none';
        const approveBtn = (!isCompanion && d.status !== 'submitted' && d.status !== 'discarded') ? '<button class="btn btn-approve" onclick="approveDraft(\'' + d.id + '\')">Approve</button>' : '';
        const manualLink = (isCompanion && d.submission_url) ? '<a href="' + escapeHTML(d.submission_url) + '" target="_blank" class="btn btn-approve" style="text-decoration:none; display:inline-block;">Open Form</a>' : '';
        const discardBtn = (d.status !== 'discarded' && d.status !== 'submitted') ? '<button class="btn btn-discard" onclick="discardDraft(\'' + d.id + '\')">Discard</button>' : '';
        return '<tr>' +
          '<td><code>' + d.id + '</code></td>' +
          '<td>' + escapeHTML(d.title || '') + '</td>' +
          '<td>' + escapeHTML(targetName) + '</td>' +
          '<td><span class="badge">' + protocol + '</span></td>' +
          '<td><span class="status-tag ' + statusClass + '">' + d.status + '</span></td>' +
          '<td>' + new Date(d.created_at).toLocaleString() + '</td>' +
          '<td>' +
            '<button class="btn btn-inspect" onclick="inspectDraft(\'' + d.id + '\')">Inspect</button>' +
            approveBtn +
            manualLink +
            discardBtn +
          '</td>' +
        '</tr>';
      }).join('');
    }

    function inspectDraft(id) {
      const d = currentDrafts.find(x => x.id === id);
      if (!d) return;
      document.getElementById('modal-title').textContent = 'Draft: ' + d.title;
      let bodyHtml = '';

      if (d.status === 'companion_only' || (d.template && d.template.policy && d.template.policy.ai_opt_out)) {
        const policy = (d.template && d.template.policy) || {};
        const reason = policy.opt_out_reason || 'Upstream maintainer restricts automated or AI-assisted issue filing';
        bodyHtml += '<div style="margin-bottom:16px; padding:12px; background:rgba(88,166,255,0.1); border:1px solid var(--accent); border-radius:6px;">' +
          '<h4 style="margin:0 0 6px 0; color:var(--accent);">Maintainer Empathy &bull; Companion Mode</h4>' +
          '<p style="margin:0 0 8px 0; font-size:0.85rem;">' + escapeHTML(reason) + '</p>';
        if (policy.checklist_rules && policy.checklist_rules.length > 0) {
          bodyHtml += '<p style="margin:4px 0 2px 0; font-weight:600; font-size:0.8rem;">Maintainer Checklist Rules:</p><ul style="margin:0; padding-left:20px; font-size:0.8rem;">';
          for (const rule of policy.checklist_rules) {
            bodyHtml += '<li>' + escapeHTML(rule) + '</li>';
          }
          bodyHtml += '</ul>';
        }
        if (d.submission_url) {
          bodyHtml += '<div style="margin-top:10px;"><a href="' + escapeHTML(d.submission_url) + '" target="_blank" class="btn btn-approve" style="text-decoration:none; display:inline-block;">Open Submission Form (Manual Filing)</a></div>';
        }
        bodyHtml += '</div>';
      }

      bodyHtml += '<h4>Target Metadata</h4><p>Target: <b>' + (d.target.canonical_name || '') + '</b> | Protocol: <b>' + (d.target.tracker.protocol || '') + '</b></p>';
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
      if (d.related_issues && d.related_issues.length > 0) {
        const relDep = d.related_dependency ? ' (' + escapeHTML(d.related_dependency) + ')' : '';
        bodyHtml += '<div style="margin-top:12px; padding:12px; background:rgba(88,166,255,0.08); border:1px solid rgba(88,166,255,0.3); border-radius:6px;">';
        bodyHtml += '<h4 style="margin:0 0 8px 0; color:var(--accent);">Correlated Evidence' + relDep + '</h4><ul style="margin:0; padding-left:20px;">';
        for (const rel of d.related_issues) {
          const link = (rel.url && (rel.url.startsWith('https://') || rel.url.startsWith('http://'))) ?
            '<a href="' + escapeHTML(rel.url) + '" target="_blank" style="color:var(--accent);">' + escapeHTML(rel.title || rel.id) + '</a>' :
            escapeHTML(rel.title || rel.id);
          bodyHtml += '<li>[#' + escapeHTML(rel.id) + '] ' + link + ' (' + escapeHTML(rel.state || 'unknown') + ')</li>';
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

    function openComposerModal() {
      const errEl = document.getElementById('composer-error');
      if (errEl) errEl.style.display = 'none';
      document.getElementById('composer-modal').style.display = 'flex';
    }

    function closeComposerModal(e) {
      if (e && e.target !== document.getElementById('composer-modal')) return;
      document.getElementById('composer-modal').style.display = 'none';
    }

    async function submitGuidedDraft() {
      const query = document.getElementById('comp-query').value.trim();
      const title = document.getElementById('comp-title').value.trim();
      const summary = document.getElementById('comp-summary').value.trim();
      const steps = document.getElementById('comp-steps').value.trim();
      const expected = document.getElementById('comp-expected').value.trim();
      const actual = document.getElementById('comp-actual').value.trim();
      const logs = document.getElementById('comp-logs').value.trim();
      const includeTelemetry = document.getElementById('comp-telemetry').checked;
      const strictQuality = document.getElementById('comp-strict').checked;

      const errEl = document.getElementById('composer-error');
      if (!query || !title) {
        errEl.textContent = 'Target query and title are required.';
        errEl.style.display = 'block';
        return;
      }

      const btn = document.getElementById('btn-submit-draft');
      btn.disabled = true;
      btn.textContent = 'Staging...';
      errEl.style.display = 'none';

      try {
        const res = await fetch('/api/v1/drafts', {
          method: 'POST',
          headers: {
            ...getHeaders(),
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            query: query,
            title: title,
            summary: summary,
            steps_to_reproduce: steps,
            expected_behavior: expected,
            actual_behavior: actual,
            logs: logs,
            include_telemetry: includeTelemetry,
            strict_quality: strictQuality
          })
        });

        if (!res.ok) {
          if (res.status === 422) {
            const quality = await res.json();
            let msg = 'Strict quality check failed (Score: ' + quality.score + '/100, Grade: ' + quality.grade + '):';
            if (quality.issues && quality.issues.length > 0) {
              msg += '\n- ' + quality.issues.join('\n- ');
            }
            alert(msg);
          } else {
            const errText = await res.text();
            alert('Failed to stage draft: ' + errText);
          }
          return;
        }

        const createdDraft = await res.json();
        closeComposerModal();
        await fetchDrafts();
        await fetchAudit();
        inspectDraft(createdDraft.id);
      } catch (err) {
        alert('Network error: ' + err.message);
      } finally {
        btn.disabled = false;
        btn.textContent = 'Stage Draft';
      }
    }

    function refreshQueue() {
      fetchPatches();
      fetchServices();
      fetchDrafts();
      fetchAudit();
      fetchStack(false);
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

    async function fetchStack(checkUpstream = false) {
      const tbody = document.getElementById('stack-table');
      if (checkUpstream) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color: var(--muted);">Scanning upstream trackers for open bugs...</td></tr>';
      }
      try {
        const url = '/api/v1/stack' + (checkUpstream ? '?check_upstream=1' : '');
        const res = await fetch(url, { headers: getHeaders() });
        const report = await res.json();
        renderStack(report);
      } catch (err) {
        tbody.innerHTML = '<tr><td colspan="7" style="color:var(--danger); text-align:center;">Failed to load stack radar: ' + err.message + '</td></tr>';
      }
    }

    function renderStack(report) {
      const tbody = document.getElementById('stack-table');
      if (!report || !report.entries || report.entries.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color: var(--muted);">No workspace dependencies discovered.</td></tr>';
        return;
      }
      tbody.innerHTML = report.entries.map(e => {
        const d = e.dependency;
        const target = d.target;
        const protocol = (target && target.tracker && target.tracker.protocol) || (d.resolution_error ? 'error' : 'unresolved');
        const trackerURL = (target && target.tracker && (target.tracker.url || target.tracker.email)) || (d.resolution_error || '-');
        let trackerLink = escapeHTML(trackerURL);
        if (trackerURL.startsWith('http://') || trackerURL.startsWith('https://')) {
          trackerLink = '<a href="' + escapeHTML(trackerURL) + '" target="_blank" style="color:var(--accent);">' + escapeHTML(trackerURL) + '</a>';
        }

        let bugsHtml = '<span style="color:var(--muted);">No issues flagged</span>';
        if (e.upstream_bugs && e.upstream_bugs.length > 0) {
          bugsHtml = '<ul style="margin:0; padding-left:16px;">' + e.upstream_bugs.map(b => {
            const bLink = (b.url && (b.url.startsWith('http://') || b.url.startsWith('https://'))) ?
              '<a href="' + escapeHTML(b.url) + '" target="_blank" style="color:var(--warning);">' + escapeHTML(b.title || b.id) + '</a>' :
              escapeHTML(b.title || b.id);
            return '<li>[#' + escapeHTML(b.id) + '] ' + bLink + '</li>';
          }).join('') + '</ul>';
        }

        return '<tr>' +
          '<td><b>' + escapeHTML(d.name || '') + '</b></td>' +
          '<td><code>' + escapeHTML(d.version || 'latest') + '</code></td>' +
          '<td><span class="badge">' + escapeHTML(d.ecosystem || '') + '</span></td>' +
          '<td>' + escapeHTML(d.manifest || '') + '</td>' +
          '<td><span class="badge">' + escapeHTML(protocol) + '</span></td>' +
          '<td>' + trackerLink + '</td>' +
          '<td>' + bugsHtml + '</td>' +
        '</tr>';
      }).join('');
    }

    fetchPatches();
    fetchServices();
    fetchDrafts();
    fetchAudit();
    fetchStack(false);
  </script>
</body>
</html>
`
