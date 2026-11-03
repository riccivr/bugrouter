package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/riccivr/bugrouter/internal/adapter"
	"github.com/riccivr/bugrouter/internal/dedup"
	"github.com/riccivr/bugrouter/internal/httpx"
	"github.com/riccivr/bugrouter/internal/introspector"
	"github.com/riccivr/bugrouter/internal/resolver"
	"github.com/riccivr/bugrouter/internal/version"
)

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
	servicesMu      sync.Mutex
	patchStore      *adapter.PatchStore
	parkedStore     *adapter.ParkedStore
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
		parkedStore:  adapter.NewParkedStore(""),
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

// WithParkedStore overrides the default parked store for testing or custom configuration.
func (s *Server) WithParkedStore(store *adapter.ParkedStore) *Server {
	if store != nil {
		s.parkedStore = store
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

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/v1/services", s.handleListServices)
	s.mux.HandleFunc("POST /api/v1/services", s.handleUpsertService)
	s.mux.HandleFunc("DELETE /api/v1/services/{name}", s.handleDeleteService)
	s.mux.HandleFunc("GET /api/v1/patches", s.handleListPatches)
	s.mux.HandleFunc("POST /api/v1/patches/scan", s.handleScanPatches)
	s.mux.HandleFunc("POST /api/v1/patches/check", s.handleCheckPatches)
	s.mux.HandleFunc("POST /api/v1/patches", s.handleRecordPatch)
	s.mux.HandleFunc("DELETE /api/v1/patches/{id}", s.handleDeletePatch)
	s.mux.HandleFunc("GET /api/v1/parked", s.handleListParked)
	s.mux.HandleFunc("DELETE /api/v1/parked/{id}", s.handleDeleteParked)
	s.mux.HandleFunc("GET /api/v1/drafts", s.handleListDrafts)
	s.mux.HandleFunc("POST /api/v1/drafts", s.handleCreateDraft)
	s.mux.HandleFunc("POST /api/v1/drafts/{id}/approve", s.handleApproveDraft)
	s.mux.HandleFunc("POST /api/v1/drafts/{id}/discard", s.handleDiscardDraft)
	s.mux.HandleFunc("GET /api/v1/audit", s.handleAuditLog)
	s.mux.HandleFunc("GET /api/v1/stack", s.handleStack)
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

func (s *Server) recordAuditAndNotify(ctx context.Context, ev AuditEvent) {
	if s.auditLogger != nil {
		if logErr := s.auditLogger.Record(ev); logErr != nil {
			fmt.Fprintf(os.Stderr, "audit log record error: %v\n", logErr)
		}
	}
	if s.webhookNotifier != nil {
		if notifyErr := s.webhookNotifier.Notify(ctx, ev); notifyErr != nil {
			fmt.Fprintf(os.Stderr, "webhook notify error: %v\n", notifyErr)
		}
	}
}
