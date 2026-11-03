package cloud

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/riccivr/bugrouter/internal/adapter"
	"github.com/riccivr/bugrouter/internal/dedup"
	"github.com/riccivr/bugrouter/internal/introspector"
	"github.com/riccivr/bugrouter/internal/resolver"
	"github.com/riccivr/bugrouter/internal/scrubber"
	"github.com/riccivr/bugrouter/internal/telemetry"
)

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
	Query             string `json:"query"`
	Title             string `json:"title"`
	Summary           string `json:"summary"`
	StepsToReproduce  string `json:"steps_to_reproduce"`
	ExpectedBehavior  string `json:"expected_behavior,omitempty"`
	ActualBehavior    string `json:"actual_behavior,omitempty"`
	Logs              string `json:"logs,omitempty"`
	IncludeTelemetry  bool   `json:"include_telemetry"`
	StrictQuality     bool   `json:"strict_quality"`
	ParkedID          string `json:"parked_id,omitempty"`
	RelatedDependency string `json:"related_dependency,omitempty"`
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

	// Query related dependency duplicates if requested
	var relatedIssues []dedup.ExistingIssue
	req.RelatedDependency = strings.TrimSpace(req.RelatedDependency)
	if req.RelatedDependency != "" && s.resolver != nil && s.dedupFinder != nil {
		relTarget, relErr := s.resolver.Resolve(r.Context(), req.RelatedDependency)
		if relErr == nil && relTarget != nil {
			searchQuery := scrubber.Scrub(req.Title + " " + req.Summary)
			if relDups, err := s.dedupFinder.FindDuplicates(r.Context(), *relTarget, searchQuery); err == nil {
				relatedIssues = relDups
			}
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
		Target:            *target,
		Template:          schema,
		Title:             req.Title,
		Summary:           req.Summary,
		StepsToReproduce:  req.StepsToReproduce,
		ExpectedBehavior:  req.ExpectedBehavior,
		ActualBehavior:    req.ActualBehavior,
		Logs:              req.Logs,
		Duplicates:        dups,
		Telemetry:         sysTelemetry,
		RelatedDependency: req.RelatedDependency,
		RelatedIssues:     relatedIssues,
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

	// If spawned from a parked bug, transition the parked bug to "triaged"
	if req.ParkedID != "" && s.parkedStore != nil {
		if p, getErr := s.parkedStore.Get(req.ParkedID); getErr == nil && p != nil {
			p.Status = "triaged"
			if saveErr := s.parkedStore.Save(p); saveErr != nil {
				fmt.Fprintf(os.Stderr, "failed to update parked bug status to triaged: %v\n", saveErr)
			}
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
	s.recordAuditAndNotify(r.Context(), ev)

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
	s.recordAuditAndNotify(r.Context(), ev)

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
	s.recordAuditAndNotify(r.Context(), ev)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"status": "discarded",
		"id":     id,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
