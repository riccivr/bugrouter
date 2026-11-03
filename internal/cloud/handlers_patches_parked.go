package cloud

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/riccivr/bugrouter/internal/adapter"
	"github.com/riccivr/bugrouter/internal/resolver"
)

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

func (s *Server) handleScanPatches(w http.ResponseWriter, r *http.Request) {
	if s.patchStore == nil {
		http.Error(w, "patch store not configured", http.StatusInternalServerError)
		return
	}
	added, err := s.patchStore.SyncWorkspace(s.stackDir)
	if err != nil {
		http.Error(w, fmt.Sprintf("scan workspace patches: %v", err), http.StatusInternalServerError)
		return
	}
	if added == nil {
		added = []adapter.DependencyPatch{}
	}

	remoteIP := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		remoteIP = strings.TrimSpace(strings.Split(fwd, ",")[0])
	}
	ev := AuditEvent{
		Timestamp: time.Now().UTC(),
		Action:    "patch.scanned",
		Target:    s.stackDir,
		RemoteIP:  remoteIP,
	}
	s.recordAuditAndNotify(r.Context(), ev)

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]any{
		"added_count": len(added),
		"added":       added,
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
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
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024*1024)).Decode(&req); err != nil {
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
	s.recordAuditAndNotify(r.Context(), ev)

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
	s.recordAuditAndNotify(r.Context(), ev)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"status": "deleted",
		"id":     id,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleListParked(w http.ResponseWriter, r *http.Request) {
	if s.parkedStore == nil {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte("[]")); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	bugs, err := s.parkedStore.List()
	if err != nil {
		http.Error(w, fmt.Sprintf("list parked: %v", err), http.StatusInternalServerError)
		return
	}
	showAll := r.URL.Query().Get("all") == "1" || r.URL.Query().Get("all") == "true"
	if !showAll {
		var active []*adapter.ParkedBug
		for _, b := range bugs {
			if b.Status != "triaged" {
				active = append(active, b)
			}
		}
		bugs = active
	}
	if bugs == nil {
		bugs = []*adapter.ParkedBug{}
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(bugs); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleDeleteParked(w http.ResponseWriter, r *http.Request) {
	if s.parkedStore == nil {
		http.Error(w, "parked store not configured", http.StatusInternalServerError)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		trimmed := strings.TrimPrefix(r.URL.Path, "/api/v1/parked/")
		id = strings.Trim(trimmed, "/")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		http.Error(w, "missing parked bug id in path", http.StatusBadRequest)
		return
	}

	if err := s.parkedStore.Delete(id); err != nil {
		http.Error(w, fmt.Sprintf("parked bug %q not found: %v", id, err), http.StatusNotFound)
		return
	}

	// Record audit event
	remoteIP := r.RemoteAddr
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		remoteIP = strings.TrimSpace(strings.Split(fwd, ",")[0])
	}
	ev := AuditEvent{
		Timestamp: time.Now().UTC(),
		Action:    "parked.deleted",
		DraftID:   id,
		Target:    id,
		RemoteIP:  remoteIP,
	}
	s.recordAuditAndNotify(r.Context(), ev)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"status": "deleted",
		"id":     id,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
