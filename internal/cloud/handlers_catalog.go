package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/riccivr/bugrouter/internal/dedup"
	"github.com/riccivr/bugrouter/internal/resolver"
)

func (s *Server) handleListServices(w http.ResponseWriter, r *http.Request) {
	s.servicesMu.Lock()
	defer s.servicesMu.Unlock()

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

	if err := func() error {
		s.servicesMu.Lock()
		defer s.servicesMu.Unlock()

		var reg resolver.OrgCloudRegistry
		if data, err := os.ReadFile(s.servicesPath); err == nil {
			if unmarshalErr := json.Unmarshal(data, &reg); unmarshalErr != nil {
				return fmt.Errorf("read existing services file: %w", unmarshalErr)
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("read existing services file: %w", err)
		}

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

		if err := writeRegistryAtomic(s.servicesPath, &reg); err != nil {
			return fmt.Errorf("save services: %w", err)
		}
		return nil
	}(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
	s.recordAuditAndNotify(r.Context(), ev)

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

	var notFound bool
	if err := func() error {
		s.servicesMu.Lock()
		defer s.servicesMu.Unlock()

		data, err := os.ReadFile(s.servicesPath)
		if err != nil {
			if os.IsNotExist(err) {
				notFound = true
				return nil
			}
			return fmt.Errorf("read services file: %w", err)
		}

		var reg resolver.OrgCloudRegistry
		if err := json.Unmarshal(data, &reg); err != nil {
			return fmt.Errorf("unmarshal services: %w", err)
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
			notFound = true
			return nil
		}

		reg.Services = updated
		if err := writeRegistryAtomic(s.servicesPath, &reg); err != nil {
			return fmt.Errorf("save services: %w", err)
		}
		return nil
	}(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if notFound {
		http.Error(w, fmt.Sprintf("service %q not found", name), http.StatusNotFound)
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
	s.recordAuditAndNotify(r.Context(), ev)

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
