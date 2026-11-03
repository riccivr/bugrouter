package cloud

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

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
