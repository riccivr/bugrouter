package resolver

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/riccivr/bugrouter/internal/httpx"
)

// WebDomainProbe resolves web domains and SaaS hosts via .well-known discovery.
type WebDomainProbe struct {
	client *httpx.Client
	scheme string
}

// NewWebDomainProbe initializes a web domain probe defaulting to HTTPS.
func NewWebDomainProbe(client *httpx.Client) *WebDomainProbe {
	return &WebDomainProbe{
		client: client,
		scheme: "https",
	}
}

// Name returns the probe identifier.
func (w *WebDomainProbe) Name() string {
	return "web-domain"
}

// Layer returns the resolution layer classification.
func (w *WebDomainProbe) Layer() SourceLayer {
	return LayerWebDomain
}

type wellKnownBugReport struct {
	CanonicalName string `json:"canonical_name"`
	BugsURL       string `json:"bugs_url"`
	BugsEmail     string `json:"bugs_email"`
	RepositoryURL string `json:"repository_url"`
}

// Resolve attempts discovery via .well-known/bug-report and RFC 9116 security.txt.
func (w *WebDomainProbe) Resolve(ctx context.Context, query string) (*Target, error) {
	domain := strings.TrimSpace(query)
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimRight(domain, "/")

	if !strings.Contains(domain, ".") || strings.ContainsAny(domain, " \t\r\n@/") {
		return nil, ErrNotFound
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || strings.Contains(domain, "..") {
		return nil, ErrNotFound
	}

	// 1. Check .well-known/bug-report endpoint
	bugReportURL := fmt.Sprintf("%s://%s/.well-known/bug-report", w.scheme, domain)
	var report wellKnownBugReport
	if err := w.client.GetJSON(ctx, bugReportURL, &report); err == nil {
		tracker, normRepo := ClassifyTracker(report.BugsURL, report.BugsEmail, report.RepositoryURL)
		if isValidTracker(tracker) {
			canonicalName := report.CanonicalName
			if canonicalName == "" {
				canonicalName = domain
			}
			return &Target{
				Query:         query,
				CanonicalName: canonicalName,
				Layer:         LayerWebDomain,
				RepositoryURL: normRepo,
				Tracker:       tracker,
			}, nil
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// 2. Fallback to RFC 9116 .well-known/security.txt
	secURL := fmt.Sprintf("%s://%s/.well-known/security.txt", w.scheme, domain)
	data, err := w.client.GetBytes(ctx, secURL, "text/plain")
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		var bugsURL string
		var bugsEmail string

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "#") {
				continue
			}

			if len(line) >= 8 && strings.EqualFold(line[:8], "contact:") {
				val := strings.TrimSpace(line[8:])
				if strings.HasPrefix(val, "mailto:") {
					email := strings.TrimSpace(strings.TrimPrefix(val, "mailto:"))
					email, _, _ = strings.Cut(email, "?")
					if bugsEmail == "" && email != "" {
						bugsEmail = email
					}
				} else if strings.HasPrefix(val, "https://") {
					if bugsURL == "" {
						bugsURL = val
					}
				}
			}
		}
		if scanErr := scanner.Err(); scanErr != nil {
			return nil, fmt.Errorf("scan security.txt for %s: %w", domain, scanErr)
		}

		if bugsURL != "" || bugsEmail != "" {
			tracker, normRepo := ClassifyTracker(bugsURL, bugsEmail, "")
			if isValidTracker(tracker) {
				return &Target{
					Query:         query,
					CanonicalName: domain,
					Layer:         LayerWebDomain,
					RepositoryURL: normRepo,
					Tracker:       tracker,
				}, nil
			}
		}
	}

	return nil, ErrNotFound
}
