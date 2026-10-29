package dedup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/riccivr/bugrouter/internal/httpx"
	"github.com/riccivr/bugrouter/internal/resolver"
	"github.com/riccivr/bugrouter/internal/scrubber"
)

// ExistingIssue represents a potentially duplicate upstream bug report.
type ExistingIssue struct {
	ID    string  `json:"id"`
	Title string  `json:"title"`
	URL   string  `json:"url"`
	State string  `json:"state"`
	Score float64 `json:"score"` // 0.0 to 1.0 token overlap similarity
}

// Endpoints allows overriding upstream search API base URLs for testing.
type Endpoints struct {
	GitHubAPIBaseURL string // Default: "https://api.github.com"
	GitLabBaseURL    string // Default: "https://gitlab.com"
	GiteaBaseURL     string // Default: derived from tracker URL
}

// Finder searches upstream bug trackers for potential duplicate issues.
type Finder struct {
	client    *httpx.Client
	endpoints Endpoints
}

// NewFinder initializes a duplicate finder backed by bounded httpx client.
func NewFinder(client *httpx.Client) *Finder {
	if client == nil {
		client = httpx.NewClient(0)
	}
	return &Finder{
		client: client,
		endpoints: Endpoints{
			GitHubAPIBaseURL: "https://api.github.com",
			GitLabBaseURL:    "https://gitlab.com",
		},
	}
}

// WithEndpoints overrides API endpoints for testing or private forge mirrors.
func (f *Finder) WithEndpoints(e Endpoints) *Finder {
	if e.GitHubAPIBaseURL != "" {
		f.endpoints.GitHubAPIBaseURL = strings.TrimRight(e.GitHubAPIBaseURL, "/")
	}
	if e.GitLabBaseURL != "" {
		f.endpoints.GitLabBaseURL = strings.TrimRight(e.GitLabBaseURL, "/")
	}
	if e.GiteaBaseURL != "" {
		f.endpoints.GiteaBaseURL = strings.TrimRight(e.GiteaBaseURL, "/")
	}
	return f
}

var stopWords = map[string]bool{
	"the": true, "and": true, "when": true, "with": true, "from": true,
	"into": true, "bug": true, "issue": true, "error": true, "crash": true,
	"fails": true, "failing": true, "failed": true, "for": true, "not": true,
	"that": true, "this": true, "are": true, "was": true, "were": true,
	"will": true, "can": true, "has": true, "have": true, "had": true,
	"but": true, "all": true, "any": true, "how": true, "why": true,
	"what": true, "who": true, "which": true, "out": true, "over": true,
	"some": true, "such": true, "only": true, "also": true,
	"use": true, "used": true, "uses": true, "using": true,
}

// ExtractSearchTerms sanitizes a title and extracts up to 5 salient keywords.
func ExtractSearchTerms(title scrubber.ScrubbedText) []string {
	scrubbed := scrubber.Scrub(string(title))
	raw := string(scrubbed)

	// Remove redaction markers [REDACTED_*]
	for {
		start := strings.Index(raw, "[REDACTED_")
		if start == -1 {
			break
		}
		end := strings.Index(raw[start:], "]")
		if end == -1 {
			break
		}
		raw = raw[:start] + " " + raw[start+end+1:]
	}

	raw = strings.ToLower(raw)

	var sb strings.Builder
	for _, r := range raw {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			sb.WriteRune(r)
		} else {
			sb.WriteRune(' ')
		}
	}

	fields := strings.Fields(sb.String())
	var terms []string
	seen := make(map[string]bool)

	for _, f := range fields {
		if len(f) < 3 || stopWords[f] {
			continue
		}
		if !seen[f] {
			seen[f] = true
			terms = append(terms, f)
			if len(terms) >= 5 {
				break
			}
		}
	}

	return terms
}

func extractCandidateTokens(text string) []string {
	text = strings.ToLower(text)
	var sb strings.Builder
	for _, r := range text {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			sb.WriteRune(r)
		} else {
			sb.WriteRune(' ')
		}
	}

	fields := strings.Fields(sb.String())
	var tokens []string
	seen := make(map[string]bool)
	for _, f := range fields {
		if len(f) < 3 || stopWords[f] {
			continue
		}
		if !seen[f] {
			seen[f] = true
			tokens = append(tokens, f)
		}
	}
	return tokens
}

// ScoreSimilarity calculates token overlap between search terms and candidate title.
func ScoreSimilarity(queryTerms []string, candidateTitle string) float64 {
	if len(queryTerms) == 0 {
		return 0.0
	}
	candTokens := extractCandidateTokens(candidateTitle)
	if len(candTokens) == 0 {
		return 0.0
	}

	querySet := make(map[string]bool)
	for _, q := range queryTerms {
		querySet[q] = true
	}

	candSet := make(map[string]bool)
	for _, c := range candTokens {
		candSet[c] = true
	}

	matches := 0
	for q := range querySet {
		if candSet[q] {
			matches++
		}
	}

	if matches == 0 {
		return 0.0
	}

	unionSize := len(querySet)
	for c := range candSet {
		if !querySet[c] {
			unionSize++
		}
	}

	score := float64(matches) / float64(unionSize)
	return math.Round(score*100) / 100
}

func extractOwnerRepo(target resolver.Target) (string, string, error) {
	raw := target.RepositoryURL
	if raw == "" {
		raw = target.Tracker.URL
	}
	if raw == "" {
		return "", "", errors.New("missing repository or tracker url")
	}

	if strings.HasPrefix(raw, "git@github.com:") {
		raw = "https://github.com/" + strings.TrimPrefix(raw, "git@github.com:")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("parse url %s: %w", raw, err)
	}

	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("insufficient path segments in url %s", raw)
	}

	owner := parts[0]
	repo := strings.TrimSuffix(parts[1], ".git")
	return owner, repo, nil
}

func extractGitLabProjectPath(target resolver.Target) (string, error) {
	raw := target.RepositoryURL
	if raw == "" {
		raw = target.Tracker.URL
	}
	if raw == "" {
		return "", errors.New("missing repository or tracker url")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse gitlab url %s: %w", raw, err)
	}

	projectPath := strings.Trim(u.Path, "/")
	projectPath = strings.TrimSuffix(projectPath, "/-/issues")
	projectPath = strings.TrimSuffix(projectPath, "/issues")
	projectPath = strings.TrimSuffix(projectPath, ".git")

	if projectPath == "" {
		return "", fmt.Errorf("empty project path in url %s", raw)
	}

	return projectPath, nil
}

// FindDuplicates queries the upstream tracker for existing issues matching the title.
func (f *Finder) FindDuplicates(ctx context.Context, target resolver.Target, title scrubber.ScrubbedText) ([]ExistingIssue, error) {
	scrubbed := scrubber.Scrub(string(title))
	terms := ExtractSearchTerms(scrubbed)
	if len(terms) == 0 {
		return nil, nil
	}

	protocol := target.Tracker.Protocol
	switch protocol {
	case resolver.ProtocolGitHub:
		return f.findGitHub(ctx, target, terms)
	case resolver.ProtocolGitLab:
		return f.findGitLab(ctx, target, terms)
	case resolver.ProtocolBugzilla:
		return f.findBugzilla(ctx, target, terms)
	case resolver.ProtocolGitea, resolver.ProtocolCodeberg:
		return f.findGitea(ctx, target, terms)
	default:
		return nil, nil
	}
}

func (f *Finder) findGitHub(ctx context.Context, target resolver.Target, terms []string) ([]ExistingIssue, error) {
	owner, repo, err := extractOwnerRepo(target)
	if err != nil {
		return nil, err
	}

	baseURL := f.endpoints.GitHubAPIBaseURL
	if baseURL == "" || baseURL == "https://api.github.com" {
		rawURL := target.Tracker.URL
		if rawURL == "" {
			rawURL = target.RepositoryURL
		}
		if u, parseErr := url.Parse(rawURL); parseErr == nil && u.Host != "" && !strings.EqualFold(u.Host, "github.com") {
			baseURL = fmt.Sprintf("%s://%s/api/v3", u.Scheme, u.Host)
		} else if baseURL == "" {
			baseURL = "https://api.github.com"
		}
	}
	baseURL = strings.TrimRight(baseURL, "/")

	q := fmt.Sprintf("repo:%s/%s is:issue %s", owner, repo, strings.Join(terms, " "))
	reqURL := fmt.Sprintf("%s/search/issues?q=%s&per_page=5", baseURL, url.QueryEscape(q))

	var headers map[string]string
	for _, env := range []string{"GITHUB_TOKEN", "GH_TOKEN", "BUGROUTER_GITHUB_TOKEN"} {
		if tok := os.Getenv(env); tok != "" {
			headers = map[string]string{"Authorization": "Bearer " + tok}
			break
		}
	}
	data, err := f.client.GetBytesWithHeaders(ctx, reqURL, "application/vnd.github.v3+json", headers)
	if err != nil {
		return nil, fmt.Errorf("github search: %w", err)
	}

	var ghRes struct {
		Items []struct {
			Number  int    `json:"number"`
			Title   string `json:"title"`
			HTMLURL string `json:"html_url"`
			State   string `json:"state"`
		} `json:"items"`
	}
	if unmarshalErr := json.Unmarshal(data, &ghRes); unmarshalErr != nil {
		return nil, fmt.Errorf("decode github search response: %w", unmarshalErr)
	}

	var results []ExistingIssue
	for _, item := range ghRes.Items {
		score := ScoreSimilarity(terms, item.Title)
		if score >= 0.20 {
			results = append(results, ExistingIssue{
				ID:    strconv.Itoa(item.Number),
				Title: item.Title,
				URL:   item.HTMLURL,
				State: item.State,
				Score: score,
			})
		}
	}

	return sortAndCapDuplicates(results), nil
}

func (f *Finder) findGitLab(ctx context.Context, target resolver.Target, terms []string) ([]ExistingIssue, error) {
	projectPath, err := extractGitLabProjectPath(target)
	if err != nil {
		return nil, err
	}

	baseURL := f.endpoints.GitLabBaseURL
	if baseURL == "" || baseURL == "https://gitlab.com" {
		rawURL := target.Tracker.URL
		if rawURL == "" {
			rawURL = target.RepositoryURL
		}
		if u, parseErr := url.Parse(rawURL); parseErr == nil && u.Host != "" && !strings.EqualFold(u.Host, "gitlab.com") {
			baseURL = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
		} else if baseURL == "" {
			baseURL = "https://gitlab.com"
		}
	}
	baseURL = strings.TrimRight(baseURL, "/")

	encodedPath := url.PathEscape(projectPath)
	searchParam := strings.Join(terms, " ")
	reqURL := fmt.Sprintf("%s/api/v4/projects/%s/issues?search=%s&per_page=5", baseURL, encodedPath, url.QueryEscape(searchParam))

	var headers map[string]string
	for _, env := range []string{"GITLAB_TOKEN", "GL_TOKEN", "BUGROUTER_GITLAB_TOKEN"} {
		if tok := os.Getenv(env); tok != "" {
			headers = map[string]string{"PRIVATE-TOKEN": tok}
			break
		}
	}
	data, err := f.client.GetBytesWithHeaders(ctx, reqURL, "application/json", headers)
	if err != nil {
		return nil, fmt.Errorf("gitlab search: %w", err)
	}

	var glRes []struct {
		IID    int    `json:"iid"`
		Title  string `json:"title"`
		WebURL string `json:"web_url"`
		State  string `json:"state"`
	}
	if unmarshalErr := json.Unmarshal(data, &glRes); unmarshalErr != nil {
		return nil, fmt.Errorf("decode gitlab search response: %w", unmarshalErr)
	}

	var results []ExistingIssue
	for _, item := range glRes {
		score := ScoreSimilarity(terms, item.Title)
		if score >= 0.20 {
			results = append(results, ExistingIssue{
				ID:    strconv.Itoa(item.IID),
				Title: item.Title,
				URL:   item.WebURL,
				State: item.State,
				Score: score,
			})
		}
	}

	return sortAndCapDuplicates(results), nil
}

func (f *Finder) findBugzilla(ctx context.Context, target resolver.Target, terms []string) ([]ExistingIssue, error) {
	raw := target.Tracker.URL
	if raw == "" {
		return nil, errors.New("missing bugzilla tracker url")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse bugzilla url %s: %w", raw, err)
	}

	baseURL := u.Scheme + "://" + u.Host
	searchParam := strings.Join(terms, " ")
	reqURL := fmt.Sprintf("%s/rest/bug?quicksearch=%s&limit=5", baseURL, url.QueryEscape(searchParam))

	data, err := f.client.GetBytes(ctx, reqURL, "application/json")
	if err != nil {
		return nil, fmt.Errorf("bugzilla search: %w", err)
	}

	var bzRes struct {
		Bugs []struct {
			ID      int    `json:"id"`
			Summary string `json:"summary"`
			Status  string `json:"status"`
		} `json:"bugs"`
	}
	if unmarshalErr := json.Unmarshal(data, &bzRes); unmarshalErr != nil {
		return nil, fmt.Errorf("decode bugzilla search response: %w", unmarshalErr)
	}

	var results []ExistingIssue
	for _, item := range bzRes.Bugs {
		score := ScoreSimilarity(terms, item.Summary)
		if score >= 0.20 {
			results = append(results, ExistingIssue{
				ID:    strconv.Itoa(item.ID),
				Title: item.Summary,
				URL:   fmt.Sprintf("%s/show_bug.cgi?id=%d", baseURL, item.ID),
				State: item.Status,
				Score: score,
			})
		}
	}

	return sortAndCapDuplicates(results), nil
}

func sortAndCapDuplicates(items []ExistingIssue) []ExistingIssue {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Score != items[j].Score {
			return items[i].Score > items[j].Score
		}
		return items[i].ID < items[j].ID
	})
	if len(items) > 5 {
		return items[:5]
	}
	return items
}

func (f *Finder) findGitea(ctx context.Context, target resolver.Target, terms []string) ([]ExistingIssue, error) {
	owner, repo, err := extractOwnerRepo(target)
	if err != nil {
		return nil, err
	}

	baseURL := f.endpoints.GiteaBaseURL
	if baseURL == "" {
		raw := target.Tracker.URL
		if raw == "" {
			raw = target.RepositoryURL
		}
		if u, parseErr := url.Parse(raw); parseErr == nil && u.Host != "" {
			baseURL = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
		}
	}
	if baseURL == "" {
		baseURL = "https://codeberg.org"
	}
	baseURL = strings.TrimRight(baseURL, "/")

	searchParam := strings.Join(terms, " ")
	reqURL := fmt.Sprintf("%s/api/v1/repos/%s/%s/issues?type=issues&state=open&q=%s&limit=5", baseURL, owner, repo, url.QueryEscape(searchParam))

	var headers map[string]string
	for _, env := range []string{"GITEA_TOKEN", "BUGROUTER_GITEA_TOKEN", "CODEBERG_TOKEN"} {
		if tok := os.Getenv(env); tok != "" {
			headers = map[string]string{"Authorization": "token " + tok}
			break
		}
	}

	data, err := f.client.GetBytesWithHeaders(ctx, reqURL, "application/json", headers)
	if err != nil {
		return nil, fmt.Errorf("gitea search: %w", err)
	}

	var giteaRes []struct {
		Number  int    `json:"number"`
		Title   string `json:"title"`
		HTMLURL string `json:"html_url"`
		State   string `json:"state"`
	}
	if unmarshalErr := json.Unmarshal(data, &giteaRes); unmarshalErr != nil {
		return nil, fmt.Errorf("decode gitea search response: %w", unmarshalErr)
	}

	var results []ExistingIssue
	for _, item := range giteaRes {
		score := ScoreSimilarity(terms, item.Title)
		if score >= 0.20 {
			results = append(results, ExistingIssue{
				ID:    strconv.Itoa(item.Number),
				Title: item.Title,
				URL:   item.HTMLURL,
				State: item.State,
				Score: score,
			})
		}
	}

	return sortAndCapDuplicates(results), nil
}

func prioritizeVersion(items []ExistingIssue, version string) []ExistingIssue {
	if version == "" || len(items) <= 1 {
		return items
	}
	vLower := strings.ToLower(version)
	sort.SliceStable(items, func(i, j int) bool {
		iHas := strings.Contains(strings.ToLower(items[i].Title), vLower)
		jHas := strings.Contains(strings.ToLower(items[j].Title), vLower)
		if iHas && !jHas {
			return true
		}
		if !iHas && jHas {
			return false
		}
		return false
	})
	return items
}

// ListActiveIssues queries open issues for the target repository without rejecting
// issues via title token-overlap scoring. If version is non-empty, issues mentioning
// the version are prioritized.
func (f *Finder) ListActiveIssues(ctx context.Context, target resolver.Target, version string) ([]ExistingIssue, error) {
	protocol := target.Tracker.Protocol
	switch protocol {
	case resolver.ProtocolGitHub:
		return f.listActiveGitHub(ctx, target, version)
	case resolver.ProtocolGitLab:
		return f.listActiveGitLab(ctx, target, version)
	case resolver.ProtocolBugzilla:
		return f.listActiveBugzilla(ctx, target, version)
	case resolver.ProtocolGitea, resolver.ProtocolCodeberg:
		return f.listActiveGitea(ctx, target, version)
	default:
		return nil, nil
	}
}

func (f *Finder) listActiveGitHub(ctx context.Context, target resolver.Target, version string) ([]ExistingIssue, error) {
	owner, repo, err := extractOwnerRepo(target)
	if err != nil {
		return nil, err
	}

	baseURL := f.endpoints.GitHubAPIBaseURL
	if baseURL == "" || baseURL == "https://api.github.com" {
		rawURL := target.Tracker.URL
		if rawURL == "" {
			rawURL = target.RepositoryURL
		}
		if u, parseErr := url.Parse(rawURL); parseErr == nil && u.Host != "" && !strings.EqualFold(u.Host, "github.com") {
			baseURL = fmt.Sprintf("%s://%s/api/v3", u.Scheme, u.Host)
		} else if baseURL == "" {
			baseURL = "https://api.github.com"
		}
	}
	baseURL = strings.TrimRight(baseURL, "/")

	var headers map[string]string
	for _, env := range []string{"GITHUB_TOKEN", "GH_TOKEN", "BUGROUTER_GITHUB_TOKEN"} {
		if tok := os.Getenv(env); tok != "" {
			headers = map[string]string{"Authorization": "Bearer " + tok}
			break
		}
	}

	fetchGH := func(q string) ([]ExistingIssue, error) {
		reqURL := fmt.Sprintf("%s/search/issues?q=%s&per_page=5", baseURL, url.QueryEscape(q))
		data, err := f.client.GetBytesWithHeaders(ctx, reqURL, "application/vnd.github.v3+json", headers)
		if err != nil {
			return nil, err
		}
		var ghRes struct {
			Items []struct {
				Number  int    `json:"number"`
				Title   string `json:"title"`
				HTMLURL string `json:"html_url"`
				State   string `json:"state"`
			} `json:"items"`
		}
		if unmarshalErr := json.Unmarshal(data, &ghRes); unmarshalErr != nil {
			return nil, fmt.Errorf("decode github search response: %w", unmarshalErr)
		}
		var issues []ExistingIssue
		for _, item := range ghRes.Items {
			issues = append(issues, ExistingIssue{
				ID:    strconv.Itoa(item.Number),
				Title: item.Title,
				URL:   item.HTMLURL,
				State: item.State,
				Score: 1.0,
			})
		}
		return issues, nil
	}

	var results []ExistingIssue
	if version != "" {
		q := fmt.Sprintf("repo:%s/%s is:issue is:open %s", owner, repo, version)
		results, _ = fetchGH(q)
	}
	if len(results) == 0 {
		q := fmt.Sprintf("repo:%s/%s is:issue is:open", owner, repo)
		r, err := fetchGH(q)
		if err != nil && len(results) == 0 {
			return nil, fmt.Errorf("github list active issues: %w", err)
		}
		results = r
	}

	results = prioritizeVersion(results, version)
	if len(results) > 5 {
		results = results[:5]
	}
	return results, nil
}

func (f *Finder) listActiveGitLab(ctx context.Context, target resolver.Target, version string) ([]ExistingIssue, error) {
	projectPath, err := extractGitLabProjectPath(target)
	if err != nil {
		return nil, err
	}

	baseURL := f.endpoints.GitLabBaseURL
	if baseURL == "" || baseURL == "https://gitlab.com" {
		rawURL := target.Tracker.URL
		if rawURL == "" {
			rawURL = target.RepositoryURL
		}
		if u, parseErr := url.Parse(rawURL); parseErr == nil && u.Host != "" && !strings.EqualFold(u.Host, "gitlab.com") {
			baseURL = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
		} else if baseURL == "" {
			baseURL = "https://gitlab.com"
		}
	}
	baseURL = strings.TrimRight(baseURL, "/")
	encodedPath := url.PathEscape(projectPath)

	var headers map[string]string
	for _, env := range []string{"GITLAB_TOKEN", "GL_TOKEN", "BUGROUTER_GITLAB_TOKEN"} {
		if tok := os.Getenv(env); tok != "" {
			headers = map[string]string{"PRIVATE-TOKEN": tok}
			break
		}
	}

	fetchGL := func(search string) ([]ExistingIssue, error) {
		reqURL := fmt.Sprintf("%s/api/v4/projects/%s/issues?state=opened&per_page=5", baseURL, encodedPath)
		if search != "" {
			reqURL += "&search=" + url.QueryEscape(search)
		}
		data, err := f.client.GetBytesWithHeaders(ctx, reqURL, "application/json", headers)
		if err != nil {
			return nil, err
		}
		var glRes []struct {
			IID    int    `json:"iid"`
			Title  string `json:"title"`
			WebURL string `json:"web_url"`
			State  string `json:"state"`
		}
		if unmarshalErr := json.Unmarshal(data, &glRes); unmarshalErr != nil {
			return nil, fmt.Errorf("decode gitlab search response: %w", unmarshalErr)
		}
		var issues []ExistingIssue
		for _, item := range glRes {
			issues = append(issues, ExistingIssue{
				ID:    strconv.Itoa(item.IID),
				Title: item.Title,
				URL:   item.WebURL,
				State: item.State,
				Score: 1.0,
			})
		}
		return issues, nil
	}

	var results []ExistingIssue
	if version != "" {
		results, _ = fetchGL(version)
	}
	if len(results) == 0 {
		r, err := fetchGL("")
		if err != nil && len(results) == 0 {
			return nil, fmt.Errorf("gitlab list active issues: %w", err)
		}
		results = r
	}

	results = prioritizeVersion(results, version)
	if len(results) > 5 {
		results = results[:5]
	}
	return results, nil
}

func (f *Finder) listActiveBugzilla(ctx context.Context, target resolver.Target, version string) ([]ExistingIssue, error) {
	raw := target.Tracker.URL
	if raw == "" {
		return nil, errors.New("missing bugzilla tracker url")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse bugzilla url %s: %w", raw, err)
	}

	baseURL := u.Scheme + "://" + u.Host

	fetchBZ := func(search string) ([]ExistingIssue, error) {
		reqURL := fmt.Sprintf("%s/rest/bug?bug_status=NEW&bug_status=ASSIGNED&bug_status=REOPENED&limit=5", baseURL)
		if search != "" {
			reqURL += "&quicksearch=" + url.QueryEscape(search)
		}
		data, err := f.client.GetBytes(ctx, reqURL, "application/json")
		if err != nil {
			return nil, err
		}
		var bzRes struct {
			Bugs []struct {
				ID      int    `json:"id"`
				Summary string `json:"summary"`
				Status  string `json:"status"`
			} `json:"bugs"`
		}
		if unmarshalErr := json.Unmarshal(data, &bzRes); unmarshalErr != nil {
			return nil, fmt.Errorf("decode bugzilla search response: %w", unmarshalErr)
		}
		var issues []ExistingIssue
		for _, item := range bzRes.Bugs {
			issues = append(issues, ExistingIssue{
				ID:    strconv.Itoa(item.ID),
				Title: item.Summary,
				URL:   fmt.Sprintf("%s/show_bug.cgi?id=%d", baseURL, item.ID),
				State: item.Status,
				Score: 1.0,
			})
		}
		return issues, nil
	}

	var results []ExistingIssue
	if version != "" {
		results, _ = fetchBZ(version)
	}
	if len(results) == 0 {
		r, err := fetchBZ("")
		if err != nil && len(results) == 0 {
			return nil, fmt.Errorf("bugzilla list active issues: %w", err)
		}
		results = r
	}

	results = prioritizeVersion(results, version)
	if len(results) > 5 {
		results = results[:5]
	}
	return results, nil
}

func (f *Finder) listActiveGitea(ctx context.Context, target resolver.Target, version string) ([]ExistingIssue, error) {
	owner, repo, err := extractOwnerRepo(target)
	if err != nil {
		return nil, err
	}

	baseURL := f.endpoints.GiteaBaseURL
	if baseURL == "" {
		raw := target.Tracker.URL
		if raw == "" {
			raw = target.RepositoryURL
		}
		if u, parseErr := url.Parse(raw); parseErr == nil && u.Host != "" {
			baseURL = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
		}
	}
	if baseURL == "" {
		baseURL = "https://codeberg.org"
	}
	baseURL = strings.TrimRight(baseURL, "/")

	var headers map[string]string
	for _, env := range []string{"GITEA_TOKEN", "BUGROUTER_GITEA_TOKEN", "CODEBERG_TOKEN"} {
		if tok := os.Getenv(env); tok != "" {
			headers = map[string]string{"Authorization": "token " + tok}
			break
		}
	}

	fetchGitea := func(q string) ([]ExistingIssue, error) {
		reqURL := fmt.Sprintf("%s/api/v1/repos/%s/%s/issues?type=issues&state=open&limit=5", baseURL, owner, repo)
		if q != "" {
			reqURL += "&q=" + url.QueryEscape(q)
		}
		data, err := f.client.GetBytesWithHeaders(ctx, reqURL, "application/json", headers)
		if err != nil {
			return nil, err
		}
		var giteaRes []struct {
			Number  int    `json:"number"`
			Title   string `json:"title"`
			HTMLURL string `json:"html_url"`
			State   string `json:"state"`
		}
		if unmarshalErr := json.Unmarshal(data, &giteaRes); unmarshalErr != nil {
			return nil, fmt.Errorf("decode gitea search response: %w", unmarshalErr)
		}
		var issues []ExistingIssue
		for _, item := range giteaRes {
			issues = append(issues, ExistingIssue{
				ID:    strconv.Itoa(item.Number),
				Title: item.Title,
				URL:   item.HTMLURL,
				State: item.State,
				Score: 1.0,
			})
		}
		return issues, nil
	}

	var results []ExistingIssue
	if version != "" {
		results, _ = fetchGitea(version)
	}
	if len(results) == 0 {
		r, err := fetchGitea("")
		if err != nil && len(results) == 0 {
			return nil, fmt.Errorf("gitea list active issues: %w", err)
		}
		results = r
	}

	results = prioritizeVersion(results, version)
	if len(results) > 5 {
		results = results[:5]
	}
	return results, nil
}
