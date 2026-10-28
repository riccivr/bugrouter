package introspector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/riccivr/bugrouter/internal/httpx"
	"github.com/riccivr/bugrouter/internal/resolver"
)

// Endpoints configures API base URLs for remote tracker introspections.
type Endpoints struct {
	GitHubAPIBaseURL string
	GitLabBaseURL    string
}

// ErrNoTemplateFound signals that no upstream issue template could be discovered.
var ErrNoTemplateFound = errors.New("no upstream issue template found")

// Introspector discovers and retrieves upstream issue templates.
type Introspector struct {
	client    *httpx.Client
	cache     resolver.TargetCache
	endpoints Endpoints
}

// New creates an introspector backed by the provided HTTP client and default API endpoints.
func New(client *httpx.Client) *Introspector {
	return &Introspector{
		client: client,
		endpoints: Endpoints{
			GitHubAPIBaseURL: "https://api.github.com",
			GitLabBaseURL:    "https://gitlab.com",
		},
	}
}

// WithCache configures optional caching for discovered issue templates.
func (intro *Introspector) WithCache(c resolver.TargetCache) *Introspector {
	intro.cache = c
	return intro
}

// WithEndpoints overrides default API base URLs for testing or enterprise endpoints.
func (intro *Introspector) WithEndpoints(ep Endpoints) *Introspector {
	if ep.GitHubAPIBaseURL != "" {
		intro.endpoints.GitHubAPIBaseURL = ep.GitHubAPIBaseURL
	}
	if ep.GitLabBaseURL != "" {
		intro.endpoints.GitLabBaseURL = ep.GitLabBaseURL
	}
	return intro
}

// Introspect discovers and parses an upstream issue template for the specified target.
func (intro *Introspector) Introspect(ctx context.Context, target resolver.Target) (*TemplateSchema, error) {
	cacheKey := "template:" + string(target.Tracker.Protocol) + ":" + target.Tracker.URL
	if intro.cache != nil {
		var cached TemplateSchema
		hit, err := intro.cache.Get(cacheKey, &cached)
		if err == nil && hit {
			return &cached, nil
		}
	}

	var schema *TemplateSchema
	var err error

	switch target.Tracker.Protocol {
	case resolver.ProtocolGitHub:
		schema, err = intro.introspectGitHub(ctx, target)
	case resolver.ProtocolGitLab:
		schema, err = intro.introspectGitLab(ctx, target)
	case resolver.ProtocolBugzilla:
		schema, err = intro.introspectBugzilla(ctx, target)
	default:
		return nil, ErrNoTemplateFound
	}

	if err != nil {
		return nil, err
	}
	if schema == nil {
		return nil, ErrNoTemplateFound
	}

	if intro.cache != nil {
		if putErr := intro.cache.Put(cacheKey, schema); putErr != nil {
			// Non-fatal cache write failure; schema resolution succeeded.
		}
	}

	return schema, nil
}

type ghContentItem struct {
	Name        string `json:"name"`
	DownloadURL string `json:"download_url"`
	Type        string `json:"type"`
}

func extractGitHubOwnerRepo(target resolver.Target) (string, string, error) {
	raw := target.RepositoryURL
	if raw == "" {
		raw = target.Tracker.URL
	}
	if raw == "" {
		return "", "", ErrNoTemplateFound
	}
	if strings.HasPrefix(raw, "git@github.com:") {
		raw = "https://github.com/" + strings.TrimPrefix(raw, "git@github.com:")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("parse github url %s: %w", raw, err)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid github url %s: insufficient path components", raw)
	}
	owner := parts[0]
	repo := strings.TrimSuffix(parts[1], ".git")
	return owner, repo, nil
}

func (intro *Introspector) introspectGitHub(ctx context.Context, target resolver.Target) (*TemplateSchema, error) {
	owner, repo, err := extractGitHubOwnerRepo(target)
	if err != nil {
		return nil, err
	}

	baseURL := intro.endpoints.GitHubAPIBaseURL
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	baseURL = strings.TrimRight(baseURL, "/")

	dirURL := fmt.Sprintf("%s/repos/%s/%s/contents/.github/ISSUE_TEMPLATE", baseURL, owner, repo)

	var candidates []ghContentItem
	data, err := intro.client.GetBytes(ctx, dirURL, "application/json")
	if err == nil {
		var items []ghContentItem
		if unmarshalErr := json.Unmarshal(data, &items); unmarshalErr == nil {
			for _, item := range items {
				lower := strings.ToLower(item.Name)
				if strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".md") {
					candidates = append(candidates, item)
				}
			}
		}
	}

	if len(candidates) == 0 {
		fileURL := fmt.Sprintf("%s/repos/%s/%s/contents/.github/ISSUE_TEMPLATE.md", baseURL, owner, repo)
		fileData, fileErr := intro.client.GetBytes(ctx, fileURL, "application/json")
		if fileErr != nil {
			return nil, ErrNoTemplateFound
		}
		var singleItem ghContentItem
		if unmarshalErr := json.Unmarshal(fileData, &singleItem); unmarshalErr != nil {
			return nil, fmt.Errorf("decode github file item: %w", unmarshalErr)
		}
		candidates = append(candidates, singleItem)
	}

	if len(candidates) == 0 {
		return nil, ErrNoTemplateFound
	}

	extScore := func(name string) int {
		lower := strings.ToLower(name)
		if strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml") {
			return 2
		}
		if strings.HasSuffix(lower, ".md") {
			return 1
		}
		return 0
	}

	sort.Slice(candidates, func(i, j int) bool {
		si := extScore(candidates[i].Name)
		sj := extScore(candidates[j].Name)
		if si != sj {
			return si > sj
		}
		bugI := strings.Contains(strings.ToLower(candidates[i].Name), "bug")
		bugJ := strings.Contains(strings.ToLower(candidates[j].Name), "bug")
		if bugI != bugJ {
			return bugI
		}
		return candidates[i].Name < candidates[j].Name
	})

	best := candidates[0]
	var rawData []byte
	if best.DownloadURL != "" {
		rawData, err = intro.client.GetBytes(ctx, best.DownloadURL, "text/plain")
		if err != nil {
			return nil, fmt.Errorf("fetch raw template %s: %w", best.DownloadURL, err)
		}
	} else {
		rawURL := fmt.Sprintf("%s/repos/%s/%s/contents/.github/ISSUE_TEMPLATE/%s", baseURL, owner, repo, best.Name)
		rawData, err = intro.client.GetBytes(ctx, rawURL, "application/vnd.github.v3.raw")
		if err != nil {
			return nil, fmt.Errorf("fetch raw template %s: %w", rawURL, err)
		}
	}

	lowerName := strings.ToLower(best.Name)
	if strings.HasSuffix(lowerName, ".yml") || strings.HasSuffix(lowerName, ".yaml") {
		return ParseGitHubYAMLForm(best.Name, rawData)
	}
	return ParseMarkdownTemplate(best.Name, resolver.ProtocolGitHub, rawData)
}

type gitlabTreeItem struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type"`
}

func (intro *Introspector) introspectGitLab(ctx context.Context, target resolver.Target) (*TemplateSchema, error) {
	raw := target.RepositoryURL
	if raw == "" {
		raw = target.Tracker.URL
	}
	if raw == "" {
		return nil, ErrNoTemplateFound
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse gitlab url %s: %w", raw, err)
	}

	projectPath := strings.Trim(u.Path, "/")
	projectPath = strings.TrimSuffix(projectPath, "/-/issues")
	projectPath = strings.TrimSuffix(projectPath, "/issues")
	projectPath = strings.TrimSuffix(projectPath, ".git")

	encodedPath := url.PathEscape(projectPath)

	baseURL := intro.endpoints.GitLabBaseURL
	if baseURL == "" {
		baseURL = "https://gitlab.com"
	}
	baseURL = strings.TrimRight(baseURL, "/")

	treeURL := fmt.Sprintf("%s/api/v4/projects/%s/repository/tree?path=.gitlab/issue_templates", baseURL, encodedPath)

	data, err := intro.client.GetBytes(ctx, treeURL, "application/json")
	if err != nil {
		return nil, ErrNoTemplateFound
	}

	var items []gitlabTreeItem
	if unmarshalErr := json.Unmarshal(data, &items); unmarshalErr != nil {
		return nil, fmt.Errorf("decode gitlab tree response: %w", unmarshalErr)
	}

	var candidates []gitlabTreeItem
	for _, it := range items {
		if strings.HasSuffix(strings.ToLower(it.Name), ".md") {
			candidates = append(candidates, it)
		}
	}

	if len(candidates) == 0 {
		return nil, ErrNoTemplateFound
	}

	sort.Slice(candidates, func(i, j int) bool {
		bugI := strings.Contains(strings.ToLower(candidates[i].Name), "bug")
		bugJ := strings.Contains(strings.ToLower(candidates[j].Name), "bug")
		if bugI != bugJ {
			return bugI
		}
		return candidates[i].Name < candidates[j].Name
	})

	selected := candidates[0]
	filePath := selected.Path
	if filePath == "" {
		filePath = ".gitlab/issue_templates/" + selected.Name
	}
	encodedFilePath := url.PathEscape(filePath)

	rawURL := fmt.Sprintf("%s/api/v4/projects/%s/repository/files/%s/raw?ref=HEAD", baseURL, encodedPath, encodedFilePath)
	rawData, err := intro.client.GetBytes(ctx, rawURL, "text/plain")
	if err != nil {
		return nil, fmt.Errorf("fetch gitlab raw template %s: %w", rawURL, err)
	}

	return ParseMarkdownTemplate(selected.Name, resolver.ProtocolGitLab, rawData)
}

func (intro *Introspector) introspectBugzilla(ctx context.Context, target resolver.Target) (*TemplateSchema, error) {
	if target.Tracker.URL == "" {
		return nil, ErrNoTemplateFound
	}

	u, err := url.Parse(target.Tracker.URL)
	if err != nil {
		return nil, fmt.Errorf("parse bugzilla url %s: %w", target.Tracker.URL, err)
	}

	baseURL := u.Scheme + "://" + u.Host

	data, err := intro.client.GetBytes(ctx, baseURL+"/rest/product?type=enterable", "application/json")
	if err == nil {
		schema, parseErr := ParseBugzillaRESTSchema(data)
		if parseErr == nil {
			return schema, nil
		}
	}

	fieldData, fieldErr := intro.client.GetBytes(ctx, baseURL+"/rest/field/bug", "application/json")
	if fieldErr != nil {
		return nil, ErrNoTemplateFound
	}

	return ParseBugzillaRESTSchema(fieldData)
}
