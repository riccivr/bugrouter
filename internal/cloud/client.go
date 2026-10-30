package cloud

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/riccivr/bugrouter/internal/adapter"
	"github.com/riccivr/bugrouter/internal/httpx"
	"github.com/riccivr/bugrouter/internal/resolver"
)

// ForgeClient provides authenticated OAuth and token-based issue creation.
type ForgeClient struct {
	httpClient *httpx.Client
	tokens     map[resolver.Protocol]string
	baseURLs   map[resolver.Protocol]string
	linearURL  string
}

// NewForgeClient creates an enterprise forge client backed by bounded httpx.
func NewForgeClient(client *httpx.Client) *ForgeClient {
	if client == nil {
		client = httpx.NewClient(0)
	}
	return &ForgeClient{
		httpClient: client,
		tokens:     make(map[resolver.Protocol]string),
		baseURLs:   make(map[resolver.Protocol]string),
		linearURL:  "https://api.linear.app/graphql",
	}
}

// WithToken configures an explicit token for a protocol.
func (c *ForgeClient) WithToken(protocol resolver.Protocol, token string) *ForgeClient {
	c.tokens[protocol] = token
	return c
}

// WithBaseURL configures an explicit API base URL override for a protocol.
func (c *ForgeClient) WithBaseURL(protocol resolver.Protocol, baseURL string) *ForgeClient {
	c.baseURLs[protocol] = strings.TrimRight(baseURL, "/")
	return c
}

// WithLinearURL overrides the default Linear GraphQL API endpoint.
func (c *ForgeClient) WithLinearURL(linearURL string) *ForgeClient {
	c.linearURL = linearURL
	return c
}

func (c *ForgeClient) getToken(protocol resolver.Protocol) string {
	if tok, ok := c.tokens[protocol]; ok && tok != "" {
		return tok
	}
	switch protocol {
	case resolver.ProtocolGitHub:
		for _, k := range []string{"GITHUB_TOKEN", "GH_TOKEN", "BUGROUTER_GITHUB_TOKEN"} {
			if v := os.Getenv(k); v != "" {
				return v
			}
		}
	case resolver.ProtocolGitLab:
		for _, k := range []string{"GITLAB_TOKEN", "GL_TOKEN", "BUGROUTER_GITLAB_TOKEN"} {
			if v := os.Getenv(k); v != "" {
				return v
			}
		}
	case resolver.ProtocolJira:
		for _, k := range []string{"JIRA_TOKEN", "BUGROUTER_JIRA_TOKEN"} {
			if v := os.Getenv(k); v != "" {
				return v
			}
		}
	case resolver.ProtocolLinear:
		for _, k := range []string{"LINEAR_API_KEY", "LINEAR_TOKEN", "BUGROUTER_LINEAR_TOKEN"} {
			if v := os.Getenv(k); v != "" {
				return v
			}
		}
	case resolver.ProtocolGitea, resolver.ProtocolCodeberg:
		for _, k := range []string{"GITEA_TOKEN", "BUGROUTER_GITEA_TOKEN", "CODEBERG_TOKEN"} {
			if v := os.Getenv(k); v != "" {
				return v
			}
		}
	}
	return ""
}

// Submit dispatches the staged draft to its canonical tracker using authenticated APIs.
func (c *ForgeClient) Submit(ctx context.Context, draft *adapter.StagedDraft) (string, error) {
	if draft == nil {
		return "", errors.New("draft cannot be nil")
	}

	if draft.Status == "companion_only" || (draft.Template != nil && draft.Template.Policy != nil && draft.Template.Policy.AIOptOut) {
		reason := "upstream restrictions"
		if draft.Template != nil && draft.Template.Policy != nil && draft.Template.Policy.OptOutReason != "" {
			reason = draft.Template.Policy.OptOutReason
		}
		return "", fmt.Errorf("maintainer policy opt-out: upstream repository restricts automated/AI submissions (%s); use draft as a local human companion only", reason)
	}

	protocol := draft.Target.Tracker.Protocol
	switch protocol {
	case resolver.ProtocolGitHub:
		return c.submitGitHub(ctx, draft)
	case resolver.ProtocolGitLab:
		return c.submitGitLab(ctx, draft)
	case resolver.ProtocolJira:
		return c.submitJira(ctx, draft)
	case resolver.ProtocolLinear:
		return c.submitLinear(ctx, draft)
	case resolver.ProtocolGitea, resolver.ProtocolCodeberg:
		return c.submitGitea(ctx, draft)
	default:
		return "", fmt.Errorf("no authenticated connector for protocol %s", protocol)
	}
}

func extractOwnerRepo(draft *adapter.StagedDraft) (string, string, error) {
	raw := draft.Target.RepositoryURL
	if raw == "" {
		raw = draft.Target.Tracker.URL
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

func (c *ForgeClient) submitGitHub(ctx context.Context, draft *adapter.StagedDraft) (string, error) {
	token := c.getToken(resolver.ProtocolGitHub)
	if token == "" {
		return "", errors.New("missing github authentication token")
	}

	owner, repo, err := extractOwnerRepo(draft)
	if err != nil {
		return "", err
	}

	apiBase := c.baseURLs[resolver.ProtocolGitHub]
	if apiBase == "" {
		rawURL := draft.Target.Tracker.URL
		if rawURL == "" {
			rawURL = draft.Target.RepositoryURL
		}
		u, parseErr := url.Parse(rawURL)
		if parseErr == nil && !strings.EqualFold(u.Host, "github.com") && u.Host != "" {
			apiBase = fmt.Sprintf("%s://%s/api/v3", u.Scheme, u.Host)
		} else {
			apiBase = "https://api.github.com"
		}
	}
	apiBase = strings.TrimRight(apiBase, "/")

	issueURL := fmt.Sprintf("%s/repos/%s/%s/issues", apiBase, owner, repo)

	reqPayload := map[string]any{
		"title": string(draft.Title),
		"body":  string(draft.MarkdownBody),
	}
	if draft.Template != nil && len(draft.Template.Labels) > 0 {
		reqPayload["labels"] = draft.Template.Labels
	}

	data, err := json.Marshal(reqPayload)
	if err != nil {
		return "", fmt.Errorf("marshal github issue payload: %w", err)
	}

	respBody, err := c.postJSON(ctx, issueURL, data, map[string]string{
		"Authorization": "Bearer " + token,
		"Accept":        "application/vnd.github.v3+json",
	})
	if err != nil {
		return "", fmt.Errorf("github api: %w", err)
	}

	var res struct {
		HTMLURL string `json:"html_url"`
		URL     string `json:"url"`
	}
	if unmarshalErr := json.Unmarshal(respBody, &res); unmarshalErr != nil {
		return "", fmt.Errorf("unmarshal github response: %w", unmarshalErr)
	}

	if res.HTMLURL != "" {
		return res.HTMLURL, nil
	}
	return res.URL, nil
}

func (c *ForgeClient) submitGitLab(ctx context.Context, draft *adapter.StagedDraft) (string, error) {
	token := c.getToken(resolver.ProtocolGitLab)
	if token == "" {
		return "", errors.New("missing gitlab authentication token")
	}

	raw := draft.Target.RepositoryURL
	if raw == "" {
		raw = draft.Target.Tracker.URL
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse gitlab url %s: %w", raw, err)
	}

	projectPath := strings.Trim(u.Path, "/")
	projectPath = strings.TrimSuffix(projectPath, "/-/issues")
	projectPath = strings.TrimSuffix(projectPath, "/issues")
	projectPath = strings.TrimSuffix(projectPath, ".git")

	projectID := url.PathEscape(projectPath)

	apiBase := c.baseURLs[resolver.ProtocolGitLab]
	if apiBase == "" {
		apiBase = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	}
	apiBase = strings.TrimRight(apiBase, "/")

	issueURL := fmt.Sprintf("%s/api/v4/projects/%s/issues", apiBase, projectID)

	reqPayload := map[string]any{
		"title":       string(draft.Title),
		"description": string(draft.MarkdownBody),
	}
	if draft.Template != nil && len(draft.Template.Labels) > 0 {
		reqPayload["labels"] = strings.Join(draft.Template.Labels, ",")
	}

	data, err := json.Marshal(reqPayload)
	if err != nil {
		return "", fmt.Errorf("marshal gitlab issue payload: %w", err)
	}

	respBody, err := c.postJSON(ctx, issueURL, data, map[string]string{
		"PRIVATE-TOKEN": token,
	})
	if err != nil {
		return "", fmt.Errorf("gitlab api: %w", err)
	}

	var res struct {
		WebURL string `json:"web_url"`
	}
	if unmarshalErr := json.Unmarshal(respBody, &res); unmarshalErr != nil {
		return "", fmt.Errorf("unmarshal gitlab response: %w", unmarshalErr)
	}

	return res.WebURL, nil
}

func (c *ForgeClient) submitJira(ctx context.Context, draft *adapter.StagedDraft) (string, error) {
	token := c.getToken(resolver.ProtocolJira)
	if token == "" {
		return "", errors.New("missing jira authentication token")
	}

	jiraBase := c.baseURLs[resolver.ProtocolJira]
	if jiraBase == "" {
		raw := draft.Target.Tracker.URL
		u, err := url.Parse(raw)
		if err != nil {
			return "", fmt.Errorf("parse jira url %s: %w", raw, err)
		}
		jiraBase = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	}
	jiraBase = strings.TrimRight(jiraBase, "/")

	issueURL := fmt.Sprintf("%s/rest/api/2/issue", jiraBase)

	projectKey := "BUG"
	if draft.Template != nil {
		for _, f := range draft.Template.Fields {
			if (f.ID == "product" || f.ID == "project") && f.Value != "" {
				projectKey = f.Value
				break
			}
		}
	}
	if projectKey == "BUG" && draft.Target.CanonicalName != "" {
		clean := strings.ToUpper(strings.ReplaceAll(draft.Target.CanonicalName, "-", ""))
		if len(clean) > 0 && len(clean) <= 10 {
			projectKey = clean
		}
	}

	reqPayload := map[string]any{
		"fields": map[string]any{
			"project": map[string]any{
				"key": projectKey,
			},
			"summary":     string(draft.Title),
			"description": string(draft.MarkdownBody),
			"issuetype": map[string]any{
				"name": "Bug",
			},
		},
	}

	data, err := json.Marshal(reqPayload)
	if err != nil {
		return "", fmt.Errorf("marshal jira issue payload: %w", err)
	}

	authHeader := token
	if strings.Contains(token, ":") && !strings.HasPrefix(token, "Basic ") {
		authHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(token))
	} else if !strings.HasPrefix(token, "Basic ") && !strings.HasPrefix(token, "Bearer ") {
		authHeader = "Bearer " + token
	}

	respBody, err := c.postJSON(ctx, issueURL, data, map[string]string{
		"Authorization": authHeader,
	})
	if err != nil {
		return "", fmt.Errorf("jira api: %w", err)
	}

	var res struct {
		Key  string `json:"key"`
		Self string `json:"self"`
	}
	if unmarshalErr := json.Unmarshal(respBody, &res); unmarshalErr != nil {
		return "", fmt.Errorf("unmarshal jira response: %w", unmarshalErr)
	}

	if res.Key != "" {
		return fmt.Sprintf("%s/browse/%s", jiraBase, res.Key), nil
	}
	return res.Self, nil
}

func (c *ForgeClient) submitLinear(ctx context.Context, draft *adapter.StagedDraft) (string, error) {
	token := c.getToken(resolver.ProtocolLinear)
	if token == "" {
		return "", errors.New("missing linear authentication token")
	}

	endpoint := c.linearURL
	if endpoint == "" {
		endpoint = "https://api.linear.app/graphql"
	}

	authHeader := token
	if !strings.HasPrefix(token, "Bearer ") && !strings.HasPrefix(token, "lin_api_") {
		authHeader = token
	}

	teamID := os.Getenv("LINEAR_TEAM_ID")
	if teamID == "" {
		// Attempt to resolve the first accessible team id
		teamQuery := []byte(`{"query": "query { teams(first: 1) { nodes { id } } }"}`)
		if teamResp, teamErr := c.postJSON(ctx, endpoint, teamQuery, map[string]string{
			"Authorization": authHeader,
		}); teamErr == nil {
			var tr struct {
				Data struct {
					Teams struct {
						Nodes []struct {
							ID string `json:"id"`
						} `json:"nodes"`
					} `json:"teams"`
				} `json:"data"`
			}
			if err := json.Unmarshal(teamResp, &tr); err == nil && len(tr.Data.Teams.Nodes) > 0 {
				teamID = tr.Data.Teams.Nodes[0].ID
			}
		}
	}

	input := map[string]any{
		"title":       string(draft.Title),
		"description": string(draft.MarkdownBody),
	}
	if teamID != "" {
		input["teamId"] = teamID
	}

	reqPayload := map[string]any{
		"query": "mutation IssueCreate($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id title url } } }",
		"variables": map[string]any{
			"input": input,
		},
	}

	data, err := json.Marshal(reqPayload)
	if err != nil {
		return "", fmt.Errorf("marshal linear mutation: %w", err)
	}

	respBody, err := c.postJSON(ctx, endpoint, data, map[string]string{
		"Authorization": authHeader,
	})
	if err != nil {
		return "", fmt.Errorf("linear api: %w", err)
	}

	var res struct {
		Data struct {
			IssueCreate struct {
				Success bool `json:"success"`
				Issue   struct {
					ID  string `json:"id"`
					URL string `json:"url"`
				} `json:"issue"`
			} `json:"issueCreate"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if unmarshalErr := json.Unmarshal(respBody, &res); unmarshalErr != nil {
		return "", fmt.Errorf("unmarshal linear response: %w", unmarshalErr)
	}

	if len(res.Errors) > 0 {
		return "", fmt.Errorf("linear graphql error: %s", res.Errors[0].Message)
	}

	return res.Data.IssueCreate.Issue.URL, nil
}

func (c *ForgeClient) submitGitea(ctx context.Context, draft *adapter.StagedDraft) (string, error) {
	token := c.getToken(draft.Target.Tracker.Protocol)
	if token == "" {
		token = c.getToken(resolver.ProtocolGitea)
	}
	if token == "" {
		token = c.getToken(resolver.ProtocolCodeberg)
	}
	if token == "" {
		return "", errors.New("missing gitea authentication token")
	}

	owner, repo, err := extractOwnerRepo(draft)
	if err != nil {
		return "", err
	}

	apiBase := c.baseURLs[draft.Target.Tracker.Protocol]
	if apiBase == "" {
		rawURL := draft.Target.Tracker.URL
		if rawURL == "" {
			rawURL = draft.Target.RepositoryURL
		}
		u, parseErr := url.Parse(rawURL)
		if parseErr == nil && u.Host != "" {
			apiBase = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
		} else {
			apiBase = "https://codeberg.org"
		}
	}
	apiBase = strings.TrimRight(apiBase, "/")

	issueURL := fmt.Sprintf("%s/api/v1/repos/%s/%s/issues", apiBase, owner, repo)

	reqPayload := map[string]any{
		"title": string(draft.Title),
		"body":  string(draft.MarkdownBody),
	}

	data, err := json.Marshal(reqPayload)
	if err != nil {
		return "", fmt.Errorf("marshal gitea issue payload: %w", err)
	}

	respBody, err := c.postJSON(ctx, issueURL, data, map[string]string{
		"Authorization": "token " + token,
		"Accept":        "application/json",
	})
	if err != nil {
		return "", fmt.Errorf("gitea api: %w", err)
	}

	var res struct {
		HTMLURL string `json:"html_url"`
		URL     string `json:"url"`
	}
	if unmarshalErr := json.Unmarshal(respBody, &res); unmarshalErr != nil {
		return "", fmt.Errorf("unmarshal gitea response: %w", unmarshalErr)
	}

	if res.HTMLURL != "" {
		return res.HTMLURL, nil
	}
	return res.URL, nil
}

func (c *ForgeClient) postJSON(ctx context.Context, targetURL string, body []byte, headers map[string]string) ([]byte, error) {
	return c.httpClient.PostBytes(ctx, targetURL, "application/json", body, headers)
}
