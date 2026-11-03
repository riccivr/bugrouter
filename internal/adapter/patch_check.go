package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/riccivr/bugrouter/internal/httpx"
)

// PatchStatusResult encapsulates the upstream issue tracking state of a temporary dependency patch.
type PatchStatusResult struct {
	Patch         DependencyPatch `json:"patch"`
	UpstreamState string          `json:"upstream_state"` // "open", "closed", "unknown", "no_url"
	CanRevert     bool            `json:"can_revert"`     // true when UpstreamState == "closed"
	CheckError    string          `json:"check_error,omitempty"`
}

// CheckPatchUpstreamStatus inspects upstream tracker issue states for a list of tracked patches.
// It executes bounded concurrency queries with a 5-worker semaphore and per-request timeouts.
func CheckPatchUpstreamStatus(ctx context.Context, client *httpx.Client, patches []DependencyPatch) ([]PatchStatusResult, error) {
	if client == nil {
		client = httpx.NewClient(5 * time.Second)
	}

	results := make([]PatchStatusResult, len(patches))
	if len(patches) == 0 {
		return results, nil
	}

	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup

	for i, p := range patches {
		wg.Add(1)
		go func(idx int, patch DependencyPatch) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[idx] = PatchStatusResult{
					Patch:         patch,
					UpstreamState: "unknown",
					CanRevert:     false,
					CheckError:    ctx.Err().Error(),
				}
				return
			}
			defer func() { <-sem }()

			reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			res := checkSinglePatchUpstream(reqCtx, client, patch)
			results[idx] = res
		}(i, p)
	}

	wg.Wait()
	return results, nil
}

func checkSinglePatchUpstream(ctx context.Context, client *httpx.Client, patch DependencyPatch) PatchStatusResult {
	res := PatchStatusResult{
		Patch: patch,
	}

	trimmedURL := strings.TrimSpace(patch.UpstreamIssueURL)
	if trimmedURL == "" {
		res.UpstreamState = "no_url"
		res.CanRevert = false
		return res
	}

	u, err := url.Parse(trimmedURL)
	if err != nil || u.Host == "" {
		res.UpstreamState = "unknown"
		res.CanRevert = false
		if err != nil {
			res.CheckError = fmt.Sprintf("invalid upstream url %q: %v", trimmedURL, err)
		} else {
			res.CheckError = fmt.Sprintf("invalid upstream url %q: missing host", trimmedURL)
		}
		return res
	}

	state, checkErr := queryIssueState(ctx, client, u, trimmedURL)
	if checkErr != nil {
		res.UpstreamState = "unknown"
		res.CanRevert = false
		res.CheckError = checkErr.Error()
		return res
	}

	res.UpstreamState = state
	res.CanRevert = (state == "closed")
	return res
}

func queryIssueState(ctx context.Context, client *httpx.Client, u *url.URL, rawURL string) (string, error) {
	lowerHost := strings.ToLower(u.Host)
	lowerPath := strings.ToLower(u.Path)

	// 1. Bugzilla
	if strings.Contains(lowerPath, "show_bug.cgi") || strings.Contains(lowerPath, "/rest/bug") {
		return queryBugzillaIssueState(ctx, client, u)
	}

	// 2. GitLab
	if strings.Contains(lowerPath, "/-/issues/") || strings.Contains(lowerPath, "/api/v4/projects/") || (strings.Contains(lowerHost, "gitlab") && strings.Contains(lowerPath, "/issues/")) {
		return queryGitLabIssueState(ctx, client, u, rawURL)
	}

	// 3. Gitea / Codeberg / Forgejo
	if strings.Contains(lowerHost, "codeberg.org") || strings.Contains(lowerHost, "gitea") || strings.Contains(lowerHost, "forgejo") || strings.Contains(lowerHost, "blender.org") || strings.Contains(lowerPath, "/api/v1/repos/") {
		return queryGiteaIssueState(ctx, client, u, rawURL)
	}

	// 4. GitHub (Default for issue/pull paths)
	return queryGitHubIssueState(ctx, client, u)
}

func queryBugzillaIssueState(ctx context.Context, client *httpx.Client, u *url.URL) (string, error) {
	id := u.Query().Get("id")
	if id == "" {
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) > 0 {
			id = parts[len(parts)-1]
		}
	}
	if id == "" {
		return "", errors.New("cannot extract bugzilla bug id from url")
	}

	apiURL := fmt.Sprintf("%s://%s/rest/bug/%s", u.Scheme, u.Host, url.PathEscape(id))
	data, err := client.GetBytes(ctx, apiURL, "application/json")
	if err != nil {
		return "", fmt.Errorf("bugzilla query: %w", err)
	}

	var bzResp struct {
		Bugs []struct {
			ID     any    `json:"id"`
			Status string `json:"status"`
		} `json:"bugs"`
	}
	if err := json.Unmarshal(data, &bzResp); err != nil {
		return "", fmt.Errorf("decode bugzilla response: %w", err)
	}
	if len(bzResp.Bugs) == 0 {
		return "", errors.New("no bug records returned by bugzilla")
	}

	statusUpper := strings.ToUpper(strings.TrimSpace(bzResp.Bugs[0].Status))
	if statusUpper == "RESOLVED" || statusUpper == "VERIFIED" || statusUpper == "CLOSED" {
		return "closed", nil
	}
	return "open", nil
}

func queryGitLabIssueState(ctx context.Context, client *httpx.Client, u *url.URL, rawURL string) (string, error) {
	var apiURL string
	if strings.Contains(u.Path, "/api/v4/projects/") {
		apiURL = rawURL
	} else if strings.Contains(u.Path, "/-/issues/") {
		parts := strings.Split(u.Path, "/-/issues/")
		projectPath := strings.Trim(parts[0], "/")
		iid := strings.Trim(parts[1], "/")
		apiURL = fmt.Sprintf("%s://%s/api/v4/projects/%s/issues/%s", u.Scheme, u.Host, url.PathEscape(projectPath), url.PathEscape(iid))
	} else {
		idx := strings.Index(u.Path, "/issues/")
		if idx == -1 {
			return "", errors.New("cannot parse gitlab issue path")
		}
		projectPath := strings.Trim(u.Path[:idx], "/")
		iid := strings.Trim(u.Path[idx+len("/issues/"):], "/")
		apiURL = fmt.Sprintf("%s://%s/api/v4/projects/%s/issues/%s", u.Scheme, u.Host, url.PathEscape(projectPath), url.PathEscape(iid))
	}

	var headers map[string]string
	if hName, hVal := gitLabAuthHeader(u.Host); hName != "" {
		headers = map[string]string{hName: hVal}
	}

	data, err := client.GetBytesWithHeaders(ctx, apiURL, "application/json", headers)
	if err != nil {
		return "", fmt.Errorf("gitlab query: %w", err)
	}

	var glResp struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(data, &glResp); err != nil {
		return "", fmt.Errorf("decode gitlab response: %w", err)
	}

	st := strings.ToLower(strings.TrimSpace(glResp.State))
	if st == "closed" {
		return "closed", nil
	}
	if st == "opened" || st == "open" {
		return "open", nil
	}
	if st != "" {
		return st, nil
	}
	return "unknown", nil
}

func queryGiteaIssueState(ctx context.Context, client *httpx.Client, u *url.URL, rawURL string) (string, error) {
	var apiURL string
	cleanPath := strings.Trim(u.Path, "/")
	if strings.HasPrefix(cleanPath, "api/v1/repos/") {
		apiURL = rawURL
	} else {
		parts := strings.Split(cleanPath, "/")
		if len(parts) >= 4 && (parts[2] == "issues" || parts[2] == "pulls") {
			owner := parts[0]
			repo := parts[1]
			index := parts[3]
			apiURL = fmt.Sprintf("%s://%s/api/v1/repos/%s/%s/issues/%s", u.Scheme, u.Host, owner, repo, index)
		} else {
			return "", errors.New("cannot parse gitea issue path")
		}
	}

	var headers map[string]string
	if hName, hVal := giteaAuthHeader(u.Host); hName != "" {
		headers = map[string]string{hName: hVal}
	}

	data, err := client.GetBytesWithHeaders(ctx, apiURL, "application/json", headers)
	if err != nil {
		return "", fmt.Errorf("gitea query: %w", err)
	}

	var giteaResp struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(data, &giteaResp); err != nil {
		return "", fmt.Errorf("decode gitea response: %w", err)
	}

	st := strings.ToLower(strings.TrimSpace(giteaResp.State))
	if st == "closed" {
		return "closed", nil
	}
	if st == "open" {
		return "open", nil
	}
	if st != "" {
		return st, nil
	}
	return "unknown", nil
}

func queryGitHubIssueState(ctx context.Context, client *httpx.Client, u *url.URL) (string, error) {
	cleanPath := strings.Trim(u.Path, "/")
	var apiURL string

	if strings.HasPrefix(cleanPath, "repos/") {
		apiURL = fmt.Sprintf("%s://%s/%s", u.Scheme, u.Host, cleanPath)
	} else {
		parts := strings.Split(cleanPath, "/")
		if len(parts) >= 4 && (parts[2] == "issues" || parts[2] == "pull") {
			owner := parts[0]
			repo := parts[1]
			num := parts[3]
			if strings.EqualFold(u.Host, "github.com") {
				apiURL = fmt.Sprintf("https://api.github.com/repos/%s/%s/issues/%s", owner, repo, num)
			} else if strings.Contains(strings.ToLower(u.Host), "github") {
				apiURL = fmt.Sprintf("%s://%s/api/v3/repos/%s/%s/issues/%s", u.Scheme, u.Host, owner, repo, num)
			} else {
				// Local test server or custom enterprise proxy
				apiURL = fmt.Sprintf("%s://%s/repos/%s/%s/issues/%s", u.Scheme, u.Host, owner, repo, num)
			}
		} else {
			return "", errors.New("cannot parse github issue/pull path")
		}
	}

	var headers map[string]string
	if hName, hVal := gitHubAuthHeader(u.Host); hName != "" {
		headers = map[string]string{hName: hVal}
	}

	data, err := client.GetBytesWithHeaders(ctx, apiURL, "application/vnd.github.v3+json", headers)
	if err != nil {
		return "", fmt.Errorf("github query: %w", err)
	}

	var ghResp struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(data, &ghResp); err != nil {
		return "", fmt.Errorf("decode github response: %w", err)
	}

	st := strings.ToLower(strings.TrimSpace(ghResp.State))
	if st == "closed" {
		return "closed", nil
	}
	if st == "open" {
		return "open", nil
	}
	if st != "" {
		return st, nil
	}
	return "unknown", nil
}

func gitHubAuthHeader(host string) (string, string) {
	if explicit := os.Getenv("BUGROUTER_GITHUB_TOKEN"); explicit != "" {
		return "Authorization", "Bearer " + explicit
	}
	if strings.EqualFold(host, "github.com") || strings.Contains(strings.ToLower(host), "github") {
		for _, env := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
			if tok := os.Getenv(env); tok != "" {
				return "Authorization", "Bearer " + tok
			}
		}
	}
	return "", ""
}

func gitLabAuthHeader(host string) (string, string) {
	if explicit := os.Getenv("BUGROUTER_GITLAB_TOKEN"); explicit != "" {
		return "PRIVATE-TOKEN", explicit
	}
	if strings.Contains(strings.ToLower(host), "gitlab") {
		for _, env := range []string{"GITLAB_TOKEN", "GL_TOKEN"} {
			if tok := os.Getenv(env); tok != "" {
				return "PRIVATE-TOKEN", tok
			}
		}
	}
	return "", ""
}

func giteaAuthHeader(host string) (string, string) {
	if explicit := os.Getenv("BUGROUTER_GITEA_TOKEN"); explicit != "" {
		return "Authorization", "token " + explicit
	}
	lowerHost := strings.ToLower(host)
	if strings.Contains(lowerHost, "codeberg.org") {
		if tok := os.Getenv("CODEBERG_TOKEN"); tok != "" {
			return "Authorization", "token " + tok
		}
	} else if strings.Contains(lowerHost, "gitea") || strings.Contains(lowerHost, "forgejo") || strings.Contains(lowerHost, "blender.org") {
		if tok := os.Getenv("GITEA_TOKEN"); tok != "" {
			return "Authorization", "token " + tok
		}
	}
	return "", ""
}
