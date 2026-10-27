package httpx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/riccivr/bugrouter/internal/version"
)

const (
	defaultMaxBodyBytes = 2 * 1024 * 1024 // 2 MiB
	defaultTimeout      = 3 * time.Second
)

// RateLimitError represents an HTTP 429 or 503 rate limiting response.
type RateLimitError struct {
	StatusCode int
	RetryAfter string
	Duration   time.Duration
}

func (e *RateLimitError) Error() string {
	if e.Duration > 0 {
		return fmt.Sprintf("rate limited (status %d): retry after %s", e.StatusCode, e.Duration)
	}
	if e.RetryAfter != "" {
		return fmt.Sprintf("rate limited (status %d): retry after %s", e.StatusCode, e.RetryAfter)
	}
	return fmt.Sprintf("rate limited (status %d)", e.StatusCode)
}

// Client wraps an http.Client with enforced bounds on timeouts and payload sizes.
type Client struct {
	httpClient   *http.Client
	maxBodyBytes int64
}

// NewClient returns a bounded Client with the specified request timeout.
func NewClient(timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Client{
		httpClient:   &http.Client{Timeout: timeout},
		maxBodyBytes: defaultMaxBodyBytes,
	}
}

// GetJSON executes a GET request against the target URL and decodes the JSON payload.
func (c *Client) GetJSON(ctx context.Context, url string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create request for %s: %w", url, err)
	}
	req.Header.Set("User-Agent", version.UserAgent())
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("execute request to %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode == http.StatusServiceUnavailable && resp.Header.Get("Retry-After") != "") {
		retryAfter := resp.Header.Get("Retry-After")
		var dur time.Duration
		if secs, parseErr := strconv.Atoi(retryAfter); parseErr == nil && secs > 0 {
			dur = time.Duration(secs) * time.Second
		} else if t, parseErr := http.ParseTime(retryAfter); parseErr == nil {
			dur = time.Until(t)
		}
		return &RateLimitError{
			StatusCode: resp.StatusCode,
			RetryAfter: retryAfter,
			Duration:   dur,
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}

	reader := io.LimitReader(resp.Body, c.maxBodyBytes+1)
	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("read response from %s: %w", url, err)
	}
	if int64(len(data)) > c.maxBodyBytes {
		return fmt.Errorf("response from %s exceeds max body limit (%d bytes)", url, c.maxBodyBytes)
	}

	if err := json.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("decode response from %s: %w", url, err)
	}
	return nil
}
