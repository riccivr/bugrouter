package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
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

// Client wraps an http.Client with enforced bounds on timeouts, payload sizes, and network targets.
type Client struct {
	httpClient        *http.Client
	maxBodyBytes      int64
	allowPrivateHosts bool
	lookupIP          func(ctx context.Context, network, host string) ([]net.IP, error)
	dialContext       func(ctx context.Context, network, addr string) (net.Conn, error)
}

func isBlockedIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() ||
		ip.IsUnspecified()
}

// NewClient returns a bounded Client blocking private and loopback networks by default.
func NewClient(timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	c := &Client{
		maxBodyBytes:      defaultMaxBodyBytes,
		allowPrivateHosts: false,
	}

	dialer := &net.Dialer{
		Timeout: timeout,
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Guard against SSRF and DNS rebinding by inspecting resolved IP addresses before dialing.
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("parse address %s: %w", addr, err)
		}

		dialFn := dialer.DialContext
		if c.dialContext != nil {
			dialFn = c.dialContext
		}

		if !c.allowPrivateHosts {
			parsedIP := net.ParseIP(host)
			if parsedIP != nil {
				if isBlockedIP(parsedIP) {
					return nil, fmt.Errorf("blocked connection to private or loopback address %s", parsedIP)
				}
				return dialFn(ctx, network, addr)
			}

			lookup := net.DefaultResolver.LookupIP
			if c.lookupIP != nil {
				lookup = c.lookupIP
			}
			ips, lookupErr := lookup(ctx, "ip", host)
			if lookupErr != nil {
				return nil, fmt.Errorf("resolve host %s: %w", host, lookupErr)
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("no IP addresses found for host %s", host)
			}

			for _, ip := range ips {
				if isBlockedIP(ip) {
					return nil, fmt.Errorf("blocked connection to private or loopback address %s", ip)
				}
			}

			var lastErr error
			for _, ip := range ips {
				targetAddr := net.JoinHostPort(ip.String(), port)
				conn, dialErr := dialFn(ctx, network, targetAddr)
				if dialErr == nil {
					return conn, nil
				}
				lastErr = dialErr
			}
			return nil, lastErr
		}

		return dialFn(ctx, network, addr)
	}

	c.httpClient = &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("stopped after 5 redirects")
			}

			if len(via) > 0 && (!strings.EqualFold(req.URL.Scheme, via[0].URL.Scheme) || !strings.EqualFold(req.URL.Host, via[0].URL.Host)) {
				req.Header.Del("Authorization")
				req.Header.Del("PRIVATE-TOKEN")
			}

			return nil
		},
	}

	return c
}

// NewTestClient returns a bounded Client permitting loopback hosts for unit testing.
func NewTestClient(timeout time.Duration) *Client {
	c := NewClient(timeout)
	c.allowPrivateHosts = true
	return c
}

// AllowPrivateHosts toggles whether connection to private, loopback, or link-local hosts is permitted.
func (c *Client) AllowPrivateHosts(allow bool) {
	c.allowPrivateHosts = allow
}

// GetBytes executes a GET request against the target URL and returns the response body bytes.
func (c *Client) GetBytes(ctx context.Context, url string, accept string) ([]byte, error) {
	return c.GetBytesWithHeaders(ctx, url, accept, nil)
}

// GetBytesWithHeaders executes a GET request against the target URL with custom headers and returns response bytes.
func (c *Client) GetBytesWithHeaders(ctx context.Context, url string, accept string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request for %s: %w", url, err)
	}
	req.Header.Set("User-Agent", version.UserAgent())
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request to %s: %w", url, err)
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
		return nil, &RateLimitError{
			StatusCode: resp.StatusCode,
			RetryAfter: retryAfter,
			Duration:   dur,
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}

	reader := io.LimitReader(resp.Body, c.maxBodyBytes+1)
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read response from %s: %w", url, err)
	}
	if int64(len(data)) > c.maxBodyBytes {
		return nil, fmt.Errorf("response from %s exceeds max body limit (%d bytes)", url, c.maxBodyBytes)
	}

	return data, nil
}

// GetJSON executes a GET request against the target URL and decodes the JSON payload.
func (c *Client) GetJSON(ctx context.Context, url string, dst any) error {
	data, err := c.GetBytes(ctx, url, "application/json")
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("decode response from %s: %w", url, err)
	}
	return nil
}

// PostBytes executes a bounded POST request with custom headers and returns response bytes.
func (c *Client) PostBytes(ctx context.Context, url string, contentType string, body []byte, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request for %s: %w", url, err)
	}
	req.Header.Set("User-Agent", version.UserAgent())
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request to %s: %w", url, err)
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
		return nil, &RateLimitError{
			StatusCode: resp.StatusCode,
			RetryAfter: retryAfter,
			Duration:   dur,
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		reader := io.LimitReader(resp.Body, 1024)
		errData, readErr := io.ReadAll(reader)
		if readErr != nil || len(errData) == 0 {
			return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
		}
		return nil, fmt.Errorf("unexpected status %d from %s: %s", resp.StatusCode, url, strings.TrimSpace(string(errData)))
	}

	reader := io.LimitReader(resp.Body, c.maxBodyBytes+1)
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read response from %s: %w", url, err)
	}
	if int64(len(data)) > c.maxBodyBytes {
		return nil, fmt.Errorf("response from %s exceeds max body limit (%d bytes)", url, c.maxBodyBytes)
	}

	return data, nil
}
