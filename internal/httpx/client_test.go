package httpx

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/riccivr/bugrouter/internal/version"
)

func TestClientUserAgent(t *testing.T) {
	var capturedUA, capturedAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUA = r.Header.Get("User-Agent")
		capturedAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"status":"ok"}`)
	}))
	defer srv.Close()

	client := NewClient(time.Second)
	var dst map[string]string
	if err := client.GetJSON(context.Background(), srv.URL, &dst); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedUA := version.UserAgent()
	if capturedUA != expectedUA {
		t.Errorf("User-Agent = %q, want %q", capturedUA, expectedUA)
	}
	if capturedAccept != "application/json" {
		t.Errorf("Accept = %q, want application/json", capturedAccept)
	}
	if dst["status"] != "ok" {
		t.Errorf("dst[status] = %q, want ok", dst["status"])
	}
}

func TestClientGetBytesPlainText(t *testing.T) {
	const content = "Contact: https://example.com/security\n"
	var capturedAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, content)
	}))
	defer srv.Close()

	client := NewClient(time.Second)
	data, err := client.GetBytes(context.Background(), srv.URL, "text/plain")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedAccept != "text/plain" {
		t.Errorf("Accept = %q, want text/plain", capturedAccept)
	}
	if string(data) != content {
		t.Errorf("body = %q, want %q", string(data), content)
	}
}

func TestClientTimeoutCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		fmt.Fprintln(w, `{"status":"slow"}`)
	}))
	defer srv.Close()

	client := NewClient(30 * time.Millisecond)
	var dst map[string]string
	err := client.GetJSON(context.Background(), srv.URL, &dst)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestClientRateLimitError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprintln(w, `{"error":"slow down"}`)
	}))
	defer srv.Close()

	client := NewClient(time.Second)
	var dst map[string]string
	err := client.GetJSON(context.Background(), srv.URL, &dst)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var rle *RateLimitError
	if !errors.As(err, &rle) {
		t.Fatalf("expected RateLimitError, got %T: %v", err, err)
	}
	if rle.StatusCode != http.StatusTooManyRequests {
		t.Errorf("StatusCode = %d, want %d", rle.StatusCode, http.StatusTooManyRequests)
	}
	if rle.Duration != 60*time.Second {
		t.Errorf("Duration = %v, want 60s", rle.Duration)
	}
	if rle.RetryAfter != "60" {
		t.Errorf("RetryAfter = %q, want 60", rle.RetryAfter)
	}
}

func TestClientOversizedPayload(t *testing.T) {
	largeBody := `{"payload":"` + strings.Repeat("A", 1024) + `"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, largeBody)
	}))
	defer srv.Close()

	client := NewClient(time.Second)
	client.maxBodyBytes = 64

	var dst map[string]string
	err := client.GetJSON(context.Background(), srv.URL, &dst)
	if err == nil {
		t.Fatal("expected error on oversized payload, got nil")
	}
}
