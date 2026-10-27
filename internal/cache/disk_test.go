package cache

import (
	"path/filepath"
	"testing"
	"time"
)

type sampleData struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

func TestDiskCacheHitAndMiss(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir, time.Hour)

	// Miss on non-existent key
	var out sampleData
	hit, err := store.Get("nonexistent", &out)
	if err != nil {
		t.Fatalf("unexpected error on cache miss: %v", err)
	}
	if hit {
		t.Fatal("expected cache miss, got hit")
	}

	// Put value and verify hit
	val := sampleData{Name: "express", URL: "https://github.com/expressjs/express"}
	if err := store.Put("express", val); err != nil {
		t.Fatalf("unexpected error on Put: %v", err)
	}

	hit, err = store.Get("express", &out)
	if err != nil {
		t.Fatalf("unexpected error on Get: %v", err)
	}
	if !hit {
		t.Fatal("expected cache hit, got miss")
	}
	if out.Name != val.Name || out.URL != val.URL {
		t.Errorf("got %+v, want %+v", out, val)
	}
}

func TestDiskCacheTTLExpiration(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir, 25*time.Millisecond)

	val := sampleData{Name: "flask", URL: "https://github.com/pallets/flask"}
	if err := store.Put("flask", val); err != nil {
		t.Fatalf("unexpected error on Put: %v", err)
	}

	var out sampleData
	hit, err := store.Get("flask", &out)
	if err != nil {
		t.Fatalf("unexpected error on Get before expiry: %v", err)
	}
	if !hit {
		t.Fatal("expected immediate cache hit")
	}

	time.Sleep(35 * time.Millisecond)

	hit, err = store.Get("flask", &out)
	if err != nil {
		t.Fatalf("unexpected error on Get after expiry: %v", err)
	}
	if hit {
		t.Fatal("expected cache miss after TTL expiration")
	}
}

func TestDiskCacheKeyNormalization(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir, time.Hour)

	val := sampleData{Name: "tokio", URL: "https://github.com/tokio-rs/tokio"}
	if err := store.Put("  Tokio  ", val); err != nil {
		t.Fatalf("unexpected error on Put: %v", err)
	}

	var out sampleData
	hit, err := store.Get("tokio", &out)
	if err != nil {
		t.Fatalf("unexpected error on Get: %v", err)
	}
	if !hit {
		t.Fatal("expected normalized key hit")
	}
	if out.Name != val.Name {
		t.Errorf("got %q, want %q", out.Name, val.Name)
	}
}

func TestDiskCacheDefaultDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmp)

	store := NewStore("", 0)
	expected := filepath.Join(tmp, "bugrouter", "targets")
	if store.dir != expected {
		t.Errorf("store.dir = %q, want %q", store.dir, expected)
	}
	if store.ttl != 24*time.Hour {
		t.Errorf("store.ttl = %v, want 24h", store.ttl)
	}
}
