package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Store provides TTL-bounded local disk caching for resolved targets.
type Store struct {
	dir string
	ttl time.Duration
}

// NewStore initializes a cache store backed by the specified directory and TTL.
func NewStore(dir string, ttl time.Duration) *Store {
	if dir == "" {
		if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
			dir = filepath.Join(xdg, "bugrouter", "targets")
		} else if userCache, err := os.UserCacheDir(); err == nil && userCache != "" {
			dir = filepath.Join(userCache, "bugrouter", "targets")
		} else {
			dir = filepath.Join(os.TempDir(), "bugrouter", "targets")
		}
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &Store{
		dir: dir,
		ttl: ttl,
	}
}

type cacheEntry struct {
	StoredAt time.Time       `json:"stored_at"`
	Value    json.RawMessage `json:"value"`
}

func (s *Store) keyPath(key string) string {
	normalized := strings.ToLower(strings.TrimSpace(key))
	hash := sha256.Sum256([]byte(normalized))
	filename := hex.EncodeToString(hash[:]) + ".json"
	return filepath.Join(s.dir, filename)
}

// Get retrieves and unmarshals a cached entry if present and not expired.
func (s *Store) Get(key string, dst any) (bool, error) {
	path := s.keyPath(key)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read cache file %s: %w", path, err)
	}

	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return false, fmt.Errorf("unmarshal cache entry %s: %w", path, err)
	}

	if time.Since(entry.StoredAt) > s.ttl {
		return false, nil
	}

	if err := json.Unmarshal(entry.Value, dst); err != nil {
		return false, fmt.Errorf("unmarshal cached value for %s: %w", key, err)
	}

	return true, nil
}

// Put writes an entry atomically to the cache store with the current timestamp.
func (s *Store) Put(key string, val any) error {
	if err := os.MkdirAll(s.dir, 0755); err != nil {
		return fmt.Errorf("create cache directory %s: %w", s.dir, err)
	}

	rawVal, err := json.Marshal(val)
	if err != nil {
		return fmt.Errorf("marshal cache value for %s: %w", key, err)
	}

	entry := cacheEntry{
		StoredAt: time.Now().UTC(),
		Value:    rawVal,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal cache entry for %s: %w", key, err)
	}

	targetPath := s.keyPath(key)

	// Write to temporary file in the same directory to allow atomic rename across filesystems.
	tmpFile, err := os.CreateTemp(s.dir, "target-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp cache file in %s: %w", s.dir, err)
	}
	tmpName := tmpFile.Name()

	if _, err := tmpFile.Write(data); err != nil {
		closeErr := tmpFile.Close()
		if rmErr := os.Remove(tmpName); rmErr != nil && !os.IsNotExist(rmErr) {
			return fmt.Errorf("write temp cache file %s: %w; close error: %v; cleanup error: %v", tmpName, err, closeErr, rmErr)
		}
		if closeErr != nil {
			return fmt.Errorf("write temp cache file %s: %w; close error: %v", tmpName, err, closeErr)
		}
		return fmt.Errorf("write temp cache file %s: %w", tmpName, err)
	}

	if err := tmpFile.Close(); err != nil {
		if rmErr := os.Remove(tmpName); rmErr != nil && !os.IsNotExist(rmErr) {
			return fmt.Errorf("close temp cache file %s: %w; cleanup error: %v", tmpName, err, rmErr)
		}
		return fmt.Errorf("close temp cache file %s: %w", tmpName, err)
	}

	if err := os.Rename(tmpName, targetPath); err != nil {
		if rmErr := os.Remove(tmpName); rmErr != nil && !os.IsNotExist(rmErr) {
			return fmt.Errorf("rename temp cache file to %s: %w; cleanup error: %v", targetPath, err, rmErr)
		}
		return fmt.Errorf("rename temp cache file to %s: %w", targetPath, err)
	}

	return nil
}
