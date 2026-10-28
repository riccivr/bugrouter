package resolver

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type mockProbe struct {
	name    string
	layer   SourceLayer
	resolve func(ctx context.Context, query string) (*Target, error)
}

func (m *mockProbe) Name() string       { return m.name }
func (m *mockProbe) Layer() SourceLayer { return m.layer }
func (m *mockProbe) Resolve(ctx context.Context, query string) (*Target, error) {
	return m.resolve(ctx, query)
}

func TestWaterfallPriorityOrder(t *testing.T) {
	target1 := &Target{Query: "test", CanonicalName: "pkg1", Layer: LayerOrgCloud}
	target2 := &Target{Query: "test", CanonicalName: "pkg2", Layer: LayerOSPackage}

	var probe2Called int32
	p1 := &mockProbe{
		name:  "probe1",
		layer: LayerOrgCloud,
		resolve: func(ctx context.Context, query string) (*Target, error) {
			return target1, nil
		},
	}
	p2 := &mockProbe{
		name:  "probe2",
		layer: LayerOSPackage,
		resolve: func(ctx context.Context, query string) (*Target, error) {
			atomic.StoreInt32(&probe2Called, 1)
			return target2, nil
		},
	}

	wf := NewWaterfall(time.Second, p1, p2)
	got, err := wf.Resolve(context.Background(), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.CanonicalName != target1.CanonicalName {
		t.Errorf("got %q, want %q", got.CanonicalName, target1.CanonicalName)
	}
	if atomic.LoadInt32(&probe2Called) != 0 {
		t.Error("probe2 should not have been called")
	}
}

func TestWaterfallFallbackOnError(t *testing.T) {
	target2 := &Target{Query: "test", CanonicalName: "pkg2", Layer: LayerOSPackage}

	p1 := &mockProbe{
		name:  "probe1",
		layer: LayerOrgCloud,
		resolve: func(ctx context.Context, query string) (*Target, error) {
			return nil, ErrNotFound
		},
	}
	p2 := &mockProbe{
		name:  "probe2",
		layer: LayerOSPackage,
		resolve: func(ctx context.Context, query string) (*Target, error) {
			return target2, nil
		},
	}

	wf := NewWaterfall(time.Second, p1, p2)
	got, err := wf.Resolve(context.Background(), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.CanonicalName != target2.CanonicalName {
		t.Errorf("got %q, want %q", got.CanonicalName, target2.CanonicalName)
	}
}

func TestWaterfallFallbackOnTimeout(t *testing.T) {
	target2 := &Target{Query: "test", CanonicalName: "pkg2", Layer: LayerRegistry}

	p1 := &mockProbe{
		name:  "slow-probe",
		layer: LayerOrgCloud,
		resolve: func(ctx context.Context, query string) (*Target, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	p2 := &mockProbe{
		name:  "fast-probe",
		layer: LayerRegistry,
		resolve: func(ctx context.Context, query string) (*Target, error) {
			return target2, nil
		},
	}

	wf := NewWaterfall(30*time.Millisecond, p1, p2)
	got, err := wf.Resolve(context.Background(), "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.CanonicalName != target2.CanonicalName {
		t.Errorf("got %q, want %q", got.CanonicalName, target2.CanonicalName)
	}
}

func TestWaterfallAllFail(t *testing.T) {
	p1 := &mockProbe{
		name:  "probe1",
		layer: LayerOrgCloud,
		resolve: func(ctx context.Context, query string) (*Target, error) {
			return nil, errors.New("network error")
		},
	}
	p2 := &mockProbe{
		name:  "probe2",
		layer: LayerOSPackage,
		resolve: func(ctx context.Context, query string) (*Target, error) {
			return nil, ErrNotFound
		},
	}

	wf := NewWaterfall(time.Second, p1, p2)
	_, err := wf.Resolve(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected error wrapping ErrNotFound, got: %v", err)
	}
}

func TestWaterfallEmptyQueryRejection(t *testing.T) {
	var probeCalled int32
	p := &mockProbe{
		name:  "probe",
		layer: LayerWorkspace,
		resolve: func(ctx context.Context, query string) (*Target, error) {
			atomic.StoreInt32(&probeCalled, 1)
			return &Target{CanonicalName: "unexpected"}, nil
		},
	}

	wf := NewWaterfall(time.Second, p)

	for _, input := range []string{"", "   ", "\t\n"} {
		_, err := wf.Resolve(context.Background(), input)
		if err == nil {
			t.Errorf("expected error for empty query %q, got nil", input)
		}
	}

	if atomic.LoadInt32(&probeCalled) != 0 {
		t.Error("probe was invoked despite empty query")
	}
}

type mockTargetCache struct {
	items map[string]Target
	gets  int32
	puts  int32
}

func (m *mockTargetCache) Get(key string, dst any) (bool, error) {
	atomic.AddInt32(&m.gets, 1)
	targetDst, ok := dst.(*Target)
	if !ok {
		return false, errors.New("invalid dst type")
	}
	val, exists := m.items[key]
	if !exists {
		return false, nil
	}
	*targetDst = val
	return true, nil
}

func (m *mockTargetCache) Put(key string, val any) error {
	atomic.AddInt32(&m.puts, 1)
	switch v := val.(type) {
	case *Target:
		m.items[key] = *v
	case Target:
		m.items[key] = v
	default:
		return errors.New("invalid val type")
	}
	return nil
}

func TestWaterfallCacheHitAndMiss(t *testing.T) {
	var probeCalls int32
	p := &mockProbe{
		name:  "cache-probe",
		layer: LayerOrgCloud,
		resolve: func(ctx context.Context, query string) (*Target, error) {
			atomic.AddInt32(&probeCalls, 1)
			return &Target{Query: query, CanonicalName: "cached-pkg", Layer: LayerOrgCloud}, nil
		},
	}

	cache := &mockTargetCache{items: make(map[string]Target)}
	wf := NewWaterfall(time.Second, p).WithCache(cache)

	// Miss: probe should run and write to cache
	got1, err := wf.Resolve(context.Background(), "my-lib")
	if err != nil {
		t.Fatalf("first Resolve failed: %v", err)
	}
	if got1.CanonicalName != "cached-pkg" {
		t.Errorf("got %q, want cached-pkg", got1.CanonicalName)
	}
	if atomic.LoadInt32(&probeCalls) != 1 {
		t.Errorf("probe calls = %d, want 1", atomic.LoadInt32(&probeCalls))
	}
	if atomic.LoadInt32(&cache.puts) != 1 {
		t.Errorf("cache puts = %d, want 1", atomic.LoadInt32(&cache.puts))
	}

	// Hit: probe should NOT run again
	got2, err := wf.Resolve(context.Background(), "my-lib")
	if err != nil {
		t.Fatalf("second Resolve failed: %v", err)
	}
	if got2.CanonicalName != "cached-pkg" {
		t.Errorf("got %q, want cached-pkg", got2.CanonicalName)
	}
	if atomic.LoadInt32(&probeCalls) != 1 {
		t.Errorf("probe calls after second resolve = %d, want 1", atomic.LoadInt32(&probeCalls))
	}
	if atomic.LoadInt32(&cache.gets) != 2 {
		t.Errorf("cache gets = %d, want 2", atomic.LoadInt32(&cache.gets))
	}
}
