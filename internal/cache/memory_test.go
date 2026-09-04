package cache

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// fakeClock lets expiry be tested without sleeping through a TTL.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
}

func newTestCache(t *testing.T, maxEntries int) (*Memory, *fakeClock) {
	t.Helper()

	memory, err := NewMemory(maxEntries)
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}

	clock := newFakeClock()
	memory.now = clock.Now

	return memory, clock
}

func TestMemoryRoundTrip(t *testing.T) {
	ctx := context.Background()
	memory, _ := newTestCache(t, 10)

	stored := Decision{Outcome: OutcomeAllow, User: "alice", Groups: []string{"web-users"}}

	if err := memory.Set(ctx, "k", stored, time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, found, err := memory.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if !found {
		t.Fatal("entry not found straight after it was stored")
	}

	if got.Outcome != OutcomeAllow || got.User != "alice" || len(got.Groups) != 1 {
		t.Errorf("Get returned %+v, want the stored decision", got)
	}
}

func TestMemoryMissOnUnknownKey(t *testing.T) {
	memory, _ := newTestCache(t, 10)

	_, found, err := memory.Get(context.Background(), "absent")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if found {
		t.Fatal("an unknown key reported a hit")
	}

	if stats := memory.Stats(); stats.Misses != 1 {
		t.Errorf("misses = %d, want 1", stats.Misses)
	}
}

func TestMemoryExpiry(t *testing.T) {
	ctx := context.Background()
	memory, clock := newTestCache(t, 10)

	if err := memory.Set(ctx, "k", Decision{Outcome: OutcomeAllow}, time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	clock.Advance(59 * time.Second)

	if _, found, _ := memory.Get(ctx, "k"); !found {
		t.Fatal("entry expired before its TTL elapsed")
	}

	// Exactly at the expiry instant the entry is gone: the comparison is
	// "still before expiry", so a TTL of one minute does not include the
	// sixtieth second.
	clock.Advance(time.Second)

	if _, found, _ := memory.Get(ctx, "k"); found {
		t.Fatal("entry survived its TTL")
	}

	if stats := memory.Stats(); stats.Expired != 1 {
		t.Errorf("expired = %d, want 1", stats.Expired)
	}
}

// TestMemoryZeroTTLStoresNothing is how negative caching stays off by default.
func TestMemoryZeroTTLStoresNothing(t *testing.T) {
	ctx := context.Background()
	memory, _ := newTestCache(t, 10)

	for _, ttl := range []time.Duration{0, -time.Second} {
		if err := memory.Set(ctx, "k", Decision{Outcome: OutcomeInvalidCredentials}, ttl); err != nil {
			t.Fatalf("Set with ttl %s: %v", ttl, err)
		}

		if _, found, _ := memory.Get(ctx, "k"); found {
			t.Fatalf("a ttl of %s stored an entry", ttl)
		}
	}

	if stats := memory.Stats(); stats.Entries != 0 {
		t.Errorf("entries = %d, want 0", stats.Entries)
	}
}

// TestMemoryEvictsLeastRecentlyUsed covers the bound that stops a spray of
// invalid usernames from growing the process.
func TestMemoryEvictsLeastRecentlyUsed(t *testing.T) {
	ctx := context.Background()
	memory, _ := newTestCache(t, 3)

	for _, key := range []string{"a", "b", "c"} {
		if err := memory.Set(ctx, key, Decision{Outcome: OutcomeAllow, User: key}, time.Minute); err != nil {
			t.Fatalf("Set %s: %v", key, err)
		}
	}

	// Touching "a" makes "b" the least recently used.
	if _, found, _ := memory.Get(ctx, "a"); !found {
		t.Fatal("a is missing")
	}

	if err := memory.Set(ctx, "d", Decision{Outcome: OutcomeAllow, User: "d"}, time.Minute); err != nil {
		t.Fatalf("Set d: %v", err)
	}

	if _, found, _ := memory.Get(ctx, "b"); found {
		t.Error("b survived, want the least recently used entry evicted")
	}

	for _, key := range []string{"a", "c", "d"} {
		if _, found, _ := memory.Get(ctx, key); !found {
			t.Errorf("%s was evicted, want it kept", key)
		}
	}

	stats := memory.Stats()

	if stats.Entries != 3 {
		t.Errorf("entries = %d, want the cache held at its bound of 3", stats.Entries)
	}

	if stats.Evictions != 1 {
		t.Errorf("evictions = %d, want 1", stats.Evictions)
	}
}

func TestMemoryOverwriteDoesNotGrow(t *testing.T) {
	ctx := context.Background()
	memory, _ := newTestCache(t, 3)

	for range 10 {
		if err := memory.Set(ctx, "k", Decision{Outcome: OutcomeAllow}, time.Minute); err != nil {
			t.Fatalf("Set: %v", err)
		}
	}

	if stats := memory.Stats(); stats.Entries != 1 {
		t.Errorf("entries = %d, want 1 after repeated writes to one key", stats.Entries)
	}
}

// TestMemoryClonesGroups checks that a caller cannot reach into the cache.
func TestMemoryClonesGroups(t *testing.T) {
	ctx := context.Background()
	memory, _ := newTestCache(t, 10)

	groups := []string{"web-users"}

	if err := memory.Set(ctx, "k", Decision{Outcome: OutcomeAllow, Groups: groups}, time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Mutating the slice that was handed to Set must not change what is
	// stored.
	groups[0] = "admins"

	first, _, _ := memory.Get(ctx, "k")
	if first.Groups[0] != "web-users" {
		t.Errorf("stored groups = %v, want the slice copied on write", first.Groups)
	}

	// Nor must mutating what Get returned change what the next reader sees.
	first.Groups[0] = "admins"

	second, _, _ := memory.Get(ctx, "k")
	if second.Groups[0] != "web-users" {
		t.Errorf("stored groups = %v, want the slice copied on read", second.Groups)
	}
}

func TestMemoryRejectsUnboundedSize(t *testing.T) {
	for _, maxEntries := range []int{0, -1} {
		if _, err := NewMemory(maxEntries); err == nil {
			t.Errorf("NewMemory(%d) was accepted, want an error", maxEntries)
		}
	}
}

// TestMemoryConcurrentAccess is meaningful under -race: nginx drives one
// authentication request per HTTP request, so concurrent reads and writes of
// the same key are the normal case, not an edge case.
func TestMemoryConcurrentAccess(t *testing.T) {
	ctx := context.Background()

	memory, err := NewMemory(64)
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}

	var wg sync.WaitGroup

	for worker := range 8 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for i := range 200 {
				key := fmt.Sprintf("key-%d", i%16)

				if err := memory.Set(ctx, key, Decision{
					Outcome: OutcomeAllow,
					User:    fmt.Sprintf("user-%d", worker),
					Groups:  []string{"web-users"},
				}, time.Minute); err != nil {
					t.Errorf("Set: %v", err)

					return
				}

				if decision, found, _ := memory.Get(ctx, key); found {
					_ = decision.Groups
				}
			}
		}()
	}

	wg.Wait()

	if stats := memory.Stats(); stats.Entries > 64 {
		t.Errorf("entries = %d, want no more than the bound of 64", stats.Entries)
	}
}

func TestDisabledAlwaysMisses(t *testing.T) {
	ctx := context.Background()
	disabled := Disabled{}

	if err := disabled.Set(ctx, "k", Decision{Outcome: OutcomeAllow}, time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if _, found, _ := disabled.Get(ctx, "k"); found {
		t.Fatal("the disabled cache returned a hit")
	}
}

func TestOutcomeLabels(t *testing.T) {
	// The strings become the result label of the metrics in milestone 2, so
	// they are stable identifiers rather than prose.
	want := map[Outcome]string{
		OutcomeAllow:              "allow",
		OutcomeInvalidCredentials: "invalid_credentials",
		OutcomeUnauthorized:       "unauthorized",
	}

	for outcome, label := range want {
		if got := outcome.String(); got != label {
			t.Errorf("Outcome(%d).String() = %q, want %q", outcome, got, label)
		}
	}

	if !OutcomeAllow.Allowed() {
		t.Error("OutcomeAllow does not grant access")
	}

	for _, outcome := range []Outcome{OutcomeInvalidCredentials, OutcomeUnauthorized} {
		if outcome.Allowed() {
			t.Errorf("%s grants access", outcome)
		}
	}
}
