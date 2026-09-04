package ratelimit

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

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

func newTestLimiter(t *testing.T, cfg Config) (*Limiter, *fakeClock) {
	t.Helper()

	limiter, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	clock := newFakeClock()
	limiter.now = clock.Now

	return limiter, clock
}

func testConfig() Config {
	return Config{
		Window:                time.Minute,
		BlockDuration:         5 * time.Minute,
		MaxFailuresPerUser:    3,
		MaxFailuresPerAddress: 10,
		MaxEntries:            100,
	}
}

func TestBlocksAtTheUserLimit(t *testing.T) {
	limiter, _ := newTestLimiter(t, testConfig())

	for i := range 2 {
		limiter.RecordFailure("alice", "10.0.0.1")

		if verdict := limiter.Check("alice", "10.0.0.1"); verdict.Blocked {
			t.Fatalf("blocked after %d failures, want the limit of 3 to be reached first", i+1)
		}
	}

	limiter.RecordFailure("alice", "10.0.0.1")

	verdict := limiter.Check("alice", "10.0.0.1")
	if !verdict.Blocked {
		t.Fatal("not blocked after reaching the failure limit")
	}

	if verdict.Scope != ScopeUser {
		t.Errorf("scope = %q, want %q", verdict.Scope, ScopeUser)
	}

	if verdict.RetryAfter <= 0 || verdict.RetryAfter > 5*time.Minute {
		t.Errorf("retry after = %s, want it within the block duration", verdict.RetryAfter)
	}
}

func TestBlockExpires(t *testing.T) {
	limiter, clock := newTestLimiter(t, testConfig())

	for range 3 {
		limiter.RecordFailure("alice", "10.0.0.1")
	}

	if !limiter.Check("alice", "10.0.0.1").Blocked {
		t.Fatal("not blocked after reaching the limit")
	}

	clock.Advance(5 * time.Minute)

	if limiter.Check("alice", "10.0.0.1").Blocked {
		t.Fatal("still blocked after the block duration elapsed")
	}
}

// TestWindowSlides checks that failures spread thinly do not accumulate
// forever.
func TestWindowSlides(t *testing.T) {
	limiter, clock := newTestLimiter(t, testConfig())

	// Two failures, then a wait longer than the window, then two more. Four
	// failures in total but never three inside one window.
	limiter.RecordFailure("alice", "10.0.0.1")
	limiter.RecordFailure("alice", "10.0.0.1")

	clock.Advance(61 * time.Second)

	limiter.RecordFailure("alice", "10.0.0.1")
	limiter.RecordFailure("alice", "10.0.0.1")

	if limiter.Check("alice", "10.0.0.1").Blocked {
		t.Fatal("blocked without three failures inside one window")
	}
}

func TestRecordSuccessResetsUser(t *testing.T) {
	limiter, _ := newTestLimiter(t, testConfig())

	limiter.RecordFailure("alice", "10.0.0.1")
	limiter.RecordFailure("alice", "10.0.0.1")
	limiter.RecordSuccess("alice")
	limiter.RecordFailure("alice", "10.0.0.1")
	limiter.RecordFailure("alice", "10.0.0.1")

	if limiter.Check("alice", "10.0.0.1").Blocked {
		t.Fatal("a successful authentication did not clear the failure count")
	}
}

// TestRecordSuccessDoesNotResetAddress is a security property.
//
// If success cleared the address counter, anyone holding one valid account
// could authenticate between guesses and keep their address budget permanently
// fresh while working through other people's passwords.
func TestRecordSuccessDoesNotResetAddress(t *testing.T) {
	cfg := testConfig()
	cfg.MaxFailuresPerUser = 0
	cfg.MaxFailuresPerAddress = 3

	limiter, _ := newTestLimiter(t, cfg)

	limiter.RecordFailure("victim-one", "10.0.0.1")
	limiter.RecordFailure("victim-two", "10.0.0.1")

	limiter.RecordSuccess("attacker")

	limiter.RecordFailure("victim-three", "10.0.0.1")

	verdict := limiter.Check("victim-four", "10.0.0.1")
	if !verdict.Blocked {
		t.Fatal("the address budget was cleared by an unrelated successful login")
	}

	if verdict.Scope != ScopeAddress {
		t.Errorf("scope = %q, want %q", verdict.Scope, ScopeAddress)
	}
}

// TestUsernameCaseIsOneBudget is a security property.
//
// LDAP matches uid case-insensitively, so alice and ALICE are one account.
// Keying them separately would multiply an attacker's budget by the number of
// ways the name can be spelled.
func TestUsernameCaseIsOneBudget(t *testing.T) {
	limiter, _ := newTestLimiter(t, testConfig())

	limiter.RecordFailure("alice", "10.0.0.1")
	limiter.RecordFailure("ALICE", "10.0.0.2")
	limiter.RecordFailure("Alice", "10.0.0.3")

	if !limiter.Check("aLiCe", "10.0.0.4").Blocked {
		t.Fatal("case variants of one username were counted as separate accounts")
	}
}

func TestAddressLimitIsIndependentOfUser(t *testing.T) {
	cfg := testConfig()
	cfg.MaxFailuresPerUser = 0
	cfg.MaxFailuresPerAddress = 3

	limiter, _ := newTestLimiter(t, cfg)

	// Three different usernames from one address: no user limit is reached,
	// but the address budget is spent.
	for i := range 3 {
		limiter.RecordFailure(fmt.Sprintf("user-%d", i), "10.0.0.1")
	}

	if !limiter.Check("user-99", "10.0.0.1").Blocked {
		t.Fatal("username spraying from one address was not caught")
	}

	if limiter.Check("user-99", "10.0.0.2").Blocked {
		t.Fatal("an unrelated address was blocked")
	}
}

// TestEmptyIdentityIsNotCounted keeps unrelated clients from blocking each
// other. A request without an Authorization header is a probe or a
// misconfiguration, not a password guess.
func TestEmptyIdentityIsNotCounted(t *testing.T) {
	cfg := testConfig()
	cfg.MaxFailuresPerUser = 2
	cfg.MaxFailuresPerAddress = 0

	limiter, _ := newTestLimiter(t, cfg)

	for range 10 {
		limiter.RecordFailure("", "10.0.0.1")
	}

	if limiter.Check("", "10.0.0.1").Blocked {
		t.Fatal("requests with no username were counted against a shared empty key")
	}

	if limiter.Check("alice", "10.0.0.1").Blocked {
		t.Fatal("an unrelated user was blocked by anonymous requests")
	}
}

// TestFailsClosedWhenOutOfCapacity covers the throttle's own exhaustion.
//
// Reaching this state means every tracked identity is an active block, which is
// a large distributed guessing attempt. Serving requests that cannot be counted
// would switch the throttle off exactly when it matters; making room by
// evicting an active block would let an attacker clear their own block on
// demand. Refusing is the only option left that is not one of those two.
func TestFailsClosedWhenOutOfCapacity(t *testing.T) {
	cfg := Config{
		Window:                time.Minute,
		BlockDuration:         5 * time.Minute,
		MaxFailuresPerUser:    1,
		MaxFailuresPerAddress: 0,
		MaxEntries:            3,
	}

	limiter, _ := newTestLimiter(t, cfg)

	for i := range 3 {
		limiter.RecordFailure(fmt.Sprintf("user-%d", i), "10.0.0.1")
	}

	verdict := limiter.Check("someone-else", "10.0.0.1")
	if !verdict.Blocked {
		t.Fatal("requests were served while the throttle could no longer count them")
	}

	if verdict.Scope != ScopeCapacity {
		t.Errorf("scope = %q, want %q", verdict.Scope, ScopeCapacity)
	}

	if stats := limiter.Stats(); stats.CapacityDenied == 0 {
		t.Error("capacity denials are not counted, so the condition would be invisible")
	}
}

// TestEvictionPrefersIdleEntries checks that ordinary churn does not trip the
// capacity refusal: an entry that is merely counting, not blocking, is
// evictable.
func TestEvictionPrefersIdleEntries(t *testing.T) {
	cfg := Config{
		Window:                time.Minute,
		BlockDuration:         5 * time.Minute,
		MaxFailuresPerUser:    5,
		MaxFailuresPerAddress: 0,
		MaxEntries:            3,
	}

	limiter, _ := newTestLimiter(t, cfg)

	// Three identities with one failure each: none is blocked, all are
	// evictable.
	for i := range 3 {
		limiter.RecordFailure(fmt.Sprintf("user-%d", i), "10.0.0.1")
	}

	limiter.RecordFailure("user-3", "10.0.0.1")

	if verdict := limiter.Check("user-4", "10.0.0.1"); verdict.Blocked {
		t.Fatalf("blocked with scope %q while idle entries were available to evict", verdict.Scope)
	}

	if stats := limiter.Stats(); stats.Entries > 3 {
		t.Errorf("entries = %d, want no more than the bound of 3", stats.Entries)
	}
}

func TestNewRejectsUselessConfigurations(t *testing.T) {
	tests := map[string]Config{
		"no window":     {BlockDuration: time.Minute, MaxFailuresPerUser: 1, MaxEntries: 1},
		"no block":      {Window: time.Minute, MaxFailuresPerUser: 1, MaxEntries: 1},
		"no capacity":   {Window: time.Minute, BlockDuration: time.Minute, MaxFailuresPerUser: 1},
		"no limits set": {Window: time.Minute, BlockDuration: time.Minute, MaxEntries: 1},
		"negative": {
			Window: time.Minute, BlockDuration: time.Minute,
			MaxFailuresPerUser: -1, MaxEntries: 1,
		},
	}

	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := New(cfg); err == nil {
				t.Error("configuration was accepted, want an error")
			}
		})
	}
}

func TestDisabledNeverBlocks(t *testing.T) {
	disabled := Disabled{}

	for range 100 {
		disabled.RecordFailure("alice", "10.0.0.1")
	}

	if disabled.Check("alice", "10.0.0.1").Blocked {
		t.Fatal("the disabled throttle blocked a request")
	}
}

// TestConcurrentUse is meaningful under -race.
func TestConcurrentUse(t *testing.T) {
	limiter, err := New(Config{
		Window:                time.Minute,
		BlockDuration:         time.Minute,
		MaxFailuresPerUser:    5,
		MaxFailuresPerAddress: 20,
		MaxEntries:            64,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var wg sync.WaitGroup

	for worker := range 8 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for i := range 200 {
				user := fmt.Sprintf("user-%d", i%16)
				address := fmt.Sprintf("10.0.0.%d", worker)

				limiter.Check(user, address)
				limiter.RecordFailure(user, address)

				if i%7 == 0 {
					limiter.RecordSuccess(user)
				}
			}
		}()
	}

	wg.Wait()

	if stats := limiter.Stats(); stats.Entries > 64 {
		t.Errorf("entries = %d, want no more than the bound of 64", stats.Entries)
	}
}
