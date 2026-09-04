package cache

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

// EnvRedisAddress points the suite at a real Redis instead of the in-process
// one.
//
// The default is miniredis, which is a real RESP implementation on a real
// socket — go-redis talks to it unmodified — but it is not the same software
// that runs in production. Being able to re-run the identical assertions
// against a real server is what keeps that difference from becoming a blind
// spot:
//
//	NGINX_LDAP_AUTH_REDIS_ADDR=127.0.0.1:6379 go test ./internal/cache/
const EnvRedisAddress = "NGINX_LDAP_AUTH_REDIS_ADDR"

// redisFixture starts a server and returns a cache pointed at it.
//
// The returned control handle is nil when running against a real server: the
// tests that need to manipulate the server itself skip in that case rather than
// pretending they can.
func redisFixture(t *testing.T, observer Observer) (*Redis, *miniredis.Miniredis) {
	t.Helper()

	address := os.Getenv(EnvRedisAddress)

	var server *miniredis.Miniredis

	if address == "" {
		server = miniredis.RunT(t)
		address = server.Addr()
	}

	shared, err := NewRedis(RedisOptions{
		Address:  address,
		Database: 0,
		Timeout:  2 * time.Second,
		Observer: observer,
	})
	if err != nil {
		t.Fatalf("NewRedis: %v", err)
	}

	t.Cleanup(func() {
		if err := shared.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})

	return shared, server
}

func TestRedisRoundTrip(t *testing.T) {
	ctx := t.Context()
	shared, _ := redisFixture(t, nil)

	stored := Decision{
		Outcome: OutcomeAllow,
		User:    "alice",
		Groups:  []string{"web-users", "staff"},
	}

	key := KeyPrefix + "roundtrip"

	if err := shared.Set(ctx, key, stored, time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, found, err := shared.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if !found {
		t.Fatal("entry not found straight after it was stored")
	}

	if got.Outcome != OutcomeAllow || got.User != "alice" {
		t.Errorf("Get returned %+v, want the stored decision", got)
	}

	if strings.Join(got.Groups, ",") != "web-users,staff" {
		t.Errorf("groups = %v, want them preserved in order", got.Groups)
	}
}

func TestRedisMissOnUnknownKey(t *testing.T) {
	shared, _ := redisFixture(t, nil)

	_, found, err := shared.Get(t.Context(), KeyPrefix+"absent")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if found {
		t.Fatal("an unknown key reported a hit")
	}

	if stats := shared.Stats(); stats.Misses != 1 || stats.Errors != 0 {
		t.Errorf("stats = %+v, want one miss and no error: a missing key is not a failure", stats)
	}
}

// TestRedisOutcomeIsStoredByName is the property that makes a rolling restart
// safe.
//
// The numeric outcome values exist only to make the zero value a denial, and
// their order has already changed once. With the number on the wire, that
// change would have reinterpreted every entry written by an instance still
// running the older build — turning stored denials into grants for as long as
// the two versions overlapped.
func TestRedisOutcomeIsStoredByName(t *testing.T) {
	ctx := t.Context()
	shared, server := redisFixture(t, nil)

	if server == nil {
		t.Skipf("needs the in-process server to inspect the raw value; unset %s to run it", EnvRedisAddress)
	}

	key := KeyPrefix + "wire"

	if err := shared.Set(ctx, key, Decision{Outcome: OutcomeUnauthorized, User: "bob"}, time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	raw, err := server.Get(key)
	if err != nil {
		t.Fatalf("read raw value: %v", err)
	}

	if !strings.Contains(raw, `"outcome":"unauthorized"`) {
		t.Errorf("raw value is %s, want the outcome stored by name", raw)
	}
}

// TestRedisRejectsUnreadableEntries is the fail-safe direction for a shared
// cache, which can hold anything anybody wrote into it.
func TestRedisRejectsUnreadableEntries(t *testing.T) {
	ctx := t.Context()
	shared, server := redisFixture(t, nil)

	if server == nil {
		t.Skipf("needs the in-process server to plant malformed values; unset %s to run it", EnvRedisAddress)
	}

	tests := map[string]string{
		"not json":            "{{{",
		"empty object":        "{}",
		"unknown outcome":     `{"outcome":"probably_fine"}`,
		"numeric outcome":     `{"outcome":0}`,
		"outcome omitted":     `{"user":"alice","groups":["web-users"]}`,
		"json but wrong type": `["allow"]`,
	}

	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			key := KeyPrefix + "malformed"
			if err := server.Set(key, value); err != nil {
				t.Fatalf("plant value: %v", err)
			}

			decision, found, err := shared.Get(ctx, key)

			if found {
				t.Errorf("a malformed entry was reported as a hit with outcome %s", decision.Outcome)
			}

			if err == nil {
				t.Error("no error reported, so the caller could not log why the cache is useless")
			}

			// Belt and braces: even if some future change did return
			// it, the decision must not grant access.
			if decision.Outcome.Allowed() {
				t.Error("a malformed entry decoded into a grant")
			}
		})
	}
}

// TestRedisOutageIsAMissNotADecision is the §18 row "Redis unavailable →
// Continue with LDAP", asserted against a server that really goes away.
//
// If a read error denied, a Redis restart would log everybody out of every
// protected site. If it granted, a Redis restart would open them. It has to be
// neither.
func TestRedisOutageIsAMissNotADecision(t *testing.T) {
	ctx := t.Context()
	shared, server := redisFixture(t, nil)

	if server == nil {
		t.Skipf("needs the in-process server to stop it mid-test; unset %s to run it", EnvRedisAddress)
	}

	key := KeyPrefix + "outage"

	if err := shared.Set(ctx, key, Decision{Outcome: OutcomeAllow, User: "alice"}, time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if _, found, _ := shared.Get(ctx, key); !found {
		t.Fatal("the entry was not stored, so the outage is not what this test would measure")
	}

	server.Close()

	decision, found, err := shared.Get(ctx, key)

	if found {
		t.Error("an unreachable cache reported a hit")
	}

	if err == nil {
		t.Error("an unreachable cache reported success, so nothing would be logged about the outage")
	}

	if decision.Outcome.Allowed() {
		t.Error("an unreachable cache produced a grant")
	}

	// A write must fail loudly too, rather than appearing to have stored a
	// decision that is not there.
	if err := shared.Set(ctx, key, Decision{Outcome: OutcomeAllow}, time.Minute); err == nil {
		t.Error("writing to an unreachable cache reported success")
	}

	stats := shared.Stats()

	if stats.Errors < 2 {
		t.Errorf("errors = %d, want the failed read and write both counted", stats.Errors)
	}

	if stats.EntriesKnown {
		t.Error("the Redis backend claims to know its entry count; that would need a round trip inside a scrape")
	}
}

func TestRedisTTLExpires(t *testing.T) {
	ctx := t.Context()
	shared, server := redisFixture(t, nil)

	if server == nil {
		t.Skipf("needs the in-process server to advance its clock; unset %s to run it", EnvRedisAddress)
	}

	key := KeyPrefix + "ttl"

	if err := shared.Set(ctx, key, Decision{Outcome: OutcomeAllow}, time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	server.FastForward(59 * time.Second)

	if _, found, _ := shared.Get(ctx, key); !found {
		t.Fatal("the entry expired before its TTL elapsed")
	}

	server.FastForward(2 * time.Second)

	if _, found, _ := shared.Get(ctx, key); found {
		t.Fatal("the entry outlived its TTL; a revoked decision would stay valid")
	}
}

// TestRedisZeroTTLStoresNothing is how negative caching stays off by default,
// and it matters more here than in memory: an entry written to a shared cache
// is visible to every other instance.
func TestRedisZeroTTLStoresNothing(t *testing.T) {
	ctx := t.Context()
	shared, _ := redisFixture(t, nil)

	key := KeyPrefix + "zerottl"

	for _, ttl := range []time.Duration{0, -time.Second} {
		if err := shared.Set(ctx, key, Decision{Outcome: OutcomeInvalidCredentials}, ttl); err != nil {
			t.Fatalf("Set with ttl %s: %v", ttl, err)
		}

		if _, found, _ := shared.Get(ctx, key); found {
			t.Fatalf("a ttl of %s stored an entry", ttl)
		}
	}
}

// recordingRedisObserver captures the reported durations.
type recordingRedisObserver struct {
	mu    sync.Mutex
	count int
}

func (o *recordingRedisObserver) ObserveRedis(time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.count++
}

func (o *recordingRedisObserver) Count() int {
	o.mu.Lock()
	defer o.mu.Unlock()

	return o.count
}

// TestRedisOperationsAreObserved: the whole reason to know Redis latency is to
// notice when the cache has become slower than the directory it spares.
func TestRedisOperationsAreObserved(t *testing.T) {
	ctx := t.Context()
	observer := &recordingRedisObserver{}
	shared, _ := redisFixture(t, observer)

	key := KeyPrefix + "observed"

	if err := shared.Set(ctx, key, Decision{Outcome: OutcomeAllow}, time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if _, _, err := shared.Get(ctx, key); err != nil {
		t.Fatalf("Get: %v", err)
	}

	if got := observer.Count(); got != 2 {
		t.Errorf("observed %d operations, want 2", got)
	}
}

func TestRedisRespectsACancelledContext(t *testing.T) {
	shared, _ := redisFixture(t, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, found, err := shared.Get(ctx, KeyPrefix+"cancelled")

	if found {
		t.Error("a cancelled lookup reported a hit")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestNewRedisRejectsUselessOptions(t *testing.T) {
	tests := map[string]RedisOptions{
		"no address": {Timeout: time.Second},
		"no timeout": {Address: "127.0.0.1:6379"},
	}

	for name, opts := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NewRedis(opts); err == nil {
				t.Error("options were accepted, want an error")
			}
		})
	}
}

func TestParseOutcomeRoundTrip(t *testing.T) {
	for _, outcome := range []Outcome{OutcomeAllow, OutcomeInvalidCredentials, OutcomeUnauthorized} {
		got, err := ParseOutcome(outcome.String())
		if err != nil {
			t.Errorf("ParseOutcome(%q): %v", outcome, err)

			continue
		}

		if got != outcome {
			t.Errorf("ParseOutcome(%q) = %s, want %s", outcome, got, outcome)
		}
	}

	// An unknown name must not decode into a grant. This is the entry a
	// future version writes with an outcome this build has never heard of.
	got, err := ParseOutcome("invented_later")
	if err == nil {
		t.Error("an unknown outcome name was accepted")
	}

	if got.Allowed() {
		t.Error("an unknown outcome name decoded into a grant")
	}
}
