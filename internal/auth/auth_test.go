package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"git.boone-schulz.de/go/nginx-ldap-auth/internal/cache"
	"git.boone-schulz.de/go/nginx-ldap-auth/internal/config"
	"git.boone-schulz.de/go/nginx-ldap-auth/internal/ldap"
	"git.boone-schulz.de/go/nginx-ldap-auth/internal/policy"
	"git.boone-schulz.de/go/nginx-ldap-auth/internal/ratelimit"
)

// fakeDirectory answers on command and counts how often it was asked.
//
// The call count is what most tests here actually assert: the ordering rules
// are only observable as "the directory was not consulted", so a fake that
// counts is the instrument, not a convenience.
type fakeDirectory struct {
	calls    atomic.Int64
	respond  func(user, password string) (*ldap.Identity, error)
	nameText string
}

func (f *fakeDirectory) Authenticate(_ context.Context, user, password string) (*ldap.Identity, error) {
	f.calls.Add(1)

	return f.respond(user, password)
}

func (f *fakeDirectory) Name() string {
	if f.nameText == "" {
		return "fake"
	}

	return f.nameText
}

func (f *fakeDirectory) Calls() int64 {
	return f.calls.Load()
}

// knownUser answers for one credential pair and rejects everything else.
func knownUser(user, password string, groups ...string) func(string, string) (*ldap.Identity, error) {
	return func(gotUser, gotPassword string) (*ldap.Identity, error) {
		if gotUser != user || gotPassword != password {
			return nil, fmt.Errorf("%w: fake directory", ldap.ErrInvalidCredentials)
		}

		identity := &ldap.Identity{
			DN:   "uid=" + user + ",dc=example,dc=org",
			User: user,
		}

		for _, group := range groups {
			identity.Groups = append(identity.Groups, ldap.Group{Name: group})
		}

		return identity, nil
	}
}

// harness bundles an Authenticator with the pieces a test needs to inspect.
type harness struct {
	auth      *Authenticator
	directory *fakeDirectory
	cache     cache.Cache
	throttle  ratelimit.Throttle
}

type harnessOptions struct {
	respond     func(user, password string) (*ldap.Identity, error)
	cacheOn     bool
	negativeTTL time.Duration
	throttle    ratelimit.Throttle
	policies    map[string]*config.Policy
	defaultName string
}

func newHarness(t *testing.T, opts harnessOptions) *harness {
	t.Helper()

	if opts.policies == nil {
		opts.policies = map[string]*config.Policy{
			"intranet": {
				Name:          "intranet",
				Realm:         "Intranet",
				LDAP:          "primary",
				RequireGroups: []string{"web-users"},
			},
			"open": {
				Name:         "open",
				Realm:        "Open",
				LDAP:         "primary",
				AllowAnyUser: true,
			},
		}
	}

	policies, err := policy.NewSet(&config.Config{
		Policies:      opts.policies,
		DefaultPolicy: opts.defaultName,
	})
	if err != nil {
		t.Fatalf("policy.NewSet: %v", err)
	}

	directory := &fakeDirectory{respond: opts.respond}

	var (
		decisionCache cache.Cache = cache.Disabled{}
		keyer         *cache.Keyer
	)

	if opts.cacheOn {
		memory, err := cache.NewMemory(100)
		if err != nil {
			t.Fatalf("cache.NewMemory: %v", err)
		}

		keyer, err = cache.NewKeyer([]byte(strings.Repeat("k", 32)))
		if err != nil {
			t.Fatalf("cache.NewKeyer: %v", err)
		}

		decisionCache = memory
	}

	throttle := opts.throttle
	if throttle == nil {
		throttle = ratelimit.Disabled{}
	}

	authenticator, err := New(Options{
		Policies:    policies,
		Directories: map[string]Directory{"primary": directory},
		Cache:       decisionCache,
		Keyer:       keyer,
		Throttle:    throttle,
		PositiveTTL: time.Minute,
		NegativeTTL: opts.negativeTTL,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return &harness{auth: authenticator, directory: directory, cache: decisionCache, throttle: throttle}
}

// request runs one authentication attempt.
func (h *harness) request(policyName, user, password, address string) Result {
	authorization := ""
	if user != "" || password != "" {
		authorization = basicHeader(user, password)
	}

	return h.auth.Authenticate(context.Background(), Request{
		PolicyHeader:  policyName,
		Authorization: authorization,
		RemoteAddress: address,
	})
}

func TestAuthenticateAllows(t *testing.T) {
	h := newHarness(t, harnessOptions{respond: knownUser("alice", "s3cret", "web-users")})

	result := h.request("intranet", "alice", "s3cret", "10.0.0.1")

	if result.Status != StatusAllow {
		t.Fatalf("status = %s (%s), want allow", result.Status, result.Reason)
	}

	if result.User != "alice" {
		t.Errorf("user = %q, want alice", result.User)
	}

	if len(result.Groups) != 1 || result.Groups[0] != "web-users" {
		t.Errorf("groups = %v, want [web-users]", result.Groups)
	}

	if result.MatchedGroup != "web-users" {
		t.Errorf("matched group = %q, want the group that granted access", result.MatchedGroup)
	}

	if result.Policy != "intranet" {
		t.Errorf("policy = %q, want intranet", result.Policy)
	}
}

func TestAuthenticateRejectsWrongPassword(t *testing.T) {
	h := newHarness(t, harnessOptions{respond: knownUser("alice", "s3cret", "web-users")})

	result := h.request("intranet", "alice", "wrong", "10.0.0.1")

	if result.Status != StatusUnauthenticated {
		t.Fatalf("status = %s, want unauthenticated", result.Status)
	}

	if result.Reason != "invalid_credentials" {
		t.Errorf("reason = %q, want invalid_credentials", result.Reason)
	}

	if result.Realm != "Intranet" {
		t.Errorf("realm = %q, want the policy's realm so the client can be challenged", result.Realm)
	}
}

func TestAuthenticateSeparatesAuthenticationFromAuthorization(t *testing.T) {
	// Valid credentials, wrong group: 403, not 401. Answering 401 would
	// invite the browser to prompt again for a password that was correct.
	h := newHarness(t, harnessOptions{respond: knownUser("alice", "s3cret", "other-group")})

	result := h.request("intranet", "alice", "s3cret", "10.0.0.1")

	if result.Status != StatusForbidden {
		t.Fatalf("status = %s, want forbidden", result.Status)
	}

	if result.Reason != "group_required" {
		t.Errorf("reason = %q, want group_required", result.Reason)
	}

	if result.User != "alice" {
		t.Errorf("user = %q, want the authenticated identity to still be reported", result.User)
	}
}

// TestEmptyPasswordNeverReachesTheDirectory is the anonymous-bind bypass, at
// the layer that is supposed to stop it first.
func TestEmptyPasswordNeverReachesTheDirectory(t *testing.T) {
	h := newHarness(t, harnessOptions{
		respond: func(string, string) (*ldap.Identity, error) {
			t.Error("the directory was consulted with an empty password")

			return nil, errors.New("unreachable")
		},
	})

	result := h.request("intranet", "alice", "", "10.0.0.1")

	if result.Status != StatusUnauthenticated {
		t.Fatalf("status = %s, want unauthenticated", result.Status)
	}

	if result.Reason != "empty_password" {
		t.Errorf("reason = %q, want empty_password so it is distinguishable in the log", result.Reason)
	}

	if h.directory.Calls() != 0 {
		t.Errorf("directory calls = %d, want 0", h.directory.Calls())
	}
}

func TestMissingCredentialsAreChallenged(t *testing.T) {
	h := newHarness(t, harnessOptions{respond: knownUser("alice", "s3cret", "web-users")})

	result := h.auth.Authenticate(context.Background(), Request{
		PolicyHeader:  "intranet",
		RemoteAddress: "10.0.0.1",
	})

	if result.Status != StatusUnauthenticated {
		t.Fatalf("status = %s, want unauthenticated", result.Status)
	}

	if result.Reason != "no_credentials" {
		t.Errorf("reason = %q, want no_credentials", result.Reason)
	}

	if result.Realm == "" {
		t.Error("no realm, so the client would get a 401 it cannot answer")
	}

	if h.directory.Calls() != 0 {
		t.Errorf("directory calls = %d, want 0", h.directory.Calls())
	}
}

// TestUnknownPolicyIsRefusedNotDefaulted guards the authorization boundary
// between applications sharing one instance.
func TestUnknownPolicyIsRefusedNotDefaulted(t *testing.T) {
	h := newHarness(t, harnessOptions{
		respond:     knownUser("alice", "s3cret", "web-users"),
		defaultName: "open",
	})

	result := h.request("does-not-exist", "alice", "s3cret", "10.0.0.1")

	if result.Status != StatusForbidden {
		t.Fatalf("status = %s, want forbidden", result.Status)
	}

	if result.Reason != "policy_unresolved" {
		t.Errorf("reason = %q, want policy_unresolved", result.Reason)
	}

	if h.directory.Calls() != 0 {
		t.Errorf("directory calls = %d, want 0: an unresolvable policy is answered before any work", h.directory.Calls())
	}
}

func TestMissingPolicyWithoutDefaultIsRefused(t *testing.T) {
	h := newHarness(t, harnessOptions{respond: knownUser("alice", "s3cret", "web-users")})

	result := h.request("", "alice", "s3cret", "10.0.0.1")

	if result.Status != StatusForbidden {
		t.Fatalf("status = %s, want forbidden", result.Status)
	}
}

func TestDirectoryOutageIsNotAnAuthenticationFailure(t *testing.T) {
	h := newHarness(t, harnessOptions{
		respond: func(string, string) (*ldap.Identity, error) {
			return nil, errors.New("connection refused")
		},
	})

	result := h.request("intranet", "alice", "s3cret", "10.0.0.1")

	if result.Status != StatusError {
		t.Fatalf("status = %s, want error: an outage must never be answered as a rejection", result.Status)
	}

	if result.Reason != "directory_error" {
		t.Errorf("reason = %q, want directory_error", result.Reason)
	}
}

// TestOutageIsNotCountedAgainstTheUser guards against turning a directory
// outage into a service-wide lockout that outlives it by the block duration.
func TestOutageIsNotCountedAgainstTheUser(t *testing.T) {
	throttle, err := ratelimit.New(ratelimit.Config{
		Window:                time.Minute,
		BlockDuration:         5 * time.Minute,
		MaxFailuresPerUser:    2,
		MaxFailuresPerAddress: 0,
		MaxEntries:            10,
	})
	if err != nil {
		t.Fatalf("ratelimit.New: %v", err)
	}

	h := newHarness(t, harnessOptions{
		respond: func(string, string) (*ldap.Identity, error) {
			return nil, errors.New("connection refused")
		},
		throttle: throttle,
	})

	for range 5 {
		if status := h.request("intranet", "alice", "s3cret", "10.0.0.1").Status; status != StatusError {
			t.Fatalf("status = %s, want error", status)
		}
	}

	if verdict := throttle.Check("alice", "10.0.0.1"); verdict.Blocked {
		t.Fatal("the user was blocked by failures that were the directory's fault, not theirs")
	}
}

func TestThrottleStopsRequestsBeforeTheDirectory(t *testing.T) {
	throttle, err := ratelimit.New(ratelimit.Config{
		Window:                time.Minute,
		BlockDuration:         5 * time.Minute,
		MaxFailuresPerUser:    3,
		MaxFailuresPerAddress: 0,
		MaxEntries:            10,
	})
	if err != nil {
		t.Fatalf("ratelimit.New: %v", err)
	}

	h := newHarness(t, harnessOptions{
		respond:  knownUser("alice", "s3cret", "web-users"),
		throttle: throttle,
	})

	for range 3 {
		if status := h.request("intranet", "alice", "wrong", "10.0.0.1").Status; status != StatusUnauthenticated {
			t.Fatalf("status = %s, want unauthenticated", status)
		}
	}

	callsBefore := h.directory.Calls()

	result := h.request("intranet", "alice", "wrong", "10.0.0.1")
	if result.Status != StatusThrottled {
		t.Fatalf("status = %s, want throttled", result.Status)
	}

	if result.RetryAfter <= 0 {
		t.Error("no retry-after, so the client cannot be told when to come back")
	}

	if h.directory.Calls() != callsBefore {
		t.Error("a throttled request still reached the directory, which is the load the throttle exists to prevent")
	}
}

// TestThrottleBlocksCorrectPasswordToo documents a deliberate consequence: once
// an identity is blocked, the block holds even for the right password. Letting
// a correct guess through would make the block a filter on wrong answers only,
// which is precisely what an attacker is looking for.
func TestThrottleBlocksCorrectPasswordToo(t *testing.T) {
	throttle, err := ratelimit.New(ratelimit.Config{
		Window:                time.Minute,
		BlockDuration:         5 * time.Minute,
		MaxFailuresPerUser:    2,
		MaxFailuresPerAddress: 0,
		MaxEntries:            10,
	})
	if err != nil {
		t.Fatalf("ratelimit.New: %v", err)
	}

	h := newHarness(t, harnessOptions{
		respond:  knownUser("alice", "s3cret", "web-users"),
		throttle: throttle,
	})

	for range 2 {
		h.request("intranet", "alice", "wrong", "10.0.0.1")
	}

	if status := h.request("intranet", "alice", "s3cret", "10.0.0.1").Status; status != StatusThrottled {
		t.Fatalf("status = %s, want throttled", status)
	}
}

// TestEmptyPasswordCountsAgainstTheUsername is a regression test.
//
// The per-address limit is switched off here on purpose: with the username
// discarded, nothing counted these attempts at all, and an attacker could
// hammer one account with the anonymous-bind bypass indefinitely.
func TestEmptyPasswordCountsAgainstTheUsername(t *testing.T) {
	throttle, err := ratelimit.New(ratelimit.Config{
		Window:                time.Minute,
		BlockDuration:         5 * time.Minute,
		MaxFailuresPerUser:    2,
		MaxFailuresPerAddress: 0,
		MaxEntries:            10,
	})
	if err != nil {
		t.Fatalf("ratelimit.New: %v", err)
	}

	h := newHarness(t, harnessOptions{
		respond: func(string, string) (*ldap.Identity, error) {
			t.Error("the directory was consulted with an empty password")

			return nil, errors.New("unreachable")
		},
		throttle: throttle,
	})

	for i := range 2 {
		if status := h.request("intranet", "alice", "", "10.0.0.1").Status; status != StatusUnauthenticated {
			t.Fatalf("attempt %d status = %s, want unauthenticated", i+1, status)
		}
	}

	result := h.request("intranet", "alice", "", "10.0.0.1")
	if result.Status != StatusThrottled {
		t.Fatalf("status = %s, want throttled after reaching the per-username limit", result.Status)
	}

	// A different account from the same address is unaffected, because the
	// address limit is what was switched off.
	if status := h.request("intranet", "bob", "", "10.0.0.1").Status; status != StatusUnauthenticated {
		t.Errorf("bob status = %s, want unauthenticated: only alice reached her limit", status)
	}
}

// TestCacheFieldIsEmptyWhenTheCacheWasNotConsulted keeps the log field
// meaningful: it reports what happened to this decision, not which backend is
// configured.
func TestCacheFieldIsEmptyWhenTheCacheWasNotConsulted(t *testing.T) {
	h := newHarness(t, harnessOptions{
		respond: knownUser("alice", "s3cret", "web-users"),
		cacheOn: true,
	})

	for name, result := range map[string]Result{
		"no credentials": h.request("intranet", "", "", "10.0.0.1"),
		"empty password": h.request("intranet", "alice", "", "10.0.0.1"),
		"unknown policy": h.request("nope", "alice", "s3cret", "10.0.0.1"),
	} {
		if result.Cache != "" {
			t.Errorf("%s: cache = %q, want empty", name, result.Cache)
		}
	}

	if got := h.request("intranet", "alice", "s3cret", "10.0.0.1").Cache; got != CacheMiss {
		t.Errorf("cache = %q, want %q once the cache is actually consulted", got, CacheMiss)
	}
}

func TestCacheHitSkipsTheDirectory(t *testing.T) {
	h := newHarness(t, harnessOptions{
		respond: knownUser("alice", "s3cret", "web-users"),
		cacheOn: true,
	})

	first := h.request("intranet", "alice", "s3cret", "10.0.0.1")
	if first.Cache != CacheMiss {
		t.Errorf("first request cache = %q, want %q", first.Cache, CacheMiss)
	}

	second := h.request("intranet", "alice", "s3cret", "10.0.0.1")
	if second.Cache != CacheHit {
		t.Errorf("second request cache = %q, want %q", second.Cache, CacheHit)
	}

	if second.Status != StatusAllow {
		t.Errorf("status = %s, want allow", second.Status)
	}

	if second.User != "alice" || len(second.Groups) != 1 {
		t.Errorf("cached decision lost the identity: %+v", second)
	}

	if calls := h.directory.Calls(); calls != 1 {
		t.Errorf("directory calls = %d, want 1: the second request should not have reached it", calls)
	}
}

// TestCacheIsKeyedByPolicy stops one policy's decision from answering for
// another with different group requirements.
func TestCacheIsKeyedByPolicy(t *testing.T) {
	h := newHarness(t, harnessOptions{
		respond: knownUser("alice", "s3cret", "web-users"),
		cacheOn: true,
	})

	if status := h.request("intranet", "alice", "s3cret", "10.0.0.1").Status; status != StatusAllow {
		t.Fatalf("intranet status = %s, want allow", status)
	}

	second := h.request("open", "alice", "s3cret", "10.0.0.1")
	if second.Cache != CacheMiss {
		t.Errorf("cache = %q, want a miss under a different policy", second.Cache)
	}

	if calls := h.directory.Calls(); calls != 2 {
		t.Errorf("directory calls = %d, want 2", calls)
	}
}

func TestCacheIsKeyedByPassword(t *testing.T) {
	h := newHarness(t, harnessOptions{
		respond: knownUser("alice", "s3cret", "web-users"),
		cacheOn: true,
	})

	h.request("intranet", "alice", "s3cret", "10.0.0.1")

	// A changed password must not be answered from the entry the old one
	// created.
	if status := h.request("intranet", "alice", "different", "10.0.0.1").Status; status != StatusUnauthenticated {
		t.Fatalf("status = %s, want unauthenticated", status)
	}

	if calls := h.directory.Calls(); calls != 2 {
		t.Errorf("directory calls = %d, want 2", calls)
	}
}

// TestUnauthorizedDecisionIsCached covers the reason it uses the positive TTL:
// the bind succeeded, so re-binding for every asset on a page the user may not
// see would be work with a known answer.
func TestUnauthorizedDecisionIsCached(t *testing.T) {
	h := newHarness(t, harnessOptions{
		respond: knownUser("alice", "s3cret", "other-group"),
		cacheOn: true,
	})

	for range 3 {
		if status := h.request("intranet", "alice", "s3cret", "10.0.0.1").Status; status != StatusForbidden {
			t.Fatalf("status = %s, want forbidden", status)
		}
	}

	if calls := h.directory.Calls(); calls != 1 {
		t.Errorf("directory calls = %d, want 1", calls)
	}
}

// TestNegativeCachingIsOffByDefault: a corrected password has to work
// immediately, so failures are not remembered unless configured.
func TestNegativeCachingIsOffByDefault(t *testing.T) {
	h := newHarness(t, harnessOptions{
		respond: knownUser("alice", "s3cret", "web-users"),
		cacheOn: true,
	})

	for range 3 {
		h.request("intranet", "alice", "wrong", "10.0.0.1")
	}

	if calls := h.directory.Calls(); calls != 3 {
		t.Errorf("directory calls = %d, want 3: failures must not be cached by default", calls)
	}

	// And the correct password works on the next attempt.
	if status := h.request("intranet", "alice", "s3cret", "10.0.0.1").Status; status != StatusAllow {
		t.Errorf("status = %s, want allow", status)
	}
}

func TestNegativeCachingWhenEnabled(t *testing.T) {
	h := newHarness(t, harnessOptions{
		respond:     knownUser("alice", "s3cret", "web-users"),
		cacheOn:     true,
		negativeTTL: time.Minute,
	})

	for range 3 {
		if status := h.request("intranet", "alice", "wrong", "10.0.0.1").Status; status != StatusUnauthenticated {
			t.Fatalf("status = %s, want unauthenticated", status)
		}
	}

	if calls := h.directory.Calls(); calls != 1 {
		t.Errorf("directory calls = %d, want 1 with negative caching enabled", calls)
	}
}

// TestCachedFailureStillCountsTowardsTheThrottle stops negative caching from
// becoming a way around the throttle rather than a supplement to it.
func TestCachedFailureStillCountsTowardsTheThrottle(t *testing.T) {
	throttle, err := ratelimit.New(ratelimit.Config{
		Window:                time.Minute,
		BlockDuration:         5 * time.Minute,
		MaxFailuresPerUser:    3,
		MaxFailuresPerAddress: 0,
		MaxEntries:            10,
	})
	if err != nil {
		t.Fatalf("ratelimit.New: %v", err)
	}

	h := newHarness(t, harnessOptions{
		respond:     knownUser("alice", "s3cret", "web-users"),
		cacheOn:     true,
		negativeTTL: time.Minute,
		throttle:    throttle,
	})

	for range 3 {
		h.request("intranet", "alice", "wrong", "10.0.0.1")
	}

	if status := h.request("intranet", "alice", "wrong", "10.0.0.1").Status; status != StatusThrottled {
		t.Fatalf("status = %s, want throttled: cached failures must still be counted", status)
	}
}

func TestSuccessClearsTheFailureCount(t *testing.T) {
	throttle, err := ratelimit.New(ratelimit.Config{
		Window:                time.Minute,
		BlockDuration:         5 * time.Minute,
		MaxFailuresPerUser:    3,
		MaxFailuresPerAddress: 0,
		MaxEntries:            10,
	})
	if err != nil {
		t.Fatalf("ratelimit.New: %v", err)
	}

	h := newHarness(t, harnessOptions{
		respond:  knownUser("alice", "s3cret", "web-users"),
		throttle: throttle,
	})

	h.request("intranet", "alice", "wrong", "10.0.0.1")
	h.request("intranet", "alice", "wrong", "10.0.0.1")

	if status := h.request("intranet", "alice", "s3cret", "10.0.0.1").Status; status != StatusAllow {
		t.Fatalf("status = %s, want allow", status)
	}

	h.request("intranet", "alice", "wrong", "10.0.0.1")
	h.request("intranet", "alice", "wrong", "10.0.0.1")

	if status := h.request("intranet", "alice", "wrong", "10.0.0.1").Status; status == StatusThrottled {
		t.Fatal("the successful login did not clear the earlier failures")
	}
}

// TestNewRequiresKeyerWhenCacheIsEnabled: a cache that stores something must
// never run without a pepper, because an unkeyed key would be a plain hash of
// the credentials.
func TestNewRequiresKeyerWhenCacheIsEnabled(t *testing.T) {
	policies, err := policy.NewSet(&config.Config{
		Policies: map[string]*config.Policy{
			"open": {Name: "open", Realm: "Open", LDAP: "primary", AllowAnyUser: true},
		},
	})
	if err != nil {
		t.Fatalf("policy.NewSet: %v", err)
	}

	memory, err := cache.NewMemory(10)
	if err != nil {
		t.Fatalf("cache.NewMemory: %v", err)
	}

	_, err = New(Options{
		Policies: policies,
		Cache:    memory,
		Throttle: ratelimit.Disabled{},
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err == nil {
		t.Fatal("an enabled cache without a keyer was accepted")
	}
}

func TestStatusLabels(t *testing.T) {
	want := map[Status]string{
		StatusAllow:           "allow",
		StatusUnauthenticated: "unauthenticated",
		StatusForbidden:       "forbidden",
		StatusThrottled:       "throttled",
		StatusError:           "error",
	}

	for status, label := range want {
		if got := status.String(); got != label {
			t.Errorf("Status(%d).String() = %q, want %q", status, got, label)
		}
	}
}

// brokenCache fails every operation, the way an unreachable Redis would.
type brokenCache struct{}

func (brokenCache) Get(context.Context, string) (cache.Decision, bool, error) {
	return cache.Decision{}, false, errors.New("redis: connection refused")
}

func (brokenCache) Set(context.Context, string, cache.Decision, time.Duration) error {
	return errors.New("redis: connection refused")
}

func (brokenCache) Stats() cache.Stats { return cache.Stats{} }
func (brokenCache) Name() string       { return "broken" }

// lyingCache violates the Cache contract in the one direction that matters: it
// reports a hit and an error at the same time, and the decision it hands back
// is the zero value.
//
// A Redis backend that cannot deserialise a stored entry is exactly this shape.
type lyingCache struct{}

func (lyingCache) Get(context.Context, string) (cache.Decision, bool, error) {
	return cache.Decision{}, true, errors.New("redis: malformed entry")
}

func (lyingCache) Set(context.Context, string, cache.Decision, time.Duration) error { return nil }
func (lyingCache) Stats() cache.Stats                                               { return cache.Stats{} }
func (lyingCache) Name() string                                                     { return "lying" }

// withCache replaces the harness's cache, keeping everything else.
func (h *harness) withCache(t *testing.T, replacement cache.Cache) {
	t.Helper()

	h.auth.cache = replacement
	h.cache = replacement
}

// TestBrokenCacheFallsThroughToTheDirectory is the §18 row "Redis unavailable →
// Continue with LDAP", which had nothing behind it.
//
// A cache that cannot answer must be a cache miss and nothing else. If a read
// error denied access, a Redis restart would log everybody out of every
// protected site; if it granted access, a Redis restart would open them.
func TestBrokenCacheFallsThroughToTheDirectory(t *testing.T) {
	h := newHarness(t, harnessOptions{
		respond: knownUser("alice", "s3cret", "web-users"),
		cacheOn: true,
	})

	h.withCache(t, brokenCache{})

	for i := range 3 {
		result := h.request("intranet", "alice", "s3cret", "10.0.0.1")
		if result.Status != StatusAllow {
			t.Fatalf("attempt %d status = %s (%s), want allow", i+1, result.Status, result.Reason)
		}
	}

	if calls := h.directory.Calls(); calls != 3 {
		t.Errorf("directory calls = %d, want 3: every request has to reach the directory", calls)
	}

	// And a wrong password is still wrong. A broken cache must not become a
	// way past the directory in either direction.
	if status := h.request("intranet", "alice", "wrong", "10.0.0.1").Status; status != StatusUnauthenticated {
		t.Errorf("status = %s, want unauthenticated", status)
	}
}

// TestCacheErrorIsNeverADecision covers the fail-open shape a future Redis
// backend can produce.
//
// The cache reports a hit together with an error, and the decision it returns
// is the zero value. Two things must hold: the error alone disqualifies the
// entry, and a zero-valued decision must not mean "allow" even if something
// does consume one.
func TestCacheErrorIsNeverADecision(t *testing.T) {
	h := newHarness(t, harnessOptions{
		respond: knownUser("alice", "s3cret", "web-users"),
		cacheOn: true,
	})

	h.withCache(t, lyingCache{})

	// The wrong password must be refused. If the erroring hit were used,
	// the zero-valued decision would answer for it.
	if status := h.request("intranet", "alice", "wrong", "10.0.0.1").Status; status != StatusUnauthenticated {
		t.Fatalf("status = %s, want unauthenticated: an erroring cache read granted access", status)
	}

	if calls := h.directory.Calls(); calls == 0 {
		t.Error("the directory was never consulted, so the erroring cache entry decided the request")
	}
}

// TestZeroDecisionDeniesAccess is the belt to the previous test's braces.
//
// project.md §18 closes with "the service must prefer denying access over
// accidentally granting access". A struct nobody filled in is the most likely
// way to get one for free — a failed deserialisation, a partially written
// entry, a future field added to Decision — so the zero value has to deny.
func TestZeroDecisionDeniesAccess(t *testing.T) {
	var unset cache.Decision

	if unset.Outcome.Allowed() {
		t.Fatalf("the zero value of Decision grants access (outcome %s); "+
			"anything that produces one by accident becomes an authentication bypass", unset.Outcome)
	}
}
