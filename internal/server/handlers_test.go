package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"bodsch.me/nginx-ldap-auth/internal/auth"
	"bodsch.me/nginx-ldap-auth/internal/cache"
	"bodsch.me/nginx-ldap-auth/internal/config"
	"bodsch.me/nginx-ldap-auth/internal/ldap"
	"bodsch.me/nginx-ldap-auth/internal/policy"
	"bodsch.me/nginx-ldap-auth/internal/ratelimit"
)

// stubDirectory answers for exactly one credential pair and rejects everything
// else.
//
// It enforces the real contract on purpose. An earlier version discarded the
// username and password and always returned its identity, which made every test
// in this file blind to whether the handler passed the client's credentials on
// at all: replacing the password with a constant in internal/auth left all
// eighteen of them green. A fake that accepts anything only proves the fake
// works.
//
// Leave the credential check in place.
type stubDirectory struct {
	user     string
	password string
	identity *ldap.Identity
	err      error

	// calls counts consultations, so a test can assert that a request was
	// refused *before* the authentication path was entered.
	calls *atomic.Int64
}

func (s stubDirectory) Authenticate(_ context.Context, user, password string) (*ldap.Identity, error) {
	if s.calls != nil {
		s.calls.Add(1)
	}

	if s.err != nil {
		return nil, s.err
	}

	// Production refuses an empty password before it ever reaches a
	// directory. A fake that accepts one would hide a regression in that
	// check rather than expose it.
	if strings.TrimSpace(password) == "" {
		return nil, fmt.Errorf("%w: empty password reached the directory", ldap.ErrInvalidCredentials)
	}

	if user != s.user || password != s.password {
		return nil, fmt.Errorf("%w: stub directory", ldap.ErrInvalidCredentials)
	}

	return s.identity, nil
}

func (stubDirectory) Name() string { return "stub" }

// directoryFor builds a stub that accepts alice's password and nothing else.
func directoryFor(identity *ldap.Identity) stubDirectory {
	return stubDirectory{
		user:     "alice",
		password: "s3cret",
		identity: identity,
		calls:    &atomic.Int64{},
	}
}

type testServer struct {
	handler http.Handler
	logs    *bytes.Buffer
	server  *Server
}

type testOptions struct {
	directory   auth.Directory
	throttle    ratelimit.Throttle
	logUsername bool
	clientIP    string
	requireGrp  []string

	// logAtInfo runs the logger at info instead of debug. Named for the
	// intent rather than taking a level, because the zero value of
	// slog.Level is info — a "default" level field would silently be info
	// everywhere and hide every successful decision.
	logAtInfo bool

	// cacheOn swaps the disabled cache for a real one with a real pepper,
	// for the tests that assert neither the pepper nor a credential-derived
	// key reaches the log.
	cacheOn bool

	// notReady leaves the server without a listener, which is the state a
	// process is in before Serve binds.
	notReady bool

	// observer, when set, receives the decision and HTTP reports.
	observer Observer
}

func newTestServer(t *testing.T, opts testOptions) *testServer {
	t.Helper()

	requireGroups := opts.requireGrp
	allowAny := len(requireGroups) == 0

	policies, err := policy.NewSet(&config.Config{
		DefaultPolicy: "intranet",
		Policies: map[string]*config.Policy{
			"intranet": {
				Name:          "intranet",
				Realm:         `Intranet "HQ"`,
				LDAP:          "primary",
				RequireGroups: requireGroups,
				AllowAnyUser:  allowAny,
			},
		},
	})
	if err != nil {
		t.Fatalf("policy.NewSet: %v", err)
	}

	throttle := opts.throttle
	if throttle == nil {
		throttle = ratelimit.Disabled{}
	}

	logs := &bytes.Buffer{}
	level := slog.LevelDebug
	if opts.logAtInfo {
		level = slog.LevelInfo
	}

	log := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: level}))

	var (
		decisionCache cache.Cache = cache.Disabled{}
		keyer         *cache.Keyer
	)

	if opts.cacheOn {
		memory, err := cache.NewMemory(64)
		if err != nil {
			t.Fatalf("cache.NewMemory: %v", err)
		}

		keyer, err = cache.NewKeyer([]byte(testPepper))
		if err != nil {
			t.Fatalf("cache.NewKeyer: %v", err)
		}

		decisionCache = memory
	}

	authenticator, err := auth.New(auth.Options{
		Policies:    policies,
		Directories: map[string]auth.Directory{"primary": opts.directory},
		Cache:       decisionCache,
		Keyer:       keyer,
		Throttle:    throttle,
		PositiveTTL: time.Minute,
		Logger:      log,
	})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}

	clientIP := opts.clientIP
	if clientIP == "" {
		clientIP = "X-Real-IP"
	}

	srv, err := New(Options{
		Config: config.Server{
			Listen:          "127.0.0.1:0",
			ClientIPHeader:  clientIP,
			ReadTimeout:     config.Duration(5 * time.Second),
			WriteTimeout:    config.Duration(5 * time.Second),
			IdleTimeout:     config.Duration(30 * time.Second),
			ShutdownTimeout: config.Duration(time.Second),
			MaxHeaderBytes:  8192,
		},
		Authenticator: authenticator,
		Cache:         decisionCache,
		Throttle:      throttle,
		LogUsername:   opts.logUsername,
		Logger:        log,
		Observer:      opts.observer,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Readiness is reached by having a listener. Tests that want the
	// pre-listener state ask for it here rather than reaching into the
	// server's state, so that what produces "not ready" stays the thing
	// under test.
	if !opts.notReady {
		srv.MarkReady()
	}

	return &testServer{handler: srv.Handler(), logs: logs, server: srv}
}

// testPepper is a throwaway HMAC key of the minimum accepted length. It is not
// a credential and never leaves the test binary.
const testPepper = "0123456789abcdef0123456789abcdef"

// authRequest drives the authentication endpoint.
func (ts *testServer) authRequest(t *testing.T, user, password string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, PathAuth, nil)
	req.RemoteAddr = "127.0.0.1:54321"

	if user != "" || password != "" {
		req.Header.Set("Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+password)))
	}

	for name, value := range headers {
		req.Header.Set(name, value)
	}

	recorder := httptest.NewRecorder()
	ts.handler.ServeHTTP(recorder, req)

	return recorder
}

func aliceIn(groups ...string) *ldap.Identity {
	identity := &ldap.Identity{DN: "uid=alice,dc=example,dc=org", User: "alice"}

	for _, group := range groups {
		identity.Groups = append(identity.Groups, ldap.Group{Name: group})
	}

	return identity
}

func TestAuthEndpointAllows(t *testing.T) {
	ts := newTestServer(t, testOptions{
		directory: directoryFor(aliceIn("web-users", "staff")),
	})

	recorder := ts.authRequest(t, "alice", "s3cret", nil)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", recorder.Code, recorder.Body)
	}

	if got := recorder.Header().Get(HeaderUser); got != "alice" {
		t.Errorf("%s = %q, want alice", HeaderUser, got)
	}

	if got := recorder.Header().Get(HeaderGroups); got != "web-users,staff" {
		t.Errorf("%s = %q, want the resolved groups", HeaderGroups, got)
	}
}

func TestAuthEndpointChallenges(t *testing.T) {
	ts := newTestServer(t, testOptions{directory: directoryFor(aliceIn())})

	recorder := ts.authRequest(t, "", "", nil)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}

	challengeHeader := recorder.Header().Get("WWW-Authenticate")
	if challengeHeader == "" {
		t.Fatal("no WWW-Authenticate header, so the browser would not prompt")
	}

	// The realm in the fixture contains quotes on purpose: an unescaped one
	// would end the quoted string early and turn the rest of the realm into
	// further auth-param syntax.
	if !strings.HasPrefix(challengeHeader, `Basic realm="Intranet \"HQ\""`) {
		t.Errorf("challenge = %q, want the realm escaped", challengeHeader)
	}

	// Identity headers must not appear on a refusal.
	if recorder.Header().Get(HeaderUser) != "" {
		t.Error("an unauthenticated response carried an identity header")
	}
}

func TestAuthEndpointEmptyPasswordIsRefused(t *testing.T) {
	ts := newTestServer(t, testOptions{
		directory: stubDirectory{
			err: errors.New("the directory must not be consulted with an empty password"),
		},
	})

	recorder := ts.authRequest(t, "alice", "", nil)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}

	if !strings.Contains(ts.logs.String(), "empty_password") {
		t.Errorf("log does not record the reason:\n%s", ts.logs)
	}
}

func TestAuthEndpointForbidsUnauthorizedUser(t *testing.T) {
	ts := newTestServer(t, testOptions{
		directory:  directoryFor(aliceIn("other-group")),
		requireGrp: []string{"web-users"},
	})

	recorder := ts.authRequest(t, "alice", "s3cret", nil)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}

	// No challenge: the password was right, and prompting again would ask
	// the user to fix something they cannot fix.
	if recorder.Header().Get("WWW-Authenticate") != "" {
		t.Error("a 403 carried an authentication challenge")
	}
}

func TestAuthEndpointRejectsUnknownPolicy(t *testing.T) {
	ts := newTestServer(t, testOptions{directory: directoryFor(aliceIn())})

	recorder := ts.authRequest(t, "alice", "s3cret", map[string]string{
		policy.Header: "does-not-exist",
	})

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 despite a configured default policy", recorder.Code)
	}
}

func TestAuthEndpointReportsBackendFailure(t *testing.T) {
	ts := newTestServer(t, testOptions{
		directory: stubDirectory{err: errors.New("connection refused")},
	})

	recorder := ts.authRequest(t, "alice", "s3cret", nil)

	// 502 rather than 500: the service is working, the directory behind it
	// is not. nginx collapses both into a 500 for the client, so the
	// distinction lives here and in the log.
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", recorder.Code)
	}

	if !strings.Contains(ts.logs.String(), "connection refused") {
		t.Errorf("the log does not carry the diagnosis:\n%s", ts.logs)
	}

	// The client is told nothing about why.
	if strings.Contains(recorder.Body.String(), "connection refused") {
		t.Error("the response body leaked the backend error")
	}
}

func TestAuthEndpointThrottles(t *testing.T) {
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

	ts := newTestServer(t, testOptions{
		directory: stubDirectory{err: fmt.Errorf("%w: no", ldap.ErrInvalidCredentials)},
		throttle:  throttle,
	})

	for range 2 {
		ts.authRequest(t, "alice", "wrong", nil)
	}

	recorder := ts.authRequest(t, "alice", "wrong", nil)

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", recorder.Code)
	}

	retryAfter := recorder.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Fatal("no Retry-After header")
	}

	seconds, err := strconv.Atoi(retryAfter)
	if err != nil || seconds <= 0 {
		t.Errorf("Retry-After = %q, want a positive number of seconds", retryAfter)
	}
}

// TestIdentityHeadersAreSanitised: the values come from the directory, which is
// trusted but not necessarily tidy. Go's HTTP writer would reject a header
// containing a newline, turning a successful login into a failed response.
func TestIdentityHeadersAreSanitised(t *testing.T) {
	ts := newTestServer(t, testOptions{
		directory: directoryFor(&ldap.Identity{
			User:   "alice\r\nX-Injected: yes",
			Groups: []ldap.Group{{Name: "web\nusers"}},
		}),
	})

	recorder := ts.authRequest(t, "alice", "s3cret", nil)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}

	if recorder.Header().Get("X-Injected") != "" {
		t.Fatal("a directory value produced an extra response header")
	}

	for _, name := range []string{HeaderUser, HeaderGroups} {
		if value := recorder.Header().Get(name); strings.ContainsAny(value, "\r\n") {
			t.Errorf("%s = %q still contains a line break", name, value)
		}
	}
}

func TestLogUsernameCanBeTurnedOff(t *testing.T) {
	for _, logUsername := range []bool{true, false} {
		t.Run(fmt.Sprintf("log_username=%v", logUsername), func(t *testing.T) {
			ts := newTestServer(t, testOptions{
				directory:   directoryFor(aliceIn("web-users")),
				logUsername: logUsername,
			})

			ts.authRequest(t, "alice", "s3cret", nil)

			contains := strings.Contains(ts.logs.String(), `"user":"alice"`)
			if contains != logUsername {
				t.Errorf("log contains the username = %v, want %v\n%s", contains, logUsername, ts.logs)
			}
		})
	}
}

// TestPasswordNeverReachesTheLog is the property that matters most about the
// log record.
func TestPasswordNeverReachesTheLog(t *testing.T) {
	const password = "uniquePasswordValue"

	ts := newTestServer(t, testOptions{
		directory: stubDirectory{err: fmt.Errorf("%w: no", ldap.ErrInvalidCredentials)},
	})

	ts.authRequest(t, "alice", password, nil)

	logged := ts.logs.String()

	if strings.Contains(logged, password) {
		t.Fatalf("the password appears in the log:\n%s", logged)
	}

	// Nor the header it arrived in, which contains the password encoded.
	if strings.Contains(logged, base64.StdEncoding.EncodeToString([]byte("alice:"+password))) {
		t.Fatalf("the Authorization header appears in the log:\n%s", logged)
	}
}

func TestClientAddress(t *testing.T) {
	ts := newTestServer(t, testOptions{directory: directoryFor(aliceIn())})

	tests := map[string]struct {
		remoteAddr string
		header     string
		want       string
	}{
		"header wins": {
			// Behind nginx the peer is always the proxy, so without
			// the header the per-address throttle would count the
			// whole internet as one client.
			remoteAddr: "127.0.0.1:54321",
			header:     "203.0.113.7",
			want:       "203.0.113.7",
		},
		"first element of a list": {
			remoteAddr: "127.0.0.1:54321",
			header:     "203.0.113.7, 10.0.0.1",
			want:       "203.0.113.7",
		},
		"falls back to the peer": {
			remoteAddr: "203.0.113.9:1234",
			header:     "",
			want:       "203.0.113.9",
		},
		"garbage falls back to the peer": {
			// Degraded — everyone counted as one client — but never
			// switched off.
			remoteAddr: "203.0.113.9:1234",
			header:     "not-an-address",
			want:       "203.0.113.9",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, PathAuth, nil)
			req.RemoteAddr = test.remoteAddr

			if test.header != "" {
				req.Header.Set("X-Real-IP", test.header)
			}

			if got := ts.server.clientAddress(req); got != test.want {
				t.Errorf("clientAddress = %q, want %q", got, test.want)
			}
		})
	}
}

func TestHealthIgnoresBackends(t *testing.T) {
	// Liveness must not depend on the directory: a failing probe leads to a
	// restart, and a restart discards the cache that was absorbing the
	// outage.
	ts := newTestServer(t, testOptions{
		directory: stubDirectory{err: errors.New("connection refused")},
	})

	recorder := httptest.NewRecorder()
	ts.handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, PathHealth, nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 while the directory is down", recorder.Code)
	}
}

func TestReadiness(t *testing.T) {
	ts := newTestServer(t, testOptions{directory: directoryFor(aliceIn())})

	recorder := httptest.NewRecorder()
	ts.handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, PathReady, nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}

	var body struct {
		Ready bool           `json:"ready"`
		Cache map[string]any `json:"cache"`
	}

	if err := json.NewDecoder(recorder.Body).Decode(&body); err != nil {
		t.Fatalf("decode readiness body: %v", err)
	}

	if !body.Ready {
		t.Error("ready = false")
	}

	if body.Cache["backend"] == nil {
		t.Error("readiness does not report the cache backend")
	}
}

// TestReadinessBeforeStartupCompletes reaches the unready state the way a real
// process does — by not having a listener yet.
//
// An earlier version set the flag by hand, which tested the handler and
// silently exempted whatever is supposed to set it. If Serve stopped marking
// the service ready, that version would still have passed.
func TestReadinessBeforeStartupCompletes(t *testing.T) {
	ts := newTestServer(t, testOptions{
		directory: directoryFor(aliceIn()),
		notReady:  true,
	})

	recorder := httptest.NewRecorder()
	ts.handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, PathReady, nil))

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 before the listener is up", recorder.Code)
	}
}

func TestChallengeEscaping(t *testing.T) {
	tests := map[string]string{
		"Intranet":     `Basic realm="Intranet", charset="UTF-8"`,
		`with "quote"`: `Basic realm="with \"quote\"", charset="UTF-8"`,
		`back\slash`:   `Basic realm="back\\slash", charset="UTF-8"`,
	}

	for realm, want := range tests {
		if got := challenge(realm); got != want {
			t.Errorf("challenge(%q) = %q, want %q", realm, got, want)
		}
	}
}

func TestSanitiseHeaderValue(t *testing.T) {
	tests := map[string]string{
		"alice":           "alice",
		"alice\r\nX-A: b": "aliceX-A: b",
		"alice\x00bob":    "alicebob",
		"tab\there":       "tab here",
		"  padded  ":      "padded",
		strings.Repeat("x", maxIdentityHeaderBytes+100): strings.Repeat("x", maxIdentityHeaderBytes),
	}

	for input, want := range tests {
		if got := sanitiseHeaderValue(input); got != want {
			t.Errorf("sanitiseHeaderValue(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestRetryAfterSecondsRoundsUp(t *testing.T) {
	// Rounding down would invite a retry that is still too early, and the
	// client would be refused again for no reason it can see.
	tests := map[time.Duration]int{
		0:                       1,
		-time.Second:            1,
		500 * time.Millisecond:  1,
		1500 * time.Millisecond: 2,
		5 * time.Minute:         300,
	}

	for d, want := range tests {
		if got := retryAfterSeconds(d); got != want {
			t.Errorf("retryAfterSeconds(%s) = %d, want %d", d, got, want)
		}
	}
}

// TestServeShutsDownOnContextCancel checks the lifecycle the systemd unit
// relies on for a clean stop.
func TestServeShutsDownOnContextCancel(t *testing.T) {
	policies, err := policy.NewSet(&config.Config{
		DefaultPolicy: "open",
		Policies: map[string]*config.Policy{
			"open": {Name: "open", Realm: "Open", LDAP: "primary", AllowAnyUser: true},
		},
	})
	if err != nil {
		t.Fatalf("policy.NewSet: %v", err)
	}

	authenticator, err := auth.New(auth.Options{
		Policies:    policies,
		Directories: map[string]auth.Directory{"primary": directoryFor(aliceIn())},
		Cache:       cache.Disabled{},
		Throttle:    ratelimit.Disabled{},
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}

	srv, err := New(Options{
		Config: config.Server{
			Listen:          "127.0.0.1:0",
			ReadTimeout:     config.Duration(time.Second),
			WriteTimeout:    config.Duration(time.Second),
			IdleTimeout:     config.Duration(time.Second),
			ShutdownTimeout: config.Duration(time.Second),
			MaxHeaderBytes:  8192,
		},
		Authenticator: authenticator,
		Cache:         cache.Disabled{},
		Throttle:      ratelimit.Disabled{},
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, stop := runningServer(t, &testServer{server: srv})

	if err := stop(); err != nil {
		t.Fatalf("Serve returned %v, want a clean shutdown", err)
	}

	// A stopped service must stop reporting itself ready, so that a
	// readiness probe during a restart sees the restart.
	if srv.ready.Load() {
		t.Error("the server still reports itself ready after shutting down")
	}
}

// TestSuccessIsLoggedAtDebug is the promise that keeps the journal usable.
//
// nginx calls this endpoint once per HTTP request, so a successful decision
// logged at info puts one line in the journal per image on every page. The
// failures — the lines an operator is actually looking for — would be buried in
// that, and on a busy site the journal would rotate them away within minutes.
func TestSuccessIsLoggedAtDebug(t *testing.T) {
	ts := newTestServer(t, testOptions{
		directory: directoryFor(aliceIn("web-users")),
		logAtInfo: true,
	})

	if code := ts.authRequest(t, "alice", "s3cret", nil).Code; code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}

	if logged := ts.logs.String(); logged != "" {
		t.Errorf("a successful authentication was logged at info:\n%s", logged)
	}

	// The counterpart: a failure has to be visible at info, or turning the
	// level up would silence everything.
	if code := ts.authRequest(t, "alice", "wrong", nil).Code; code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}

	if !strings.Contains(ts.logs.String(), "authentication failed") {
		t.Errorf("a failed authentication was not logged at info:\n%s", ts.logs)
	}
}

// TestPepperAndCacheKeyNeverReachTheLog covers the two entries of the
// project.md §11 exclusion list that had no test.
//
// The pepper is the one secret whose disclosure retroactively breaks every
// cache entry ever written: with it, a leaked cache becomes crackable offline
// against a wordlist. A credential-derived cache key is not reversible, but
// logging one hands an attacker a confirmation oracle — anyone who can read the
// journal and guess a password can check the guess against the recorded key.
func TestPepperAndCacheKeyNeverReachTheLog(t *testing.T) {
	ts := newTestServer(t, testOptions{
		directory: directoryFor(aliceIn("web-users")),
		cacheOn:   true,
	})

	// Both a miss and a hit, so the write path and the read path are both
	// exercised before the log is inspected.
	for range 2 {
		if code := ts.authRequest(t, "alice", "s3cret", nil).Code; code != http.StatusOK {
			t.Fatalf("status = %d, want 200", code)
		}
	}

	// And a failure, whose log record carries an error string built further
	// down the stack.
	ts.authRequest(t, "alice", "wrong", nil)

	logged := ts.logs.String()

	if strings.Contains(logged, testPepper) {
		t.Errorf("the cache pepper appears in the log:\n%s", logged)
	}

	keyer, err := cache.NewKeyer([]byte(testPepper))
	if err != nil {
		t.Fatalf("cache.NewKeyer: %v", err)
	}

	for _, password := range []string{"s3cret", "wrong"} {
		if key := keyer.Key("intranet", "alice", password); strings.Contains(logged, key) {
			t.Errorf("a credential-derived cache key appears in the log:\n%s", logged)
		}
	}

	// The prefix on its own would mean a key was logged with something else
	// substituted, which is the same disclosure with extra steps.
	if strings.Contains(logged, cache.KeyPrefix) {
		t.Errorf("something cache-key shaped appears in the log:\n%s", logged)
	}
}

// TestHostilePolicyNameIsBoundedInTheLog guards the one request value that is
// echoed back into a log record.
//
// An unrecognised policy name is rejected input by definition. The structured
// logger escapes it, but nothing else bounds its length or stops it carrying
// control characters into a terminal tailing the journal.
func TestHostilePolicyNameIsBoundedInTheLog(t *testing.T) {
	ts := newTestServer(t, testOptions{directory: directoryFor(aliceIn())})

	hostile := strings.Repeat("A", 4000) + "\r\n\x1b[2J"

	if code := ts.authRequest(t, "alice", "s3cret", map[string]string{
		policy.Header: hostile,
	}).Code; code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", code)
	}

	logged := ts.logs.String()

	if strings.Contains(logged, strings.Repeat("A", 200)) {
		t.Error("the rejected policy name was echoed at full length")
	}

	if strings.Contains(logged, "\x1b") {
		t.Error("an escape sequence from the request reached the log verbatim")
	}
}

// blockingDirectory holds a request until it is released, so that a shutdown
// can be triggered while one is genuinely in flight.
type blockingDirectory struct {
	entered  chan struct{}
	release  chan struct{}
	identity *ldap.Identity
}

func newBlockingDirectory(identity *ldap.Identity) *blockingDirectory {
	return &blockingDirectory{
		entered:  make(chan struct{}, 1),
		release:  make(chan struct{}),
		identity: identity,
	}
}

func (b *blockingDirectory) Authenticate(_ context.Context, user, password string) (*ldap.Identity, error) {
	select {
	case b.entered <- struct{}{}:
	default:
	}

	<-b.release

	if user != "alice" || password != "s3cret" {
		return nil, fmt.Errorf("%w: blocking directory", ldap.ErrInvalidCredentials)
	}

	return b.identity, nil
}

func (*blockingDirectory) Name() string { return "blocking" }

// runningServer starts a real listener and returns the server with its address.
//
// Tests that need to speak to a socket use this rather than httptest, because
// the limits under test — header size, read timeout, graceful shutdown — are
// enforced by net/http's connection handling and are simply absent when a
// handler is called directly.
func runningServer(t *testing.T, ts *testServer) (address string, stop func() error) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() { done <- ts.server.Serve(ctx) }()

	// Wait for the bound address rather than sleeping. A fixed sleep is
	// either too short on a loaded machine or wasted time on an idle one.
	deadline := time.Now().Add(5 * time.Second)

	for ts.server.Addr() == "" {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("the listener never published an address")
		}

		time.Sleep(time.Millisecond)
	}

	return ts.server.Addr(), func() error {
		cancel()

		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Second):
			return errors.New("Serve did not return after its context was cancelled; " +
				"systemctl stop would hang and systemd would eventually SIGKILL the process")
		}
	}
}

// TestOversizedHeaderIsRejectedBeforeTheDirectory covers the project.md §12
// requirement to limit header sizes, which nothing asserted.
//
// The endpoint is reachable by nginx, and nginx passes on whatever a client
// sent. An unbounded Authorization header is a cheap way to make the service
// allocate — and it must be refused by the connection handling, before an
// authentication attempt is built from it, so that the throttle and the
// directory never see it at all.
func TestOversizedHeaderIsRejectedBeforeTheDirectory(t *testing.T) {
	directory := directoryFor(aliceIn("web-users"))

	ts := newTestServer(t, testOptions{directory: directory})

	address, stop := runningServer(t, ts)

	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	// Well past the configured 8192 bytes.
	request := "GET " + PathAuth + " HTTP/1.1\r\nHost: localhost\r\n" +
		"Authorization: Basic " + strings.Repeat("A", 64*1024) + "\r\n\r\n"

	if _, err := io.WriteString(conn, request); err != nil {
		// A server that closes the connection mid-write is also a
		// refusal, and an acceptable one.
		t.Logf("write was cut short, which is itself a refusal: %v", err)
	}

	// Read exactly the status line. io.ReadAll would wait for EOF, which a
	// keep-alive connection never sends — so it would block until the
	// deadline and return the same "no 200 seen" either way, whether the
	// limit was enforced or not.
	statusLine, err := bufio.NewReader(conn).ReadString('\n')

	switch {
	case errors.Is(err, io.EOF) && statusLine == "":
		// The connection was closed without an answer. Refused.
	case err != nil:
		t.Fatalf("read status line: %v (read %q)", err, statusLine)
	}

	statusLine = strings.TrimRight(statusLine, "\r\n")

	if statusLine != "" && !strings.Contains(statusLine, "431") {
		t.Errorf("status line = %q, want 431 Request Header Fields Too Large", statusLine)
	}

	// The point of the limit: the request is refused by the connection
	// handling, so no authentication attempt is ever built from it.
	if calls := directory.calls.Load(); calls != 0 {
		t.Errorf("directory calls = %d, want 0: the oversized header reached the authentication path", calls)
	}

	if err := stop(); err != nil {
		t.Errorf("shutdown: %v", err)
	}
}

// TestShutdownWaitsForAnInFlightRequest is the promise the systemd unit relies
// on for `systemctl restart`.
//
// A shutdown that drops in-flight requests turns a routine restart into a burst
// of 500s for whoever was mid-page-load — and because nginx issues one
// authentication request per HTTP request, "whoever was mid-page-load" is
// everybody currently on the site.
func TestShutdownWaitsForAnInFlightRequest(t *testing.T) {
	directory := newBlockingDirectory(aliceIn("web-users"))

	ts := newTestServer(t, testOptions{directory: directory})

	address, stop := runningServer(t, ts)

	type outcome struct {
		code int
		err  error
	}

	answered := make(chan outcome, 1)

	go func() {
		req, err := http.NewRequest(http.MethodGet, "http://"+address+PathAuth, nil)
		if err != nil {
			answered <- outcome{err: err}

			return
		}

		req.SetBasicAuth("alice", "s3cret")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			answered <- outcome{err: err}

			return
		}

		defer func() { _ = resp.Body.Close() }()

		answered <- outcome{code: resp.StatusCode}
	}()

	// Only start the shutdown once the request is demonstrably inside the
	// directory call. Racing the shutdown against the request would make
	// this test pass for the wrong reason on a fast machine.
	select {
	case <-directory.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the request never reached the directory")
	}

	shutdown := make(chan error, 1)
	go func() { shutdown <- stop() }()

	close(directory.release)

	select {
	case got := <-answered:
		if got.err != nil {
			t.Fatalf("the in-flight request was dropped by the shutdown: %v", got.err)
		}

		if got.code != http.StatusOK {
			t.Errorf("status = %d, want 200: the request was already authenticated", got.code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the in-flight request never completed")
	}

	if err := <-shutdown; err != nil {
		t.Errorf("shutdown: %v", err)
	}
}

// recordingObserver captures what the server reported.
type recordingObserver struct {
	mu    sync.Mutex
	auths []observedAuth
	https []observedHTTP
}

type observedAuth struct {
	policy  string
	status  auth.Status
	reason  string
	elapsed time.Duration
}

type observedHTTP struct {
	handler string
	code    int
}

func (o *recordingObserver) ObserveAuth(policy string, status auth.Status, reason string, elapsed time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.auths = append(o.auths, observedAuth{policy, status, reason, elapsed})
}

func (o *recordingObserver) ObserveHTTP(handler string, code int, elapsed time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.https = append(o.https, observedHTTP{handler, code})
}

func (o *recordingObserver) snapshot() ([]observedAuth, []observedHTTP) {
	o.mu.Lock()
	defer o.mu.Unlock()

	return append([]observedAuth(nil), o.auths...), append([]observedHTTP(nil), o.https...)
}

// TestEveryDecisionIsObserved checks the reporting covers all five outcomes.
//
// A metric that is only incremented on the paths somebody remembered is worse
// than no metric: the ratio it feeds is wrong in the safe-looking direction,
// because the failures that were forgotten are missing from the denominator as
// well as the numerator.
func TestEveryDecisionIsObserved(t *testing.T) {
	throttle, err := ratelimit.New(ratelimit.Config{
		Window:                time.Minute,
		BlockDuration:         5 * time.Minute,
		MaxFailuresPerUser:    1,
		MaxFailuresPerAddress: 0,
		MaxEntries:            10,
	})
	if err != nil {
		t.Fatalf("ratelimit.New: %v", err)
	}

	observer := &recordingObserver{}

	ts := newTestServer(t, testOptions{
		directory:  directoryFor(aliceIn("other-group")),
		requireGrp: []string{"web-users"},
		throttle:   throttle,
		observer:   observer,
	})

	// Each request produces a different outcome.
	ts.authRequest(t, "", "", nil)                                                 // 401 no credentials
	ts.authRequest(t, "alice", "s3cret", nil)                                      // 403 group required
	ts.authRequest(t, "alice", "wrong", nil)                                       // 401 invalid
	ts.authRequest(t, "alice", "wrong", nil)                                       // 429 throttled
	ts.authRequest(t, "alice", "s3cret", map[string]string{policy.Header: "gone"}) // 403 unknown policy

	auths, https := observer.snapshot()

	if len(auths) != 5 {
		t.Fatalf("observed %d decisions, want 5: %+v", len(auths), auths)
	}

	reasons := make(map[string]bool, len(auths))
	for _, observed := range auths {
		reasons[observed.reason] = true
	}

	for _, want := range []string{"no_credentials", "group_required", "invalid_credentials",
		"throttled_user", "policy_unresolved"} {
		if !reasons[want] {
			t.Errorf("reason %q was never reported: %+v", want, auths)
		}
	}

	// The policy is empty exactly when resolution failed, and the metrics
	// layer turns that into its own constant. The server must not invent
	// one here, because the value it would invent is the request's.
	for _, observed := range auths {
		if observed.reason == "policy_unresolved" && observed.policy != "" {
			t.Errorf("an unresolved policy was reported as %q, want empty", observed.policy)
		}
	}

	if len(https) != 5 {
		t.Errorf("observed %d HTTP requests, want 5: %+v", len(https), https)
	}
}

// TestHTTPObservationRecordsTheActualCode guards the response wrapper.
//
// The wrapper is the only way to learn what a handler sent. If it lost the
// code, every request would be recorded as 200 and the HTTP metric would show a
// perfectly healthy service refusing everything.
func TestHTTPObservationRecordsTheActualCode(t *testing.T) {
	observer := &recordingObserver{}

	ts := newTestServer(t, testOptions{
		directory: directoryFor(aliceIn("web-users")),
		observer:  observer,
	})

	ts.authRequest(t, "alice", "s3cret", nil)
	ts.authRequest(t, "alice", "wrong", nil)

	recorder := httptest.NewRecorder()
	ts.handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, PathHealth, nil))

	_, https := observer.snapshot()

	want := []observedHTTP{
		{handler: "auth", code: http.StatusOK},
		{handler: "auth", code: http.StatusUnauthorized},
		{handler: "healthz", code: http.StatusOK},
	}

	if len(https) != len(want) {
		t.Fatalf("observed %+v, want %+v", https, want)
	}

	for i, expected := range want {
		if https[i] != expected {
			t.Errorf("observation %d = %+v, want %+v", i, https[i], expected)
		}
	}
}

// TestResponseWrapperStaysTransparent: the identity headers and the challenge
// have to survive the wrapper, or enabling metrics would break the login it is
// measuring.
func TestResponseWrapperStaysTransparent(t *testing.T) {
	ts := newTestServer(t, testOptions{
		directory: directoryFor(aliceIn("web-users")),
		observer:  &recordingObserver{},
	})

	allowed := ts.authRequest(t, "alice", "s3cret", nil)

	if got := allowed.Header().Get(HeaderUser); got != "alice" {
		t.Errorf("%s = %q, want it to pass through the wrapper", HeaderUser, got)
	}

	refused := ts.authRequest(t, "", "", nil)

	if refused.Header().Get("WWW-Authenticate") == "" {
		t.Error("the challenge was lost in the wrapper")
	}

	if refused.Body.Len() == 0 {
		t.Error("the body was lost in the wrapper")
	}
}
