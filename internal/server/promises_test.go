package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"bodsch.me/nginx-ldap-auth/internal/ldap"
	"bodsch.me/nginx-ldap-auth/internal/policy"
	"bodsch.me/nginx-ldap-auth/internal/ratelimit"
	"bodsch.me/nginx-ldap-auth/internal/session"
)

// project.md §12: "never let a session cookie carry a password".
//
// If it failed, every browser on the machine would be holding the user's
// directory password in a readable cookie store, and every proxy log that
// records cookies would have it too — a password disclosure from a feature
// whose entire purpose is to stop passwords being replayed.
func TestSessionCookieCarriesNoPassword(t *testing.T) {
	const password = "s3cret"

	ts := sessionServer(t, sessionConfig())

	resp := login(t, ts, "alice", password, "/")
	defer resp.Body.Close()

	cookie := cookieNamed(resp, "nginx_ldap_auth")
	if cookie == nil {
		t.Fatal("no session cookie was issued")
	}

	if strings.Contains(cookie.Value, password) {
		t.Fatal("the password appears verbatim in the session cookie")
	}

	// The value is signed, not encrypted, so the payload is readable by
	// anyone holding the cookie. What it may contain is exactly the
	// decision — and the password is not part of a decision.
	payload := cookie.Value
	if parts := strings.Split(payload, "."); len(parts) == 3 {
		decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatalf("decode payload: %v", err)
		}

		payload = string(decoded)
	}

	if strings.Contains(payload, password) {
		t.Fatalf("the password is in the decoded cookie payload: %s", payload)
	}

	var fields map[string]any
	if err := json.Unmarshal([]byte(payload), &fields); err != nil {
		t.Fatalf("payload is not the documented JSON object: %v", err)
	}

	// project.md §4a names the payload's fields. Anything else is a field
	// somebody added without deciding whether it belongs in a value the
	// client can read.
	for name := range fields {
		switch name {
		case "u", "p", "g", "i", "s":
		default:
			t.Errorf("unexpected field %q in the cookie payload", name)
		}
	}
}

// project.md §12: "Keep the session signing secret ... out of all logs".
//
// The cache pepper already has this test. The session secret is strictly worse
// to leak: the pepper protects cached decisions, while the signing secret lets
// anyone who reads a journal mint a cookie for any user in any group.
func TestSessionSecretNeverReachesTheLog(t *testing.T) {
	ts := sessionServer(t, sessionConfig())

	resp := login(t, ts, "alice", "s3cret", "/")
	defer resp.Body.Close()

	if rec := authWith(t, ts, resp); rec.Code != http.StatusOK {
		t.Fatalf("GET /auth = %d, want 200", rec.Code)
	}

	logs := ts.logs.String()

	if strings.Contains(logs, testSessionSecret) {
		t.Error("the session signing secret was written to the log")
	}

	if strings.Contains(logs, "s3cret") {
		t.Error("the password was written to the log")
	}

	// The cookie value is not a credential, but it is a bearer token: a
	// journal reader holding one is logged in as that user until it
	// expires.
	if cookie := cookieNamed(resp, "nginx_ldap_auth"); cookie != nil && strings.Contains(logs, cookie.Value) {
		t.Error("the session cookie value was written to the log")
	}
}

// project.md §4a: "A cookie is valid only for the policy it was issued for ...
// a session for the intranet must not open the monitoring UI."
//
// The second policy here admits any authenticated user, so it would have let
// alice in had she logged in against it. That is what makes this a test of the
// binding rather than of policy resolution: the refusal can only come from the
// name in the cookie.
func TestSessionDoesNotOpenAnotherPolicy(t *testing.T) {
	ts := newTestServer(t, testOptions{
		directory:  directoryFor(aliceIn("web-users")),
		sessionCfg: sessionConfig(),
		alsoPolicy: "monitoring",
	})

	resp := login(t, ts, "alice", "s3cret", "/")
	defer resp.Body.Close()

	request := httptest.NewRequest(http.MethodGet, PathAuth, nil)
	request.Header.Set(policy.Header, "monitoring")

	for _, cookie := range resp.Cookies() {
		request.AddCookie(cookie)
	}

	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, request)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("an intranet session opened the monitoring policy: /auth = %d, want 401", rec.Code)
	}

	if got := rec.Header().Get(HeaderUser); got != "" {
		t.Errorf("%s = %q; the identity of a foreign session reached the upstream headers", HeaderUser, got)
	}

	if !strings.Contains(ts.logs.String(), "session_policy_mismatch") {
		t.Errorf("the log does not name the mismatch:\n%s", ts.logs.String())
	}
}

// project.md §12: "do not count a failed CSRF check against the throttle — the
// credentials were never evaluated."
//
// If it failed, a stale form in one user's browser — or any page on the
// internet posting to the login endpoint — would lock that account out of the
// site for the block duration, without ever guessing a password.
func TestCSRFFailureDoesNotLockTheAccountOut(t *testing.T) {
	throttle, err := ratelimit.New(ratelimit.Config{
		Window:                time.Minute,
		BlockDuration:         time.Minute,
		MaxFailuresPerUser:    2,
		MaxFailuresPerAddress: 100,
		MaxEntries:            64,
	})
	if err != nil {
		t.Fatalf("ratelimit.New: %v", err)
	}

	ts := newTestServer(t, testOptions{
		directory:  directoryFor(aliceIn("web-users")),
		throttle:   throttle,
		sessionCfg: sessionConfig(),
	})

	// Five submissions carrying alice's name and no valid token.
	for range 5 {
		values := url.Values{"username": {"alice"}, "password": {"s3cret"}, "next": {"/"}}

		request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(values.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rec := httptest.NewRecorder()
		ts.handler.ServeHTTP(rec, request)
	}

	// The real user now logs in. If the CSRF failures were counted, this is
	// a 429 instead.
	resp := login(t, ts, "alice", "s3cret", "/")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("login after five CSRF failures = %d, want 303; the account was locked out by requests "+
			"that never reached the directory\n%s", resp.StatusCode, body)
	}
}

// project.md §9: a failed login "re-renders the form with the status the
// decision produced — 401, 403, 429 or 502".
//
// Only the 401 was covered. The other three are what a monitoring system sees:
// collapsing "not in the group", "throttled" and "the directory is down" into
// one status makes the difference between a user error and an outage invisible
// from outside the process.
func TestLoginFailureStatusMatchesTheDecision(t *testing.T) {
	t.Run("not authorized is 403", func(t *testing.T) {
		ts := newTestServer(t, testOptions{
			// carol authenticates but holds no group.
			directory: stubDirectory{
				user:     "carol",
				password: "c4rol",
				identity: &ldap.Identity{User: "carol"},
				calls:    &atomic.Int64{},
			},
			requireGrp: []string{"web-users"},
			sessionCfg: sessionConfig(),
		})

		resp := login(t, ts, "carol", "c4rol", "/")
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("login without the required group = %d, want 403", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), messageNotAuthorized) {
			t.Error("the form does not say the account is not permitted")
		}

		if cookie := cookieNamed(resp, "nginx_ldap_auth"); cookie != nil && cookie.Value != "" {
			t.Fatal("an unauthorized login issued a session cookie")
		}
	})

	t.Run("throttled is 429 with Retry-After", func(t *testing.T) {
		throttle, err := ratelimit.New(ratelimit.Config{
			Window:                time.Minute,
			BlockDuration:         5 * time.Minute,
			MaxFailuresPerUser:    1,
			MaxFailuresPerAddress: 100,
			MaxEntries:            64,
		})
		if err != nil {
			t.Fatalf("ratelimit.New: %v", err)
		}

		ts := newTestServer(t, testOptions{
			directory:  directoryFor(aliceIn("web-users")),
			throttle:   throttle,
			sessionCfg: sessionConfig(),
		})

		first := login(t, ts, "alice", "wrong", "/")
		first.Body.Close()

		second := login(t, ts, "alice", "wrong", "/")
		defer second.Body.Close()

		if second.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("second failed login = %d, want 429", second.StatusCode)
		}

		// Without it the browser has no idea when to come back, and a
		// user hammering the form keeps their own block alive.
		if second.Header.Get("Retry-After") == "" {
			t.Error("the throttled response carries no Retry-After header")
		}
	})

	t.Run("directory outage is 502", func(t *testing.T) {
		ts := newTestServer(t, testOptions{
			directory: stubDirectory{
				user:     "alice",
				password: "s3cret",
				err:      errors.New("dial tcp 127.0.0.1:3893: connect: connection refused"),
				calls:    &atomic.Int64{},
			},
			sessionCfg: sessionConfig(),
		})

		resp := login(t, ts, "alice", "s3cret", "/")
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("login during a directory outage = %d, want 502", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(body), "connection refused") {
			t.Error("the directory's error reached the page; it belongs in the log only")
		}
	})
}

// README: a session is answered "without touching the throttle, the cache or
// the directory".
//
// That is not only a performance claim. It is what keeps people working
// through an LDAP outage instead of every page turning into a login form the
// directory cannot answer — the failure this whole service is shaped to avoid.
func TestSessionSurvivesADirectoryOutage(t *testing.T) {
	directory := &failableDirectory{stub: directoryFor(aliceIn("web-users"))}

	ts := newTestServer(t, testOptions{directory: directory, sessionCfg: sessionConfig()})

	resp := login(t, ts, "alice", "s3cret", "/")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login = %d, want 303", resp.StatusCode)
	}

	// The directory goes down after the login, which is when an outage
	// actually happens.
	directory.fail.Store(true)

	rec := authWith(t, ts, resp)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /auth during a directory outage = %d, want 200; the session should not need it", rec.Code)
	}

	if got := rec.Header().Get(HeaderUser); got != "alice" {
		t.Errorf("%s = %q, want alice", HeaderUser, got)
	}
}

// failableDirectory is a directory that can be taken down mid-test.
//
// Provoking the outage rather than constructing a server that never had a
// working directory is the point: the session has to survive a directory that
// worked at login time and stopped afterwards.
type failableDirectory struct {
	stub stubDirectory
	fail atomic.Bool
}

func (d *failableDirectory) Authenticate(ctx context.Context, user, password string) (*ldap.Identity, error) {
	if d.fail.Load() {
		return nil, errors.New("dial tcp 127.0.0.1:3893: connect: connection refused")
	}

	return d.stub.Authenticate(ctx, user, password)
}

func (d *failableDirectory) Name() string { return "failable" }

// project.md §4a: the cookie "is re-issued once its last-seen stamp is older
// than refresh_interval" — not on every request.
//
// nginx makes one auth subrequest per HTTP request. A Set-Cookie on each one
// means a header on every image on every page, and nginx has to copy each of
// them out of the subrequest: the cost is paid per asset, forever.
func TestSlidingRefreshDoesNotSetACookieOnEveryRequest(t *testing.T) {
	ts := sessionServer(t, sessionConfig())

	resp := login(t, ts, "alice", "s3cret", "/")
	defer resp.Body.Close()

	refreshed := 0

	for range 20 {
		rec := authWith(t, ts, resp)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /auth = %d, want 200", rec.Code)
		}

		if rec.Header().Get("Set-Cookie") != "" {
			refreshed++
		}
	}

	if refreshed != 0 {
		t.Errorf("%d of 20 requests re-issued the cookie inside the 5 minute refresh interval", refreshed)
	}
}

// project.md §4a: "The page must be self-contained — no external stylesheet,
// script, font or image."
//
// A login page that pulls an asset from a CDN is a login page that hangs, or
// renders unusably, exactly when the network is the thing that is broken —
// while the application behind it is up and waiting.
func TestLoginPageFetchesNothing(t *testing.T) {
	ts := sessionServer(t, sessionConfig())

	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))

	body := rec.Body.String()

	for _, forbidden := range []string{"http://", "https://", "//fonts.", "<script", "<img", "<link"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Errorf("the built-in login page contains %q, so it depends on something it does not carry", forbidden)
		}
	}
}

// project.md §4a: "Failure messages must not distinguish 'no such user' from
// 'wrong password'."
//
// A form that does is a username oracle: it confirms which accounts exist to
// anyone who can load the page, which is the first step of every credential
// stuffing run.
func TestLoginDoesNotRevealWhichAccountsExist(t *testing.T) {
	ts := sessionServer(t, sessionConfig())

	wrongPassword := login(t, ts, "alice", "definitely-wrong", "/")
	defer wrongPassword.Body.Close()

	noSuchUser := login(t, ts, "nobody-here", "definitely-wrong", "/")
	defer noSuchUser.Body.Close()

	if wrongPassword.StatusCode != noSuchUser.StatusCode {
		t.Errorf("status differs: wrong password = %d, unknown user = %d",
			wrongPassword.StatusCode, noSuchUser.StatusCode)
	}

	first, _ := io.ReadAll(wrongPassword.Body)
	second, _ := io.ReadAll(noSuchUser.Body)

	// The pages differ only where the form echoes the submitted username
	// back, so the comparison is on the message rather than the document.
	if messageIn(string(first)) != messageIn(string(second)) {
		t.Errorf("message differs: wrong password says %q, unknown user says %q",
			messageIn(string(first)), messageIn(string(second)))
	}
}

// messageIn extracts the error paragraph from a rendered form.
func messageIn(body string) string {
	const marker = `role="alert">`

	start := strings.Index(body, marker)
	if start < 0 {
		return ""
	}

	rest := body[start+len(marker):]

	end := strings.Index(rest, "<")
	if end < 0 {
		return rest
	}

	return rest[:end]
}

// The login endpoint is a trust boundary: anyone who can reach the site can
// post to it. maxLoginBodyBytes is the bound, and a bound nobody tests is a
// bound that gets removed by a refactor.
func TestLoginRejectsAnOversizedBody(t *testing.T) {
	directory := directoryFor(aliceIn("web-users"))
	ts := newTestServer(t, testOptions{directory: directory, sessionCfg: sessionConfig()})

	// A valid form, and a valid token, so that the only thing wrong with
	// the submission is its size. An earlier version of this test sent a
	// junk token and passed for the wrong reason: it was measuring the CSRF
	// check, and removing the body limit entirely left it green.
	form := httptest.NewRecorder()
	ts.handler.ServeHTTP(form, httptest.NewRequest(http.MethodGet, "/login", nil))

	token := csrfTokenFrom(t, form.Body.String())

	values := url.Values{
		"username":   {"alice"},
		"password":   {"s3cret"},
		"csrf_token": {token},
		"next":       {"/"},

		// The oversized part. A browser never sends this; a script does.
		"padding": {strings.Repeat("A", 64<<10)},
	}

	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	for _, cookie := range form.Result().Cookies() {
		request.AddCookie(cookie)
	}

	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, request)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST /login with a 64 KiB body = %d, want 400", rec.Code)
	}

	// The credentials in that body were correct. Reaching the directory
	// would mean the bound is decorative: an attacker could pay one LDAP
	// bind per megabyte they choose to upload.
	if calls := directory.calls.Load(); calls != 0 {
		t.Errorf("directory was consulted %d times for an oversized body, want 0", calls)
	}

	if cookie := cookieNamed(rec.Result(), "nginx_ldap_auth"); cookie != nil && cookie.Value != "" {
		t.Error("an oversized submission issued a session")
	}
}

// safeNext is unit-tested, but the handler is where it has to be applied. A
// redirect target that reaches the Location header unfiltered is an open
// redirect on the page that takes a password — the one page where a
// look-alike is worth building.
func TestLoginRedirectStaysOnTheSite(t *testing.T) {
	ts := sessionServer(t, sessionConfig())

	for _, target := range []string{
		"https://evil.example.org/harvest",
		"//evil.example.org/harvest",
		"/\\evil.example.org",
	} {
		resp := login(t, ts, "alice", "s3cret", target)

		location := resp.Header.Get("Location")
		resp.Body.Close()

		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("login with next=%q = %d, want 303", target, resp.StatusCode)
		}

		if location != "/" {
			t.Errorf("next=%q redirected to %q, want /", target, location)
		}
	}
}

// project.md §9: logout accepts "GET ... alongside POST".
//
// An application embedding a logout button posts it; a link gets it. Only one
// of the two was covered, and the one that was not is the one a form-based
// application uses.
func TestLogoutAcceptsPost(t *testing.T) {
	ts := sessionServer(t, sessionConfig())

	resp := login(t, ts, "alice", "s3cret", "/")
	defer resp.Body.Close()

	request := httptest.NewRequest(http.MethodPost, "/logout", nil)
	for _, cookie := range resp.Cookies() {
		request.AddCookie(cookie)
	}

	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, request)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /logout = %d, want 303", rec.Code)
	}

	cleared := cookieNamed(rec.Result(), "nginx_ldap_auth")
	if cleared == nil || cleared.Value != "" {
		t.Fatal("POST /logout did not clear the session cookie")
	}
}

// An unsupported method has to say so, and say what is allowed. Answering a
// PUT with the login form would make a misrouted request look like a working
// endpoint.
func TestLoginRejectsOtherMethods(t *testing.T) {
	ts := sessionServer(t, sessionConfig())

	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		rec := httptest.NewRecorder()
		ts.handler.ServeHTTP(rec, httptest.NewRequest(method, "/login", nil))

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /login = %d, want 405", method, rec.Code)
		}

		if allow := rec.Header().Get("Allow"); allow == "" {
			t.Errorf("%s /login carries no Allow header", method)
		}
	}
}

// A template that does not parse must stop the process, not wait to fail at
// the first login of the day — which is typically 08:00 on a Monday, with
// nobody able to reach the site and nothing in the journal from the restart
// that introduced it.
func TestBrokenLoginTemplateRefusesToStart(t *testing.T) {
	cfg := sessionConfig()
	cfg.LoginTemplateSource = []byte(`<form>{{if .Realm}}no end tag`)

	if _, err := NewSessions(*cfg); err == nil {
		t.Fatal("NewSessions accepted a template that does not parse")
	}
}

// A valid signature over a payload that is missing fields is what a format
// change looks like in a rolling restart, or a truncated write into a shared
// store. The decision must be refused rather than built from zero values —
// project.md §12's "a decision nobody set must deny" applies to a session as
// much as to a cached decision.
func TestSessionWithAnIncompletePayloadIsRefused(t *testing.T) {
	ts := sessionServer(t, sessionConfig())

	signer, err := session.NewSigner([]byte(testSessionSecret))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	// Signed by this service, current, and naming the right policy — so
	// every other check passes and the missing username is the only thing
	// left to refuse it. An earlier version left the policy empty, which
	// meant the policy comparison rejected it and the payload check was
	// never exercised: removing that check entirely left the test green.
	//
	// Without the check the session authorizes with an empty user, and the
	// application behind nginx receives a request with no identity at all.
	value, err := signer.Encode(session.Session{
		Policy:   "intranet",
		Groups:   []string{"web-users"},
		IssuedAt: time.Now(),
		SeenAt:   time.Now(),
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, PathAuth, nil)
	request.AddCookie(&http.Cookie{Name: "nginx_ldap_auth", Value: value})

	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, request)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /auth with an empty but validly signed session = %d, want 401", rec.Code)
	}

	if got := rec.Header().Get(HeaderUser); got != "" {
		t.Errorf("%s = %q, want no identity at all", HeaderUser, got)
	}
}
