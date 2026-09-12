package server

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"bodsch.me/nginx-ldap-auth/internal/config"
	"bodsch.me/nginx-ldap-auth/internal/policy"
	"bodsch.me/nginx-ldap-auth/internal/session"
)

// testSessionSecret is the documented `openssl rand -hex 32` shape.
const testSessionSecret = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

// sessionConfig returns a session configuration with the defaults the
// documentation promises, so a test that changes one of them says so.
func sessionConfig() *config.Session {
	secure := false // httptest speaks plain HTTP; a Secure cookie would never come back.

	return &config.Session{
		Enabled:         true,
		CookieName:      "nginx_ldap_auth",
		Secret:          []byte(testSessionSecret),
		AbsoluteTimeout: config.Duration(8 * time.Hour),
		IdleTimeout:     config.Duration(30 * time.Minute),
		RefreshInterval: config.Duration(5 * time.Minute),
		CookiePath:      "/",
		Secure:          &secure,
		SameSite:        "lax",
		LoginPath:       "/login",
		LogoutPath:      "/logout",
		AllowBasic:      true,
	}
}

// sessionServer is a server with the login form enabled and a directory that
// accepts alice.
func sessionServer(t *testing.T, cfg *config.Session) *testServer {
	t.Helper()

	return newTestServer(t, testOptions{
		directory:  directoryFor(aliceIn("web-users")),
		sessionCfg: cfg,
	})
}

// login drives the whole browser flow: fetch the form, submit it, and return
// the response to the submission along with the cookies it set.
func login(t *testing.T, ts *testServer, username, password, next string) *http.Response {
	t.Helper()

	target := "/login"
	if next != "" {
		target += "?next=" + url.QueryEscape(next)
	}

	form := httptest.NewRecorder()
	ts.handler.ServeHTTP(form, httptest.NewRequest(http.MethodGet, target, nil))

	if form.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", target, form.Code)
	}

	token := csrfTokenFrom(t, form.Body.String())

	values := url.Values{
		"username":   {username},
		"password":   {password},
		"csrf_token": {token},
		"next":       {next},
	}

	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	for _, cookie := range form.Result().Cookies() {
		request.AddCookie(cookie)
	}

	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, request)

	return rec.Result()
}

// csrfTokenFrom pulls the hidden field out of the rendered form.
func csrfTokenFrom(t *testing.T, body string) string {
	t.Helper()

	const marker = `name="csrf_token" value="`

	start := strings.Index(body, marker)
	if start < 0 {
		t.Fatal("rendered login form carries no CSRF token")
	}

	rest := body[start+len(marker):]

	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatal("CSRF token field is unterminated")
	}

	return rest[:end]
}

// cookieNamed returns the named cookie from a response.
func cookieNamed(resp *http.Response, name string) *http.Cookie {
	for _, cookie := range resp.Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}

	return nil
}

// authWith issues an /auth subrequest carrying the cookies of a response.
func authWith(t *testing.T, ts *testServer, resp *http.Response) *httptest.ResponseRecorder {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, PathAuth, nil)
	for _, cookie := range resp.Cookies() {
		request.AddCookie(cookie)
	}

	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, request)

	return rec
}

// The end-to-end path: a login produces a cookie, and that cookie is what makes
// the next /auth subrequest succeed without any credentials at all.
func TestLoginIssuesASessionThatAuthorizes(t *testing.T) {
	ts := sessionServer(t, sessionConfig())

	resp := login(t, ts, "alice", "s3cret", "/reports/q3")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /login = %d, want 303\n%s", resp.StatusCode, body)
	}

	if location := resp.Header.Get("Location"); location != "/reports/q3" {
		t.Errorf("Location = %q, want /reports/q3", location)
	}

	cookie := cookieNamed(resp, "nginx_ldap_auth")
	if cookie == nil {
		t.Fatal("no session cookie was set")
	}

	if !cookie.HttpOnly {
		t.Error("session cookie is not HttpOnly")
	}

	rec := authWith(t, ts, resp)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /auth with the session cookie = %d, want 200", rec.Code)
	}

	if got := rec.Header().Get(HeaderUser); got != "alice" {
		t.Errorf("%s = %q, want alice", HeaderUser, got)
	}

	if got := rec.Header().Get(HeaderGroups); got != "web-users" {
		t.Errorf("%s = %q, want web-users", HeaderGroups, got)
	}
}

// A session must not cost a directory lookup per request; that is the entire
// reason it exists.
func TestSessionDoesNotConsultTheDirectory(t *testing.T) {
	directory := directoryFor(aliceIn("web-users"))

	ts := newTestServer(t, testOptions{directory: directory, sessionCfg: sessionConfig()})

	resp := login(t, ts, "alice", "s3cret", "/")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST /login = %d, want 303", resp.StatusCode)
	}

	after := directory.calls.Load()

	for range 10 {
		if rec := authWith(t, ts, resp); rec.Code != http.StatusOK {
			t.Fatalf("GET /auth = %d, want 200", rec.Code)
		}
	}

	if calls := directory.calls.Load(); calls != after {
		t.Errorf("directory was consulted %d times for session-authorized requests, want 0", calls-after)
	}
}

// Wrong credentials must not produce a session, and must not tell the visitor
// whether the account exists.
func TestLoginRejectsWrongCredentials(t *testing.T) {
	ts := sessionServer(t, sessionConfig())

	resp := login(t, ts, "alice", "wrong", "/")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST /login = %d, want 401", resp.StatusCode)
	}

	if cookie := cookieNamed(resp, "nginx_ldap_auth"); cookie != nil && cookie.Value != "" {
		t.Fatal("a failed login issued a session cookie")
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), messageInvalidCredentials) {
		t.Errorf("body does not carry the failure message:\n%s", body)
	}

	if strings.Contains(strings.ToLower(string(body)), "wrong") &&
		strings.Contains(string(body), "s3cret") {
		t.Error("the submitted password was reflected into the page")
	}
}

// A submission without the token is what a cross-site forgery looks like, and
// it must never reach the directory.
func TestLoginRequiresTheCSRFToken(t *testing.T) {
	directory := directoryFor(aliceIn("web-users"))
	ts := newTestServer(t, testOptions{directory: directory, sessionCfg: sessionConfig()})

	values := url.Values{"username": {"alice"}, "password": {"s3cret"}, "next": {"/"}}

	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, request)

	if rec.Code != http.StatusBadRequest && rec.Code != http.StatusForbidden {
		t.Fatalf("POST /login without a token = %d, want 400 or 403", rec.Code)
	}

	if cookie := cookieNamed(rec.Result(), "nginx_ldap_auth"); cookie != nil && cookie.Value != "" {
		t.Fatal("a submission without a CSRF token issued a session")
	}

	if calls := directory.calls.Load(); calls != 0 {
		t.Errorf("directory was consulted %d times for a request that failed the CSRF check, want 0", calls)
	}
}

// An expired session has to be refused. Both timeouts are exercised through a
// cookie this test signs itself: the real ones are measured in minutes and
// hours, and a test that sleeps through them is a test nobody runs.
func TestAuthRefusesExpiredSessions(t *testing.T) {
	ts := sessionServer(t, sessionConfig())

	signer, err := session.NewSigner([]byte(testSessionSecret))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	now := time.Now()

	for name, tc := range map[string]struct {
		issued time.Time
		seen   time.Time
		reason string
	}{
		"idle for longer than the idle timeout": {
			issued: now.Add(-time.Hour),
			seen:   now.Add(-31 * time.Minute),
			reason: "session_expired_idle",
		},
		"in constant use past the absolute timeout": {
			issued: now.Add(-9 * time.Hour),
			seen:   now.Add(-time.Second),
			reason: "session_expired_absolute",
		},
	} {
		t.Run(name, func(t *testing.T) {
			value, err := signer.Encode(session.Session{
				User:     "alice",
				Policy:   "intranet",
				Groups:   []string{"web-users"},
				IssuedAt: tc.issued,
				SeenAt:   tc.seen,
			})
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}

			ts.logs.Reset()

			request := httptest.NewRequest(http.MethodGet, PathAuth, nil)
			request.AddCookie(&http.Cookie{Name: "nginx_ldap_auth", Value: value})

			rec := httptest.NewRecorder()
			ts.handler.ServeHTTP(rec, request)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("GET /auth = %d, want 401", rec.Code)
			}

			if !strings.Contains(ts.logs.String(), tc.reason) {
				t.Errorf("the log does not say %q:\n%s", tc.reason, ts.logs.String())
			}
		})
	}
}

// A cookie signed with another secret must be refused and must be visible in
// the log as what it is.
func TestAuthRefusesAForgedSession(t *testing.T) {
	ts := sessionServer(t, sessionConfig())

	other, err := session.NewSigner([]byte(strings.Repeat("a", 64)))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	now := time.Now()

	value, err := other.Encode(session.Session{
		User:     "root",
		Policy:   "intranet",
		Groups:   []string{"web-users"},
		IssuedAt: now,
		SeenAt:   now,
	})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, PathAuth, nil)
	request.AddCookie(&http.Cookie{Name: "nginx_ldap_auth", Value: value})

	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, request)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /auth with a foreign signature = %d, want 401", rec.Code)
	}

	if rec.Header().Get(HeaderUser) != "" {
		t.Error("a forged cookie reached the identity headers")
	}

	if !strings.Contains(ts.logs.String(), "session_forged") {
		t.Errorf("the log does not report a forged session:\n%s", ts.logs.String())
	}
}

// The browser must not be challenged while a login form exists, or it opens its
// own password dialog and caches the credentials until it is closed — the
// original problem.
func TestAuthDoesNotChallengeWhileSessionsAreEnabled(t *testing.T) {
	ts := sessionServer(t, sessionConfig())

	request := httptest.NewRequest(http.MethodGet, PathAuth, nil)
	request.Header.Set(HeaderOriginalURI, "/reports/q3")

	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, request)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /auth without credentials = %d, want 401", rec.Code)
	}

	if challenge := rec.Header().Get("WWW-Authenticate"); challenge != "" {
		t.Errorf("WWW-Authenticate = %q, want no challenge while the login form is enabled", challenge)
	}

	want := "/login?next=" + url.QueryEscape("/reports/q3")
	if got := rec.Header().Get(HeaderLoginURL); got != want {
		t.Errorf("%s = %q, want %q", HeaderLoginURL, got, want)
	}
}

// Basic Authentication has to keep working for the clients that cannot hold a
// cookie, without being advertised to browsers.
func TestBasicStillWorksAlongsideSessions(t *testing.T) {
	ts := sessionServer(t, sessionConfig())

	request := httptest.NewRequest(http.MethodGet, PathAuth, nil)
	request.Header.Set("Authorization", basicHeader("alice", "s3cret"))

	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, request)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /auth with Basic credentials = %d, want 200", rec.Code)
	}

	if got := rec.Header().Get(HeaderUser); got != "alice" {
		t.Errorf("%s = %q, want alice", HeaderUser, got)
	}
}

func TestBasicCanBeTurnedOff(t *testing.T) {
	cfg := sessionConfig()
	cfg.AllowBasic = false

	directory := directoryFor(aliceIn("web-users"))
	ts := newTestServer(t, testOptions{directory: directory, sessionCfg: cfg})

	request := httptest.NewRequest(http.MethodGet, PathAuth, nil)
	request.Header.Set("Authorization", basicHeader("alice", "s3cret"))

	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, request)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /auth with Basic credentials = %d, want 401", rec.Code)
	}

	if calls := directory.calls.Load(); calls != 0 {
		t.Errorf("directory was consulted %d times while Basic is disabled, want 0", calls)
	}
}

// An nginx location naming a policy that does not exist is refused, session or
// no session. The name says what this measures: policy resolution, not the
// cookie's binding — a session for one *configured* policy against another is
// TestSessionDoesNotOpenAnotherPolicy, which is the harder and more useful
// case.
func TestAuthRefusesAnUnknownPolicyEvenWithASession(t *testing.T) {
	ts := sessionServer(t, sessionConfig())

	resp := login(t, ts, "alice", "s3cret", "/")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST /login = %d, want 303", resp.StatusCode)
	}

	request := httptest.NewRequest(http.MethodGet, PathAuth, nil)
	request.Header.Set(policy.Header, "does-not-exist")

	for _, cookie := range resp.Cookies() {
		request.AddCookie(cookie)
	}

	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, request)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET /auth for an unknown policy = %d, want 403", rec.Code)
	}
}

// Logging out has to end the session, and the cleared cookie has to match the
// one that was set, or the browser keeps the original.
func TestLogoutEndsTheSession(t *testing.T) {
	ts := sessionServer(t, sessionConfig())

	resp := login(t, ts, "alice", "s3cret", "/")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST /login = %d, want 303", resp.StatusCode)
	}

	request := httptest.NewRequest(http.MethodGet, "/logout", nil)
	for _, cookie := range resp.Cookies() {
		request.AddCookie(cookie)
	}

	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, request)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("GET /logout = %d, want 303", rec.Code)
	}

	if location := rec.Header().Get("Location"); location != "/login" {
		t.Errorf("Location = %q, want /login", location)
	}

	cleared := cookieNamed(rec.Result(), "nginx_ldap_auth")
	if cleared == nil {
		t.Fatal("logout did not clear the session cookie")
	}

	issued := cookieNamed(resp, "nginx_ldap_auth")

	if cleared.Value != "" || cleared.MaxAge >= 0 {
		t.Errorf("cleared cookie = %q with MaxAge %d, want empty with a negative MaxAge",
			cleared.Value, cleared.MaxAge)
	}

	if cleared.Path != issued.Path {
		t.Errorf("cleared cookie path %q does not match the issued %q, so the browser keeps both",
			cleared.Path, issued.Path)
	}

	// The cleared response is what the browser now holds: no session.
	if rec := authWith(t, ts, rec.Result()); rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /auth after logout = %d, want 401", rec.Code)
	}
}

// The redirect target comes from a query parameter, so it is client-controlled.
// Following it unchecked turns the login page into an open redirect.
func TestSafeNextRefusesToLeaveTheSite(t *testing.T) {
	for value, want := range map[string]string{
		"":                         "/",
		"/reports":                 "/reports",
		"/reports?page=2":          "/reports?page=2",
		"//evil.example.org":       "/",
		"/\\evil.example.org":      "/",
		"https://evil.example.org": "/",
		"javascript:alert(1)":      "/",
		"/ok\nSet-Cookie: a=b":     "/",
	} {
		if got := safeNext(value); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", value, got, want)
		}
	}
}

// Somebody who already has a session must not be shown a form that starts a
// second one.
func TestLoginFormRedirectsAnActiveSession(t *testing.T) {
	ts := sessionServer(t, sessionConfig())

	resp := login(t, ts, "alice", "s3cret", "/")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST /login = %d, want 303", resp.StatusCode)
	}

	request := httptest.NewRequest(http.MethodGet, "/login?next=/dashboard", nil)
	for _, cookie := range resp.Cookies() {
		request.AddCookie(cookie)
	}

	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, request)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("GET /login with a session = %d, want 303", rec.Code)
	}

	if location := rec.Header().Get("Location"); location != "/dashboard" {
		t.Errorf("Location = %q, want /dashboard", location)
	}
}

// The login page takes a password, so it must not be cached, framed, or allowed
// to load anything from anywhere.
func TestLoginPageHeaders(t *testing.T) {
	ts := sessionServer(t, sessionConfig())

	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))

	for header, want := range map[string]string{
		"Cache-Control":          "no-store",
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}

	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self'") {
		t.Errorf("Content-Security-Policy = %q, want it to restrict form-action", csp)
	}
}

// Sessions are off unless configured, and the service then behaves exactly as
// it did before: a Basic challenge, and no login endpoints at all.
func TestSessionsDisabledKeepsTheChallenge(t *testing.T) {
	ts := newTestServer(t, testOptions{
		directory: directoryFor(aliceIn("web-users")),
	})

	rec := httptest.NewRecorder()
	ts.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, PathAuth, nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /auth = %d, want 401", rec.Code)
	}

	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("no challenge was sent while sessions are disabled")
	}

	form := httptest.NewRecorder()
	ts.handler.ServeHTTP(form, httptest.NewRequest(http.MethodGet, "/login", nil))

	if form.Code != http.StatusNotFound {
		t.Errorf("GET /login = %d, want 404 while sessions are disabled", form.Code)
	}
}

// basicHeader renders credentials the way a client that cannot hold a cookie
// sends them.
func basicHeader(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}
