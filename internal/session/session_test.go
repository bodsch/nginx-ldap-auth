package session

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testSecret is 64 hex characters, which is what the documented
// `openssl rand -hex 32` produces.
const testSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func testConfig() Config {
	return Config{
		CookieName:      "nginx_ldap_auth",
		AbsoluteTimeout: 8 * time.Hour,
		IdleTimeout:     30 * time.Minute,
		RefreshInterval: 5 * time.Minute,
		Path:            "/",
		Secure:          true,
		SameSite:        http.SameSiteLaxMode,
	}
}

// newTestManager returns a manager whose clock the test controls.
func newTestManager(t *testing.T, cfg Config, now *time.Time) *Manager {
	t.Helper()

	manager, err := NewManager([]byte(testSecret), cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	if now != nil {
		manager.now = func() time.Time { return *now }
	}

	return manager
}

// requestWithCookie builds a request carrying the cookie the recorder was
// given, which is how a browser's next request is modelled here.
func requestWithCookie(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Request {
	t.Helper()

	r := httptest.NewRequest(http.MethodGet, "/auth", nil)

	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == name {
			r.AddCookie(cookie)
		}
	}

	return r
}

func TestSignerRoundTrip(t *testing.T) {
	signer, err := NewSigner([]byte(testSecret))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	issued := time.Now().Truncate(time.Second)

	want := Session{
		User:     "alice",
		Policy:   "intranet",
		Groups:   []string{"web-users", "ops"},
		IssuedAt: issued,
		SeenAt:   issued.Add(time.Minute),
	}

	value, err := signer.Encode(want)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	got, err := signer.Decode(value)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if got.User != want.User || got.Policy != want.Policy {
		t.Errorf("identity = %q/%q, want %q/%q", got.User, got.Policy, want.User, want.Policy)
	}

	if strings.Join(got.Groups, ",") != strings.Join(want.Groups, ",") {
		t.Errorf("groups = %v, want %v", got.Groups, want.Groups)
	}

	if !got.IssuedAt.Equal(want.IssuedAt) || !got.SeenAt.Equal(want.SeenAt) {
		t.Errorf("timestamps = %v/%v, want %v/%v", got.IssuedAt, got.SeenAt, want.IssuedAt, want.SeenAt)
	}
}

// A cookie whose payload was edited must not be accepted, whatever it now
// claims. This is the whole security property of a stateless session.
func TestSignerRejectsTamperedPayload(t *testing.T) {
	signer, _ := NewSigner([]byte(testSecret))

	now := time.Now()

	value, err := signer.Encode(Session{User: "alice", Policy: "intranet", IssuedAt: now, SeenAt: now})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		t.Fatalf("value has %d segments, want 3", len(parts))
	}

	// Re-encode the payload with a different user, keeping the original
	// signature — the forgery an attacker who can read a cookie would try.
	forged, err := signer.Encode(Session{User: "root", Policy: "intranet", IssuedAt: now, SeenAt: now})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	forgedParts := strings.Split(forged, ".")

	for name, candidate := range map[string]string{
		"swapped payload":  parts[0] + "." + forgedParts[1] + "." + parts[2],
		"truncated":        parts[0] + "." + parts[1],
		"empty signature":  parts[0] + "." + parts[1] + ".",
		"flipped version":  "2." + parts[1] + "." + parts[2],
		"garbage":          "not-a-cookie",
		"padding stripped": parts[0] + "." + parts[1][:len(parts[1])-1] + "." + parts[2],
	} {
		if _, err := signer.Decode(candidate); err == nil {
			t.Errorf("%s: Decode accepted a value it must reject", name)
		}
	}
}

// A signature made with another secret must not verify: this is what stops a
// second deployment, or an old backup of the secret file, from being able to
// mint sessions for this one.
func TestSignerRejectsForeignSecret(t *testing.T) {
	mine, _ := NewSigner([]byte(testSecret))
	theirs, _ := NewSigner([]byte(strings.Repeat("f", 64)))

	now := time.Now()

	value, err := theirs.Encode(Session{User: "alice", Policy: "intranet", IssuedAt: now, SeenAt: now})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	if _, err := mine.Decode(value); !errors.Is(err, ErrSignature) {
		t.Fatalf("Decode error = %v, want ErrSignature", err)
	}
}

func TestNewSignerRejectsShortSecret(t *testing.T) {
	if _, err := NewSigner([]byte("too short")); err == nil {
		t.Fatal("NewSigner accepted a 9 byte secret")
	}
}

// The idle window is what ends a session that is not being used. This is the
// behaviour the whole feature was asked for.
func TestLoadExpiresOnIdle(t *testing.T) {
	now := time.Now()
	manager := newTestManager(t, testConfig(), &now)

	rec := httptest.NewRecorder()
	if _, err := manager.Issue(rec, "alice", "intranet", []string{"web-users"}); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	request := requestWithCookie(t, rec, manager.CookieName())

	// One second before the idle timeout the session is still good.
	now = now.Add(30*time.Minute - time.Second)

	if _, err := manager.Load(request, "intranet"); err != nil {
		t.Fatalf("Load just inside the idle window: %v", err)
	}

	now = now.Add(2 * time.Second)

	if _, err := manager.Load(request, "intranet"); !errors.Is(err, ErrExpiredIdle) {
		t.Fatalf("Load error = %v, want ErrExpiredIdle", err)
	}
}

// The absolute lifetime must not be extendable by using the session, or a
// browser left open would never be logged out.
func TestLoadExpiresAbsolutelyDespiteRefreshes(t *testing.T) {
	now := time.Now()
	manager := newTestManager(t, testConfig(), &now)

	rec := httptest.NewRecorder()
	if _, err := manager.Issue(rec, "alice", "intranet", nil); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	request := requestWithCookie(t, rec, manager.CookieName())

	// Use it every ten minutes for nine hours, which is what an open tab
	// polling an application looks like.
	for elapsed := time.Duration(0); elapsed < 9*time.Hour; elapsed += 10 * time.Minute {
		now = now.Add(10 * time.Minute)

		sess, err := manager.Load(request, "intranet")
		if err != nil {
			if elapsed < 8*time.Hour-10*time.Minute {
				t.Fatalf("session ended after %s: %v", elapsed, err)
			}

			if !errors.Is(err, ErrExpiredAbsolute) {
				t.Fatalf("Load error after %s = %v, want ErrExpiredAbsolute", elapsed, err)
			}

			return
		}

		refreshed := httptest.NewRecorder()
		if _, ok := manager.Refresh(refreshed, sess); ok {
			request = requestWithCookie(t, refreshed, manager.CookieName())
		}
	}

	t.Fatal("session survived nine hours of continuous use with an eight hour absolute timeout")
}

// A cookie issued for one application must not open another one served by the
// same instance.
func TestLoadRejectsForeignPolicy(t *testing.T) {
	now := time.Now()
	manager := newTestManager(t, testConfig(), &now)

	rec := httptest.NewRecorder()
	if _, err := manager.Issue(rec, "alice", "intranet", nil); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	request := requestWithCookie(t, rec, manager.CookieName())

	if _, err := manager.Load(request, "monitoring"); !errors.Is(err, ErrPolicyMismatch) {
		t.Fatalf("Load error = %v, want ErrPolicyMismatch", err)
	}
}

// Expiry is reported before the policy mismatch, so that a stale cookie reads
// as stale in the log rather than as an attempt to use it elsewhere.
func TestLoadReportsExpiryBeforePolicyMismatch(t *testing.T) {
	now := time.Now()
	manager := newTestManager(t, testConfig(), &now)

	rec := httptest.NewRecorder()
	if _, err := manager.Issue(rec, "alice", "intranet", nil); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	request := requestWithCookie(t, rec, manager.CookieName())
	now = now.Add(9 * time.Hour)

	if _, err := manager.Load(request, "monitoring"); !errors.Is(err, ErrExpiredAbsolute) {
		t.Fatalf("Load error = %v, want ErrExpiredAbsolute", err)
	}
}

// The refresh interval is what keeps Set-Cookie off every asset request.
func TestRefreshOnlyAfterTheInterval(t *testing.T) {
	now := time.Now()
	manager := newTestManager(t, testConfig(), &now)

	rec := httptest.NewRecorder()

	sess, err := manager.Issue(rec, "alice", "intranet", nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	now = now.Add(time.Minute)

	if _, refreshed := manager.Refresh(httptest.NewRecorder(), sess); refreshed {
		t.Error("session refreshed one minute into a five minute interval")
	}

	now = now.Add(5 * time.Minute)

	updated, refreshed := manager.Refresh(httptest.NewRecorder(), sess)
	if !refreshed {
		t.Fatal("session was not refreshed six minutes into a five minute interval")
	}

	if !updated.SeenAt.Equal(now) {
		t.Errorf("SeenAt = %v, want %v", updated.SeenAt, now)
	}

	if !updated.IssuedAt.Equal(sess.IssuedAt) {
		t.Errorf("IssuedAt moved to %v; the absolute lifetime must not slide", updated.IssuedAt)
	}
}

// A refresh interval that is not below the idle window would let a session
// expire in the browser while the service still accepts it.
func TestRefreshIntervalIsClampedToHalfTheIdleWindow(t *testing.T) {
	cfg := testConfig()
	cfg.RefreshInterval = time.Hour

	manager := newTestManager(t, cfg, nil)

	if manager.cfg.RefreshInterval != 15*time.Minute {
		t.Errorf("RefreshInterval = %s, want 15m0s", manager.cfg.RefreshInterval)
	}
}

// Clearing has to match the attributes the cookie was set with, or the browser
// keeps the original and the user stays signed in.
func TestClearMatchesTheIssuedCookie(t *testing.T) {
	manager := newTestManager(t, testConfig(), nil)

	issued := httptest.NewRecorder()
	if _, err := manager.Issue(issued, "alice", "intranet", nil); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	cleared := httptest.NewRecorder()
	manager.Clear(cleared)

	before := issued.Result().Cookies()[0]
	after := cleared.Result().Cookies()[0]

	if after.Value != "" || after.MaxAge >= 0 {
		t.Errorf("cleared cookie = %q with MaxAge %d, want an empty value and a negative MaxAge",
			after.Value, after.MaxAge)
	}

	if after.Path != before.Path || after.Domain != before.Domain ||
		after.Secure != before.Secure || after.SameSite != before.SameSite {
		t.Errorf("cleared cookie attributes %+v do not match the issued ones %+v", after, before)
	}
}

// The session cookie must never be readable by scripts or sent over plaintext.
func TestIssuedCookieAttributes(t *testing.T) {
	manager := newTestManager(t, testConfig(), nil)

	rec := httptest.NewRecorder()
	if _, err := manager.Issue(rec, "alice", "intranet", nil); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	cookie := rec.Result().Cookies()[0]

	switch {
	case !cookie.HttpOnly:
		t.Error("cookie is not HttpOnly")
	case !cookie.Secure:
		t.Error("cookie is not Secure")
	case cookie.SameSite != http.SameSiteLaxMode:
		t.Errorf("SameSite = %v, want Lax", cookie.SameSite)
	case cookie.MaxAge > int((30 * time.Minute).Seconds()):
		t.Errorf("MaxAge = %d, want at most the idle timeout", cookie.MaxAge)
	}
}

// A user in an unreasonable number of groups has to end up logged in, not in a
// redirect loop caused by a cookie the browser silently dropped.
func TestIssueTruncatesOversizedGroupLists(t *testing.T) {
	manager := newTestManager(t, testConfig(), nil)

	groups := make([]string, 0, 400)
	for i := range 400 {
		groups = append(groups, "very-long-group-name-for-testing-"+strings.Repeat("x", 20)+string(rune('a'+i%26)))
	}

	rec := httptest.NewRecorder()

	if _, err := manager.Issue(rec, "alice", "intranet", groups); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	cookie := rec.Result().Cookies()[0]
	if len(cookie.Value) > maxCookieBytes {
		t.Fatalf("cookie is %d bytes, over the %d byte limit", len(cookie.Value), maxCookieBytes)
	}

	sess, err := manager.Load(requestWithCookie(t, rec, manager.CookieName()), "intranet")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(sess.Groups) == 0 || len(sess.Groups) == len(groups) {
		t.Errorf("groups = %d, want a truncated but non-empty list", len(sess.Groups))
	}
}

func TestLoadWithoutCookie(t *testing.T) {
	manager := newTestManager(t, testConfig(), nil)

	if _, err := manager.Load(httptest.NewRequest(http.MethodGet, "/auth", nil), "intranet"); !errors.Is(err, ErrNoCookie) {
		t.Fatalf("Load error = %v, want ErrNoCookie", err)
	}
}

func TestReasonNamesEveryFailure(t *testing.T) {
	for err, want := range map[error]string{
		nil:                 "session",
		ErrNoCookie:         "no_session",
		ErrExpiredAbsolute:  "session_expired_absolute",
		ErrExpiredIdle:      "session_expired_idle",
		ErrPolicyMismatch:   "session_policy_mismatch",
		ErrSignature:        "session_forged",
		ErrMalformed:        "session_malformed",
		errors.New("other"): "session_invalid",
	} {
		if got := Reason(err); got != want {
			t.Errorf("Reason(%v) = %q, want %q", err, got, want)
		}
	}
}

func TestParseSameSite(t *testing.T) {
	for value, want := range map[string]http.SameSite{
		"":       http.SameSiteLaxMode,
		"lax":    http.SameSiteLaxMode,
		"Strict": http.SameSiteStrictMode,
		" none ": http.SameSiteNoneMode,
	} {
		got, err := ParseSameSite(value)
		if err != nil {
			t.Fatalf("ParseSameSite(%q): %v", value, err)
		}

		if got != want {
			t.Errorf("ParseSameSite(%q) = %v, want %v", value, got, want)
		}
	}

	if _, err := ParseSameSite("sometimes"); err == nil {
		t.Error("ParseSameSite accepted an unknown value")
	}
}

// project.md §12: "Verify a session cookie's signature before parsing its
// payload".
//
// The order is the point. A decoder that runs first is a decoder fed
// attacker-chosen bytes on every request, and the JSON parser is the largest
// piece of code a forged cookie can reach. This cookie has a payload that
// cannot be decoded at all, so the error it produces says which check ran
// first.
func TestSignatureIsCheckedBeforeThePayload(t *testing.T) {
	signer, err := NewSigner([]byte(testSecret))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	_, err = signer.Decode(version + ".!!!not-base64!!!.also-not-base64")

	if !errors.Is(err, ErrSignature) {
		t.Fatalf("Decode error = %v, want ErrSignature; an undecodable payload reached the parser "+
			"before the signature was checked", err)
	}
}

// The signature must cover the version, or a future format can be produced by
// relabelling an old cookie — the downgrade this design is shaped to prevent.
func TestSignatureCoversTheVersion(t *testing.T) {
	signer, err := NewSigner([]byte(testSecret))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	now := time.Now()

	value, err := signer.Encode(Session{User: "alice", Policy: "intranet", IssuedAt: now, SeenAt: now})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	parts := strings.Split(value, ".")

	// Same payload, same signature, different version label.
	if _, err := signer.Decode("2." + parts[1] + "." + parts[2]); err == nil {
		t.Fatal("Decode accepted a cookie whose version label was changed")
	}
}
