package session

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestCSRF(t *testing.T, now *time.Time) *CSRF {
	t.Helper()

	guard, err := NewCSRF([]byte(testSecret), testConfig(), time.Hour)
	if err != nil {
		t.Fatalf("NewCSRF: %v", err)
	}

	if now != nil {
		guard.now = func() time.Time { return *now }
	}

	return guard
}

// submit models a browser posting the form: the token in a field, and the
// cookie the browser was given, unless the test withholds it.
func submit(t *testing.T, rec *httptest.ResponseRecorder, withCookie bool) *http.Request {
	t.Helper()

	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(""))

	if withCookie {
		for _, cookie := range rec.Result().Cookies() {
			r.AddCookie(cookie)
		}
	}

	return r
}

func TestCSRFAcceptsItsOwnToken(t *testing.T) {
	guard := newTestCSRF(t, nil)

	rec := httptest.NewRecorder()

	token, err := guard.Issue(rec)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if err := guard.Verify(submit(t, rec, true), token); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// A cross-site POST does not carry a SameSite=Strict cookie, which is what this
// models: the attacker controls the form field and nothing else.
func TestCSRFRejectsSubmissionWithoutTheCookie(t *testing.T) {
	guard := newTestCSRF(t, nil)

	rec := httptest.NewRecorder()

	token, err := guard.Issue(rec)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if err := guard.Verify(submit(t, rec, false), token); !errors.Is(err, ErrCSRFMissing) {
		t.Fatalf("Verify error = %v, want ErrCSRFMissing", err)
	}
}

func TestCSRFRejectsMismatchAndForgery(t *testing.T) {
	guard := newTestCSRF(t, nil)

	rec := httptest.NewRecorder()

	token, err := guard.Issue(rec)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	other := httptest.NewRecorder()

	otherToken, err := guard.Issue(other)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if err := guard.Verify(submit(t, rec, true), otherToken); !errors.Is(err, ErrCSRFMismatch) {
		t.Fatalf("Verify with another form's token = %v, want ErrCSRFMismatch", err)
	}

	if err := guard.Verify(submit(t, other, true), token); !errors.Is(err, ErrCSRFMismatch) {
		t.Fatalf("Verify with another browser's cookie = %v, want ErrCSRFMismatch", err)
	}

	if err := guard.Verify(submit(t, rec, true), ""); !errors.Is(err, ErrCSRFMissing) {
		t.Fatalf("Verify with an empty token = %v, want ErrCSRFMissing", err)
	}
}

// A token nobody issued must not verify even when it is submitted in both
// places, which is what an attacker able to set a cookie would try.
func TestCSRFRejectsUnsignedToken(t *testing.T) {
	guard := newTestCSRF(t, nil)

	invented := encoding.EncodeToString(make([]byte, 8+csrfTokenBytes)) + ".AAAA"

	r := httptest.NewRequest(http.MethodPost, "/login", nil)
	r.AddCookie(&http.Cookie{Name: "nginx_ldap_auth_csrf", Value: invented})

	if err := guard.Verify(r, invented); !errors.Is(err, ErrCSRFInvalid) {
		t.Fatalf("Verify error = %v, want ErrCSRFInvalid", err)
	}
}

func TestCSRFTokenExpires(t *testing.T) {
	now := time.Now()
	guard := newTestCSRF(t, &now)

	rec := httptest.NewRecorder()

	token, err := guard.Issue(rec)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	now = now.Add(time.Hour + time.Second)

	if err := guard.Verify(submit(t, rec, true), token); !errors.Is(err, ErrCSRFInvalid) {
		t.Fatalf("Verify error = %v, want ErrCSRFInvalid", err)
	}
}

func TestCSRFCookieIsStrict(t *testing.T) {
	guard := newTestCSRF(t, nil)

	rec := httptest.NewRecorder()
	if _, err := guard.Issue(rec); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	cookie := rec.Result().Cookies()[0]

	switch {
	case cookie.SameSite != http.SameSiteStrictMode:
		t.Errorf("SameSite = %v, want Strict; a Lax cookie is sent with a cross-site POST", cookie.SameSite)
	case !cookie.HttpOnly:
		t.Error("cookie is not HttpOnly")
	case cookie.Name != "nginx_ldap_auth_csrf":
		t.Errorf("cookie name = %q, want nginx_ldap_auth_csrf", cookie.Name)
	}
}
