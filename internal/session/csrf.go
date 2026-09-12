package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Errors returned by CSRF.Verify.
var (
	// ErrCSRFMissing means the request carried no token, or no token
	// cookie. A browser that followed the login form always has both.
	ErrCSRFMissing = errors.New("no CSRF token")

	// ErrCSRFMismatch means the form field and the cookie disagree, which
	// is what a cross-site submission looks like.
	ErrCSRFMismatch = errors.New("CSRF token does not match")

	// ErrCSRFInvalid means the token was not issued by this service, or has
	// expired.
	ErrCSRFInvalid = errors.New("CSRF token is invalid or expired")
)

// csrfTokenBytes is the random part of a token.
const csrfTokenBytes = 16

// csrfSuffix names the cookie the token is mirrored in. It is appended to the
// session cookie's name so that the two are recognisably a pair in a browser's
// cookie list.
const csrfSuffix = "_csrf"

// CSRF issues and checks the login form's anti-forgery token.
//
// Without it the login form is a cross-site request forgery target in the one
// direction people forget: an attacker cannot read the response, but they can
// make a visitor's browser submit *the attacker's* credentials, and everything
// the visitor then does happens in the attacker's session.
//
// The scheme is a double submit — the same signed token in a cookie and in a
// form field — with SameSite=Strict on the cookie doing the real work: a
// cross-site POST does not carry it, so the check fails before the values are
// even compared. The signature bounds the token's lifetime and stops one being
// invented without ever talking to this service.
type CSRF struct {
	key        []byte
	cookieName string
	ttl        time.Duration
	path       string
	domain     string
	secure     bool

	now func() time.Time
}

// NewCSRF returns a CSRF guard keyed from the session secret.
//
// The key is derived rather than reused so that a token can never be mistaken
// for a session cookie, whatever either format grows into later.
func NewCSRF(secret []byte, cfg Config, ttl time.Duration) (*CSRF, error) {
	if len(secret) < minSecretBytes {
		return nil, fmt.Errorf("session secret is %d bytes, at least %d are required", len(secret), minSecretBytes)
	}

	derive := hmac.New(sha256.New, secret)
	derive.Write([]byte("nginx-ldap-auth csrf v1"))

	if ttl <= 0 {
		ttl = 15 * time.Minute
	}

	path := cfg.Path
	if path == "" {
		path = "/"
	}

	return &CSRF{
		key:        derive.Sum(nil),
		cookieName: cfg.CookieName + csrfSuffix,
		ttl:        ttl,
		path:       path,
		domain:     cfg.Domain,
		secure:     cfg.Secure,
		now:        time.Now,
	}, nil
}

// Issue mints a token, sets its cookie and returns the value to embed in the
// form.
func (c *CSRF) Issue(w http.ResponseWriter) (string, error) {
	nonce := make([]byte, csrfTokenBytes)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate CSRF token: %w", err)
	}

	payload := make([]byte, 8, 8+csrfTokenBytes)

	// A Unix timestamp in this century is positive, and the value is read
	// back through the same conversion.
	binary.BigEndian.PutUint64(payload, uint64(c.now().Add(c.ttl).Unix())) //nolint:gosec // an expiry timestamp is never negative
	payload = append(payload, nonce...)

	token := encoding.EncodeToString(payload) + "." + encoding.EncodeToString(c.mac(payload))

	// Secure follows the configuration rather than being hard-coded: a
	// deployment without TLS would otherwise never receive the cookie and
	// could never submit the form. Configuration validation warns about
	// that arrangement, which is where the decision belongs.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure mirrors session.secure, which validation warns about
		Name:   c.cookieName,
		Value:  token,
		Path:   c.path,
		Domain: c.domain,
		MaxAge: int(c.ttl.Seconds()),
		Secure: c.secure,

		HttpOnly: true,

		// Strict, not Lax: this cookie exists precisely to be absent
		// from a cross-site submission, and Lax would send it with a
		// top-level POST from another origin.
		SameSite: http.SameSiteStrictMode,
	})

	return token, nil
}

// Verify checks a submitted token against the cookie.
func (c *CSRF) Verify(r *http.Request, submitted string) error {
	cookie, err := r.Cookie(c.cookieName)
	if err != nil || cookie.Value == "" || submitted == "" {
		return ErrCSRFMissing
	}

	if !hmac.Equal([]byte(cookie.Value), []byte(submitted)) {
		return ErrCSRFMismatch
	}

	encodedPayload, encodedMAC, found := strings.Cut(submitted, ".")
	if !found {
		return ErrCSRFInvalid
	}

	payload, err := encoding.DecodeString(encodedPayload)
	if err != nil || len(payload) != 8+csrfTokenBytes {
		return ErrCSRFInvalid
	}

	provided, err := encoding.DecodeString(encodedMAC)
	if err != nil {
		return ErrCSRFInvalid
	}

	if !hmac.Equal(provided, c.mac(payload)) {
		return ErrCSRFInvalid
	}

	if expiry := int64(binary.BigEndian.Uint64(payload)); c.now().Unix() >= expiry { //nolint:gosec // the value was written from a positive int64
		return ErrCSRFInvalid
	}

	return nil
}

// Clear removes the token cookie, so that a completed login does not leave one
// behind for the next visitor to the same browser profile.
func (c *CSRF) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure mirrors session.secure; the attributes must match the issued cookie
		Name:     c.cookieName,
		Value:    "",
		Path:     c.path,
		Domain:   c.domain,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
		Secure:   c.secure,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// mac signs a token payload.
func (c *CSRF) mac(payload []byte) []byte {
	sum := hmac.New(sha256.New, c.key)
	sum.Write(payload)

	return sum.Sum(nil)
}
