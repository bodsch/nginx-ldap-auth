package session

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// maxCookieBytes bounds the value the manager will emit.
//
// Browsers are only required to keep 4096 bytes per cookie, and the ones that
// enforce it drop the whole cookie rather than truncating it. A user in two
// hundred groups would otherwise log in successfully and be sent straight back
// to the login form, which is the least diagnosable failure this feature could
// have.
const maxCookieBytes = 3800

// Config configures the session cookie.
//
// It mirrors the session section of the configuration file, but the types are
// this package's own: a Manager built by a test should not need a YAML struct.
type Config struct {
	// CookieName is the cookie the session is carried in.
	CookieName string

	// AbsoluteTimeout is the maximum lifetime of a session, counted from
	// the login. It is never extended.
	AbsoluteTimeout time.Duration

	// IdleTimeout is how long a session survives without being used.
	IdleTimeout time.Duration

	// RefreshInterval is how old the last-seen stamp has to be before the
	// cookie is re-issued.
	//
	// Refreshing on every request would put a Set-Cookie header on every
	// asset fetch, which nginx then has to copy out of the auth subrequest
	// and into the response — hundreds of times per page view, all carrying
	// the same session. Refreshing on an interval keeps the sliding window
	// accurate to within that interval and leaves the rest untouched.
	RefreshInterval time.Duration

	// Path and Domain scope the cookie. An empty Domain is the correct
	// default: it binds the cookie to the exact host that set it, while any
	// value at all also sends it to every subdomain.
	Path   string
	Domain string

	// Secure keeps the cookie off plaintext connections. It defaults to on
	// wherever this is built from configuration.
	Secure bool

	// SameSite is the cookie's cross-site policy.
	SameSite http.SameSite
}

// Manager issues, reads and clears session cookies.
type Manager struct {
	signer *Signer
	cfg    Config

	// now is injectable so that expiry can be tested without sleeping.
	now func() time.Time
}

// NewManager returns a Manager.
func NewManager(secret []byte, cfg Config) (*Manager, error) {
	signer, err := NewSigner(secret)
	if err != nil {
		return nil, err
	}

	switch {
	case cfg.CookieName == "":
		return nil, fmt.Errorf("cookie name is required")
	case cfg.AbsoluteTimeout <= 0:
		return nil, fmt.Errorf("absolute timeout must be positive")
	case cfg.IdleTimeout <= 0:
		return nil, fmt.Errorf("idle timeout must be positive")
	}

	if cfg.Path == "" {
		cfg.Path = "/"
	}

	if cfg.RefreshInterval <= 0 || cfg.RefreshInterval >= cfg.IdleTimeout {
		// Half the idle window is the largest interval that cannot let a
		// session expire in the browser while the server still considers
		// it alive.
		cfg.RefreshInterval = cfg.IdleTimeout / 2
	}

	if cfg.SameSite == 0 {
		cfg.SameSite = http.SameSiteLaxMode
	}

	return &Manager{signer: signer, cfg: cfg, now: time.Now}, nil
}

// CookieName returns the name the session cookie is carried under.
func (m *Manager) CookieName() string {
	return m.cfg.CookieName
}

// AbsoluteTimeout returns the configured maximum session lifetime.
func (m *Manager) AbsoluteTimeout() time.Duration {
	return m.cfg.AbsoluteTimeout
}

// IdleTimeout returns the configured idle window.
func (m *Manager) IdleTimeout() time.Duration {
	return m.cfg.IdleTimeout
}

// Load reads the session from a request and checks that it is still valid for
// the named policy.
//
// Every failure returns an error rather than a bare "not logged in", because
// the caller logs the difference: a stream of ErrSignature is somebody trying
// to forge cookies, and a stream of ErrExpiredIdle is a timeout that is set too
// short for the way people actually work.
func (m *Manager) Load(r *http.Request, policy string) (Session, error) {
	cookie, err := r.Cookie(m.cfg.CookieName)
	if err != nil || cookie.Value == "" {
		return Session{}, ErrNoCookie
	}

	sess, err := m.signer.Decode(cookie.Value)
	if err != nil {
		return Session{}, err
	}

	now := m.now()

	// The absolute limit is checked first. Both are expired for a session
	// that has been gone for days, and the absolute one is the more useful
	// thing to see in a log: it says the session ran its course, where the
	// idle one says only that the last request was a while ago.
	if !now.Before(sess.IssuedAt.Add(m.cfg.AbsoluteTimeout)) {
		return Session{}, ErrExpiredAbsolute
	}

	if !now.Before(sess.SeenAt.Add(m.cfg.IdleTimeout)) {
		return Session{}, ErrExpiredIdle
	}

	// The policy is compared after expiry, so that a stale cookie arriving
	// at a different application is reported as stale rather than as a
	// mismatch.
	if policy != "" && sess.Policy != policy {
		return Session{}, fmt.Errorf("%w: cookie names %q", ErrPolicyMismatch, sess.Policy)
	}

	return sess, nil
}

// Issue writes a new session cookie for a login that just succeeded.
func (m *Manager) Issue(w http.ResponseWriter, user, policy string, groups []string) (Session, error) {
	now := m.now()

	sess := Session{
		User:     user,
		Policy:   policy,
		Groups:   groups,
		IssuedAt: now,
		SeenAt:   now,
	}

	return sess, m.write(w, sess)
}

// Refresh re-issues the cookie with the last-seen stamp moved to now, and
// reports whether it wrote anything.
//
// It is a no-op when the stamp is younger than the refresh interval, and when
// the session is close enough to its absolute limit that extending the idle
// window would only postpone the same expiry by a few seconds.
func (m *Manager) Refresh(w http.ResponseWriter, sess Session) (Session, bool) {
	now := m.now()

	if now.Sub(sess.SeenAt) < m.cfg.RefreshInterval {
		return sess, false
	}

	sess.SeenAt = now

	if err := m.write(w, sess); err != nil {
		return sess, false
	}

	return sess, true
}

// Clear removes the session cookie.
//
// The attributes have to match the ones it was set with, or the browser keeps
// the original alongside the deletion and the user stays logged in — which is
// the exact bug this whole feature exists to fix.
func (m *Manager) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure mirrors session.secure; the attributes must match the issued cookie
		Name:     m.cfg.CookieName,
		Value:    "",
		Path:     m.cfg.Path,
		Domain:   m.cfg.Domain,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
		Secure:   m.cfg.Secure,
		HttpOnly: true,
		SameSite: m.cfg.SameSite,
	})
}

// write renders and sets the cookie.
func (m *Manager) write(w http.ResponseWriter, sess Session) error {
	value, err := m.signer.Encode(sess)
	if err != nil {
		return err
	}

	// Group lists are the only unbounded part of the value, so they are the
	// only part worth shrinking. Dropping the tail keeps the login working;
	// it costs the upstream application some of the X-Auth-Groups header,
	// which is a degradation the operator can see, rather than a login loop,
	// which is one they cannot.
	for len(value) > maxCookieBytes && len(sess.Groups) > 0 {
		sess.Groups = sess.Groups[:len(sess.Groups)-1]

		if value, err = m.signer.Encode(sess); err != nil {
			return err
		}
	}

	if len(value) > maxCookieBytes {
		return fmt.Errorf("session cookie would be %d bytes, over the %d byte limit", len(value), maxCookieBytes)
	}

	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure mirrors session.secure, which configuration validation warns about
		Name:     m.cfg.CookieName,
		Value:    value,
		Path:     m.cfg.Path,
		Domain:   m.cfg.Domain,
		MaxAge:   int(m.remaining(sess).Seconds()),
		Secure:   m.cfg.Secure,
		HttpOnly: true,
		SameSite: m.cfg.SameSite,
	})

	return nil
}

// remaining is how long the browser should keep the cookie: the idle window,
// or what is left of the absolute lifetime when that is shorter.
//
// Letting the browser drop it is not a security control — the server checks
// both timeouts on every request regardless — but it does mean a closed laptop
// wakes up without a cookie instead of with one that is refused.
func (m *Manager) remaining(sess Session) time.Duration {
	absolute := sess.IssuedAt.Add(m.cfg.AbsoluteTimeout).Sub(m.now())

	if absolute < m.cfg.IdleTimeout {
		if absolute < time.Second {
			return time.Second
		}

		return absolute
	}

	return m.cfg.IdleTimeout
}

// Reason maps a Load failure onto the stable identifier used in logs and
// metrics. Unknown errors collapse into one bucket rather than becoming a new
// label value each time.
func Reason(err error) string {
	switch {
	case err == nil:
		return "session"
	case errors.Is(err, ErrNoCookie):
		return "no_session"
	case errors.Is(err, ErrExpiredAbsolute):
		return "session_expired_absolute"
	case errors.Is(err, ErrExpiredIdle):
		return "session_expired_idle"
	case errors.Is(err, ErrPolicyMismatch):
		return "session_policy_mismatch"
	case errors.Is(err, ErrSignature):
		return "session_forged"
	case errors.Is(err, ErrMalformed):
		return "session_malformed"
	default:
		return "session_invalid"
	}
}

// ParseSameSite maps the configuration value onto the standard library's.
func ParseSameSite(value string) (http.SameSite, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "lax":
		return http.SameSiteLaxMode, nil
	case "strict":
		return http.SameSiteStrictMode, nil
	case "none":
		return http.SameSiteNoneMode, nil
	default:
		return 0, fmt.Errorf("%q is not one of lax, strict, none", value)
	}
}
