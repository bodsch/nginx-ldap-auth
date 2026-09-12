package server

import (
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"bodsch.me/nginx-ldap-auth/internal/config"
	"bodsch.me/nginx-ldap-auth/internal/session"
)

// csrfTokenTTL is how long a rendered login form stays submittable.
//
// It is not a security parameter — the token's job is to be absent from a
// cross-site submission, not to be short-lived — so it is set to the largest
// value that still expires: an hour is longer than anyone spends typing a
// password, and short enough that a form left open in a shared browser cannot
// be submitted the next day.
const csrfTokenTTL = time.Hour

// maxLoginBodyBytes bounds the login form submission. A password and a
// redirect target do not need more, and without a bound the endpoint accepts
// an upload of any size before rejecting it.
const maxLoginBodyBytes = 8 << 10

// Sessions bundles everything the login form and the session cookie need.
//
// A nil *Sessions is how the feature stays off: every call site checks it once,
// and the rest of the request path is the Basic-Authentication-only service
// that existed before.
type Sessions struct {
	manager *session.Manager
	csrf    *session.CSRF
	tmpl    *template.Template

	loginPath  string
	logoutPath string

	// allowBasic keeps Basic Authentication accepted for clients that
	// cannot hold a cookie.
	allowBasic bool
}

// NewSessions prepares the session support from a validated configuration, or
// returns nil when sessions are disabled.
func NewSessions(cfg config.Session) (*Sessions, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	sameSite, err := session.ParseSameSite(cfg.SameSite)
	if err != nil {
		return nil, fmt.Errorf("session.same_site: %w", err)
	}

	managerCfg := session.Config{
		CookieName:      cfg.CookieName,
		AbsoluteTimeout: cfg.AbsoluteTimeout.Duration(),
		IdleTimeout:     cfg.IdleTimeout.Duration(),
		RefreshInterval: cfg.RefreshInterval.Duration(),
		Path:            cfg.CookiePath,
		Domain:          cfg.CookieDomain,
		Secure:          cfg.SecureCookie(),
		SameSite:        sameSite,
	}

	manager, err := session.NewManager(cfg.Secret, managerCfg)
	if err != nil {
		return nil, err
	}

	guard, err := session.NewCSRF(cfg.Secret, managerCfg, csrfTokenTTL)
	if err != nil {
		return nil, err
	}

	// Parsed at startup, so that a broken template is a service that does
	// not start rather than a 500 on the first login of the day.
	tmpl := loginTemplate

	if len(cfg.LoginTemplateSource) > 0 {
		tmpl, err = template.New("login").Parse(string(cfg.LoginTemplateSource))
		if err != nil {
			return nil, fmt.Errorf("session.login_template: %w", err)
		}
	}

	return &Sessions{
		manager:    manager,
		csrf:       guard,
		tmpl:       tmpl,
		loginPath:  cfg.LoginPath,
		logoutPath: cfg.LogoutPath,
		allowBasic: cfg.AllowBasic,
	}, nil
}

// loginPage is what the login template is rendered with.
type loginPage struct {
	// Realm names the application, taken from the policy.
	Realm string

	// Policy is the policy the login will be evaluated under.
	Policy string

	// Action is the path the form posts back to, with the redirect target
	// already attached.
	Action string

	// Next is the path to return to after a successful login.
	Next string

	// CSRFToken has to be submitted with the form.
	CSRFToken string

	// Username is what the previous attempt typed, so a failed login does
	// not make the user enter it again.
	Username string

	// Error is a message for the user. It is deliberately vague: telling
	// somebody that the account exists but the password is wrong is telling
	// everybody which accounts exist.
	Error string
}

// safeNext reduces a redirect target to something that cannot leave this site.
//
// The value arrives in a query parameter, so it is client-controlled, and a
// redirect that follows it unchecked is an open redirect: a link to the
// perfectly genuine login page of this service that lands the user on somebody
// else's copy of it after they authenticate.
//
// Only a path is accepted. Anything else — an absolute URL, a scheme-relative
// "//host", a backslash Windows browsers normalise into a slash — falls back to
// the site root.
func safeNext(value string) string {
	if value == "" || !strings.HasPrefix(value, "/") {
		return "/"
	}

	if strings.HasPrefix(value, "//") || strings.HasPrefix(value, "/\\") {
		return "/"
	}

	// A control character in a Location header ends it and starts whatever
	// the rest of the value says. Go's writer rejects the response outright,
	// which turns a redirect into a 500.
	if strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return "/"
	}

	return value
}

// loginURL builds the address a request should be sent to in order to log in.
func (s *Sessions) loginURL(next string) string {
	next = safeNext(next)
	if next == "/" {
		return s.loginPath
	}

	return s.loginPath + "?next=" + url.QueryEscape(next)
}

// loginTemplate is the built-in form.
//
// It is one self-contained document: no stylesheet, no script, no font and no
// image is fetched. A login page that depends on an external asset is a login
// page that fails while the site behind it is up, and a Content-Security-Policy
// that permits none of them is a policy nothing can weaken later.
var loginTemplate = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="same-origin">
<title>Sign in{{if .Realm}} &middot; {{.Realm}}{{end}}</title>
<style>
:root { color-scheme: light dark; --bg:#f4f4f5; --fg:#18181b; --card:#fff; --line:#d4d4d8; --muted:#52525b; --accent:#1d4ed8; --error:#b91c1c; }
@media (prefers-color-scheme: dark) { :root { --bg:#18181b; --fg:#f4f4f5; --card:#27272a; --line:#3f3f46; --muted:#a1a1aa; --accent:#60a5fa; --error:#f87171; } }
* { box-sizing: border-box; }
body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:1.5rem;
       background:var(--bg); color:var(--fg); font:16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { width:100%; max-width:22rem; background:var(--card); border:1px solid var(--line); border-radius:0.75rem; padding:1.75rem; }
h1 { margin:0 0 1.25rem; font-size:1.15rem; }
label { display:block; margin-bottom:0.35rem; font-size:0.85rem; color:var(--muted); }
input[type=text], input[type=password] { width:100%; padding:0.6rem 0.7rem; margin-bottom:1rem; font-size:1rem;
       color:var(--fg); background:var(--bg); border:1px solid var(--line); border-radius:0.4rem; }
input:focus-visible { outline:2px solid var(--accent); outline-offset:1px; }
button { width:100%; padding:0.65rem; font-size:1rem; font-weight:600; color:#fff; background:var(--accent);
       border:0; border-radius:0.4rem; cursor:pointer; }
button:hover { filter:brightness(1.08); }
.error { margin:0 0 1rem; padding:0.6rem 0.7rem; border-radius:0.4rem; font-size:0.9rem;
       color:var(--error); border:1px solid var(--error); }
</style>
</head>
<body>
<main>
<h1>{{if .Realm}}{{.Realm}}{{else}}Sign in{{end}}</h1>
{{if .Error}}<p class="error" role="alert">{{.Error}}</p>{{end}}
<form method="post" action="{{.Action}}" autocomplete="on">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
<input type="hidden" name="next" value="{{.Next}}">
<label for="username">Username</label>
<input id="username" name="username" type="text" value="{{.Username}}" autocomplete="username" autocapitalize="none" autocorrect="off" spellcheck="false" required autofocus>
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Sign in</button>
</form>
</main>
</body>
</html>
`))

// renderLogin writes the login form.
//
// The headers are what stop the page from being framed, from leaking the
// redirect target to another site, and from being kept in a shared cache — all
// three matter more here than on any other page this service serves, because
// this is the one that takes a password.
func (s *Server) renderLogin(w http.ResponseWriter, status int, page loginPage) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")

	w.WriteHeader(status)

	if err := s.sessions.tmpl.Execute(w, page); err != nil {
		// The status line is already sent, so there is nothing useful to
		// tell the client. The log is where this has to be visible.
		s.log.Error("render login form", slog.String("error", err.Error()))
	}
}
