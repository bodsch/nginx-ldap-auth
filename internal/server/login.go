package server

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"bodsch.me/nginx-ldap-auth/internal/auth"
	"bodsch.me/nginx-ldap-auth/internal/policy"
	"bodsch.me/nginx-ldap-auth/internal/session"
)

// Messages shown on the login form.
//
// They are constants, and they are vague on purpose. "No such user" and "wrong
// password" are the same message here, because a form that distinguishes them
// is a form that confirms which accounts exist to anyone who can reach it.
const (
	messageInvalidCredentials = "Wrong username or password."
	messageNotAuthorized      = "Your account is not permitted to access this application."
	messageThrottled          = "Too many failed attempts. Try again later."
	messageBackendUnavailable = "The directory is currently unreachable. Try again in a moment."
	messageFormExpired        = "The form expired before it was submitted. Please try again."
	messageSessionFailed      = "The session could not be created. Please try again."
)

// handleLogin serves the login form and processes its submission.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		s.showLogin(w, r)
	case http.MethodPost:
		s.submitLogin(w, r)
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, "method not allowed\n", http.StatusMethodNotAllowed)
	}
}

// showLogin renders the form for a visitor who is not signed in.
func (s *Server) showLogin(w http.ResponseWriter, r *http.Request) {
	entry, err := s.auth.ResolvePolicy(r.Header.Get(policy.Header))
	if err != nil {
		// The login form is reached through nginx, which is what sets the
		// policy header. An unresolvable one is a mistake in that
		// configuration, and offering a password field for access rules
		// that do not exist would collect credentials for nothing.
		s.log.Warn("login form requested for an unresolved policy", slog.String("error", err.Error()))
		http.Error(w, "forbidden\n", http.StatusForbidden)

		return
	}

	next := safeNext(r.URL.Query().Get("next"))

	// Somebody who is already signed in has no business on a login form:
	// showing it would invite them to start a second session while the
	// first one is still perfectly good.
	if _, err := s.sessions.manager.Load(r, entry.Name()); err == nil {
		//nolint:gosec // safeNext has already reduced this to a same-site path
		http.Redirect(w, r, next, http.StatusSeeOther)

		return
	}

	s.renderLoginForm(w, r, entry.Name(), entry.Realm(), next, "", "", http.StatusOK)
}

// submitLogin evaluates a submitted form.
func (s *Server) submitLogin(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

	entry, err := s.auth.ResolvePolicy(r.Header.Get(policy.Header))
	if err != nil {
		s.log.Warn("login submitted for an unresolved policy", slog.String("error", err.Error()))
		http.Error(w, "forbidden\n", http.StatusForbidden)

		return
	}

	// A password and a return path do not need more than this, and without
	// a bound the endpoint reads whatever is sent before rejecting it.
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)

	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form submission\n", http.StatusBadRequest)

		return
	}

	next := safeNext(r.PostFormValue("next"))
	username := r.PostFormValue("username")

	if err := s.sessions.csrf.Verify(r, r.PostFormValue("csrf_token")); err != nil {
		// Not an authentication failure: the credentials were never
		// evaluated, so this must not count against the throttle. It is
		// logged at warn because the two things that produce it are a
		// stale form and a cross-site submission, and only the log can
		// say which one is happening.
		s.log.Warn("login rejected: CSRF check failed",
			slog.String("reason", "csrf_failed"),
			slog.String("remote_addr", s.clientAddress(r)),
			slog.String("error", err.Error()))

		s.observer.ObserveAuth(entry.Name(), auth.StatusUnauthenticated, "csrf_failed", time.Since(started))

		status := http.StatusBadRequest
		if errors.Is(err, session.ErrCSRFMismatch) {
			status = http.StatusForbidden
		}

		s.renderLoginForm(w, r, entry.Name(), entry.Realm(), next, username, messageFormExpired, status)

		return
	}

	result := s.auth.Authenticate(r.Context(), auth.Request{
		PolicyHeader: r.Header.Get(policy.Header),
		Credentials: &auth.Credentials{
			User:     username,
			Password: r.PostFormValue("password"),
		},
		RemoteAddress: s.clientAddress(r),
	})

	elapsed := time.Since(started)

	if result.Status == auth.StatusAllow {
		s.completeLogin(w, r, result, next, elapsed)

		return
	}

	s.logDecision(r, result, elapsed)
	s.observer.ObserveAuth(result.Policy, result.Status, result.Reason, elapsed)

	status, message := loginFailure(result)

	if result.Status == auth.StatusThrottled {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(result.RetryAfter)))
	}

	s.renderLoginForm(w, r, entry.Name(), entry.Realm(), next, username, message, status)
}

// completeLogin issues the session cookie and sends the browser onward.
func (s *Server) completeLogin(
	w http.ResponseWriter,
	r *http.Request,
	result auth.Result,
	next string,
	elapsed time.Duration,
) {
	sess, err := s.sessions.manager.Issue(w, result.User, result.Policy, result.Groups)
	if err != nil {
		// The credentials were right, so this is the service's fault and
		// is logged as such. The user is told to try again rather than
		// given a reason they can do nothing with.
		s.log.Error("session cookie could not be issued",
			slog.String("policy", result.Policy),
			slog.String("error", err.Error()))

		s.observer.ObserveAuth(result.Policy, auth.StatusError, "session_not_issued", elapsed)
		s.renderLoginForm(w, r, result.Policy, result.Realm, next, result.User,
			messageSessionFailed, http.StatusInternalServerError)

		return
	}

	// The form's token has served its purpose. Leaving it behind would keep
	// a valid one in the browser of anyone who logs out and walks away.
	s.sessions.csrf.Clear(w)

	result.Reason = "session_established"

	s.logDecision(r, result, elapsed)
	s.observer.ObserveAuth(result.Policy, auth.StatusAllow, result.Reason, elapsed)

	attrs := []slog.Attr{
		slog.String("policy", result.Policy),
		slog.String("expires_at", sess.IssuedAt.Add(s.sessions.manager.AbsoluteTimeout()).Format(time.RFC3339)),
		slog.String("idle_timeout", s.sessions.manager.IdleTimeout().String()),
	}

	if s.logUsername {
		attrs = append(attrs, slog.String("user", sess.User))
	}

	s.log.LogAttrs(r.Context(), slog.LevelInfo, "session established", attrs...)

	// 303, not 302: the browser has to switch to GET for the redirect, or
	// it re-posts the credentials to whatever the user was originally
	// trying to reach.
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// handleLogout ends a session.
//
// GET is accepted alongside POST. A logout link is what people expect, and the
// worst a forged logout can do is end a session the user can start again — a
// nuisance, where refusing GET would mean every application embedding a logout
// link has to grow a form to use it.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	entry, err := s.auth.ResolvePolicy(r.Header.Get(policy.Header))

	policyName := ""
	if err == nil {
		policyName = entry.Name()
	}

	// Read before it is cleared, so the log can say whose session ended.
	// A missing or unreadable cookie is not an error here: logging out
	// twice, or without ever having logged in, has to be a no-op that
	// still ends on the login form.
	if sess, loadErr := s.sessions.manager.Load(r, policyName); loadErr == nil {
		attrs := []slog.Attr{
			slog.String("policy", sess.Policy),
			slog.String("remote_addr", s.clientAddress(r)),
		}

		if s.logUsername {
			attrs = append(attrs, slog.String("user", sess.User))
		}

		s.log.LogAttrs(r.Context(), slog.LevelInfo, "session ended", attrs...)
		s.observer.ObserveAuth(sess.Policy, auth.StatusUnauthenticated, "session_ended", 0)
	}

	s.sessions.manager.Clear(w)
	s.sessions.csrf.Clear(w)

	next := safeNext(r.URL.Query().Get("next"))

	//nolint:gosec // safeNext has already reduced this to a same-site path
	http.Redirect(w, r, s.sessions.loginURL(next), http.StatusSeeOther)
}

// renderLoginForm mints a fresh CSRF token and renders the form.
//
// The token is re-issued on every render, including after a failed attempt: the
// previous one is still valid, but reusing it would mean a form served once
// keeps working for as long as the page is open, and re-issuing costs a hash.
func (s *Server) renderLoginForm(
	w http.ResponseWriter,
	r *http.Request,
	policyName, realm, next, username, message string,
	status int,
) {
	token, err := s.sessions.csrf.Issue(w)
	if err != nil {
		s.log.Error("CSRF token could not be issued", slog.String("error", err.Error()))
		http.Error(w, "internal error\n", http.StatusInternalServerError)

		return
	}

	// HEAD gets the headers and the status of the page it asks about, and
	// no body. Go would discard the body anyway; rendering it would only
	// spend the work.
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)

		return
	}

	s.renderLogin(w, status, loginPage{
		Realm:      realm,
		Policy:     policyName,
		Action:     s.sessions.loginURL(next),
		Next:       next,
		CSRFToken:  token,
		Username:   username,
		Error:      message,
		Decoration: loginDecoration,
	})
}

// loginFailure maps a refused decision onto what the visitor is shown.
func loginFailure(result auth.Result) (status int, message string) {
	switch result.Status {
	case auth.StatusForbidden:
		return http.StatusForbidden, messageNotAuthorized
	case auth.StatusThrottled:
		return http.StatusTooManyRequests, messageThrottled
	case auth.StatusError:
		return http.StatusBadGateway, messageBackendUnavailable
	case auth.StatusUnauthenticated:
		return http.StatusUnauthorized, messageInvalidCredentials
	default:
		return http.StatusUnauthorized, messageInvalidCredentials
	}
}
