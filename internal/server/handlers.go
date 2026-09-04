package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"bodsch.me/nginx-ldap-auth/internal/auth"
	"bodsch.me/nginx-ldap-auth/internal/policy"
)

// Response headers carrying the authenticated identity upstream.
const (
	HeaderUser   = "X-Auth-User"
	HeaderGroups = "X-Auth-Groups"
)

// maxIdentityHeaderBytes bounds the identity headers.
//
// The values come from the directory, which is trusted but not necessarily
// tidy: a user in two hundred groups would otherwise produce a header large
// enough for nginx to refuse the response, turning a successful login into a
// 500.
const maxIdentityHeaderBytes = 4096

// handleAuth is the endpoint nginx calls through auth_request.
func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

	// Any method is accepted. nginx issues the subrequest itself and the
	// method it uses is not part of the authentication question; rejecting
	// one would only add a way for a working configuration to break after
	// an nginx upgrade.
	result := s.auth.Authenticate(r.Context(), auth.Request{
		PolicyHeader:  r.Header.Get(policy.Header),
		Authorization: r.Header.Get("Authorization"),
		RemoteAddress: s.clientAddress(r),
	})

	elapsed := time.Since(started)

	s.writeAuthResponse(w, result)
	s.logDecision(r, result, elapsed)
	s.observer.ObserveAuth(result.Policy, result.Status, result.Reason, elapsed)
}

// writeAuthResponse turns a decision into the response nginx evaluates.
func (s *Server) writeAuthResponse(w http.ResponseWriter, result auth.Result) {
	switch result.Status {
	case auth.StatusAllow:
		if result.User != "" {
			w.Header().Set(HeaderUser, sanitiseHeaderValue(result.User))
		}

		if len(result.Groups) > 0 {
			w.Header().Set(HeaderGroups, sanitiseHeaderValue(strings.Join(result.Groups, ",")))
		}

		w.WriteHeader(http.StatusOK)

	case auth.StatusUnauthenticated:
		// The challenge is what makes a browser prompt. Without it a
		// 401 is a dead end for the user, and nginx passes the header
		// through to the client unchanged.
		w.Header().Set("WWW-Authenticate", challenge(result.Realm))
		http.Error(w, "authentication required\n", http.StatusUnauthorized)

	case auth.StatusForbidden:
		http.Error(w, "forbidden\n", http.StatusForbidden)

	case auth.StatusThrottled:
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(result.RetryAfter)))
		http.Error(w, "too many failed authentication attempts\n", http.StatusTooManyRequests)

	case auth.StatusError:
		// 502 rather than 500: the service is working, the directory
		// behind it is not. nginx collapses everything outside
		// 2xx/401/403 into a 500 for the client anyway, so the
		// distinction lives in the logs, which is where it is useful.
		http.Error(w, "authentication backend unavailable\n", http.StatusBadGateway)

	default:
		http.Error(w, "authentication backend unavailable\n", http.StatusBadGateway)
	}
}

// handleHealth is the liveness endpoint.
//
// It reports on the process and nothing else. Making it depend on the directory
// would turn an LDAP outage into a restart loop, and each restart would discard
// the cache that was keeping the site up.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "ok")
}

// handleReady is the readiness endpoint.
func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	status := http.StatusOK
	if !s.ready.Load() {
		status = http.StatusServiceUnavailable
	}

	body := struct {
		Ready    bool   `json:"ready"`
		Uptime   string `json:"uptime"`
		Cache    any    `json:"cache"`
		Throttle any    `json:"throttle"`
	}{
		Ready:  s.ready.Load(),
		Uptime: time.Since(s.startedAt).Round(time.Second).String(),
	}

	if s.cache != nil {
		stats := s.cache.Stats()
		body.Cache = map[string]any{
			"backend":   s.cache.Name(),
			"entries":   stats.Entries,
			"hits":      stats.Hits,
			"misses":    stats.Misses,
			"evictions": stats.Evictions,
			"expired":   stats.Expired,
		}
	}

	if s.throttle != nil {
		stats := s.throttle.Stats()
		body.Throttle = map[string]any{
			"entries":         stats.Entries,
			"blocked":         stats.Blocked,
			"trips":           stats.Trips,
			"capacity_denied": stats.CapacityDenied,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(body); err != nil {
		s.log.Debug("write readiness response", slog.String("error", err.Error()))
	}
}

// logDecision writes the one log record per authentication request.
//
// Successful decisions are logged at debug on purpose. nginx calls this
// endpoint once per HTTP request, so info-level success would put a line in the
// journal for every image on every page — and bury the failures that matter.
func (s *Server) logDecision(r *http.Request, result auth.Result, elapsed time.Duration) {
	attrs := []slog.Attr{
		slog.String("result", result.Status.String()),
		slog.String("reason", result.Reason),
		slog.String("remote_addr", s.clientAddress(r)),
		slog.Int64("duration_ms", elapsed.Milliseconds()),
	}

	if result.Policy != "" {
		attrs = append(attrs, slog.String("policy", result.Policy))
	}

	// Omitted when the request was answered before the cache was consulted,
	// so that the field always means something about this decision.
	if result.Cache != "" {
		attrs = append(attrs, slog.String("cache", result.Cache))
	}

	if s.logUsername {
		if user := result.User; user != "" {
			attrs = append(attrs, slog.String("user", user))
		}
	}

	if result.MatchedGroup != "" {
		attrs = append(attrs, slog.String("matched_group", result.MatchedGroup))
	}

	if result.RetryAfter > 0 {
		attrs = append(attrs, slog.String("retry_after", result.RetryAfter.Round(time.Second).String()))
	}

	// The error is the diagnosis and never reaches the client. It is
	// attached to failures only: on success there is nothing to explain.
	if result.Err != nil && result.Status != auth.StatusAllow {
		attrs = append(attrs, slog.String("error", result.Err.Error()))
	}

	message, level := describe(result.Status)

	s.log.LogAttrs(r.Context(), level, message, attrs...)
}

// describe maps a status onto its log message and level.
func describe(status auth.Status) (message string, level slog.Level) {
	switch status {
	case auth.StatusAllow:
		return "authentication successful", slog.LevelDebug
	case auth.StatusUnauthenticated:
		return "authentication failed", slog.LevelInfo
	case auth.StatusForbidden:
		return "authorization failed", slog.LevelInfo
	case auth.StatusThrottled:
		return "authentication throttled", slog.LevelWarn
	case auth.StatusError:
		return "authentication backend failure", slog.LevelError
	default:
		return "authentication produced an unknown status", slog.LevelError
	}
}

// challenge builds the WWW-Authenticate value for a realm.
//
// The realm is a quoted string, so a realm containing a quote or a backslash
// would end it early and let the rest of the value be read as further
// parameters. It comes from a configuration file rather than from a request,
// which makes this cheap insurance rather than a live defence.
func challenge(realm string) string {
	escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(realm)

	return fmt.Sprintf(`Basic realm="%s", charset="UTF-8"`, escaped)
}

// retryAfterSeconds renders a block duration for the Retry-After header,
// rounding up so the value never invites a retry that is still too early.
func retryAfterSeconds(d time.Duration) int {
	if d <= 0 {
		return 1
	}

	return int(math.Ceil(d.Seconds()))
}

// sanitiseHeaderValue makes a directory-supplied value safe to put in a
// response header.
//
// Go's HTTP writer would reject a value containing a newline, which turns a
// successful authentication into a failed response. Stripping the characters
// keeps the login working and removes the header-splitting question entirely.
func sanitiseHeaderValue(value string) string {
	var builder strings.Builder

	for _, r := range value {
		if builder.Len() >= maxIdentityHeaderBytes {
			break
		}

		switch {
		case r == '\r' || r == '\n' || r == 0:
			// Dropped, not replaced: these are the characters that
			// would let a value continue into another header.
		case r < 0x20 || r == 0x7f:
			builder.WriteRune(' ')
		default:
			builder.WriteRune(r)
		}
	}

	return strings.TrimSpace(builder.String())
}
