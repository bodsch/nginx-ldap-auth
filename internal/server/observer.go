package server

import (
	"net/http"
	"time"

	"bodsch.me/nginx-ldap-auth/internal/auth"
)

// Observer receives one report per authentication decision and one per HTTP
// request.
//
// The interface is declared here, and internal/metrics implements it, so that
// this package carries no dependency on a metrics library and a test can assert
// what was reported without scraping an exposition format.
type Observer interface {
	// ObserveAuth reports a decision. The policy is empty when policy
	// resolution itself failed; the implementation decides what to record
	// in that case, because it owns the label's cardinality.
	ObserveAuth(policy string, status auth.Status, reason string, elapsed time.Duration)

	// ObserveHTTP reports a served request.
	ObserveHTTP(handler string, code int, elapsed time.Duration)
}

// nopObserver is used when no observer is configured, so that the request path
// has no branch on whether metrics are enabled.
type nopObserver struct{}

func (nopObserver) ObserveAuth(string, auth.Status, string, time.Duration) {}
func (nopObserver) ObserveHTTP(string, int, time.Duration)                 {}

// recorder captures the status code so that a request can be reported after it
// has been served.
//
// http.ResponseWriter does not expose what was written. Wrapping it is the
// only way to observe the code, and the wrapper has to stay transparent:
// anything the real writer offers and this one hides is a feature that
// silently stops working.
type recorder struct {
	http.ResponseWriter

	code    int
	written bool
}

// WriteHeader records the code on its way through.
func (r *recorder) WriteHeader(code int) {
	if !r.written {
		r.code = code
		r.written = true
	}

	r.ResponseWriter.WriteHeader(code)
}

// Write records the implicit 200 that writing a body without a WriteHeader
// call produces.
func (r *recorder) Write(b []byte) (int, error) {
	if !r.written {
		r.code = http.StatusOK
		r.written = true
	}

	return r.ResponseWriter.Write(b)
}

// Status returns the code that was sent, defaulting to 200 for a handler that
// wrote nothing at all.
func (r *recorder) Status() int {
	if !r.written {
		return http.StatusOK
	}

	return r.code
}

// observed wraps a handler so that its outcome is reported.
func (s *Server) observed(name string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		rec := &recorder{ResponseWriter: w}

		next(rec, r)

		s.observer.ObserveHTTP(name, rec.Status(), time.Since(started))
	}
}
