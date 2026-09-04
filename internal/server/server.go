// Package server exposes the authentication decision over HTTP.
//
// The package is named for what it is rather than for the directory convention,
// because a package called http next to net/http makes every file in it import
// the standard library under an alias.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"git.boone-schulz.de/go/nginx-ldap-auth/internal/auth"
	"git.boone-schulz.de/go/nginx-ldap-auth/internal/cache"
	"git.boone-schulz.de/go/nginx-ldap-auth/internal/config"
	"git.boone-schulz.de/go/nginx-ldap-auth/internal/ratelimit"
)

// Paths served by the service.
const (
	PathAuth   = "/auth"
	PathHealth = "/healthz"
	PathReady  = "/readyz"
)

// Server wires the authenticator to an HTTP listener.
type Server struct {
	cfg  config.Server
	auth *auth.Authenticator
	log  *slog.Logger

	cache    cache.Cache
	throttle ratelimit.Throttle

	// logUsername mirrors logging.log_username.
	logUsername bool

	// ready is set once startup finished. It is not tied to directory
	// reachability: a transient LDAP outage must not make the service look
	// broken, because the reaction to that is a restart, and a restart also
	// throws away the cache that was absorbing the outage.
	ready atomic.Bool

	startedAt time.Time
	httpSrv   *http.Server

	// addr is the address the listener actually bound, published once it is
	// up. With a configured port of 0 the caller cannot know it in advance,
	// and a test that guesses a port is a test that fails on a busy machine.
	addr atomic.Pointer[string]
}

// Options are the Server's dependencies.
type Options struct {
	Config        config.Server
	Authenticator *auth.Authenticator
	Cache         cache.Cache
	Throttle      ratelimit.Throttle
	LogUsername   bool
	Logger        *slog.Logger
}

// New returns a Server.
func New(opts Options) (*Server, error) {
	switch {
	case opts.Authenticator == nil:
		return nil, fmt.Errorf("authenticator is required")
	case opts.Logger == nil:
		return nil, fmt.Errorf("logger is required")
	}

	srv := &Server{
		cfg:         opts.Config,
		auth:        opts.Authenticator,
		log:         opts.Logger,
		cache:       opts.Cache,
		throttle:    opts.Throttle,
		logUsername: opts.LogUsername,
		startedAt:   time.Now(),
	}

	srv.httpSrv = &http.Server{
		Addr:    opts.Config.Listen,
		Handler: srv.Handler(),

		// ReadHeaderTimeout is separate from ReadTimeout on purpose: the
		// authentication request carries no body, so the header is all
		// there is to read, and a client that opens a connection and
		// sends nothing must not hold a slot.
		ReadHeaderTimeout: opts.Config.ReadTimeout.Duration(),
		ReadTimeout:       opts.Config.ReadTimeout.Duration(),
		WriteTimeout:      opts.Config.WriteTimeout.Duration(),
		IdleTimeout:       opts.Config.IdleTimeout.Duration(),
		MaxHeaderBytes:    opts.Config.MaxHeaderBytes,
	}

	return srv, nil
}

// Handler returns the request multiplexer, exported so that tests can drive it
// without binding a port.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(PathAuth, s.handleAuth)
	mux.HandleFunc(PathHealth, s.handleHealth)
	mux.HandleFunc(PathReady, s.handleReady)

	return mux
}

// Serve listens and serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.cfg.Listen, err)
	}

	bound := listener.Addr().String()
	s.addr.Store(&bound)
	s.ready.Store(true)

	s.log.Info("listening", slog.String("address", bound))

	serveErr := make(chan error, 1)

	go func() {
		err := s.httpSrv.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}

		serveErr <- err
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
	}

	s.ready.Store(false)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout.Duration())
	defer cancel()

	if err := s.httpSrv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}

	return <-serveErr
}

// MarkReady marks the service ready without running a listener. It exists for
// callers that drive Handler directly.
func (s *Server) MarkReady() {
	s.ready.Store(true)
}

// Addr returns the address the listener bound, or the empty string before Serve
// has bound one.
func (s *Server) Addr() string {
	if bound := s.addr.Load(); bound != nil {
		return *bound
	}

	return ""
}

// clientAddress determines the address the throttle counts against.
//
// The configured header wins when it is present, because behind nginx the peer
// address is the proxy for every request. A malformed or absent value falls
// back to the peer, which throttles everyone as one client — degraded, but
// never off.
func (s *Server) clientAddress(r *http.Request) string {
	if s.cfg.ClientIPHeader != "" {
		if value := r.Header.Get(s.cfg.ClientIPHeader); value != "" {
			// X-Forwarded-For style lists put the original client
			// first. Taking the first element means a client that
			// sends its own header prepends to it rather than
			// replacing what nginx appended.
			value, _, _ = strings.Cut(value, ",")

			if address := net.ParseIP(strings.TrimSpace(value)); address != nil {
				return address.String()
			}
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return host
}
