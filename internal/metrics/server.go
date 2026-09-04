package metrics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"bodsch.me/nginx-ldap-auth/internal/config"
)

// Path is where the exposition is served.
const Path = "/metrics"

// Listener serves the exposition on its own address.
//
// A separate listener rather than another route on the authentication port, so
// that the two can be firewalled independently. The authentication endpoint has
// to be reachable by nginx and by nothing else; the exposition has to be
// reachable by the monitoring system and by nothing else. Those are different
// sets, and one listener cannot express that.
type Listener struct {
	cfg     config.Metrics
	log     *slog.Logger
	httpSrv *http.Server
}

// NewListener returns a Listener serving m.
func NewListener(cfg config.Metrics, m *Metrics, log *slog.Logger) *Listener {
	mux := http.NewServeMux()
	mux.Handle(Path, m.Handler())

	return &Listener{
		cfg: cfg,
		log: log,
		httpSrv: &http.Server{
			Addr:    cfg.Address,
			Handler: mux,

			// A scrape carries no body, so the header is all there is
			// to read. The timeouts are generous compared to the
			// authentication listener because a scrape of a large
			// exposition is legitimately slower than a decision.
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    16 * 1024,
		},
	}
}

// Serve listens until ctx is cancelled, then shuts down.
func (l *Listener) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", l.cfg.Address)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", l.cfg.Address, err)
	}

	l.log.Info("serving metrics",
		slog.String("address", listener.Addr().String()),
		slog.String("path", Path))

	serveErr := make(chan error, 1)

	go func() {
		err := l.httpSrv.Serve(listener)
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

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := l.httpSrv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}

	return <-serveErr
}
