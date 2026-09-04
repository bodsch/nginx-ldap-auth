package ldap

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"time"

	goldap "github.com/go-ldap/ldap/v3"

	"bodsch.me/nginx-ldap-auth/internal/config"
)

// withService runs fn on the pooled service-account connection.
//
// A dropped connection is retried exactly once. Directories close idle
// connections, and a service that authenticates in bursts will find a dead
// connection on the first request after a quiet period; failing that request
// would turn an idle timeout into a 500 for a user who did nothing wrong. One
// retry covers that without turning a directory outage into a retry storm.
func (c *Client) withService(fn func(conn *goldap.Conn) error) error {
	c.serviceMu.Lock()
	defer c.serviceMu.Unlock()

	const attempts = 2

	var err error

	for attempt := range attempts {
		var conn *goldap.Conn

		conn, err = c.ensureService()
		if err != nil {
			return err
		}

		err = fn(conn)
		if err == nil {
			return nil
		}

		// Anything the directory answered is a real answer, including a
		// refusal. Only a broken transport is worth another try.
		if !isConnectionError(err) {
			return err
		}

		c.dropService()

		if attempt < attempts-1 {
			c.log.Debug("service connection lost, reconnecting", slog.String("error", err.Error()))
		}
	}

	return err
}

// ensureService returns a usable service-account connection, dialling and
// binding if necessary. The caller holds serviceMu.
func (c *Client) ensureService() (*goldap.Conn, error) {
	if c.serviceConn != nil && !c.serviceConn.IsClosing() {
		return c.serviceConn, nil
	}

	c.dropService()

	conn, err := c.dial()
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", c.cfg.URL, err)
	}

	// With no bind_dn the connection stays anonymous, which is what a
	// directory permitting anonymous search expects. Sending a bind with an
	// empty password instead would be an unauthenticated bind — the exact
	// operation this service refuses to perform on a user's behalf.
	if c.cfg.BindDN != "" {
		started := time.Now()

		err := conn.Bind(c.cfg.BindDN, c.cfg.BindPassword)

		c.observe(OperationServiceBind, started, err)

		if err != nil {
			_ = conn.Close()

			return nil, fmt.Errorf("bind as service account %s: %w", c.cfg.BindDN, err)
		}
	}

	c.serviceConn = conn

	return conn, nil
}

// dropService closes and forgets the pooled connection. The caller holds
// serviceMu.
func (c *Client) dropService() {
	if c.serviceConn != nil {
		// The connection is being discarded either way, and a close
		// error cannot change a decision that has already been made.
		_ = c.serviceConn.Close()
		c.serviceConn = nil
	}
}

// dial opens one connection to the directory.
func (c *Client) dial() (*goldap.Conn, error) {
	opts := []goldap.DialOpt{
		goldap.DialWithDialer(&net.Dialer{Timeout: c.cfg.BindTimeout.Duration()}),
	}

	if c.tls != nil {
		opts = append(opts, goldap.DialWithTLSConfig(c.tls))
	}

	conn, err := goldap.DialURL(c.cfg.URL, opts...)
	if err != nil {
		return nil, err
	}

	// Bounds every operation on this connection. go-ldap 3.4 has no
	// context-aware operations, so this deadline is what keeps a hung
	// directory from holding an nginx worker.
	conn.SetTimeout(c.cfg.OperationTimeout.Duration())

	if c.cfg.TLS.StartTLS {
		if err := conn.StartTLS(c.tls); err != nil {
			_ = conn.Close()

			return nil, fmt.Errorf("start TLS: %w", err)
		}
	}

	return conn, nil
}

// isConnectionError reports whether err describes a broken transport rather
// than an answer from the directory.
func isConnectionError(err error) bool {
	if goldap.IsErrorWithCode(err, goldap.ErrorNetwork) {
		return true
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}

	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
}

// tlsConfigFor builds the TLS settings for a directory, or returns nil for a
// plaintext connection.
func tlsConfigFor(cfg *config.LDAP) (*tls.Config, error) {
	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("parse url %q: %w", cfg.URL, err)
	}

	if parsed.Scheme != "ldaps" && !cfg.TLS.StartTLS {
		return nil, nil
	}

	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("url %q has no host to verify a certificate against", cfg.URL)
	}

	tlsConfig := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}

	if !cfg.TLS.VerifyCertificate() {
		// Reachable only through an explicit tls.verify: false, which
		// config validation reports as a warning naming the consequence.
		tlsConfig.InsecureSkipVerify = true //nolint:gosec // deliberate, opt-in, and warned about at startup
	}

	if len(cfg.TLS.CACertificates) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cfg.TLS.CACertificates) {
			return nil, fmt.Errorf("ca_file %s contains no PEM certificate", cfg.TLS.CAFile)
		}

		tlsConfig.RootCAs = pool
	}

	return tlsConfig, nil
}
