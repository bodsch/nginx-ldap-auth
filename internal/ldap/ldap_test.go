package ldap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"

	"git.boone-schulz.de/go/nginx-ldap-auth/internal/config"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestUserFilterEscapesInjection is the LDAP injection test.
//
// Interpolating a raw username into "(uid=%s)" lets the value close the
// comparison and add its own: "*)(uid=*" would turn a lookup for one account
// into a filter matching every entry with a uid, and the service would then
// find more than one match — or, with a differently shaped filter, exactly the
// wrong one.
func TestUserFilterEscapesInjection(t *testing.T) {
	client := &Client{cfg: &config.LDAP{UserFilter: "(uid=%s)"}}

	tests := map[string]string{
		"alice":       "(uid=alice)",
		"*":           `(uid=\2a)`,
		"*)(uid=*":    `(uid=\2a\29\28uid=\2a)`,
		"a(b)c":       `(uid=a\28b\29c)`,
		`back\slash`:  `(uid=back\5cslash)`,
		"nul\x00byte": `(uid=nul\00byte)`,
	}

	for user, want := range tests {
		if got := client.userFilter(user); got != want {
			t.Errorf("userFilter(%q) = %q, want %q", user, got, want)
		}
	}
}

// TestUserFilterEscapingSurvivesAComplexTemplate checks that escaping is
// applied to the value and not to the template around it.
func TestUserFilterEscapingSurvivesAComplexTemplate(t *testing.T) {
	client := &Client{cfg: &config.LDAP{
		UserFilter: "(&(objectClass=posixAccount)(uid=%s))",
	}}

	got := client.userFilter("*)(objectClass=*")
	want := `(&(objectClass=posixAccount)(uid=\2a\29\28objectClass=\2a))`

	if got != want {
		t.Errorf("userFilter = %q, want %q", got, want)
	}

	// The result has to still parse as one filter. If the escaping failed,
	// the injected parentheses would make this a different, valid filter
	// rather than an invalid one — so parsing alone is not the assertion,
	// but an unparsable result would be a second kind of bug.
	if _, err := goldap.CompileFilter(got); err != nil {
		t.Errorf("the escaped filter does not compile: %v", err)
	}
}

// TestAuthenticateRefusesEmptyPasswordWithoutConnecting is the anonymous-bind
// defence at the layer that issues the bind.
//
// The URL points nowhere. If the check were missing or ran too late, the error
// would be a connection failure — a 502 — instead of a rejection, and against a
// reachable directory it would be a successful anonymous bind.
func TestAuthenticateRefusesEmptyPasswordWithoutConnecting(t *testing.T) {
	client, err := New(&config.LDAP{
		Name:             "unreachable",
		URL:              "ldap://127.0.0.1:1",
		BaseDN:           "dc=example,dc=org",
		UserFilter:       "(uid=%s)",
		UserAttribute:    "uid",
		GroupSource:      config.GroupSourceNone,
		BindTimeout:      config.Duration(time.Second),
		OperationTimeout: config.Duration(time.Second),
	}, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	defer client.Close()

	for _, password := range []string{"", " ", "\t", "\n"} {
		_, err := client.Authenticate(context.Background(), "alice", password)

		if !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("Authenticate with password %q = %v, want ErrInvalidCredentials", password, err)
		}
	}
}

func TestAuthenticateHonoursCancelledContext(t *testing.T) {
	client, err := New(&config.LDAP{
		Name:             "unreachable",
		URL:              "ldap://127.0.0.1:1",
		BaseDN:           "dc=example,dc=org",
		UserFilter:       "(uid=%s)",
		UserAttribute:    "uid",
		GroupSource:      config.GroupSourceNone,
		BindTimeout:      config.Duration(time.Second),
		OperationTimeout: config.Duration(time.Second),
	}, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = client.Authenticate(ctx, "alice", "s3cret")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestGroupFromValue(t *testing.T) {
	tests := map[string]Group{
		"cn=web-users,ou=groups,dc=example,dc=org": {
			DN:   "cn=web-users,ou=groups,dc=example,dc=org",
			Name: "web-users",
		},
		"CN=Web-Users,OU=Groups,DC=example,DC=org": {
			DN:   "CN=Web-Users,OU=Groups,DC=example,DC=org",
			Name: "Web-Users",
		},
		// Some schemas and fixtures put a bare name in memberOf. Whether
		// the value parses as a DN is what decides how it is read.
		"web-users": {Name: "web-users"},
	}

	for value, want := range tests {
		got := groupFromValue(value)

		if got.DN != want.DN || got.Name != want.Name {
			t.Errorf("groupFromValue(%q) = %+v, want %+v", value, got, want)
		}
	}
}

func TestGroupString(t *testing.T) {
	tests := map[string]Group{
		"web-users":                     {DN: "cn=web-users,ou=groups,dc=example,dc=org", Name: "web-users"},
		"cn=nameless,dc=example,dc=org": {DN: "cn=nameless,dc=example,dc=org"},
	}

	for want, group := range tests {
		if got := group.String(); got != want {
			t.Errorf("Group%+v.String() = %q, want %q", group, got, want)
		}
	}
}

func TestTimeLimitSecondsRoundsUp(t *testing.T) {
	// Rounding down would send 0, which the protocol reads as "no limit" —
	// leaving the server free to run longer than the configured timeout.
	tests := map[time.Duration]int{
		0:                       1,
		-time.Second:            1,
		100 * time.Millisecond:  1,
		time.Second:             1,
		1500 * time.Millisecond: 2,
		5 * time.Second:         5,
	}

	for timeout, want := range tests {
		if got := timeLimitSeconds(timeout); got != want {
			t.Errorf("timeLimitSeconds(%s) = %d, want %d", timeout, got, want)
		}
	}
}

func TestTLSConfigFor(t *testing.T) {
	t.Run("ldaps verifies by default", func(t *testing.T) {
		cfg := &config.LDAP{URL: "ldaps://dir.example.org:636"}

		tlsConfig, err := tlsConfigFor(cfg)
		if err != nil {
			t.Fatalf("tlsConfigFor: %v", err)
		}

		if tlsConfig == nil {
			t.Fatal("no TLS configuration for an ldaps:// URL")
		}

		if tlsConfig.InsecureSkipVerify {
			t.Error("certificate verification is off without anyone asking for it")
		}

		if tlsConfig.ServerName != "dir.example.org" {
			t.Errorf("ServerName = %q, want the host from the URL", tlsConfig.ServerName)
		}

		if tlsConfig.MinVersion < 0x0303 {
			t.Errorf("MinVersion = %#x, want TLS 1.2 or later", tlsConfig.MinVersion)
		}
	})

	t.Run("plaintext ldap has no TLS", func(t *testing.T) {
		tlsConfig, err := tlsConfigFor(&config.LDAP{URL: "ldap://dir.example.org:389"})
		if err != nil {
			t.Fatalf("tlsConfigFor: %v", err)
		}

		if tlsConfig != nil {
			t.Error("a plaintext URL produced a TLS configuration")
		}
	})

	t.Run("StartTLS needs one", func(t *testing.T) {
		tlsConfig, err := tlsConfigFor(&config.LDAP{
			URL: "ldap://dir.example.org:389",
			TLS: config.TLS{StartTLS: true},
		})
		if err != nil {
			t.Fatalf("tlsConfigFor: %v", err)
		}

		if tlsConfig == nil {
			t.Fatal("StartTLS was configured but no TLS configuration was built")
		}
	})

	t.Run("verification can be turned off deliberately", func(t *testing.T) {
		verify := false

		tlsConfig, err := tlsConfigFor(&config.LDAP{
			URL: "ldaps://dir.example.org:636",
			TLS: config.TLS{Verify: &verify},
		})
		if err != nil {
			t.Fatalf("tlsConfigFor: %v", err)
		}

		if !tlsConfig.InsecureSkipVerify {
			t.Error("an explicit tls.verify: false was ignored")
		}
	})

	t.Run("a private CA is loaded", func(t *testing.T) {
		tlsConfig, err := tlsConfigFor(&config.LDAP{
			URL: "ldaps://dir.example.org:636",
			TLS: config.TLS{CAFile: "ca.pem", CACertificates: testCAPEM(t)},
		})
		if err != nil {
			t.Fatalf("tlsConfigFor: %v", err)
		}

		if tlsConfig.RootCAs == nil {
			t.Error("the CA file was not installed as a root")
		}
	})

	t.Run("a CA file without a certificate is an error", func(t *testing.T) {
		_, err := tlsConfigFor(&config.LDAP{
			URL: "ldaps://dir.example.org:636",
			TLS: config.TLS{CAFile: "ca.pem", CACertificates: []byte("not a certificate")},
		})
		if err == nil {
			t.Fatal("a CA file containing no PEM certificate was accepted")
		}

		if !strings.Contains(err.Error(), "ca.pem") {
			t.Errorf("error = %v, want it to name the file", err)
		}
	})
}

// TestIsConnectionError separates a broken transport, which is worth one retry,
// from an answer the directory actually gave, which is not.
func TestIsConnectionError(t *testing.T) {
	retryable := []error{
		goldap.NewError(goldap.ErrorNetwork, errors.New("connection reset")),
		io.EOF,
		net.ErrClosed,
		&net.OpError{Op: "dial", Err: errors.New("refused")},
	}

	for _, err := range retryable {
		if !isConnectionError(err) {
			t.Errorf("isConnectionError(%v) = false, want true", err)
		}
	}

	answered := []error{
		goldap.NewError(goldap.LDAPResultInvalidCredentials, errors.New("no")),
		goldap.NewError(goldap.LDAPResultNoSuchObject, errors.New("gone")),
		errors.New("something else"),
	}

	for _, err := range answered {
		if isConnectionError(err) {
			t.Errorf("isConnectionError(%v) = true, want false: the directory answered", err)
		}
	}
}

// selfSigned generates a certificate and key valid for 127.0.0.1.
//
// Generated rather than pasted in: a hardcoded certificate would either carry
// an expiry date that eventually breaks the test, or a fabricated body that
// only looks like one.
func selfSigned(t *testing.T) (certPEM []byte, pair tls.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-directory"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	pair, err = tls.X509KeyPair(certPEM, encodeKey(t, key))
	if err != nil {
		t.Fatalf("build key pair: %v", err)
	}

	return certPEM, pair
}

func encodeKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// testCAPEM keeps the CA-loading tests readable.
func testCAPEM(t *testing.T) []byte {
	t.Helper()

	certPEM, _ := selfSigned(t)

	return certPEM
}

// tlsDirectory starts a TLS listener presenting cert and returns its address.
//
// It speaks no LDAP. That is deliberate and sufficient: the TLS handshake
// happens before a single LDAP message is exchanged, so a certificate that
// cannot be verified is rejected here and never becomes an authentication
// question. The number of accepted connections is reported so a test can tell
// "the handshake failed" from "the connection was never made".
func tlsDirectory(t *testing.T, cert tls.Certificate) (address string, handshakes *atomic.Int64) {
	t.Helper()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	t.Cleanup(func() { _ = listener.Close() })

	handshakes = &atomic.Int64{}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			// The handshake is lazy, so it has to be forced before
			// it can be counted.
			if tlsConn, ok := conn.(*tls.Conn); ok {
				if err := tlsConn.Handshake(); err == nil {
					handshakes.Add(1)
				}
			}

			_ = conn.Close()
		}
	}()

	return listener.Addr().String(), handshakes
}

// directoryClient builds a client for address, with mutate applied to the
// configuration first.
func directoryClient(t *testing.T, address string, mutate func(*config.LDAP)) *Client {
	t.Helper()

	cfg := &config.LDAP{
		Name:             "test",
		URL:              "ldaps://" + address,
		BaseDN:           "dc=example,dc=org",
		UserFilter:       "(uid=%s)",
		UserAttribute:    "uid",
		GroupSource:      config.GroupSourceNone,
		BindTimeout:      config.Duration(2 * time.Second),
		OperationTimeout: config.Duration(2 * time.Second),
	}

	if mutate != nil {
		mutate(cfg)
	}

	client, err := New(cfg, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t.Cleanup(client.Close)

	return client
}

// TestUntrustedCertificateFailsSafely is the project.md §18 row "TLS
// certificate validation failure → Authentication fails safely", which had
// nothing behind it.
//
// "Safely" has a precise meaning here and both halves matter. The attempt must
// fail — a directory whose certificate cannot be verified may be an
// interception, and credentials must not be sent to it. And it must fail as an
// infrastructure error, not as ErrInvalidCredentials: a 401 would tell the user
// their password is wrong and invite them to type it again, into the connection
// that could not be trusted.
func TestUntrustedCertificateFailsSafely(t *testing.T) {
	_, pair := selfSigned(t)
	address, handshakes := tlsDirectory(t, pair)

	client := directoryClient(t, address, nil)

	_, err := client.Authenticate(context.Background(), "alice", "s3cret")
	if err == nil {
		t.Fatal("authentication succeeded against a directory with an unverifiable certificate")
	}

	if errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("err = %v, want an infrastructure error: a certificate problem is not a wrong password", err)
	}

	if !strings.Contains(err.Error(), "certificate") {
		t.Errorf("err = %v, want it to name the certificate as the cause", err)
	}

	if got := handshakes.Load(); got != 0 {
		t.Errorf("completed handshakes = %d, want 0: the client finished a handshake it should have refused", got)
	}
}

// TestConfiguredCAIsTrusted is the counterpart, and it is what makes the
// previous test mean something.
//
// Without it, "the connection failed" would be indistinguishable from "TLS is
// broken in this configuration for unrelated reasons", and tls.verify could be
// a no-op that happens to look correct because nothing ever succeeds.
func TestConfiguredCAIsTrusted(t *testing.T) {
	certPEM, pair := selfSigned(t)
	address, handshakes := tlsDirectory(t, pair)

	client := directoryClient(t, address, func(cfg *config.LDAP) {
		cfg.TLS.CAFile = "test-ca.pem"
		cfg.TLS.CACertificates = certPEM
	})

	// The listener speaks no LDAP, so this still fails — but past the
	// handshake, which is the part under test.
	_, err := client.Authenticate(context.Background(), "alice", "s3cret")
	if err == nil {
		t.Fatal("expected the LDAP exchange to fail against a listener that speaks no LDAP")
	}

	if strings.Contains(err.Error(), "certificate") {
		t.Errorf("err = %v, want the configured CA to have been accepted", err)
	}

	if got := handshakes.Load(); got == 0 {
		t.Error("no handshake completed, so the configured CA was not used as a root")
	}
}

// TestVerificationDisabledAcceptsAnyCertificate proves that tls.verify: false
// is honoured, so that the warning the configuration emits about it is not
// warning about nothing.
func TestVerificationDisabledAcceptsAnyCertificate(t *testing.T) {
	_, pair := selfSigned(t)
	address, handshakes := tlsDirectory(t, pair)

	verify := false
	client := directoryClient(t, address, func(cfg *config.LDAP) {
		cfg.TLS.Verify = &verify
	})

	_, err := client.Authenticate(context.Background(), "alice", "s3cret")
	if err == nil {
		t.Fatal("expected the LDAP exchange to fail against a listener that speaks no LDAP")
	}

	if got := handshakes.Load(); got == 0 {
		t.Errorf("no handshake completed, so tls.verify: false did not take effect (err: %v)", err)
	}
}

// TestGroupFilterEscapesInjection is the other half of the escaping promise.
//
// README and project.md §5 say every value reaching a filter is escaped. The
// user filter had a test; this one did not — and a group filter is interpolated
// with either the login name or the DN, both of which originate outside the
// service.
func TestGroupFilterEscapesInjection(t *testing.T) {
	tests := map[string]struct {
		filterValue string
		identity    *Identity
		want        string
	}{
		"login name": {
			filterValue: config.GroupFilterValueUser,
			identity:    &Identity{User: "*)(memberUid=*"},
			want:        `(&(objectClass=posixGroup)(memberUid=\2a\29\28memberUid=\2a))`,
		},
		"distinguished name": {
			filterValue: config.GroupFilterValueDN,
			identity:    &Identity{DN: `uid=a\2a,dc=example,dc=org`, User: "ignored"},
			want:        `(&(objectClass=posixGroup)(memberUid=uid=a\5c2a,dc=example,dc=org))`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client := &Client{cfg: &config.LDAP{
				GroupFilter:      "(&(objectClass=posixGroup)(memberUid=%s))",
				GroupFilterValue: test.filterValue,
			}}

			if got := client.groupFilter(test.identity); got != test.want {
				t.Errorf("groupFilter = %q, want %q", got, test.want)
			}
		})
	}
}
