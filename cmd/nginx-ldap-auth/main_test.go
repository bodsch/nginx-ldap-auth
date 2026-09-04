package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bodsch.me/nginx-ldap-auth/internal/config"
	"bodsch.me/nginx-ldap-auth/internal/metrics"
)

// validConfig writes a complete configuration plus its pepper file and returns
// the config path.
func validConfig(t *testing.T, listen string) string {
	t.Helper()

	dir := t.TempDir()

	pepper := filepath.Join(dir, "pepper.secret")
	if err := os.WriteFile(pepper, []byte(strings.Repeat("p", 64)), 0o600); err != nil {
		t.Fatalf("write pepper: %v", err)
	}

	path := filepath.Join(dir, "config.yaml")

	body := fmt.Sprintf(`
server:
  listen: %s
default_policy: intranet
policies:
  intranet:
    realm: "Intranet"
    ldap: primary
    allow_any_user: true
ldap:
  primary:
    url: ldaps://127.0.0.1:636
    base_dn: dc=example,dc=org
cache:
  enabled: true
  pepper_file: %s
`, listen, pepper)

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	return path
}

// invoke runs the command with args and captures both streams.
func invoke(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()

	var out, errOut bytes.Buffer

	err = run(args, &out, &errOut)

	return out.String(), errOut.String(), err
}

func TestVersionFlag(t *testing.T) {
	stdout, _, err := invoke(t, "--version")
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if !strings.Contains(stdout, "nginx-ldap-auth") {
		t.Errorf("stdout = %q, want the program name", stdout)
	}
}

// TestCheckAcceptsAValidConfiguration is the `--check` half of the systemd
// unit's ExecStartPre.
func TestCheckAcceptsAValidConfiguration(t *testing.T) {
	stdout, _, err := invoke(t, "--check", "--config", validConfig(t, "127.0.0.1:8080"))
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if !strings.Contains(stdout, "is valid") {
		t.Errorf("stdout = %q, want a confirmation", stdout)
	}
}

// TestCheckRefusesAnInvalidConfiguration is what turns a typo into a refused
// start rather than a running service with access rules nobody wrote.
//
// The unit runs this as ExecStartPre, so a non-nil error here is the difference
// between systemd reporting a failed start and systemd reporting success while
// the site is open.
func TestCheckRefusesAnInvalidConfiguration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	// A policy that decides nothing: no required groups and no explicit
	// allow_any_user.
	body := `
policies:
  intranet:
    realm: "Intranet"
    ldap: primary
ldap:
  primary:
    url: ldaps://127.0.0.1:636
    base_dn: dc=example,dc=org
cache:
  enabled: false
`

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	stdout, _, err := invoke(t, "--check", "--config", path)
	if err == nil {
		t.Fatal("an invalid configuration was accepted; systemd would report a successful start")
	}

	if strings.Contains(stdout, "is valid") {
		t.Errorf("stdout claims the configuration is valid: %q", stdout)
	}

	if !strings.Contains(err.Error(), "authorizes nobody and everybody") {
		t.Errorf("err = %v, want it to name the offending policy", err)
	}
}

// TestCheckDoesNotBindThePort proves `--check` is safe to run against a live
// configuration.
//
// The port is occupied for the duration of the test. If --check listened, it
// would fail here — and as ExecStartPre it would make every restart of a
// running service fail, which is the kind of guard that gets deleted rather
// than debugged.
func TestCheckDoesNotBindThePort(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	defer func() { _ = occupied.Close() }()

	if _, _, err := invoke(t, "--check", "--config", validConfig(t, occupied.Addr().String())); err != nil {
		t.Fatalf("--check failed against an occupied port, so it binds one: %v", err)
	}
}

// TestWarningsAreReportedEvenWhenLoadingFails: a bad file mode found alongside
// a validation error is still worth fixing in the same pass.
//
// Without this, an operator fixes the error, restarts, and only then learns
// that their secret file is world-readable.
func TestWarningsAreReportedEvenWhenLoadingFails(t *testing.T) {
	dir := t.TempDir()

	pepper := filepath.Join(dir, "pepper.secret")
	if err := os.WriteFile(pepper, []byte(strings.Repeat("p", 64)), 0o644); err != nil {
		t.Fatalf("write pepper: %v", err)
	}

	path := filepath.Join(dir, "config.yaml")

	body := fmt.Sprintf(`
logging:
  level: verbose
policies:
  intranet:
    realm: "Intranet"
    ldap: primary
    allow_any_user: true
ldap:
  primary:
    url: ldaps://127.0.0.1:636
    base_dn: dc=example,dc=org
cache:
  enabled: true
  pepper_file: %s
`, pepper)

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_, stderr, err := invoke(t, "--check", "--config", path)
	if err == nil {
		t.Fatal("expected the invalid logging level to be refused")
	}

	if !strings.Contains(stderr, "readable beyond its owner") {
		t.Errorf("stderr = %q, want the permission warning reported alongside the error", stderr)
	}
}

func TestMissingConfigurationFile(t *testing.T) {
	_, _, err := invoke(t, "--check", "--config", filepath.Join(t.TempDir(), "absent.yaml"))
	if err == nil {
		t.Fatal("a missing configuration file was accepted")
	}

	if !strings.Contains(err.Error(), "read configuration") {
		t.Errorf("err = %v, want it to say the file could not be read", err)
	}
}

func TestUnknownFlagIsRefused(t *testing.T) {
	// flag.ContinueOnError, so this returns rather than exiting the test
	// binary. A flag typo in the unit file must not start the service.
	if _, _, err := invoke(t, "--not-a-flag"); err == nil {
		t.Fatal("an unknown flag was accepted")
	}
}

// metricsConfig writes a configuration with both listeners enabled.
func metricsConfig(t *testing.T, listen, metricsAddress string) string {
	t.Helper()

	dir := t.TempDir()

	pepper := filepath.Join(dir, "pepper.secret")
	if err := os.WriteFile(pepper, []byte(strings.Repeat("p", 64)), 0o600); err != nil {
		t.Fatalf("write pepper: %v", err)
	}

	path := filepath.Join(dir, "config.yaml")

	body := fmt.Sprintf(`
server:
  listen: %s
default_policy: intranet
policies:
  intranet:
    realm: "Intranet"
    ldap: primary
    allow_any_user: true
ldap:
  primary:
    url: ldaps://127.0.0.1:636
    base_dn: dc=example,dc=org
cache:
  enabled: true
  pepper_file: %s
metrics:
  enabled: true
  address: %s
`, listen, pepper, metricsAddress)

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	return path
}

// TestBothListenersAreServed is the wiring test for the second listener.
//
// It is the one thing unit tests of internal/metrics cannot cover: that the
// exposition is actually reachable in a running process, on the address the
// configuration named, and not merely constructed.
func TestBothListenersAreServed(t *testing.T) {
	authAddress := freeAddress(t)
	metricsAddress := freeAddress(t)

	path := metricsConfig(t, authAddress, metricsAddress)

	cfg, _, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan error, 1)

	go func() { done <- serve(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil))) }()

	t.Cleanup(func() {
		cancel()

		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("serve did not return after its context was cancelled; " +
				"systemctl stop would hang and systemd would eventually SIGKILL the process")
		}
	})

	waitForHTTP(t, "http://"+authAddress+"/healthz")

	body := waitForHTTP(t, "http://"+metricsAddress+metrics.Path)

	for _, want := range []string{
		"nginx_ldap_auth_info",
		"nginx_ldap_auth_cache_entries",
		"nginx_ldap_auth_throttle_entries",
		"process_start_time_seconds",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the exposition is missing %q", want)
		}
	}
}

// TestSharedAddressIsRefusedBeforeStarting: two listeners on one address is a
// configuration error, and it has to be reported as one rather than as
// whichever listener lost the race to bind.
func TestSharedAddressIsRefusedBeforeStarting(t *testing.T) {
	address := freeAddress(t)

	_, _, err := invoke(t, "--check", "--config", metricsConfig(t, address, address))
	if err == nil {
		t.Fatal("a shared address was accepted")
	}

	if !strings.Contains(err.Error(), "separate addresses") {
		t.Errorf("err = %v, want it to explain the collision", err)
	}
}

// freeAddress returns a loopback address nothing is listening on.
func freeAddress(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	address := listener.Addr().String()

	if err := listener.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	return address
}

// waitForHTTP polls until the endpoint answers, and returns the body.
func waitForHTTP(t *testing.T, url string) string {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)

	for {
		resp, err := http.Get(url) //nolint:gosec,noctx // a loopback address this test just chose
		if err == nil {
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			if readErr == nil && resp.StatusCode == http.StatusOK {
				return string(body)
			}
		}

		if time.Now().After(deadline) {
			t.Fatalf("%s never answered: %v", url, err)
		}

		time.Sleep(5 * time.Millisecond)
	}
}
