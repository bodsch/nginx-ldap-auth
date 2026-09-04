package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
