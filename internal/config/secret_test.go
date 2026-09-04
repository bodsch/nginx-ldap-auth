package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadSecretFileStripsTrailingNewline(t *testing.T) {
	// Every editor and every `echo` appends one, and a bind password that
	// silently carries it fails against the directory with no clue why.
	path := writeFile(t, "bind.secret", "s3cret\n", 0o600)

	secret, warning, err := readSecretFile(path)
	if err != nil {
		t.Fatalf("readSecretFile: %v", err)
	}

	if string(secret) != "s3cret" {
		t.Errorf("secret = %q, want the trailing newline removed", secret)
	}

	if warning != "" {
		t.Errorf("unexpected warning for mode 0600: %q", warning)
	}
}

func TestReadSecretFilePreservesInteriorSpace(t *testing.T) {
	path := writeFile(t, "bind.secret", "two words\n", 0o600)

	secret, _, err := readSecretFile(path)
	if err != nil {
		t.Fatalf("readSecretFile: %v", err)
	}

	if string(secret) != "two words" {
		t.Errorf("secret = %q; interior whitespace may be part of the password", secret)
	}
}

func TestReadSecretFileRejections(t *testing.T) {
	dir := t.TempDir()

	empty := filepath.Join(dir, "empty.secret")
	if err := os.WriteFile(empty, []byte("\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		path string
		want string
	}{
		"missing":   {path: filepath.Join(dir, "absent.secret"), want: "does not exist"},
		"empty":     {path: empty, want: "is empty"},
		"directory": {path: dir, want: "is a directory"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, err := readSecretFile(test.path)
			if err == nil {
				t.Fatalf("expected an error naming %q", test.want)
			}

			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestReadSecretFileWarnsAboutPermissions(t *testing.T) {
	// A wrong mode is reported rather than refused: it has to be loud, but
	// refusing to start over it would turn the next routine restart into an
	// outage.
	path := writeFile(t, "bind.secret", "s3cret", 0o644)

	secret, warning, err := readSecretFile(path)
	if err != nil {
		t.Fatalf("readSecretFile: %v", err)
	}

	if string(secret) != "s3cret" {
		t.Errorf("secret = %q, want the file to still be read", secret)
	}

	if !strings.Contains(warning, "readable beyond its owner") {
		t.Errorf("warning = %q, want it to name the permission problem", warning)
	}

	if !strings.Contains(warning, "chmod 0640") {
		t.Errorf("warning = %q, want it to name the fix", warning)
	}
}

func TestLoadRejectsShortPepper(t *testing.T) {
	pepper := writeFile(t, "pepper.secret", "tooshort", 0o600)

	_, _, err := loadYAML(t, `
policies:
  intranet:
    ldap: primary
    allow_any_user: true
ldap:
  primary:
    url: ldaps://dir.example.org:636
    base_dn: dc=example,dc=org
cache:
  enabled: true
  pepper_file: `+pepper+`
`)
	if err == nil {
		t.Fatal("expected a short pepper to be refused")
	}

	if !strings.Contains(err.Error(), "at least 32 are required") {
		t.Errorf("error does not name the requirement: %v", err)
	}

	// The fix belongs in the message: an operator hitting this should not
	// have to look up how to generate one.
	if !strings.Contains(err.Error(), "openssl rand -hex 32") {
		t.Errorf("error does not name the fix: %v", err)
	}
}

func TestLoadRejectsMissingPepper(t *testing.T) {
	_, _, err := loadYAML(t, `
policies:
  intranet:
    ldap: primary
    allow_any_user: true
ldap:
  primary:
    url: ldaps://dir.example.org:636
    base_dn: dc=example,dc=org
cache:
  enabled: true
  pepper_file: /nonexistent/pepper.secret
`)
	if err == nil {
		t.Fatal("expected a missing pepper file to be refused")
	}

	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("error = %v, want it to say the file is missing", err)
	}
}

func TestLoadReadsSecrets(t *testing.T) {
	dir := t.TempDir()

	pepperPath := filepath.Join(dir, "pepper.secret")
	if err := os.WriteFile(pepperPath, []byte(strings.Repeat("p", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	bindPath := filepath.Join(dir, "bind.secret")
	if err := os.WriteFile(bindPath, []byte("servicepassword\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, _, err := loadYAML(t, `
policies:
  intranet:
    ldap: primary
    allow_any_user: true
ldap:
  primary:
    url: ldaps://dir.example.org:636
    base_dn: dc=example,dc=org
    bind_dn: cn=serviceuser,dc=example,dc=org
    bind_password_file: `+bindPath+`
cache:
  enabled: true
  pepper_file: `+pepperPath+`
`)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got := string(cfg.Cache.Pepper); got != strings.Repeat("p", 64) {
		t.Errorf("pepper = %q, want the file content", got)
	}

	if got := cfg.LDAP["primary"].BindPassword; got != "servicepassword" {
		t.Errorf("bind password = %q, want the file content", got)
	}
}

// TestLoadRejectsMissingBindPassword covers the §18 row "Missing or unreadable
// secret file → Refuse startup" for the directory's service account.
//
// The pepper had a test for this and the bind password did not, and the two
// fail differently: a missing pepper is caught immediately, while a bind
// password that silently loaded as the empty string would produce a service
// account performing an *unauthenticated* bind. The searches would then run
// anonymously, and on a directory that permits anonymous search everything
// would appear to work — until a user whose entry is only visible to the
// service account could not log in.
func TestLoadRejectsMissingBindPassword(t *testing.T) {
	pepper := writeFile(t, "pepper.secret", strings.Repeat("p", 64), 0o600)

	_, _, err := loadYAML(t, `
policies:
  intranet:
    ldap: primary
    allow_any_user: true
ldap:
  primary:
    url: ldaps://dir.example.org:636
    base_dn: dc=example,dc=org
    bind_dn: cn=serviceuser,dc=example,dc=org
    bind_password_file: /nonexistent/bind.secret
cache:
  enabled: true
  pepper_file: `+pepper+`
`)
	if err == nil {
		t.Fatal("expected a missing bind password file to be refused")
	}

	if !strings.Contains(err.Error(), "bind_password_file") {
		t.Errorf("error does not name the setting: %v", err)
	}
}

// TestLoadRejectsEmptyBindPassword is the same hazard from the other direction:
// a file that exists and holds nothing.
func TestLoadRejectsEmptyBindPassword(t *testing.T) {
	dir := t.TempDir()

	pepperPath := filepath.Join(dir, "pepper.secret")
	if err := os.WriteFile(pepperPath, []byte(strings.Repeat("p", 64)), 0o600); err != nil {
		t.Fatal(err)
	}

	bindPath := filepath.Join(dir, "bind.secret")
	if err := os.WriteFile(bindPath, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err := loadYAML(t, `
policies:
  intranet:
    ldap: primary
    allow_any_user: true
ldap:
  primary:
    url: ldaps://dir.example.org:636
    base_dn: dc=example,dc=org
    bind_dn: cn=serviceuser,dc=example,dc=org
    bind_password_file: `+bindPath+`
cache:
  enabled: true
  pepper_file: `+pepperPath+`
`)
	if err == nil {
		t.Fatal("expected an empty bind password file to be refused")
	}

	if !strings.Contains(err.Error(), "is empty") {
		t.Errorf("error = %v, want it to say the file is empty", err)
	}
}

// TestLoadRejectsUnreadableConfiguration covers what a crash or a bad deploy
// leaves behind: a path that is not a readable YAML file.
//
// Each of these has to produce a message naming the file. Starting with a
// half-loaded configuration would mean serving requests under access rules
// nobody wrote.
func TestLoadRejectsUnreadableConfiguration(t *testing.T) {
	dir := t.TempDir()

	binary := filepath.Join(dir, "binary.yaml")
	if err := os.WriteFile(binary, []byte{0x00, 0xff, 0xfe, 0x01, 0x02}, 0o600); err != nil {
		t.Fatal(err)
	}

	truncated := filepath.Join(dir, "truncated.yaml")
	if err := os.WriteFile(truncated, []byte("policies:\n  intranet:\n    ldap: prim"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := map[string]string{
		"a directory where a file belongs": dir,
		"a path that does not exist":       filepath.Join(dir, "absent.yaml"),
		"binary junk":                      binary,
	}

	for name, path := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Load(path); err == nil {
				t.Fatal("expected the configuration to be refused")
			}
		})
	}

	// A truncated file is the one case that can still parse: YAML is
	// happy with it, so the refusal has to come from validation rather
	// than from the parser — which is exactly why validation must not be
	// skippable.
	t.Run("a truncated file", func(t *testing.T) {
		_, _, err := Load(truncated)
		if err == nil {
			t.Fatal("expected a truncated configuration to be refused")
		}

		if !strings.Contains(err.Error(), "invalid configuration") {
			t.Errorf("err = %v, want validation to have caught it", err)
		}
	})
}

// TestEmptyConfigurationIsRefusedForTheRightReason checks the error an operator
// actually sees when they point the service at the wrong file.
//
// An empty document parses cleanly and produces a configuration with no
// policies. The message has to say that, not "unexpected EOF", or the reported
// problem is a YAML curiosity instead of the missing section.
func TestEmptyConfigurationIsRefusedForTheRightReason(t *testing.T) {
	_, _, err := loadYAML(t, "")
	if err == nil {
		t.Fatal("expected an empty configuration to be refused")
	}

	if !strings.Contains(err.Error(), "no policy configured") {
		t.Errorf("err = %v, want it to name the missing policies section", err)
	}

	if !strings.Contains(err.Error(), "no directory configured") {
		t.Errorf("err = %v, want it to name the missing ldap section too", err)
	}
}
