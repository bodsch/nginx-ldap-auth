package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeFile puts content at a path under the test's temporary directory and
// returns the absolute path.
func writeFile(t *testing.T, name, content string, mode os.FileMode) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)

	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}

	return path
}

// loadYAML writes a configuration file and loads it.
func loadYAML(t *testing.T, yaml string) (*Config, []string, error) {
	t.Helper()

	return Load(writeFile(t, "config.yaml", yaml, 0o600))
}

func TestLoadAppliesDefaults(t *testing.T) {
	cfg, warnings, err := loadYAML(t, `
policies:
  intranet:
    ldap: primary
    allow_any_user: true
ldap:
  primary:
    url: ldaps://dir.example.org:636
    base_dn: dc=example,dc=org
cache:
  enabled: false
`)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Server.Listen != "127.0.0.1:8080" {
		t.Errorf("server.listen = %q, want the loopback default", cfg.Server.Listen)
	}

	if cfg.Server.ReadTimeout.Duration() != 5*time.Second {
		t.Errorf("server.read_timeout = %s, want 5s", cfg.Server.ReadTimeout)
	}

	if got := cfg.Policies["intranet"].Realm; got != "Restricted" {
		t.Errorf("policy realm = %q, want the default", got)
	}

	if got := cfg.Policies["intranet"].Name; got != "intranet" {
		t.Errorf("policy name = %q, want it copied from the map key", got)
	}

	dir := cfg.LDAP["primary"]

	if dir.UserFilter != "(uid=%s)" {
		t.Errorf("user_filter = %q, want the default", dir.UserFilter)
	}

	if dir.GroupSource != GroupSourceNone {
		t.Errorf("group_source = %q, want %q when neither filter nor attribute is set",
			dir.GroupSource, GroupSourceNone)
	}

	if !dir.TLS.VerifyCertificate() {
		t.Error("tls.verify defaulted to false; an omitted key must not disable certificate validation")
	}

	if !cfg.Logging.LogUsername {
		t.Error("logging.log_username defaulted to false, want true")
	}

	// The cache is off in this fixture, which is worth saying out loud but
	// is not an error.
	if len(warnings) == 0 {
		t.Error("expected a warning about the disabled cache")
	}
}

// TestExplicitTLSVerifyFalseSurvives is a regression test.
//
// tls.verify defaults to true, and a map entry's defaults cannot be pre-filled.
// An earlier version normalised an absent block by setting Verify to true when
// it was false — which silently re-enabled verification for anyone who had
// deliberately turned it off, and made the startup warning disappear with it.
func TestExplicitTLSVerifyFalseSurvives(t *testing.T) {
	cfg, warnings, err := loadYAML(t, `
policies:
  intranet:
    ldap: primary
    allow_any_user: true
ldap:
  primary:
    url: ldaps://dir.example.org:636
    base_dn: dc=example,dc=org
    tls:
      verify: false
cache:
  enabled: false
`)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.LDAP["primary"].TLS.VerifyCertificate() {
		t.Fatal("an explicit tls.verify: false was overwritten with true")
	}

	if !containsSubstring(warnings, "tls.verify is false") {
		t.Errorf("expected a warning naming the disabled verification, got %q", warnings)
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	_, _, err := loadYAML(t, "server:\n  listne: 127.0.0.1:8080\n")
	if err == nil {
		t.Fatal("expected a misspelled key to be rejected")
	}

	if !strings.Contains(err.Error(), "listne") {
		t.Errorf("error does not name the offending key: %v", err)
	}
}

func TestGroupSourceInference(t *testing.T) {
	tests := map[string]struct {
		directory string
		want      string
	}{
		"filter": {
			directory: `
    group_base_dn: ou=groups,dc=example,dc=org
    group_filter: "(memberUid=%s)"`,
			want: GroupSourceFilter,
		},
		"attribute": {
			directory: "\n    group_attribute: memberOf",
			want:      GroupSourceAttribute,
		},
		"none": {
			directory: "",
			want:      GroupSourceNone,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, _, err := loadYAML(t, `
policies:
  intranet:
    ldap: primary
    allow_any_user: true
ldap:
  primary:
    url: ldaps://dir.example.org:636
    base_dn: dc=example,dc=org`+test.directory+`
cache:
  enabled: false
`)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}

			if got := cfg.LDAP["primary"].GroupSource; got != test.want {
				t.Errorf("group_source = %q, want %q", got, test.want)
			}
		})
	}
}

func TestValidationRejects(t *testing.T) {
	base := func(body string) string {
		return body + "\ncache:\n  enabled: false\n"
	}

	tests := map[string]struct {
		yaml string
		want string
	}{
		"policy without authorization decision": {
			yaml: base(`
policies:
  intranet:
    ldap: primary
ldap:
  primary:
    url: ldaps://dir.example.org:636
    base_dn: dc=example,dc=org`),
			want: "authorizes nobody and everybody at once",
		},
		"require_groups together with allow_any_user": {
			yaml: base(`
policies:
  intranet:
    ldap: primary
    allow_any_user: true
    require_groups: [admins]
ldap:
  primary:
    url: ldaps://dir.example.org:636
    base_dn: dc=example,dc=org
    group_attribute: memberOf`),
			want: "would make the group check pointless",
		},
		"require_groups without a group source": {
			yaml: base(`
policies:
  intranet:
    ldap: primary
    require_groups: [admins]
ldap:
  primary:
    url: ldaps://dir.example.org:636
    base_dn: dc=example,dc=org`),
			want: "resolves no groups",
		},
		"policy referencing an unconfigured directory": {
			yaml: base(`
policies:
  intranet:
    ldap: elsewhere
    allow_any_user: true
ldap:
  primary:
    url: ldaps://dir.example.org:636
    base_dn: dc=example,dc=org`),
			want: `is not a configured directory`,
		},
		"unknown default policy": {
			yaml: base(`
default_policy: nope
policies:
  intranet:
    ldap: primary
    allow_any_user: true
ldap:
  primary:
    url: ldaps://dir.example.org:636
    base_dn: dc=example,dc=org`),
			want: "is not a configured policy",
		},
		"plaintext ldap without StartTLS": {
			yaml: base(`
policies:
  intranet:
    ldap: primary
    allow_any_user: true
ldap:
  primary:
    url: ldap://dir.example.org:389
    base_dn: dc=example,dc=org`),
			want: "would send credentials in the clear",
		},
		"StartTLS on an ldaps URL": {
			yaml: base(`
policies:
  intranet:
    ldap: primary
    allow_any_user: true
ldap:
  primary:
    url: ldaps://dir.example.org:636
    base_dn: dc=example,dc=org
    tls:
      start_tls: true`),
			want: "cannot be used with an ldaps:// URL",
		},
		"trusted client address header on a public listener": {
			yaml: base(`
server:
  listen: 0.0.0.0:8080
policies:
  intranet:
    ldap: primary
    allow_any_user: true
ldap:
  primary:
    url: ldaps://dir.example.org:636
    base_dn: dc=example,dc=org`),
			want: "forge its own source address",
		},
		"no policies": {
			yaml: base(`
ldap:
  primary:
    url: ldaps://dir.example.org:636
    base_dn: dc=example,dc=org`),
			want: "no policy configured",
		},
		"redis without a cache": {
			yaml: base(`
redis:
  enabled: true
policies:
  intranet:
    ldap: primary
    allow_any_user: true
ldap:
  primary:
    url: ldaps://dir.example.org:636
    base_dn: dc=example,dc=org`),
			want: "Redis is a cache backend",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, err := loadYAML(t, test.yaml)
			if err == nil {
				t.Fatalf("expected the configuration to be refused, want an error naming %q", test.want)
			}

			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("error does not explain the problem\n got: %v\nwant substring: %q", err, test.want)
			}
		})
	}
}

// TestValidationReportsEveryProblem checks that fixing a configuration takes
// one pass, not one restart per mistake.
func TestValidationReportsEveryProblem(t *testing.T) {
	_, _, err := loadYAML(t, `
logging:
  level: verbose
  format: yaml
policies:
  intranet:
    ldap: primary
    allow_any_user: true
ldap:
  primary:
    url: ldaps://dir.example.org:636
    base_dn: "not a dn"
cache:
  enabled: false
`)
	if err == nil {
		t.Fatal("expected the configuration to be refused")
	}

	for _, want := range []string{"logging.level", "logging.format", "base_dn"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error omits %q, so it would take another restart to find:\n%v", want, err)
		}
	}
}

func TestFilterTemplateValidation(t *testing.T) {
	valid := []string{
		"(uid=%s)",
		"(&(objectClass=posixAccount)(uid=%s))",
		"(&(objectClass=posixGroup)(memberUid=%s))",
	}

	invalid := map[string]string{
		"":            "must be set",
		"uid=%s":      "not a parenthesised LDAP filter",
		"(uid=alice)": "expected exactly one placeholder",
		"(uid=%v)":    "uses a placeholder other than %s",
		"(%s)":        "where an attribute name belongs",
		"(uid=100%%)": "contains 2 % signs",
		// Two placeholders would leave the second as %!s(MISSING) in the
		// filter that is actually sent.
		"(|(uid=%s)(mail=%s))": "contains 2 % signs",
	}

	for _, filter := range valid {
		if err := validateFilterTemplate(filter); err != nil {
			t.Errorf("validateFilterTemplate(%q) = %v, want no error", filter, err)
		}
	}

	for filter, want := range invalid {
		err := validateFilterTemplate(filter)
		if err == nil {
			t.Errorf("validateFilterTemplate(%q) accepted the template, want an error naming %q", filter, want)

			continue
		}

		if !strings.Contains(err.Error(), want) {
			t.Errorf("validateFilterTemplate(%q) = %v, want substring %q", filter, err, want)
		}
	}
}

func TestPolicyNameCharset(t *testing.T) {
	// The name arrives in a header and becomes a metric label, so the
	// character set is deliberately narrow.
	rejected := []string{"bad name", "with/slash", "-leading-dash", "with\"quote", strings.Repeat("x", 65)}

	for _, name := range rejected {
		if policyNamePattern.MatchString(name) {
			t.Errorf("policy name %q was accepted", name)
		}
	}

	for _, name := range []string{"intranet", "web-2", "a.b_c", "X"} {
		if !policyNamePattern.MatchString(name) {
			t.Errorf("policy name %q was rejected", name)
		}
	}
}

func containsSubstring(values []string, want string) bool {
	for _, value := range values {
		if strings.Contains(value, want) {
			return true
		}
	}

	return false
}

func TestMetricsValidation(t *testing.T) {
	base := func(metrics string) string {
		return `
server:
  listen: 127.0.0.1:8080
policies:
  intranet:
    ldap: primary
    allow_any_user: true
ldap:
  primary:
    url: ldaps://dir.example.org:636
    base_dn: dc=example,dc=org
cache:
  enabled: false
` + metrics
	}

	t.Run("enabled and valid", func(t *testing.T) {
		cfg, _, err := loadYAML(t, base("metrics:\n  enabled: true\n  address: 127.0.0.1:9931\n"))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if !cfg.Metrics.Enabled {
			t.Error("metrics.enabled was not read")
		}
	})

	t.Run("no address", func(t *testing.T) {
		_, _, err := loadYAML(t, base("metrics:\n  enabled: true\n  address: \"\"\n"))
		if err == nil || !strings.Contains(err.Error(), "metrics.address must be set") {
			t.Errorf("err = %v, want a refusal naming metrics.address", err)
		}
	})

	// Two listeners cannot share an address, and the failure has to name
	// both settings rather than surfacing as "address already in use" from
	// whichever listener lost the race.
	t.Run("same address as the authentication listener", func(t *testing.T) {
		_, _, err := loadYAML(t, base("metrics:\n  enabled: true\n  address: 127.0.0.1:8080\n"))
		if err == nil {
			t.Fatal("a shared address was accepted")
		}

		for _, want := range []string{"metrics.address", "server.listen"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("err = %v, want it to name %s", err, want)
			}
		}
	})

	// The exposition names policies and carries failure counts. Binding it
	// publicly is allowed — some setups scrape across a network — but it
	// must be said out loud.
	t.Run("public address warns", func(t *testing.T) {
		_, warnings, err := loadYAML(t, base("metrics:\n  enabled: true\n  address: 0.0.0.0:9931\n"))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if !containsSubstring(warnings, "monitoring network") {
			t.Errorf("warnings = %q, want one about exposure", warnings)
		}
	})

	// Metrics used to be refused as unimplemented. A configuration that
	// enables them must now start without a warning saying otherwise.
	t.Run("no longer reported as unimplemented", func(t *testing.T) {
		_, warnings, err := loadYAML(t, base("metrics:\n  enabled: true\n  address: 127.0.0.1:9931\n"))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if containsSubstring(warnings, "not implemented") {
			t.Errorf("warnings = %q, still claim metrics are unimplemented", warnings)
		}
	})
}

func TestRedisValidation(t *testing.T) {
	pepper := writeFile(t, "pepper.secret", strings.Repeat("p", 64), 0o600)

	withRedis := func(redis string) string {
		return `
policies:
  intranet:
    ldap: primary
    allow_any_user: true
ldap:
  primary:
    url: ldaps://dir.example.org:636
    base_dn: dc=example,dc=org
    operation_timeout: 5s
cache:
  enabled: true
  pepper_file: ` + pepper + `
` + redis
	}

	t.Run("enabled and valid", func(t *testing.T) {
		cfg, _, err := loadYAML(t, withRedis("redis:\n  enabled: true\n  address: 127.0.0.1:6379\n  timeout: 1s\n"))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if !cfg.Redis.Enabled {
			t.Error("redis.enabled was not read")
		}
	})

	t.Run("bad address", func(t *testing.T) {
		_, _, err := loadYAML(t, withRedis("redis:\n  enabled: true\n  address: not-an-address\n  timeout: 1s\n"))
		if err == nil || !strings.Contains(err.Error(), "redis.address") {
			t.Errorf("err = %v, want a refusal naming redis.address", err)
		}
	})

	// A cache slower than the directory it spares is worse than no cache:
	// the request pays the Redis timeout and then does the bind anyway.
	t.Run("timeout not shorter than the directory's warns", func(t *testing.T) {
		_, warnings, err := loadYAML(t, withRedis("redis:\n  enabled: true\n  address: 127.0.0.1:6379\n  timeout: 5s\n"))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if !containsSubstring(warnings, "cost more than the directory lookup") {
			t.Errorf("warnings = %q, want one about the timeout ordering", warnings)
		}
	})

	// The shared cache holds credential-derived keys and authorization
	// decisions. An unauthenticated Redis is a decision, not a default.
	t.Run("no password warns", func(t *testing.T) {
		_, warnings, err := loadYAML(t, withRedis("redis:\n  enabled: true\n  address: 127.0.0.1:6379\n  timeout: 1s\n"))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if !containsSubstring(warnings, "should require authentication") {
			t.Errorf("warnings = %q, want one about the missing password", warnings)
		}
	})

	t.Run("password file is loaded", func(t *testing.T) {
		password := writeFile(t, "redis.secret", "redispassword\n", 0o600)

		cfg, _, err := loadYAML(t, withRedis(
			"redis:\n  enabled: true\n  address: 127.0.0.1:6379\n  timeout: 1s\n  password_file: "+password+"\n"))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if cfg.Redis.Password != "redispassword" {
			t.Errorf("redis password = %q, want the file content", cfg.Redis.Password)
		}
	})

	t.Run("missing password file refuses startup", func(t *testing.T) {
		_, _, err := loadYAML(t, withRedis(
			"redis:\n  enabled: true\n  address: 127.0.0.1:6379\n  timeout: 1s\n  password_file: /nonexistent\n"))
		if err == nil || !strings.Contains(err.Error(), "redis.password_file") {
			t.Errorf("err = %v, want a refusal naming redis.password_file", err)
		}
	})
}

func TestSessionValidation(t *testing.T) {
	secret := writeFile(t, "session.secret", strings.Repeat("s", 64), 0o600)

	withSession := func(session string) string {
		return `
policies:
  intranet:
    ldap: primary
    allow_any_user: true
ldap:
  primary:
    url: ldaps://dir.example.org:636
    base_dn: dc=example,dc=org
cache:
  enabled: false
` + session
	}

	t.Run("enabled and valid", func(t *testing.T) {
		cfg, _, err := loadYAML(t, withSession(
			"session:\n  enabled: true\n  secret_file: "+secret+"\n"))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if !cfg.Session.Enabled {
			t.Fatal("session.enabled was not read")
		}

		// The two timeouts the feature exists for, and the settings that
		// decide who the cookie reaches, all have to default without
		// being written down.
		switch {
		case cfg.Session.AbsoluteTimeout.Duration() != 8*time.Hour:
			t.Errorf("absolute_timeout = %s, want 8h", cfg.Session.AbsoluteTimeout)
		case cfg.Session.IdleTimeout.Duration() != 30*time.Minute:
			t.Errorf("idle_timeout = %s, want 30m", cfg.Session.IdleTimeout)
		case cfg.Session.CookieName != "nginx_ldap_auth":
			t.Errorf("cookie_name = %q, want nginx_ldap_auth", cfg.Session.CookieName)
		case !cfg.Session.SecureCookie():
			t.Error("secure defaulted to false; the cookie would travel over plaintext HTTP")
		case !cfg.Session.AllowBasic:
			t.Error("allow_basic defaulted to false; every curl client would break on upgrade")
		case string(cfg.Session.Secret) != strings.Repeat("s", 64):
			t.Error("the signing secret was not loaded")
		}
	})

	// Sessions are off unless asked for. Enabling them changes how every
	// protected location behaves, so it must not happen on an upgrade.
	t.Run("disabled by default", func(t *testing.T) {
		cfg, _, err := loadYAML(t, withSession(""))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if cfg.Session.Enabled {
			t.Error("session.enabled defaulted to true")
		}
	})

	// An unsigned cookie is a request parameter: a visitor could name any
	// user in any group.
	t.Run("no secret file", func(t *testing.T) {
		_, _, err := loadYAML(t, withSession("session:\n  enabled: true\n"))
		if err == nil || !strings.Contains(err.Error(), "session.secret_file") {
			t.Errorf("err = %v, want a refusal naming session.secret_file", err)
		}
	})

	t.Run("short secret", func(t *testing.T) {
		short := writeFile(t, "short.secret", "too-short", 0o600)

		_, _, err := loadYAML(t, withSession("session:\n  enabled: true\n  secret_file: "+short+"\n"))
		if err == nil || !strings.Contains(err.Error(), "at least 32") {
			t.Errorf("err = %v, want a refusal naming the minimum length", err)
		}
	})

	// An idle window longer than the absolute lifetime can never end a
	// session, which makes it a setting that silently does nothing.
	t.Run("idle longer than absolute", func(t *testing.T) {
		_, _, err := loadYAML(t, withSession(
			"session:\n  enabled: true\n  secret_file: "+secret+
				"\n  absolute_timeout: 1h\n  idle_timeout: 2h\n"))
		if err == nil || !strings.Contains(err.Error(), "idle_timeout") {
			t.Errorf("err = %v, want a refusal naming idle_timeout", err)
		}
	})

	// A login form on /auth would answer every authorization subrequest
	// with an HTML page and a 200.
	t.Run("login path shadows an endpoint", func(t *testing.T) {
		_, _, err := loadYAML(t, withSession(
			"session:\n  enabled: true\n  secret_file: "+secret+"\n  login_path: /auth\n"))
		if err == nil || !strings.Contains(err.Error(), "session.login_path") {
			t.Errorf("err = %v, want a refusal naming session.login_path", err)
		}
	})

	t.Run("login and logout on the same path", func(t *testing.T) {
		_, _, err := loadYAML(t, withSession(
			"session:\n  enabled: true\n  secret_file: "+secret+
				"\n  login_path: /sso\n  logout_path: /sso\n"))
		if err == nil || !strings.Contains(err.Error(), "logout_path") {
			t.Errorf("err = %v, want a refusal about the two paths being equal", err)
		}
	})

	t.Run("relative path", func(t *testing.T) {
		_, _, err := loadYAML(t, withSession(
			"session:\n  enabled: true\n  secret_file: "+secret+"\n  login_path: login\n"))
		if err == nil || !strings.Contains(err.Error(), "must start with a slash") {
			t.Errorf("err = %v, want a refusal about the missing slash", err)
		}
	})

	// Browsers reject SameSite=None without Secure, so the combination would
	// mean no session cookie is ever stored.
	t.Run("same_site none without secure", func(t *testing.T) {
		_, _, err := loadYAML(t, withSession(
			"session:\n  enabled: true\n  secret_file: "+secret+
				"\n  same_site: none\n  secure: false\n"))
		if err == nil || !strings.Contains(err.Error(), "same_site") {
			t.Errorf("err = %v, want a refusal naming session.same_site", err)
		}
	})

	t.Run("unknown same_site", func(t *testing.T) {
		_, _, err := loadYAML(t, withSession(
			"session:\n  enabled: true\n  secret_file: "+secret+"\n  same_site: sometimes\n"))
		if err == nil || !strings.Contains(err.Error(), "same_site") {
			t.Errorf("err = %v, want a refusal naming session.same_site", err)
		}
	})

	t.Run("bad cookie name", func(t *testing.T) {
		_, _, err := loadYAML(t, withSession(
			"session:\n  enabled: true\n  secret_file: "+secret+"\n  cookie_name: \"session cookie\"\n"))
		if err == nil || !strings.Contains(err.Error(), "cookie_name") {
			t.Errorf("err = %v, want a refusal naming session.cookie_name", err)
		}
	})

	t.Run("insecure cookie warns", func(t *testing.T) {
		_, warnings, err := loadYAML(t, withSession(
			"session:\n  enabled: true\n  secret_file: "+secret+"\n  secure: false\n"))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if !containsSubstring(warnings, "plaintext HTTP") {
			t.Errorf("warnings = %q, want one about the cookie travelling in the clear", warnings)
		}
	})

	// A stateless cookie cannot be revoked, so a long lifetime is a
	// credential that outlives the account being disabled.
	t.Run("very long absolute timeout warns", func(t *testing.T) {
		_, warnings, err := loadYAML(t, withSession(
			"session:\n  enabled: true\n  secret_file: "+secret+
				"\n  absolute_timeout: 720h\n  idle_timeout: 30m\n"))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if !containsSubstring(warnings, "cannot be revoked") {
			t.Errorf("warnings = %q, want one about revocation", warnings)
		}
	})

	// A refresh interval at or above the idle window would let a session
	// expire in the browser while the service still accepts it.
	t.Run("refresh interval not below the idle window warns", func(t *testing.T) {
		_, warnings, err := loadYAML(t, withSession(
			"session:\n  enabled: true\n  secret_file: "+secret+
				"\n  idle_timeout: 30m\n  refresh_interval: 45m\n"))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if !containsSubstring(warnings, "refresh_interval") {
			t.Errorf("warnings = %q, want one about refresh_interval", warnings)
		}
	})

	t.Run("cookie domain warns", func(t *testing.T) {
		_, warnings, err := loadYAML(t, withSession(
			"session:\n  enabled: true\n  secret_file: "+secret+"\n  cookie_domain: .example.org\n"))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}

		if !containsSubstring(warnings, "every subdomain") {
			t.Errorf("warnings = %q, want one about the cookie reaching subdomains", warnings)
		}
	})

	// A missing template is a startup failure with a path in the message,
	// not a 500 at the first login of the day.
	t.Run("missing login template", func(t *testing.T) {
		_, _, err := loadYAML(t, withSession(
			"session:\n  enabled: true\n  secret_file: "+secret+
				"\n  login_template: /does/not/exist.html\n"))
		if err == nil || !strings.Contains(err.Error(), "login_template") {
			t.Errorf("err = %v, want a refusal naming session.login_template", err)
		}
	})

	// A secret that is never read cannot fail to be read: a disabled
	// session must not turn a stale path into a startup failure.
	t.Run("disabled ignores its settings", func(t *testing.T) {
		_, _, err := loadYAML(t, withSession(
			"session:\n  enabled: false\n  secret_file: /does/not/exist\n  login_path: /auth\n"))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
	})
}

// A user_attribute pointing at a container attribute authenticates, authorizes
// and grants access — and hands every user to the application under the same
// name, so the application cannot tell two people apart. Nothing else in the
// system reports it: the only visible symptom is a log line naming a container.
func TestUserAttributeContainerWarning(t *testing.T) {
	withAttribute := func(attribute string) string {
		return `
policies:
  intranet:
    ldap: primary
    allow_any_user: true
ldap:
  primary:
    url: ldaps://dir.example.org:636
    base_dn: dc=example,dc=org
    user_attribute: ` + attribute + `
cache:
  enabled: false
`
	}

	for _, attribute := range []string{"ou", "OU", "memberOf", "objectClass", "dc"} {
		_, warnings, err := loadYAML(t, withAttribute(attribute))
		if err != nil {
			t.Fatalf("Load with user_attribute %q: %v", attribute, err)
		}

		if !containsSubstring(warnings, "same X-Auth-User") {
			t.Errorf("user_attribute %q produced no warning: %q", attribute, warnings)
		}
	}

	// The attributes that actually carry a login name must stay silent, or
	// the warning becomes noise that operators learn to scroll past.
	for _, attribute := range []string{"uid", "sAMAccountName", "cn", "userPrincipalName", "mail"} {
		_, warnings, err := loadYAML(t, withAttribute(attribute))
		if err != nil {
			t.Fatalf("Load with user_attribute %q: %v", attribute, err)
		}

		if containsSubstring(warnings, "same X-Auth-User") {
			t.Errorf("user_attribute %q was warned about: %q", attribute, warnings)
		}
	}
}
