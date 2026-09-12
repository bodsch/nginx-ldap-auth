// Package config parses, defaults and validates the YAML configuration and
// loads the secrets it references.
//
// The package refuses to produce a Config that the rest of the service would
// have to defend itself against: every reference between policies and
// directories is resolved here, every filter template is checked here, and
// every secret is read here. A Config returned by Load is safe to use without
// further checks.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the complete service configuration.
type Config struct {
	Server        Server             `yaml:"server"`
	DefaultPolicy string             `yaml:"default_policy"`
	Policies      map[string]*Policy `yaml:"policies"`
	LDAP          map[string]*LDAP   `yaml:"ldap"`
	Session       Session            `yaml:"session"`
	Cache         Cache              `yaml:"cache"`
	Redis         Redis              `yaml:"redis"`
	RateLimit     RateLimit          `yaml:"rate_limit"`
	Logging       Logging            `yaml:"logging"`
	Metrics       Metrics            `yaml:"metrics"`
}

// Server holds the HTTP listener settings.
type Server struct {
	Listen string `yaml:"listen"`

	// ClientIPHeader names the header carrying the real client address.
	//
	// Behind nginx every request arrives from the proxy, so RemoteAddr is
	// the same loopback address for all of them and the per-address throttle
	// would count the whole internet as one client. nginx has to pass the
	// original address on, and this is where the service is told which
	// header it used.
	//
	// The value is trusted, which is only safe because the endpoint is
	// internal. Setting it empty falls back to the peer address.
	ClientIPHeader string `yaml:"client_ip_header"`

	ReadTimeout     Duration `yaml:"read_timeout"`
	WriteTimeout    Duration `yaml:"write_timeout"`
	IdleTimeout     Duration `yaml:"idle_timeout"`
	ShutdownTimeout Duration `yaml:"shutdown_timeout"`
	MaxHeaderBytes  int      `yaml:"max_header_bytes"`
}

// Policy is a named bundle of realm, directory and authorization rules. nginx
// selects one per protected location through the X-Auth-Policy header.
type Policy struct {
	// Name is the map key, copied in for error messages and logging.
	Name string `yaml:"-"`

	Realm         string   `yaml:"realm"`
	LDAP          string   `yaml:"ldap"`
	RequireGroups []string `yaml:"require_groups"`

	// AllowAnyUser has to be set explicitly when RequireGroups is empty.
	// "Any authenticated user may pass" is a decision, not a default that
	// should fall out of an omitted key.
	AllowAnyUser bool `yaml:"allow_any_user"`
}

// TLS holds the transport settings for one directory.
type TLS struct {
	// Verify is a pointer so that an omitted key can be told apart from an
	// explicit "verify: false". Certificate verification defaults to on,
	// and for a map entry that default cannot be pre-filled — turning a
	// deliberate "false" back into "true" would be a silent config change,
	// and defaulting an absent key to the bool zero value would be a silent
	// downgrade to an unverified connection.
	Verify   *bool  `yaml:"verify"`
	CAFile   string `yaml:"ca_file"`
	StartTLS bool   `yaml:"start_tls"`

	// CACertificates is the parsed content of CAFile.
	CACertificates []byte `yaml:"-"`
}

// VerifyCertificate reports whether the directory's certificate has to be
// validated. An unset value means yes.
func (t TLS) VerifyCertificate() bool {
	return t.Verify == nil || *t.Verify
}

// Group source kinds for LDAP.GroupSource.
const (
	// GroupSourceFilter evaluates GroupFilter against GroupBaseDN, for
	// member/memberUid style schemas.
	GroupSourceFilter = "filter"

	// GroupSourceAttribute reads GroupAttribute from the user entry, for
	// memberOf style schemas.
	GroupSourceAttribute = "attribute"

	// GroupSourceNone disables group resolution entirely.
	GroupSourceNone = "none"
)

// Values for LDAP.GroupFilterValue.
const (
	// GroupFilterValueUser interpolates the user's login name.
	GroupFilterValueUser = "user"

	// GroupFilterValueDN interpolates the user's distinguished name.
	GroupFilterValueDN = "dn"
)

// LDAP describes one directory. Directories are configured as a named map and
// referenced by a policy; each policy uses exactly one directory.
type LDAP struct {
	// Name is the map key, copied in for error messages and logging.
	Name string `yaml:"-"`

	URL    string `yaml:"url"`
	BaseDN string `yaml:"base_dn"`

	// UserFilter is a template with exactly one %s, filled with the escaped
	// login name.
	UserFilter string `yaml:"user_filter"`

	// UserAttribute is the attribute carrying the canonical login name. Its
	// value, not the name the client typed, is what reaches the upstream
	// application and the group filter.
	UserAttribute string `yaml:"user_attribute"`

	GroupSource        string `yaml:"group_source"`
	GroupBaseDN        string `yaml:"group_base_dn"`
	GroupFilter        string `yaml:"group_filter"`
	GroupFilterValue   string `yaml:"group_filter_value"`
	GroupAttribute     string `yaml:"group_attribute"`
	GroupNameAttribute string `yaml:"group_name_attribute"`

	// BindDN and BindPasswordFile configure the service account used for
	// searches. Both empty means anonymous search.
	BindDN           string `yaml:"bind_dn"`
	BindPasswordFile string `yaml:"bind_password_file"`

	BindTimeout      Duration `yaml:"bind_timeout"`
	OperationTimeout Duration `yaml:"operation_timeout"`

	TLS TLS `yaml:"tls"`

	// BindPassword is loaded from BindPasswordFile.
	BindPassword string `yaml:"-"`
}

// Session configures the login form and the signed session cookie.
//
// It is what gives the service an expiring login. Basic Authentication has
// neither a logout nor an expiry — the browser replays the credentials until it
// is closed — so without this section a login lasts as long as the browser
// window does, which in practice is days.
//
// Disabled by default, because enabling it changes how every protected location
// behaves and requires a secret file and an nginx change to go with it.
type Session struct {
	Enabled bool `yaml:"enabled"`

	// CookieName is the cookie the session travels in. Two services on the
	// same domain need two different names, or each will overwrite the
	// other's session.
	CookieName string `yaml:"cookie_name"`

	// SecretFile keys the HMAC that signs the cookie. Required while
	// sessions are enabled: an unsigned cookie is a request parameter, and
	// a visitor would be able to name any user in any group.
	SecretFile string `yaml:"secret_file"`

	// AbsoluteTimeout is the maximum lifetime of a session, counted from
	// the login and never extended.
	//
	// It is the only bound on a stateless cookie: there is no server-side
	// session table to delete from, so a cookie that has been copied stays
	// usable until this expires. Eight hours is a working day.
	AbsoluteTimeout Duration `yaml:"absolute_timeout"`

	// IdleTimeout is how long a session survives without being used.
	IdleTimeout Duration `yaml:"idle_timeout"`

	// RefreshInterval is how old the cookie's last-seen stamp has to be
	// before it is re-issued.
	//
	// nginx makes one authentication subrequest per HTTP request, so
	// refreshing on every one of them would put a Set-Cookie on every image
	// on every page. Zero, or anything not below the idle timeout, falls
	// back to half the idle window.
	RefreshInterval Duration `yaml:"refresh_interval"`

	CookiePath   string `yaml:"cookie_path"`
	CookieDomain string `yaml:"cookie_domain"`

	// Secure is a pointer for the same reason as TLS.Verify: an omitted key
	// has to mean "on", and the bool zero value would silently mean the
	// opposite. A cookie without it travels over plaintext HTTP.
	Secure *bool `yaml:"secure"`

	// SameSite is one of lax, strict, none.
	SameSite string `yaml:"same_site"`

	// LoginPath and LogoutPath are served by this service and proxied by
	// nginx. Unlike /auth they are reached by the browser directly, not
	// through auth_request.
	LoginPath  string `yaml:"login_path"`
	LogoutPath string `yaml:"logout_path"`

	// LoginTemplate replaces the built-in form. It is an html/template
	// parsed once at startup, so a syntax error is a startup failure rather
	// than a 500 on the first login.
	LoginTemplate string `yaml:"login_template"`

	// AllowBasic keeps HTTP Basic Authentication working alongside the
	// session, for curl, monitoring checks and API clients. The browser is
	// never challenged with it while sessions are enabled — a WWW-
	// Authenticate header would make the browser open its own password
	// dialog instead of following the redirect to the login form, and the
	// credentials it cached there would be back to never expiring.
	AllowBasic bool `yaml:"allow_basic"`

	// Secret is loaded from SecretFile.
	Secret []byte `yaml:"-"`

	// LoginTemplateSource is the parsed content of LoginTemplate.
	LoginTemplateSource []byte `yaml:"-"`
}

// SecureCookie reports whether the session cookie is restricted to HTTPS. An
// unset value means yes.
func (s Session) SecureCookie() bool {
	return s.Secure == nil || *s.Secure
}

// Cache configures the in-process decision cache.
type Cache struct {
	Enabled     bool     `yaml:"enabled"`
	TTL         Duration `yaml:"ttl"`
	NegativeTTL Duration `yaml:"negative_ttl"`

	// MaxEntries bounds the cache. This is a security control, not only a
	// memory setting: a spray of invalid usernames must not be able to grow
	// the process without limit.
	MaxEntries int `yaml:"max_entries"`

	PepperFile string `yaml:"pepper_file"`

	// Pepper is loaded from PepperFile and keys the cache-key HMAC.
	Pepper []byte `yaml:"-"`
}

// Redis configures the optional shared cache backend.
//
// It replaces the in-process cache rather than sitting behind it. A memory tier
// in front of Redis would serve a decision another instance had already
// revoked, which defeats the only reason to share them.
type Redis struct {
	Enabled  bool     `yaml:"enabled"`
	Address  string   `yaml:"address"`
	Database int      `yaml:"database"`
	Timeout  Duration `yaml:"timeout"`

	// PasswordFile holds the AUTH password, if the server requires one.
	PasswordFile string `yaml:"password_file"`

	// Password is loaded from PasswordFile.
	Password string `yaml:"-"`
}

// RateLimit configures the failure throttle.
type RateLimit struct {
	Enabled            bool     `yaml:"enabled"`
	Window             Duration `yaml:"window"`
	MaxFailuresPerUser int      `yaml:"max_failures_per_user"`
	MaxFailuresPerIP   int      `yaml:"max_failures_per_ip"`
	BlockDuration      Duration `yaml:"block_duration"`
	MaxEntries         int      `yaml:"max_entries"`
}

// Logging configures the structured logger.
type Logging struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`

	// LogUsername controls whether login names appear in log records. On by
	// default: a directory administrator can see usernames anyway, and
	// without them a lockout cannot be investigated.
	LogUsername bool `yaml:"log_username"`
}

// Metrics configures the Prometheus listener. Milestone 2.
type Metrics struct {
	Enabled bool   `yaml:"enabled"`
	Address string `yaml:"address"`
}

// Defaults returns a Config pre-filled with the documented defaults. Decoding
// the file on top of it means an omitted key keeps its default while a key that
// is present always wins, including when it is present with a zero value.
func Defaults() *Config {
	return &Config{
		Server: Server{
			Listen:          "127.0.0.1:8080",
			ClientIPHeader:  "X-Real-IP",
			ReadTimeout:     Duration(5 * time.Second),
			WriteTimeout:    Duration(5 * time.Second),
			IdleTimeout:     Duration(30 * time.Second),
			ShutdownTimeout: Duration(10 * time.Second),
			MaxHeaderBytes:  8192,
		},
		Session: Session{
			Enabled:         false,
			CookieName:      "nginx_ldap_auth",
			AbsoluteTimeout: Duration(8 * time.Hour),
			IdleTimeout:     Duration(30 * time.Minute),
			RefreshInterval: Duration(5 * time.Minute),
			CookiePath:      "/",
			SameSite:        "lax",
			LoginPath:       "/login",
			LogoutPath:      "/logout",
			AllowBasic:      true,
		},
		Cache: Cache{
			Enabled:     true,
			TTL:         Duration(60 * time.Second),
			NegativeTTL: 0,
			MaxEntries:  10000,
		},
		Redis: Redis{
			Enabled:  false,
			Address:  "127.0.0.1:6379",
			Database: 0,
			Timeout:  Duration(2 * time.Second),
		},
		RateLimit: RateLimit{
			Enabled:            true,
			Window:             Duration(time.Minute),
			MaxFailuresPerUser: 10,
			MaxFailuresPerIP:   30,
			BlockDuration:      Duration(5 * time.Minute),
			MaxEntries:         10000,
		},
		Logging: Logging{
			Level:       "info",
			Format:      "json",
			LogUsername: true,
		},
		Metrics: Metrics{
			Enabled: false,
			Address: "127.0.0.1:9931",
		},
	}
}

// Load reads, defaults, validates and completes the configuration at path.
//
// The returned warnings describe conditions that are allowed but worth saying
// out loud — a disabled TLS verification, a secret file readable by everyone.
// They are not errors: refusing to start over a file mode would take down a
// running site on the next restart.
func Load(path string) (cfg *Config, warnings []string, err error) {
	// The path is the operator-supplied --config value. Reading a file
	// named on the command line is what this function is for.
	raw, err := os.ReadFile(path) //nolint:gosec // the configuration path is the caller's choice by design
	if err != nil {
		return nil, nil, fmt.Errorf("read configuration: %w", err)
	}

	cfg = Defaults()

	dec := yaml.NewDecoder(bytes.NewReader(raw))

	// A misspelled key is a configuration error, not something to ignore:
	// silently dropping "requre_groups" would produce a policy that lets
	// every authenticated user through.
	dec.KnownFields(true)

	// An empty file decodes to io.EOF. That is not a parse error, but it does
	// leave a configuration without policies, which validate then rejects
	// with a message that names the actual problem.
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, fmt.Errorf("parse configuration %s: %w", path, err)
	}

	cfg.applyDefaults()

	secretWarnings, err := cfg.loadSecrets()
	warnings = append(warnings, secretWarnings...)

	if err != nil {
		return nil, warnings, err
	}

	validationWarnings, err := cfg.validate()
	warnings = append(warnings, validationWarnings...)

	if err != nil {
		return nil, warnings, err
	}

	return cfg, warnings, nil
}

// applyDefaults fills the per-entry defaults of the policy and directory maps.
// They cannot be pre-filled in Defaults because their keys are not known until
// the file has been decoded.
func (c *Config) applyDefaults() {
	for name, policy := range c.Policies {
		if policy == nil {
			policy = &Policy{}
			c.Policies[name] = policy
		}

		policy.Name = name

		if policy.Realm == "" {
			policy.Realm = "Restricted"
		}
	}

	for name, dir := range c.LDAP {
		if dir == nil {
			dir = &LDAP{}
			c.LDAP[name] = dir
		}

		dir.Name = name

		if dir.UserFilter == "" {
			dir.UserFilter = "(uid=%s)"
		}

		if dir.UserAttribute == "" {
			dir.UserAttribute = "uid"
		}

		if dir.BindTimeout == 0 {
			dir.BindTimeout = Duration(5 * time.Second)
		}

		if dir.OperationTimeout == 0 {
			dir.OperationTimeout = Duration(5 * time.Second)
		}

		if dir.GroupNameAttribute == "" {
			dir.GroupNameAttribute = "cn"
		}

		if dir.GroupFilterValue == "" {
			dir.GroupFilterValue = GroupFilterValueUser
		}

		// The group source is inferred from whichever of the two mutually
		// exclusive settings is present, so a working configuration does
		// not need to state the obvious. Stating it is still allowed, and
		// a contradiction is caught by validate.
		if dir.GroupSource == "" {
			switch {
			case dir.GroupFilter != "":
				dir.GroupSource = GroupSourceFilter
			case dir.GroupAttribute != "":
				dir.GroupSource = GroupSourceAttribute
			default:
				dir.GroupSource = GroupSourceNone
			}
		}

		if dir.TLS.Verify == nil {
			verify := true
			dir.TLS.Verify = &verify
		}
	}
}

// Policy returns the named policy, or nil when it does not exist.
func (c *Config) Policy(name string) *Policy {
	return c.Policies[name]
}

// Directory returns the directory a policy references. The reference is
// guaranteed to resolve because validate rejects a policy pointing at a
// directory that is not configured.
func (c *Config) Directory(p *Policy) *LDAP {
	return c.LDAP[p.LDAP]
}
