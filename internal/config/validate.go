package config

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// policyNamePattern restricts policy names to a conservative character set.
//
// A policy name arrives in the X-Auth-Policy header and later becomes a
// Prometheus label and a log field. Constraining it at configuration time is
// what makes the header value safe to echo: an unknown name is rejected before
// it is used anywhere, and a known name can only be one of these.
var policyNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// validate checks the whole configuration and reports every problem it finds
// at once. An operator fixing a config file should not have to restart the
// service six times to discover six mistakes.
func (c *Config) validate() (warnings []string, err error) {
	var problems []error

	problems = append(problems, c.validateServer()...)

	logProblems, logWarnings := c.validateLogging()
	problems = append(problems, logProblems...)
	warnings = append(warnings, logWarnings...)

	dirProblems, dirWarnings := c.validateDirectories()
	problems = append(problems, dirProblems...)
	warnings = append(warnings, dirWarnings...)

	problems = append(problems, c.validatePolicies()...)

	cacheProblems, cacheWarnings := c.validateCache()
	problems = append(problems, cacheProblems...)
	warnings = append(warnings, cacheWarnings...)

	rateProblems, rateWarnings := c.validateRateLimit()
	problems = append(problems, rateProblems...)
	warnings = append(warnings, rateWarnings...)

	metricsProblems, metricsWarnings := c.validateMetrics()
	problems = append(problems, metricsProblems...)
	warnings = append(warnings, metricsWarnings...)

	redisProblems, redisWarnings := c.validateRedis()
	problems = append(problems, redisProblems...)
	warnings = append(warnings, redisWarnings...)

	if len(problems) > 0 {
		return warnings, fmt.Errorf("invalid configuration:\n%s", indentErrors(problems))
	}

	return warnings, nil
}

func (c *Config) validateServer() []error {
	var problems []error

	if c.Server.Listen == "" {
		problems = append(problems, fmt.Errorf("server.listen must be set"))
	} else if _, _, err := net.SplitHostPort(c.Server.Listen); err != nil {
		problems = append(problems, fmt.Errorf("server.listen %q is not a host:port address: %w", c.Server.Listen, err))
	}

	if c.Server.MaxHeaderBytes <= 0 {
		problems = append(problems, fmt.Errorf("server.max_header_bytes must be positive"))
	}

	problems = append(problems, c.validateClientIPHeader()...)

	for _, t := range []struct {
		key   string
		value Duration
	}{
		{"server.read_timeout", c.Server.ReadTimeout},
		{"server.write_timeout", c.Server.WriteTimeout},
		{"server.idle_timeout", c.Server.IdleTimeout},
		{"server.shutdown_timeout", c.Server.ShutdownTimeout},
	} {
		if t.value <= 0 {
			problems = append(problems, fmt.Errorf("%s must be positive", t.key))
		}
	}

	return problems
}

// validateClientIPHeader guards the one setting that trusts request input.
//
// A client that can reach the endpoint directly can set the header to anything,
// and would then be able to spread its failures across as many fictional
// addresses as it likes. That is acceptable while only nginx can reach the
// endpoint, and it is a hole as soon as the listener is reachable from
// elsewhere — so the two settings are checked against each other.
func (c *Config) validateClientIPHeader() []error {
	var problems []error

	if c.Server.ClientIPHeader == "" {
		return problems
	}

	host, _, err := net.SplitHostPort(c.Server.Listen)
	if err != nil {
		return problems
	}

	address := net.ParseIP(host)

	switch {
	case host == "":
		problems = append(problems, fmt.Errorf(
			"server.listen binds every interface while server.client_ip_header is set: "+
				"any client able to reach the endpoint could forge its own source address and "+
				"escape the per-address throttle; bind 127.0.0.1, or clear client_ip_header"))
	case address != nil && !address.IsLoopback():
		problems = append(problems, fmt.Errorf(
			"server.listen is the non-loopback address %s while server.client_ip_header is set: "+
				"any client able to reach the endpoint could forge its own source address and "+
				"escape the per-address throttle; bind a loopback address, or clear client_ip_header",
			host))
	}

	return problems
}

func (c *Config) validateLogging() (problems []error, warnings []string) {
	switch c.Logging.Level {
	case "debug", "info", "warn", "error":
	default:
		problems = append(problems, fmt.Errorf(
			"logging.level %q is not one of debug, info, warn, error", c.Logging.Level))
	}

	switch c.Logging.Format {
	case "json", "text":
	default:
		problems = append(problems, fmt.Errorf("logging.format %q is not one of json, text", c.Logging.Format))
	}

	if c.Logging.Level == "debug" {
		warnings = append(warnings, "logging.level is debug: expect high log volume on a busy site, "+
			"since nginx issues one authentication request per HTTP request")
	}

	return problems, warnings
}

func (c *Config) validateDirectories() (problems []error, warnings []string) {
	if len(c.LDAP) == 0 {
		problems = append(problems, fmt.Errorf("no directory configured: the ldap section needs at least one entry"))
	}

	for _, name := range sortedKeys(c.LDAP) {
		dir := c.LDAP[name]
		prefix := "ldap." + name

		dirProblems, dirWarnings := dir.validate(prefix)
		problems = append(problems, dirProblems...)
		warnings = append(warnings, dirWarnings...)
	}

	return problems, warnings
}

func (d *LDAP) validate(prefix string) (problems []error, warnings []string) {
	problems = append(problems, d.validateURL(prefix)...)

	if d.BaseDN == "" {
		problems = append(problems, fmt.Errorf("%s.base_dn must be set", prefix))
	} else if _, err := ldap.ParseDN(d.BaseDN); err != nil {
		problems = append(problems, fmt.Errorf("%s.base_dn %q is not a valid DN: %w", prefix, d.BaseDN, err))
	}

	if err := validateFilterTemplate(d.UserFilter); err != nil {
		problems = append(problems, fmt.Errorf("%s.user_filter: %w", prefix, err))
	}

	if d.UserAttribute == "" {
		problems = append(problems, fmt.Errorf("%s.user_attribute must be set", prefix))
	}

	problems = append(problems, d.validateGroupSource(prefix)...)
	problems = append(problems, d.validateBindAccount(prefix)...)

	for _, t := range []struct {
		key   string
		value Duration
	}{
		{prefix + ".bind_timeout", d.BindTimeout},
		{prefix + ".operation_timeout", d.OperationTimeout},
	} {
		if t.value <= 0 {
			problems = append(problems, fmt.Errorf("%s must be positive", t.key))
		}
	}

	if !d.TLS.VerifyCertificate() {
		warnings = append(warnings, fmt.Sprintf(
			"%s.tls.verify is false: the directory's certificate is not checked, "+
				"so credentials can be captured by anyone who can intercept the connection", prefix))
	}

	return problems, warnings
}

func (d *LDAP) validateURL(prefix string) []error {
	var problems []error

	if d.URL == "" {
		problems = append(problems, fmt.Errorf("%s.url must be set", prefix))

		return problems
	}

	parsed, err := url.Parse(d.URL)
	if err != nil {
		problems = append(problems, fmt.Errorf("%s.url %q is not a valid URL: %w", prefix, d.URL, err))

		return problems
	}

	switch parsed.Scheme {
	case "ldap":
		if d.TLS.VerifyCertificate() && !d.TLS.StartTLS {
			problems = append(problems, fmt.Errorf(
				"%s.url uses plaintext ldap://, which would send credentials in the clear: "+
					"use ldaps://, or set %s.tls.start_tls to true, or state the risk with %s.tls.verify: false",
				prefix, prefix, prefix))
		}
	case "ldaps":
		if d.TLS.StartTLS {
			problems = append(problems, fmt.Errorf(
				"%s.tls.start_tls cannot be used with an ldaps:// URL: "+
					"ldaps:// is TLS from the first byte, StartTLS upgrades a plaintext connection", prefix))
		}
	default:
		problems = append(problems, fmt.Errorf("%s.url scheme %q is not one of ldap, ldaps", prefix, parsed.Scheme))
	}

	if parsed.Host == "" {
		problems = append(problems, fmt.Errorf("%s.url %q has no host", prefix, d.URL))
	}

	return problems
}

func (d *LDAP) validateGroupSource(prefix string) []error {
	var problems []error

	switch d.GroupSource {
	case GroupSourceFilter:
		if d.GroupFilter == "" {
			problems = append(problems, fmt.Errorf("%s.group_filter must be set when group_source is %q",
				prefix, GroupSourceFilter))
		} else if err := validateFilterTemplate(d.GroupFilter); err != nil {
			problems = append(problems, fmt.Errorf("%s.group_filter: %w", prefix, err))
		}

		if d.GroupBaseDN == "" {
			problems = append(problems, fmt.Errorf("%s.group_base_dn must be set when group_source is %q",
				prefix, GroupSourceFilter))
		} else if _, err := ldap.ParseDN(d.GroupBaseDN); err != nil {
			problems = append(problems, fmt.Errorf("%s.group_base_dn %q is not a valid DN: %w",
				prefix, d.GroupBaseDN, err))
		}

		switch d.GroupFilterValue {
		case GroupFilterValueUser, GroupFilterValueDN:
		default:
			problems = append(problems, fmt.Errorf("%s.group_filter_value %q is not one of %q, %q",
				prefix, d.GroupFilterValue, GroupFilterValueUser, GroupFilterValueDN))
		}

		if d.GroupAttribute != "" {
			problems = append(problems, fmt.Errorf(
				"%s sets both group_filter and group_attribute: pick one group source", prefix))
		}
	case GroupSourceAttribute:
		if d.GroupAttribute == "" {
			problems = append(problems, fmt.Errorf("%s.group_attribute must be set when group_source is %q",
				prefix, GroupSourceAttribute))
		}

		if d.GroupFilter != "" {
			problems = append(problems, fmt.Errorf(
				"%s sets both group_attribute and group_filter: pick one group source", prefix))
		}
	case GroupSourceNone:
		if d.GroupFilter != "" || d.GroupAttribute != "" {
			problems = append(problems, fmt.Errorf(
				"%s.group_source is %q but a group filter or attribute is configured", prefix, GroupSourceNone))
		}
	default:
		problems = append(problems, fmt.Errorf("%s.group_source %q is not one of %q, %q, %q",
			prefix, d.GroupSource, GroupSourceFilter, GroupSourceAttribute, GroupSourceNone))
	}

	return problems
}

func (d *LDAP) validateBindAccount(prefix string) []error {
	var problems []error

	switch {
	case d.BindDN != "" && d.BindPasswordFile == "":
		problems = append(problems, fmt.Errorf("%s.bind_dn is set but %s.bind_password_file is not", prefix, prefix))
	case d.BindDN == "" && d.BindPasswordFile != "":
		problems = append(problems, fmt.Errorf("%s.bind_password_file is set but %s.bind_dn is not", prefix, prefix))
	}

	if d.BindDN != "" {
		if _, err := ldap.ParseDN(d.BindDN); err != nil {
			problems = append(problems, fmt.Errorf("%s.bind_dn %q is not a valid DN: %w", prefix, d.BindDN, err))
		}
	}

	return problems
}

func (c *Config) validatePolicies() []error {
	var problems []error

	if len(c.Policies) == 0 {
		problems = append(problems, fmt.Errorf(
			"no policy configured: the policies section needs at least one entry, "+
				"and nginx selects one of them per location through the X-Auth-Policy header"))
	}

	for _, name := range sortedKeys(c.Policies) {
		policy := c.Policies[name]
		prefix := "policies." + name

		if !policyNamePattern.MatchString(name) {
			problems = append(problems, fmt.Errorf(
				"policy name %q must match %s: the name travels in a header and becomes a metric label",
				name, policyNamePattern))
		}

		if policy.Realm == "" {
			problems = append(problems, fmt.Errorf("%s.realm must be set", prefix))
		}

		problems = append(problems, c.validatePolicyDirectory(policy, prefix)...)
		problems = append(problems, validatePolicyAuthorization(policy, prefix)...)
	}

	if c.DefaultPolicy != "" && c.Policies[c.DefaultPolicy] == nil {
		problems = append(problems, fmt.Errorf("default_policy %q is not a configured policy (have: %s)",
			c.DefaultPolicy, strings.Join(sortedKeys(c.Policies), ", ")))
	}

	return problems
}

func (c *Config) validatePolicyDirectory(policy *Policy, prefix string) []error {
	var problems []error

	if policy.LDAP == "" {
		problems = append(problems, fmt.Errorf("%s.ldap must name a directory from the ldap section", prefix))

		return problems
	}

	dir := c.LDAP[policy.LDAP]
	if dir == nil {
		problems = append(problems, fmt.Errorf("%s.ldap %q is not a configured directory (have: %s)",
			prefix, policy.LDAP, strings.Join(sortedKeys(c.LDAP), ", ")))

		return problems
	}

	if len(policy.RequireGroups) > 0 && dir.GroupSource == GroupSourceNone {
		problems = append(problems, fmt.Errorf(
			"%s.require_groups is set but directory %q resolves no groups: "+
				"configure group_filter or group_attribute on ldap.%s",
			prefix, policy.LDAP, policy.LDAP))
	}

	return problems
}

func validatePolicyAuthorization(policy *Policy, prefix string) []error {
	var problems []error

	switch {
	case len(policy.RequireGroups) == 0 && !policy.AllowAnyUser:
		problems = append(problems, fmt.Errorf(
			"%s authorizes nobody and everybody at once: set require_groups to restrict access, "+
				"or allow_any_user: true to state that any authenticated user may pass", prefix))
	case len(policy.RequireGroups) > 0 && policy.AllowAnyUser:
		problems = append(problems, fmt.Errorf(
			"%s sets both require_groups and allow_any_user: allow_any_user would make the group check pointless",
			prefix))
	}

	for i, group := range policy.RequireGroups {
		if strings.TrimSpace(group) == "" {
			problems = append(problems, fmt.Errorf("%s.require_groups[%d] is empty", prefix, i))
		}
	}

	return problems
}

func (c *Config) validateCache() (problems []error, warnings []string) {
	if !c.Cache.Enabled {
		warnings = append(warnings, "cache.enabled is false: nginx issues one authentication request per HTTP "+
			"request, so every asset on a page becomes an LDAP bind")

		return problems, warnings
	}

	if c.Cache.PepperFile == "" {
		problems = append(problems, fmt.Errorf(
			"cache.pepper_file must be set while the cache is enabled: cache keys are derived from credentials "+
				"and an unkeyed hash would be crackable offline; generate one with: openssl rand -hex 32"))
	}

	if c.Cache.TTL <= 0 {
		problems = append(problems, fmt.Errorf("cache.ttl must be positive while the cache is enabled"))
	}

	if c.Cache.NegativeTTL < 0 {
		problems = append(problems, fmt.Errorf("cache.negative_ttl cannot be negative"))
	}

	if c.Cache.MaxEntries <= 0 {
		problems = append(problems, fmt.Errorf(
			"cache.max_entries must be positive: it is what stops a spray of invalid usernames from growing the process"))
	}

	if c.Cache.NegativeTTL > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"cache.negative_ttl is %s: failed authentications are cached, so a corrected password only takes "+
				"effect after that delay", c.Cache.NegativeTTL))

		if c.Cache.NegativeTTL > c.Cache.TTL {
			warnings = append(warnings, fmt.Sprintf(
				"cache.negative_ttl (%s) is longer than cache.ttl (%s): failures are remembered longer than "+
					"successes, which is the wrong way round", c.Cache.NegativeTTL, c.Cache.TTL))
		}
	}

	return problems, warnings
}

func (c *Config) validateRateLimit() (problems []error, warnings []string) {
	if !c.RateLimit.Enabled {
		warnings = append(warnings, "rate_limit.enabled is false: the authentication endpoint is an unthrottled "+
			"password oracle against the directory; at minimum protect it with limit_req in nginx")

		return problems, warnings
	}

	if c.RateLimit.Window <= 0 {
		problems = append(problems, fmt.Errorf("rate_limit.window must be positive while the throttle is enabled"))
	}

	if c.RateLimit.BlockDuration <= 0 {
		problems = append(problems, fmt.Errorf("rate_limit.block_duration must be positive while the throttle is enabled"))
	}

	if c.RateLimit.MaxEntries <= 0 {
		problems = append(problems, fmt.Errorf("rate_limit.max_entries must be positive"))
	}

	if c.RateLimit.MaxFailuresPerUser < 0 || c.RateLimit.MaxFailuresPerIP < 0 {
		problems = append(problems, fmt.Errorf("rate_limit failure limits cannot be negative"))
	}

	if c.RateLimit.MaxFailuresPerUser == 0 && c.RateLimit.MaxFailuresPerIP == 0 {
		problems = append(problems, fmt.Errorf(
			"rate_limit is enabled but both max_failures_per_user and max_failures_per_ip are 0, "+
				"which throttles nothing: set a limit, or set rate_limit.enabled to false"))
	}

	return problems, warnings
}

// validateRedis checks the shared cache backend.
func (c *Config) validateRedis() (problems []error, warnings []string) {
	if !c.Redis.Enabled {
		return problems, warnings
	}

	if !c.Cache.Enabled {
		problems = append(problems, fmt.Errorf(
			"redis.enabled is true but cache.enabled is false: Redis is a cache backend, "+
				"so disabling the cache disables it too"))
	}

	if c.Redis.Address == "" {
		problems = append(problems, fmt.Errorf("redis.address must be set while redis is enabled"))
	} else if _, _, err := net.SplitHostPort(c.Redis.Address); err != nil {
		problems = append(problems, fmt.Errorf("redis.address %q is not a host:port address: %w",
			c.Redis.Address, err))
	}

	if c.Redis.Timeout <= 0 {
		problems = append(problems, fmt.Errorf("redis.timeout must be positive"))
	}

	if c.Redis.Database < 0 {
		problems = append(problems, fmt.Errorf("redis.database cannot be negative"))
	}

	// A cache that is slower than the directory it spares is worse than no
	// cache: the request pays the Redis timeout and then does the bind
	// anyway.
	slowest := Duration(0)

	for _, dir := range c.LDAP {
		if dir.OperationTimeout > slowest {
			slowest = dir.OperationTimeout
		}
	}

	if slowest > 0 && c.Redis.Timeout >= slowest {
		warnings = append(warnings, fmt.Sprintf(
			"redis.timeout (%s) is not shorter than the slowest ldap operation_timeout (%s): "+
				"a slow Redis would then cost more than the directory lookup it is there to avoid",
			c.Redis.Timeout, slowest))
	}

	if c.Redis.PasswordFile == "" {
		warnings = append(warnings, "redis.password_file is not set: the shared cache holds "+
			"credential-derived keys and authorization decisions, so it should require authentication")
	}

	return problems, warnings
}

// validateMetrics checks the exposition listener.
func (c *Config) validateMetrics() (problems []error, warnings []string) {
	if !c.Metrics.Enabled {
		return problems, warnings
	}

	if c.Metrics.Address == "" {
		problems = append(problems, fmt.Errorf("metrics.address must be set while metrics are enabled"))

		return problems, warnings
	}

	host, _, err := net.SplitHostPort(c.Metrics.Address)
	if err != nil {
		problems = append(problems, fmt.Errorf("metrics.address %q is not a host:port address: %w",
			c.Metrics.Address, err))

		return problems, warnings
	}

	// Two listeners cannot share one address. Caught here so that the
	// failure names the two settings involved rather than surfacing as
	// "address already in use" from whichever listener lost the race.
	if c.Metrics.Address == c.Server.Listen {
		problems = append(problems, fmt.Errorf(
			"metrics.address and server.listen are both %q: the exposition and the authentication "+
				"endpoint need separate addresses, which is what lets them be firewalled apart",
			c.Metrics.Address))
	}

	address := net.ParseIP(host)

	switch {
	case host == "":
		warnings = append(warnings, "metrics.address binds every interface: the exposition names policies "+
			"and carries failure counts, and it should be reachable from the monitoring network only")
	case address != nil && !address.IsLoopback():
		warnings = append(warnings, fmt.Sprintf(
			"metrics.address is the non-loopback address %s: make sure only the monitoring network can "+
				"reach it", host))
	}

	return problems, warnings
}

// validateFilterTemplate checks that a filter template has exactly one
// placeholder and that it is %s.
//
// This is the counterpart to escaping at call time: escaping protects the
// value, this protects the template. A template with two placeholders would
// make Sprintf write "%!s(MISSING)" into a filter, and a template with %v or %q
// would sidestep the escaping the caller applied.
func validateFilterTemplate(filter string) error {
	if filter == "" {
		return fmt.Errorf("must be set")
	}

	if !strings.HasPrefix(filter, "(") || !strings.HasSuffix(filter, ")") {
		return fmt.Errorf("%q is not a parenthesised LDAP filter", filter)
	}

	if n := strings.Count(filter, "%"); n != 1 {
		return fmt.Errorf("%q contains %d %% signs, expected exactly one placeholder", filter, n)
	}

	if !strings.Contains(filter, "%s") {
		return fmt.Errorf("%q uses a placeholder other than %%s", filter)
	}

	// Rejects a template whose placeholder sits outside any attribute
	// comparison, such as "(%s)", where an escaped value cannot help.
	if strings.Contains(filter, "(%s") || strings.Contains(filter, "%s(") {
		return fmt.Errorf("%q places the value where an attribute name belongs", filter)
	}

	return nil
}

// sortedKeys returns the map's keys in a stable order, so that error and
// warning lists do not reshuffle between runs.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}

	slices.Sort(keys)

	return keys
}

// indentErrors renders a problem list as an indented block, so a single
// returned error still reads as a checklist in the log.
func indentErrors(problems []error) string {
	lines := make([]string, 0, len(problems))
	for _, problem := range problems {
		lines = append(lines, "  - "+problem.Error())
	}

	return strings.Join(lines, "\n")
}
