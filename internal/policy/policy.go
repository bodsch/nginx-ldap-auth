// Package policy resolves the policy a request is evaluated under and decides
// whether a user's groups satisfy it.
//
// A policy is what makes one instance able to serve several applications. The
// authentication endpoint is shared, so the request has to say which ruleset
// applies — without that, /auth cannot tell whether it is answering for the
// intranet or for the monitoring UI.
package policy

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	goldap "github.com/go-ldap/ldap/v3"

	"bodsch.me/nginx-ldap-auth/internal/config"
	"bodsch.me/nginx-ldap-auth/internal/ldap"
)

// Header is the request header nginx uses to select a policy.
const Header = "X-Auth-Policy"

// Errors returned by Set.Resolve.
var (
	// ErrUnknownPolicy means the request named a policy that is not
	// configured. This is a fault in the nginx configuration, and it is
	// answered with a refusal: falling back to some other policy would mean
	// guessing which access rules an operator meant.
	ErrUnknownPolicy = errors.New("unknown policy")

	// ErrNoPolicySelected means the request named no policy and no
	// default_policy is configured.
	ErrNoPolicySelected = errors.New("no policy selected and no default_policy configured")
)

// Entry is one configured policy with its group matcher prepared.
type Entry struct {
	Policy  *config.Policy
	Matcher *Matcher
}

// Name returns the policy's name.
func (e *Entry) Name() string {
	return e.Policy.Name
}

// Realm returns the HTTP Basic realm to challenge with.
func (e *Entry) Realm() string {
	return e.Policy.Realm
}

// Set holds every configured policy.
type Set struct {
	entries     map[string]*Entry
	defaultName string
}

// NewSet prepares the policy set from a validated configuration.
func NewSet(cfg *config.Config) (*Set, error) {
	set := &Set{
		entries:     make(map[string]*Entry, len(cfg.Policies)),
		defaultName: cfg.DefaultPolicy,
	}

	for name, policy := range cfg.Policies {
		matcher, err := NewMatcher(policy)
		if err != nil {
			return nil, fmt.Errorf("policy %s: %w", name, err)
		}

		set.entries[name] = &Entry{Policy: policy, Matcher: matcher}
	}

	return set, nil
}

// Resolve returns the policy for a request's header value.
//
// The header value is only ever used as a map key. It never reaches a filter, a
// DN, a path or a metric label, which is what makes it safe to accept from
// nginx at all — and it is validated even though /auth is an internal location,
// because "internal" is a promise in a configuration file and not an
// enforcement.
func (s *Set) Resolve(header string) (*Entry, error) {
	name := strings.TrimSpace(header)

	if name == "" {
		if s.defaultName == "" {
			return nil, ErrNoPolicySelected
		}

		name = s.defaultName
	}

	entry, ok := s.entries[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownPolicy, Redact(name))
	}

	return entry, nil
}

// Names returns the configured policy names, for the startup log.
func (s *Set) Names() []string {
	names := make([]string, 0, len(s.entries))
	for name := range s.entries {
		names = append(names, name)
	}

	return names
}

// DefaultName returns the configured default policy, or the empty string.
func (s *Set) DefaultName() string {
	return s.defaultName
}

// maxRedactedLength bounds how much of a rejected value is echoed.
const maxRedactedLength = 64

// Redact makes an unrecognised header value safe to put in a log record.
//
// The value is rejected input, so it is attacker-shaped by assumption. The
// structured logger escapes it, but nothing else bounds its length or stops it
// from carrying control characters into a terminal reading the journal.
func Redact(value string) string {
	var builder strings.Builder

	for i, r := range value {
		if i >= maxRedactedLength {
			builder.WriteString("…")

			break
		}

		if unicode.IsPrint(r) {
			builder.WriteRune(r)
		} else {
			builder.WriteRune('?')
		}
	}

	return builder.String()
}

// Matcher decides whether a set of resolved groups satisfies a policy.
//
// The policy's required groups are parsed once at startup: a DN comparison
// needs the parsed form, and doing that per request would parse the same
// constant strings on every asset fetch.
type Matcher struct {
	allowAny bool

	// requiredDNs are the entries that parsed as distinguished names.
	requiredDNs []*goldap.DN

	// requiredRaw is every entry in its original form, lowercased, matched
	// against a group's short name and, as a fallback, against a DN that
	// did not parse.
	requiredRaw []string
}

// NewMatcher prepares the matcher for one policy.
func NewMatcher(policy *config.Policy) (*Matcher, error) {
	matcher := &Matcher{allowAny: policy.AllowAnyUser}

	for _, required := range policy.RequireGroups {
		trimmed := strings.TrimSpace(required)
		if trimmed == "" {
			return nil, fmt.Errorf("require_groups contains an empty entry")
		}

		matcher.requiredRaw = append(matcher.requiredRaw, strings.ToLower(trimmed))

		// A bare group name is not a DN and does not have to be one.
		// Whether it parses decides how it is compared, not whether it
		// is accepted.
		if parsed, err := goldap.ParseDN(trimmed); err == nil {
			matcher.requiredDNs = append(matcher.requiredDNs, parsed)
		}
	}

	if !matcher.allowAny && len(matcher.requiredRaw) == 0 {
		return nil, fmt.Errorf("no required groups and allow_any_user is not set")
	}

	return matcher, nil
}

// Authorized reports whether the groups satisfy the policy, and which group
// satisfied it.
//
// One matching group is enough: require_groups is a list of groups any of which
// grants access, not a set that all have to be held.
func (m *Matcher) Authorized(groups []ldap.Group) (authorized bool, matched string) {
	if m.allowAny {
		return true, ""
	}

	for _, group := range groups {
		if m.matches(group) {
			return true, group.String()
		}
	}

	return false, ""
}

// matches compares one resolved group against the policy's requirements.
func (m *Matcher) matches(group ldap.Group) bool {
	// DN comparison first, and case-insensitively: a directory is free to
	// return "CN=Web-Users,OU=Groups,DC=example,DC=org" for a group an
	// operator configured in lower case, and a string comparison would
	// deny access over the capitalisation.
	if group.DN != "" && len(m.requiredDNs) > 0 {
		if parsed, err := goldap.ParseDN(group.DN); err == nil {
			for _, required := range m.requiredDNs {
				if required.EqualFold(parsed) {
					return true
				}
			}
		}
	}

	for _, required := range m.requiredRaw {
		if group.Name != "" && strings.EqualFold(required, group.Name) {
			return true
		}

		// Fallback for a DN neither side could parse. Without it a
		// syntactically odd but consistently spelled DN would never
		// match anything.
		if group.DN != "" && strings.EqualFold(required, group.DN) {
			return true
		}
	}

	return false
}
