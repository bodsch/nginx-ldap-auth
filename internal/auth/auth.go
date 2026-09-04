// Package auth is the authentication path: it turns a request into a decision.
//
// The order of the steps is the security design, not an implementation detail:
// policy selection, then credential parsing, then the throttle, then the cache,
// and only then the directory. Every step that can refuse a request refuses it
// before the next one spends work on it, and nothing reaches the directory that
// could have been rejected without it.
package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"git.boone-schulz.de/go/nginx-ldap-auth/internal/cache"
	"git.boone-schulz.de/go/nginx-ldap-auth/internal/config"
	"git.boone-schulz.de/go/nginx-ldap-auth/internal/ldap"
	"git.boone-schulz.de/go/nginx-ldap-auth/internal/policy"
	"git.boone-schulz.de/go/nginx-ldap-auth/internal/ratelimit"
)

// Status is the outcome of an authentication attempt, in the terms the HTTP
// layer needs.
type Status int

// The possible statuses.
const (
	// StatusAllow is answered with 200.
	StatusAllow Status = iota

	// StatusUnauthenticated is answered with 401 and a challenge.
	StatusUnauthenticated

	// StatusForbidden is answered with 403: authenticated but not
	// authorized, or a policy that does not exist.
	StatusForbidden

	// StatusThrottled is answered with 429.
	StatusThrottled

	// StatusError is answered with 502: the service could not reach a
	// decision.
	StatusError
)

// String implements fmt.Stringer.
func (s Status) String() string {
	switch s {
	case StatusAllow:
		return "allow"
	case StatusUnauthenticated:
		return "unauthenticated"
	case StatusForbidden:
		return "forbidden"
	case StatusThrottled:
		return "throttled"
	case StatusError:
		return "error"
	default:
		return "unknown"
	}
}

// Cache status values reported on a Result.
const (
	CacheHit      = "hit"
	CacheMiss     = "miss"
	CacheDisabled = "disabled"
)

// Request is one authentication attempt.
type Request struct {
	// PolicyHeader is the raw X-Auth-Policy value, unvalidated.
	PolicyHeader string

	// Authorization is the raw Authorization header value.
	Authorization string

	// RemoteAddress is the client address, reduced to a bare IP by the HTTP
	// layer. It keys the per-address throttle.
	RemoteAddress string
}

// Result is the decision.
type Result struct {
	Status Status

	// Policy is the name of the policy the request was evaluated under, or
	// empty when policy resolution itself failed.
	Policy string

	// Realm is the HTTP Basic realm to challenge with, when the status is
	// StatusUnauthenticated.
	Realm string

	// User is the canonical login name, set only on success.
	User string

	// Groups are the resolved group names, set only on success.
	Groups []string

	// MatchedGroup is the group that satisfied the policy, for the log
	// record that explains why access was granted.
	MatchedGroup string

	// Cache reports whether the decision came from the cache: one of
	// CacheHit, CacheMiss or CacheDisabled, and empty for a request that
	// was answered before the cache was consulted.
	Cache string

	// RetryAfter is set when the status is StatusThrottled.
	RetryAfter time.Duration

	// Reason is a short stable identifier for logs.
	Reason string

	// Err carries the underlying failure for StatusError, and the reason
	// for a refusal otherwise. It is never sent to the client.
	Err error
}

// Directory is the part of a directory client the authentication path uses.
//
// The concrete implementation is internal/ldap. The interface exists so that
// the ordering rules in this package — throttle before cache, cache before
// bind, group check after bind — can be tested against a directory that answers
// on command, rather than only against one that happens to be running.
type Directory interface {
	// Authenticate verifies the credentials and resolves group membership.
	// It returns an error wrapping ldap.ErrInvalidCredentials for a
	// rejected or unknown user, and any other error for an infrastructure
	// fault.
	Authenticate(ctx context.Context, user, password string) (*ldap.Identity, error)

	// Name identifies the directory in logs.
	Name() string
}

// Authenticator evaluates requests against the configured policies.
type Authenticator struct {
	policies    *policy.Set
	directories map[string]Directory
	cache       cache.Cache
	keyer       *cache.Keyer
	throttle    ratelimit.Throttle

	positiveTTL time.Duration
	negativeTTL time.Duration

	log *slog.Logger
}

// Options are the Authenticator's dependencies. Everything is injected so that
// the authentication path can be tested against a fake directory, a real cache
// and a controlled clock.
type Options struct {
	Policies    *policy.Set
	Directories map[string]Directory
	Cache       cache.Cache
	Keyer       *cache.Keyer
	Throttle    ratelimit.Throttle
	PositiveTTL time.Duration
	NegativeTTL time.Duration
	Logger      *slog.Logger
}

// New returns an Authenticator.
func New(opts Options) (*Authenticator, error) {
	switch {
	case opts.Policies == nil:
		return nil, fmt.Errorf("policy set is required")
	case opts.Cache == nil:
		return nil, fmt.Errorf("cache is required")
	case opts.Throttle == nil:
		return nil, fmt.Errorf("throttle is required")
	case opts.Logger == nil:
		return nil, fmt.Errorf("logger is required")
	}

	// A cache that stores nothing needs no keyer; a cache that stores
	// something must not run without one, because an unkeyed key would be a
	// plain hash of the credentials.
	if _, disabled := opts.Cache.(cache.Disabled); !disabled && opts.Keyer == nil {
		return nil, fmt.Errorf("cache %s is enabled but no keyer was provided", opts.Cache.Name())
	}

	return &Authenticator{
		policies:    opts.Policies,
		directories: opts.Directories,
		cache:       opts.Cache,
		keyer:       opts.Keyer,
		throttle:    opts.Throttle,
		positiveTTL: opts.PositiveTTL,
		negativeTTL: opts.NegativeTTL,
		log:         opts.Logger,
	}, nil
}

// Authenticate evaluates one request.
func (a *Authenticator) Authenticate(ctx context.Context, req Request) Result {
	entry, err := a.policies.Resolve(req.PolicyHeader)
	if err != nil {
		// No realm to challenge with, and nothing to challenge for: the
		// request named access rules that do not exist. Answering 401
		// would invite the client to retry credentials that could never
		// have been evaluated.
		return Result{
			Status: StatusForbidden,
			Reason: "policy_unresolved",
			Err:    err,
		}
	}

	result := Result{
		Policy: entry.Name(),
		Realm:  entry.Realm(),
	}

	// Parsed before the throttle is consulted, because the throttle needs
	// the username to charge an attempt to an account. ParseBasic returns
	// one even when it rejects the password as empty.
	user, password, err := ParseBasic(req.Authorization)

	// The throttle gate covers every attempt that carries an identity,
	// including the ones that never make it past parsing. Checking it only
	// on well-formed requests would make the cheapest attempt — a header
	// with no password at all — the one attempt that is never blocked.
	if verdict := a.throttle.Check(user, req.RemoteAddress); verdict.Blocked {
		result.Status = StatusThrottled
		result.RetryAfter = verdict.RetryAfter
		result.Reason = "throttled_" + string(verdict.Scope)

		return result
	}

	if err != nil {
		result.Status = StatusUnauthenticated
		result.Err = err
		result.Reason = credentialReason(err)

		// An unparsable header is not a password guess, so it does not
		// count towards the throttle: it carries no username to charge
		// and counting it would let unrelated clients block each other.
		// An empty password is a guess — the cheapest possible attempt
		// at an anonymous-bind bypass — and leaving it uncounted would
		// make it the free one.
		if errors.Is(err, ErrEmptyPassword) {
			a.throttle.RecordFailure(user, req.RemoteAddress)
		}

		return result
	}

	return a.decide(ctx, entry, req, user, password, result)
}

// decide runs the cache and, on a miss, the directory.
func (a *Authenticator) decide(
	ctx context.Context,
	entry *policy.Entry,
	req Request,
	user, password string,
	result Result,
) Result {
	key := ""
	if a.keyer != nil {
		key = a.keyer.Key(entry.Name(), user, password)
	}

	if key != "" {
		decision, found, err := a.cache.Get(ctx, key)

		// A cache that cannot answer is a cache miss, whatever else it
		// reports alongside the error. The `found` flag is deliberately
		// not consulted here: a backend that fails to deserialise an
		// entry can return both a hit and an error, and the decision it
		// hands back is then whatever the zero value happens to be.
		if err != nil {
			a.log.Warn("cache read failed, asking the directory",
				slog.String("cache", a.cache.Name()), slog.String("error", err.Error()))

			found = false
		}

		if found {
			result.Cache = CacheHit

			return a.fromDecision(decision, user, req, result)
		}

		result.Cache = CacheMiss
	} else {
		result.Cache = CacheDisabled
	}

	directory := a.directories[entry.Policy.LDAP]
	if directory == nil {
		// Unreachable through Load: configuration validation rejects a
		// policy referencing a directory that is not configured.
		result.Status = StatusError
		result.Reason = "directory_missing"
		result.Err = fmt.Errorf("policy %s references unconfigured directory %q", entry.Name(), entry.Policy.LDAP)

		return result
	}

	identity, err := directory.Authenticate(ctx, user, password)
	if err != nil {
		return a.fromDirectoryError(ctx, err, key, user, req, result)
	}

	authorized, matched := entry.Matcher.Authorized(identity.Groups)

	decision := cache.Decision{
		Outcome: cache.OutcomeAllow,
		User:    identity.User,
		Groups:  groupNames(identity.Groups),
	}

	if !authorized {
		decision.Outcome = cache.OutcomeUnauthorized
	}

	// Cached under the positive TTL in both cases. The expensive and
	// security-relevant part — the bind — succeeded, and the answer is as
	// stable as a successful one: a user browsing an area they may not enter
	// should not re-bind for every asset on the page they are being refused.
	if key != "" {
		if err := a.cache.Set(ctx, key, decision, a.positiveTTL); err != nil {
			a.log.Warn("cache write failed",
				slog.String("cache", a.cache.Name()), slog.String("error", err.Error()))
		}
	}

	result = a.fromDecision(decision, user, req, result)
	result.MatchedGroup = matched

	return result
}

// fromDirectoryError maps a directory failure onto a decision.
func (a *Authenticator) fromDirectoryError(
	ctx context.Context,
	err error,
	key, user string,
	req Request,
	result Result,
) Result {
	if !errors.Is(err, ldap.ErrInvalidCredentials) {
		// An outage is not the user's fault and must not be counted
		// against them: throttling on infrastructure errors would lock
		// out every account while the directory is down, and the lockout
		// would outlive the outage by the block duration.
		result.Status = StatusError
		result.Reason = "directory_error"
		result.Err = err

		return result
	}

	a.throttle.RecordFailure(user, req.RemoteAddress)

	if key != "" {
		decision := cache.Decision{Outcome: cache.OutcomeInvalidCredentials}

		// Negative caching is off unless configured. A stored failure
		// shortens the window in which a brute-force attempt reaches the
		// directory, but it also means a corrected password is refused
		// until the entry expires.
		if err := a.cache.Set(ctx, key, decision, a.negativeTTL); err != nil {
			a.log.Warn("cache write failed",
				slog.String("cache", a.cache.Name()), slog.String("error", err.Error()))
		}
	}

	result.Status = StatusUnauthenticated
	result.Reason = "invalid_credentials"
	result.Err = err

	return result
}

// fromDecision maps a decision — fresh or cached — onto a Result.
func (a *Authenticator) fromDecision(decision cache.Decision, user string, req Request, result Result) Result {
	switch decision.Outcome {
	case cache.OutcomeAllow:
		a.throttle.RecordSuccess(user)

		result.Status = StatusAllow
		result.Reason = "authenticated"
		result.User = decision.User
		result.Groups = decision.Groups

	case cache.OutcomeUnauthorized:
		// The credentials were valid, so this is not a failed attempt as
		// far as the throttle is concerned. Counting it would let a
		// legitimate user lock their own account out by reloading a page
		// they may not see.
		a.throttle.RecordSuccess(user)

		result.Status = StatusForbidden
		result.Reason = "group_required"
		result.User = decision.User
		result.Groups = decision.Groups

	case cache.OutcomeInvalidCredentials:
		// Reached only from a cached negative. The failure is counted
		// here too, otherwise negative caching would be a way around the
		// throttle rather than a supplement to it.
		a.throttle.RecordFailure(user, req.RemoteAddress)

		result.Status = StatusUnauthenticated
		result.Reason = "invalid_credentials"
	}

	return result
}

// credentialReason maps a parse failure onto a stable log identifier.
func credentialReason(err error) string {
	switch {
	case errors.Is(err, ErrNoCredentials):
		return "no_credentials"
	case errors.Is(err, ErrEmptyPassword):
		return "empty_password"
	default:
		return "malformed_credentials"
	}
}

// groupNames reduces resolved groups to the names that go into the identity
// header and the cache.
func groupNames(groups []ldap.Group) []string {
	if len(groups) == 0 {
		return nil
	}

	names := make([]string, 0, len(groups))
	for _, group := range groups {
		names = append(names, group.String())
	}

	return names
}

// Directories builds one client per configured directory.
//
// The returned map is keyed by the name a policy references, and the closers
// are returned separately because the Directory interface deliberately has no
// Close: a fake directory in a test has nothing to release.
func Directories(cfg *config.Config, log *slog.Logger) (map[string]Directory, []func(), error) {
	clients := make(map[string]Directory, len(cfg.LDAP))

	var closers []func()

	for name, dir := range cfg.LDAP {
		client, err := ldap.New(dir, log)
		if err != nil {
			for _, release := range closers {
				release()
			}

			return nil, nil, fmt.Errorf("directory %s: %w", name, err)
		}

		clients[name] = client
		closers = append(closers, client.Close)
	}

	return clients, closers, nil
}
