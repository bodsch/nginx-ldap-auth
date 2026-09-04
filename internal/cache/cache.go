// Package cache stores authentication decisions for a short period and derives
// the keys they are stored under.
//
// Caching is not an optimisation here. nginx issues an auth_request for every
// HTTP request, including every static asset, so without a cache a single page
// view turns into dozens of LDAP binds.
//
// The decision type lives in this package rather than in internal/auth because
// the cache is what has to persist it, and internal/auth imports this package.
// internal/auth re-exports the names so callers do not have to care.
package cache

import (
	"context"
	"time"
)

// Outcome is the verdict on one authentication attempt. It is part of the
// cached value because "wrong password" and "right password, wrong group" map
// to different HTTP statuses and must not collapse into a single "denied".
type Outcome uint8

// The possible verdicts.
//
// The order is load-bearing and must not be tidied. OutcomeInvalidCredentials
// is first so that it is the zero value: a Decision nobody filled in — a failed
// deserialisation, a partially written entry, a field added to the struct later
// — then denies access instead of granting it. project.md §18 closes with "the
// service must prefer denying access over accidentally granting access", and a
// zero value that means "allow" is the cheapest possible way to break that.
const (
	// OutcomeInvalidCredentials means the directory rejected the
	// credentials, or the user does not exist. The two are deliberately
	// indistinguishable to the client, so that the endpoint cannot be used
	// to enumerate usernames.
	//
	// This is deliberately the zero value. See the comment above.
	OutcomeInvalidCredentials Outcome = iota

	// OutcomeAllow means authenticated and authorized.
	OutcomeAllow

	// OutcomeUnauthorized means the credentials were valid but the policy's
	// group requirement was not met.
	OutcomeUnauthorized
)

// String implements fmt.Stringer. The values double as the result label of the
// metrics added in milestone 2, so they are stable identifiers, not prose.
func (o Outcome) String() string {
	switch o {
	case OutcomeAllow:
		return "allow"
	case OutcomeInvalidCredentials:
		return "invalid_credentials"
	case OutcomeUnauthorized:
		return "unauthorized"
	default:
		return "unknown"
	}
}

// Allowed reports whether the outcome grants access.
func (o Outcome) Allowed() bool {
	return o == OutcomeAllow
}

// Decision is a cached authentication result.
//
// It holds no credential material: the password only ever appears inside the
// HMAC that produced the key under which this is stored.
type Decision struct {
	Outcome Outcome

	// User is the canonical login name as the directory spells it, which is
	// not necessarily what the client typed.
	User string

	// Groups are the group names resolved for the user, in the form the
	// directory returned them.
	Groups []string
}

// Cache stores decisions under keys derived by a Keyer.
//
// Get and Set take a context and return an error even though the in-process
// implementation needs neither: the Redis backend in milestone 2 does, and a
// cache interface that has to change shape later is a cache interface that
// leaks into every call site twice.
type Cache interface {
	// Get returns the stored decision. A missing, expired or unreadable
	// entry all report found == false; only an unreadable one also returns
	// an error, and callers treat every one of the three the same way, by
	// asking the directory.
	Get(ctx context.Context, key string) (decision Decision, found bool, err error)

	// Set stores a decision for ttl. A ttl of zero or less stores nothing.
	Set(ctx context.Context, key string, decision Decision, ttl time.Duration) error

	// Stats reports counters for logging and for the readiness endpoint.
	Stats() Stats

	// Name identifies the backend in logs and, later, in metric labels.
	Name() string
}

// Stats are the cache's lifetime counters plus its current size.
//
// The counters are monotonic, which is what lets the metrics layer read them at
// scrape time instead of maintaining a second copy. Two counters for one fact
// are two counters that can drift.
type Stats struct {
	Entries   int
	Hits      uint64
	Misses    uint64
	Evictions uint64
	Expired   uint64

	// Errors counts lookups the backend could not answer. The in-process
	// cache never increments it; a network-backed one will.
	Errors uint64
}

// Disabled is a Cache that stores nothing.
//
// It exists so that the authentication path has no "is the cache enabled"
// branch: a disabled cache is a cache that always misses.
type Disabled struct{}

// Get always reports a miss.
func (Disabled) Get(context.Context, string) (Decision, bool, error) {
	return Decision{}, false, nil
}

// Set discards the decision.
func (Disabled) Set(context.Context, string, Decision, time.Duration) error {
	return nil
}

// Stats reports an empty cache.
func (Disabled) Stats() Stats {
	return Stats{}
}

// Name identifies the backend.
func (Disabled) Name() string {
	return "disabled"
}
