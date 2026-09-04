// Package ratelimit throttles repeated authentication failures.
//
// nginx calls the authentication endpoint once per HTTP request, so an
// unthrottled instance is a high-rate password oracle against the directory,
// and it can trip account lockout in directories that implement it.
//
// This throttle is deliberately not a replacement for limit_req in nginx. nginx
// limits request volume per source address; this limits *failures* per identity,
// which is what catches a slow distributed guess against one account.
package ratelimit

import (
	"container/list"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Scope names which limit tripped, for logging.
type Scope string

// The throttle scopes.
const (
	// ScopeNone means nothing tripped.
	ScopeNone Scope = ""

	// ScopeUser means the per-username limit tripped.
	ScopeUser Scope = "user"

	// ScopeAddress means the per-source-address limit tripped.
	ScopeAddress Scope = "address"

	// ScopeCapacity means the throttle ran out of tracking capacity and
	// denied the request rather than stop counting.
	ScopeCapacity Scope = "capacity"
)

// Verdict is the result of a throttle check.
type Verdict struct {
	Blocked    bool
	Scope      Scope
	RetryAfter time.Duration
}

// Throttle is the failure-throttle interface, so that the authentication path
// has no "is throttling enabled" branch.
type Throttle interface {
	// Check reports whether this attempt may reach the directory.
	Check(user, address string) Verdict

	// RecordFailure counts one failed attempt.
	RecordFailure(user, address string)

	// RecordSuccess clears the failure count for a username.
	RecordSuccess(user string)

	// Stats reports counters for logging and readiness.
	Stats() Stats
}

// Config holds the throttle settings.
type Config struct {
	// Window is the sliding window over which failures are counted.
	Window time.Duration

	// BlockDuration is how long an identity stays blocked once its limit
	// is reached.
	BlockDuration time.Duration

	// MaxFailuresPerUser and MaxFailuresPerAddress are the limits. A zero
	// limit disables that scope.
	MaxFailuresPerUser    int
	MaxFailuresPerAddress int

	// MaxEntries bounds how many identities are tracked at once.
	MaxEntries int
}

// Stats are the throttle's lifetime counters.
type Stats struct {
	Entries        int
	Blocked        uint64
	Trips          uint64
	CapacityDenied uint64
}

// Limiter is the in-process implementation.
//
// State is per process and not shared with other instances. For the
// single-service deployment this targets that is the whole population; sharing
// it across instances is a later concern.
type Limiter struct {
	cfg Config

	mu      sync.Mutex
	entries map[string]*list.Element
	order   *list.List

	// now is injectable so that windows and blocks can be tested without
	// sleeping through them.
	now func() time.Time

	stats Stats
}

// counter is the per-identity state.
//
// failures holds at most the configured limit of timestamps: once the limit is
// reached the identity is blocked and the list is cleared, so the slice cannot
// grow with the length of an attack.
type counter struct {
	key          string
	failures     []time.Time
	blockedUntil time.Time
}

// New returns a Limiter for cfg.
func New(cfg Config) (*Limiter, error) {
	switch {
	case cfg.Window <= 0:
		return nil, fmt.Errorf("window must be positive")
	case cfg.BlockDuration <= 0:
		return nil, fmt.Errorf("block duration must be positive")
	case cfg.MaxEntries <= 0:
		return nil, fmt.Errorf("max entries must be positive")
	case cfg.MaxFailuresPerUser < 0 || cfg.MaxFailuresPerAddress < 0:
		return nil, fmt.Errorf("failure limits cannot be negative")
	case cfg.MaxFailuresPerUser == 0 && cfg.MaxFailuresPerAddress == 0:
		return nil, fmt.Errorf("both failure limits are zero, which throttles nothing")
	}

	return &Limiter{
		cfg:     cfg,
		entries: make(map[string]*list.Element),
		order:   list.New(),
		now:     time.Now,
	}, nil
}

// Check reports whether the attempt may proceed.
func (l *Limiter) Check(user, address string) Verdict {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()

	for _, key := range l.keys(user, address) {
		if key.limit == 0 || key.key == "" {
			continue
		}

		element, ok := l.entries[key.key]
		if !ok {
			continue
		}

		l.order.MoveToFront(element)

		held, _ := element.Value.(*counter)

		if now.Before(held.blockedUntil) {
			l.stats.Blocked++

			return Verdict{
				Blocked:    true,
				Scope:      key.scope,
				RetryAfter: held.blockedUntil.Sub(now),
			}
		}
	}

	// Fail closed on the throttle's own exhaustion. Reaching this means the
	// tracking table is full and every entry in it is an active block —
	// which is not a state normal traffic produces, it is a large
	// distributed guessing attempt.
	//
	// Continuing to serve requests we cannot count would turn the throttle
	// off exactly when it is needed. The cost is real: while this lasts,
	// identities that were not being guessed at are refused too. That is
	// the trade the alternative cannot make safely, because making room by
	// evicting an active block would let an attacker clear their own block
	// on demand.
	if l.order.Len() >= l.cfg.MaxEntries && !l.hasEvictable(now) {
		l.stats.CapacityDenied++

		return Verdict{
			Blocked:    true,
			Scope:      ScopeCapacity,
			RetryAfter: l.cfg.BlockDuration,
		}
	}

	return Verdict{}
}

// RecordFailure counts one failure against both the username and the source
// address, and blocks either identity that reaches its limit.
func (l *Limiter) RecordFailure(user, address string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()

	for _, key := range l.keys(user, address) {
		if key.limit == 0 || key.key == "" {
			continue
		}

		held := l.counterFor(key.key, now)
		if held == nil {
			// Out of capacity. Nothing to count against, and Check
			// denies the next request for the same reason.
			continue
		}

		if now.Before(held.blockedUntil) {
			continue
		}

		held.failures = append(pruneBefore(held.failures, now.Add(-l.cfg.Window)), now)

		if len(held.failures) >= key.limit {
			held.blockedUntil = now.Add(l.cfg.BlockDuration)
			held.failures = nil
			l.stats.Trips++
		}
	}
}

// RecordSuccess clears the failure count for a username.
//
// Only the username, never the source address: an attacker who owns one valid
// account would otherwise be able to reset their own address counter between
// guesses at everyone else's.
func (l *Limiter) RecordSuccess(user string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if element, ok := l.entries[userKey(user)]; ok {
		l.removeElement(element)
	}
}

// Stats reports the counters and the number of tracked identities.
func (l *Limiter) Stats() Stats {
	l.mu.Lock()
	defer l.mu.Unlock()

	stats := l.stats
	stats.Entries = l.order.Len()

	return stats
}

// scopedKey pairs a map key with the limit and scope it belongs to.
type scopedKey struct {
	key   string
	limit int
	scope Scope
}

func (l *Limiter) keys(user, address string) [2]scopedKey {
	keys := [2]scopedKey{
		{limit: l.cfg.MaxFailuresPerUser, scope: ScopeUser},
		{limit: l.cfg.MaxFailuresPerAddress, scope: ScopeAddress},
	}

	// An empty identity is not counted. A request that arrives without an
	// Authorization header is a misconfiguration or a probe, not a password
	// guess, and keying every one of them under the same empty string would
	// let unrelated clients block each other.
	if user != "" {
		keys[0].key = userKey(user)
	}

	if address != "" {
		keys[1].key = "a\x00" + address
	}

	return keys
}

// userKey normalises the username before it becomes a counter key.
//
// LDAP matches uid case-insensitively, so "alice" and "ALICE" are one account.
// Keying them separately would let an attacker multiply their budget by the
// number of spellings a username has.
func userKey(user string) string {
	return "u\x00" + strings.ToLower(strings.TrimSpace(user))
}

// counterFor returns the counter for key, creating it if there is room.
//
// It returns nil when the throttle is at capacity and holds nothing evictable.
// The caller must treat that as "cannot count", and Check must deny — the
// alternative, evicting an active block to make room, would hand an attacker a
// way to clear their own block by spraying usernames.
func (l *Limiter) counterFor(key string, now time.Time) *counter {
	if element, ok := l.entries[key]; ok {
		l.order.MoveToFront(element)
		held, _ := element.Value.(*counter)

		return held
	}

	if l.order.Len() >= l.cfg.MaxEntries && !l.evictOne(now) {
		l.stats.CapacityDenied++

		return nil
	}

	held := &counter{key: key}
	l.entries[key] = l.order.PushFront(held)

	return held
}

// hasEvictable reports whether any tracked entry could be evicted to make room.
func (l *Limiter) hasEvictable(now time.Time) bool {
	for element := l.order.Back(); element != nil; element = element.Prev() {
		held, _ := element.Value.(*counter)

		if !now.Before(held.blockedUntil) {
			return true
		}
	}

	return false
}

// evictOne drops the least recently touched entry that is not currently
// blocking anyone, and reports whether it found one.
func (l *Limiter) evictOne(now time.Time) bool {
	for element := l.order.Back(); element != nil; element = element.Prev() {
		held, _ := element.Value.(*counter)

		if now.Before(held.blockedUntil) {
			continue
		}

		l.removeElement(element)

		return true
	}

	return false
}

func (l *Limiter) removeElement(element *list.Element) {
	held, _ := element.Value.(*counter)
	delete(l.entries, held.key)
	l.order.Remove(element)
}

// pruneBefore drops timestamps at or before cutoff. The slice is ordered, so
// the first timestamp inside the window ends the scan.
func pruneBefore(timestamps []time.Time, cutoff time.Time) []time.Time {
	for i, stamp := range timestamps {
		if stamp.After(cutoff) {
			return timestamps[i:]
		}
	}

	return nil
}

// Disabled is a Throttle that never blocks.
type Disabled struct{}

// Check always allows.
func (Disabled) Check(string, string) Verdict { return Verdict{} }

// RecordFailure does nothing.
func (Disabled) RecordFailure(string, string) {}

// RecordSuccess does nothing.
func (Disabled) RecordSuccess(string) {}

// Stats reports an empty throttle.
func (Disabled) Stats() Stats { return Stats{} }
