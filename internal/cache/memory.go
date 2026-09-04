package cache

import (
	"container/list"
	"context"
	"fmt"
	"sync"
	"time"
)

// Memory is the default cache: an in-process LRU map with per-entry TTL.
//
// For a single service on one host this is strictly better than Redis. There is
// no network hop, no second daemon to keep alive, and no credential-derived key
// leaving the process — the pepper never has to protect anything that is
// written to disk.
type Memory struct {
	mu      sync.Mutex
	entries map[string]*list.Element
	order   *list.List
	max     int

	// now is injectable so that expiry can be tested without sleeping.
	now func() time.Time

	stats Stats
}

// entry is what the LRU list holds. The key is stored alongside the value
// because eviction starts from the list and has to be able to find the map
// entry to delete.
type entry struct {
	key       string
	decision  Decision
	expiresAt time.Time
}

// NewMemory returns a cache holding at most maxEntries decisions.
//
// The bound is a security control, not only a memory setting: a spray of
// invalid usernames produces a distinct key per attempt, and without a ceiling
// that grows the process for as long as the attack lasts.
func NewMemory(maxEntries int) (*Memory, error) {
	if maxEntries <= 0 {
		return nil, fmt.Errorf("max entries is %d, must be positive", maxEntries)
	}

	return &Memory{
		entries: make(map[string]*list.Element, maxEntries),
		order:   list.New(),
		max:     maxEntries,
		now:     time.Now,
	}, nil
}

// Get returns the decision stored under key, if it is still valid.
func (m *Memory) Get(_ context.Context, key string) (Decision, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	element, ok := m.entries[key]
	if !ok {
		m.stats.Misses++

		return Decision{}, false, nil
	}

	held, _ := element.Value.(*entry)

	if !m.now().Before(held.expiresAt) {
		m.remove(element)
		m.stats.Expired++
		m.stats.Misses++

		return Decision{}, false, nil
	}

	m.order.MoveToFront(element)
	m.stats.Hits++

	return held.decision.clone(), true, nil
}

// Set stores a decision for ttl, evicting the least recently used entry when
// the cache is full.
func (m *Memory) Set(_ context.Context, key string, decision Decision, ttl time.Duration) error {
	if ttl <= 0 {
		// A zero TTL is how negative caching stays off by default. Storing
		// an already-expired entry would only occupy capacity that a
		// usable decision could have.
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	expiresAt := m.now().Add(ttl)

	if element, ok := m.entries[key]; ok {
		held, _ := element.Value.(*entry)
		held.decision = decision.clone()
		held.expiresAt = expiresAt
		m.order.MoveToFront(element)

		return nil
	}

	m.entries[key] = m.order.PushFront(&entry{
		key:       key,
		decision:  decision.clone(),
		expiresAt: expiresAt,
	})

	for m.order.Len() > m.max {
		oldest := m.order.Back()
		if oldest == nil {
			break
		}

		m.remove(oldest)
		m.stats.Evictions++
	}

	return nil
}

// Stats reports the counters and the current entry count.
func (m *Memory) Stats() Stats {
	m.mu.Lock()
	defer m.mu.Unlock()

	stats := m.stats
	stats.Entries = m.order.Len()

	return stats
}

// Name identifies the backend.
func (m *Memory) Name() string {
	return "memory"
}

// remove drops an element from both the list and the map. The caller holds the
// lock.
func (m *Memory) remove(element *list.Element) {
	held, _ := element.Value.(*entry)
	delete(m.entries, held.key)
	m.order.Remove(element)
}

// clone copies the group slice so that a caller cannot reach into the cache and
// modify a decision another request is about to read.
func (d Decision) clone() Decision {
	if d.Groups == nil {
		return d
	}

	groups := make([]string, len(d.Groups))
	copy(groups, d.Groups)
	d.Groups = groups

	return d
}
