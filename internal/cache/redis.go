package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis is the shared decision cache.
//
// It exists for the one case the in-process cache cannot serve: several
// instances that should see each other's decisions. It is not an upgrade — for
// a single service it is strictly worse, because it adds a network hop to every
// request and a second daemon that has to stay alive.
//
// Every failure mode here is a cache miss. That is the whole contract: a Redis
// outage must cost latency, never access. If a read error denied, a Redis
// restart would log everybody out of every protected site; if it granted, a
// Redis restart would open them.
type Redis struct {
	client  *redis.Client
	timeout time.Duration

	hits     atomic.Uint64
	misses   atomic.Uint64
	errors   atomic.Uint64
	observer Observer
}

// Observer receives the duration of each Redis operation.
//
// Declared here so that this package keeps no dependency on a metrics library.
type Observer interface {
	ObserveRedis(elapsed time.Duration)
}

// RedisOptions configures the shared cache.
type RedisOptions struct {
	Address  string
	Database int
	Password string
	Timeout  time.Duration
	Observer Observer
}

// storedDecision is the wire format.
//
// The outcome is stored by name, not by number. The numeric values exist only
// to make the zero value a denial, and their order has already changed once;
// with the number on the wire that change would have reinterpreted every entry
// an older instance had written.
type storedDecision struct {
	Outcome string   `json:"outcome"`
	User    string   `json:"user,omitempty"`
	Groups  []string `json:"groups,omitempty"`
}

// NewRedis returns a Redis-backed cache.
func NewRedis(opts RedisOptions) (*Redis, error) {
	if opts.Address == "" {
		return nil, fmt.Errorf("address must be set")
	}

	if opts.Timeout <= 0 {
		return nil, fmt.Errorf("timeout must be positive")
	}

	return &Redis{
		client: redis.NewClient(&redis.Options{
			Addr:     opts.Address,
			DB:       opts.Database,
			Password: opts.Password,

			// Every phase gets the same bound. A cache that is slower
			// than the directory it is meant to spare is worse than no
			// cache, so the timeout has to be short enough that
			// falling through to LDAP is the cheaper outcome.
			DialTimeout:  opts.Timeout,
			ReadTimeout:  opts.Timeout,
			WriteTimeout: opts.Timeout,
		}),
		timeout:  opts.Timeout,
		observer: opts.Observer,
	}, nil
}

// Get returns the stored decision.
func (r *Redis) Get(ctx context.Context, key string) (Decision, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	started := time.Now()
	raw, err := r.client.Get(ctx, key).Result()
	r.observe(started)

	switch {
	case errors.Is(err, redis.Nil):
		r.misses.Add(1)

		return Decision{}, false, nil
	case err != nil:
		// Counted as both: the lookup did not answer, and the caller
		// treats it as a miss. Recording only the error would make the
		// hit rate look better during an outage than it does in normal
		// operation.
		r.errors.Add(1)
		r.misses.Add(1)

		return Decision{}, false, fmt.Errorf("redis get: %w", err)
	}

	decision, err := decodeDecision(raw)
	if err != nil {
		// An entry that cannot be read is not an entry. Returning
		// found here would hand the caller whatever the zero value
		// happens to be — which is why the zero value denies, but this
		// is the layer that must not rely on that.
		r.errors.Add(1)
		r.misses.Add(1)

		return Decision{}, false, err
	}

	r.hits.Add(1)

	return decision, true, nil
}

// Set stores a decision for ttl.
func (r *Redis) Set(ctx context.Context, key string, decision Decision, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}

	encoded, err := json.Marshal(storedDecision{
		Outcome: decision.Outcome.String(),
		User:    decision.User,
		Groups:  decision.Groups,
	})
	if err != nil {
		return fmt.Errorf("encode decision: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	started := time.Now()
	err = r.client.Set(ctx, key, encoded, ttl).Err()
	r.observe(started)

	if err != nil {
		r.errors.Add(1)

		return fmt.Errorf("redis set: %w", err)
	}

	return nil
}

// Stats reports the counters.
//
// EntriesKnown stays false: the number of entries would take a round trip, and
// the caller is a metrics scrape. A slow Redis must not be able to stall the
// collection of every other metric.
func (r *Redis) Stats() Stats {
	return Stats{
		Hits:   r.hits.Load(),
		Misses: r.misses.Load(),
		Errors: r.errors.Load(),
	}
}

// Name identifies the backend.
func (r *Redis) Name() string {
	return "redis"
}

// Ping checks reachability, for a startup diagnostic.
//
// The result must not decide whether the service starts. An unreachable Redis
// costs LDAP binds and nothing else, and refusing to start over it would turn a
// cache outage into a site outage.
func (r *Redis) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	return r.client.Ping(ctx).Err()
}

// Close releases the connection pool.
func (r *Redis) Close() error {
	return r.client.Close()
}

func (r *Redis) observe(started time.Time) {
	if r.observer != nil {
		r.observer.ObserveRedis(time.Since(started))
	}
}

// decodeDecision reads a stored entry.
func decodeDecision(raw string) (Decision, error) {
	var stored storedDecision

	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		return Decision{}, fmt.Errorf("decode cached decision: %w", err)
	}

	outcome, err := ParseOutcome(stored.Outcome)
	if err != nil {
		// Reached by an entry written by a future version that added an
		// outcome this build does not know. Refusing to read it is the
		// safe direction: the alternative is guessing what a verdict
		// nobody here understands was supposed to mean.
		return Decision{}, fmt.Errorf("decode cached decision: %w", err)
	}

	return Decision{
		Outcome: outcome,
		User:    stored.User,
		Groups:  stored.Groups,
	}, nil
}
