package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"bodsch.me/nginx-ldap-auth/internal/cache"
	"bodsch.me/nginx-ldap-auth/internal/ratelimit"
)

// stateCollector reports the cache and throttle counters at scrape time.
//
// Both components already maintain these numbers, and reading them here means
// there is exactly one copy. The alternative — incrementing a Prometheus
// counter alongside every internal one — is two sources for one fact, and the
// two drift the first time somebody adds an early return.
type stateCollector struct {
	cache    cache.Cache
	throttle ratelimit.Throttle
}

var (
	cacheEntriesDesc = prometheus.NewDesc(
		namespace+"_cache_entries",
		"Decisions currently held in the cache.",
		[]string{"backend"}, nil)

	cacheRequestsDesc = prometheus.NewDesc(
		namespace+"_cache_requests_total",
		"Decision cache lookups by backend and result.",
		[]string{"backend", "result"}, nil)

	cacheEvictionsDesc = prometheus.NewDesc(
		namespace+"_cache_evictions_total",
		"Entries dropped because the cache was at its configured bound.",
		[]string{"backend"}, nil)

	cacheExpiredDesc = prometheus.NewDesc(
		namespace+"_cache_expired_total",
		"Entries dropped on read because their TTL had elapsed. "+
			"Subtract this from misses to separate cold lookups from expiry.",
		[]string{"backend"}, nil)

	throttleEntriesDesc = prometheus.NewDesc(
		namespace+"_throttle_entries",
		"Identities the failure throttle is currently tracking.",
		nil, nil)

	throttleBlockedDesc = prometheus.NewDesc(
		namespace+"_throttle_blocked_total",
		"Requests refused because an identity was already blocked.",
		nil, nil)

	throttleTripsDesc = prometheus.NewDesc(
		namespace+"_throttle_trips_total",
		"Times an identity reached its failure limit and became blocked.",
		nil, nil)

	throttleCapacityDesc = prometheus.NewDesc(
		namespace+"_throttle_capacity_denied_total",
		"Requests refused because the throttle had no capacity left to count them. "+
			"Anything other than zero means a large distributed guessing attempt.",
		nil, nil)
)

// Describe implements prometheus.Collector.
func (c *stateCollector) Describe(out chan<- *prometheus.Desc) {
	out <- cacheEntriesDesc
	out <- cacheRequestsDesc
	out <- cacheEvictionsDesc
	out <- cacheExpiredDesc
	out <- throttleEntriesDesc
	out <- throttleBlockedDesc
	out <- throttleTripsDesc
	out <- throttleCapacityDesc
}

// Collect implements prometheus.Collector.
func (c *stateCollector) Collect(out chan<- prometheus.Metric) {
	if c.cache != nil {
		backend := c.cache.Name()
		stats := c.cache.Stats()

		// Only emitted when the backend can answer without a round
		// trip. A gauge that requires network I/O inside Collect lets a
		// slow cache stall the whole scrape.
		if stats.EntriesKnown {
			out <- prometheus.MustNewConstMetric(cacheEntriesDesc,
				prometheus.GaugeValue, float64(stats.Entries), backend)
		}

		out <- prometheus.MustNewConstMetric(cacheRequestsDesc,
			prometheus.CounterValue, float64(stats.Hits), backend, "hit")
		out <- prometheus.MustNewConstMetric(cacheRequestsDesc,
			prometheus.CounterValue, float64(stats.Misses), backend, "miss")
		out <- prometheus.MustNewConstMetric(cacheRequestsDesc,
			prometheus.CounterValue, float64(stats.Errors), backend, "error")
		out <- prometheus.MustNewConstMetric(cacheEvictionsDesc,
			prometheus.CounterValue, float64(stats.Evictions), backend)
		out <- prometheus.MustNewConstMetric(cacheExpiredDesc,
			prometheus.CounterValue, float64(stats.Expired), backend)
	}

	if c.throttle != nil {
		stats := c.throttle.Stats()

		out <- prometheus.MustNewConstMetric(throttleEntriesDesc,
			prometheus.GaugeValue, float64(stats.Entries))
		out <- prometheus.MustNewConstMetric(throttleBlockedDesc,
			prometheus.CounterValue, float64(stats.Blocked))
		out <- prometheus.MustNewConstMetric(throttleTripsDesc,
			prometheus.CounterValue, float64(stats.Trips))
		out <- prometheus.MustNewConstMetric(throttleCapacityDesc,
			prometheus.CounterValue, float64(stats.CapacityDenied))
	}
}
