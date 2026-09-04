// Package metrics exposes the service's Prometheus metrics.
//
// It is the only package that imports the Prometheus client. The packages it
// reports on stay unaware of it: authentication results are recorded by the
// HTTP layer from the decision it already has, cache and throttle counters are
// read from the Stats methods those packages already expose, and the directory
// reports through a small interface it defines itself.
//
// That layering is deliberate. A metric is an observation, and letting an
// observation reach into the authentication path is how a counter ends up
// deciding whether a request is allowed.
package metrics

import (
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"bodsch.me/nginx-ldap-auth/internal/auth"
	"bodsch.me/nginx-ldap-auth/internal/cache"
	"bodsch.me/nginx-ldap-auth/internal/ratelimit"
)

// namespace prefixes every metric this service exports.
const namespace = "nginx_ldap_auth"

// Result values for the authentication counter.
//
// These are the five values project.md §10 promises. They are a coarse
// classification on purpose: they answer "what happened" for alerting and
// ratios, and the reason label answers "why" for diagnosis.
const (
	ResultSuccess = "success"

	// ResultInvalidCredentials is a metric label value, not a credential.
	// gosec matches the constant's name, not its content.
	ResultInvalidCredentials = "invalid_credentials" //nolint:gosec // G101: a label value naming a failure class

	ResultUnauthorized = "unauthorized"
	ResultThrottled    = "throttled"
	ResultError        = "error"
)

// PolicyUnknown is recorded in place of a policy name that matched nothing.
//
// The received value is never used as a label. It comes from a request, and a
// label fed from a request is unbounded cardinality that an attacker chooses —
// one series per made-up policy name, until the scrape times out.
const PolicyUnknown = "unknown"

// ReasonOther replaces a reason the metrics layer does not recognise.
//
// The reason strings are constants in internal/auth, so this should be
// unreachable. It exists because "should be unreachable" is not the same as
// "cannot happen", and the failure mode of being wrong about that is unbounded
// label cardinality rather than a missing data point.
const ReasonOther = "other"

// knownReasons is the closed set of reasons that may become a label value.
var knownReasons = map[string]struct{}{
	"authenticated":         {},
	"invalid_credentials":   {},
	"group_required":        {},
	"no_credentials":        {},
	"empty_password":        {},
	"malformed_credentials": {},
	ReasonPolicyUnresolved:  {},
	"throttled_user":        {},
	"throttled_address":     {},
	"throttled_capacity":    {},
	"directory_error":       {},
	"directory_missing":     {},
}

// Options configures the metric set.
type Options struct {
	// Version is reported by the info metric.
	Version string

	// Policies are the configured policy names. Anything else is recorded
	// as PolicyUnknown.
	//
	// project.md §10 says the policy label is safe "because its value set
	// is defined by the configuration". That is only true if this layer
	// knows the set. Trusting the caller to pass a validated name is
	// trusting a property of another package to stay true, and the failure
	// mode of being wrong is unbounded cardinality chosen by whoever can
	// set a request header.
	Policies []string

	// Timeouts are the configured operation timeouts. Each one becomes a
	// histogram boundary so that hitting it is visible in the data.
	Timeouts []time.Duration
}

// Metrics holds the collectors and the registry they are registered in.
//
// The registry is the service's own, not the client library's default. A
// package-level default registry is global mutable state: two tests cannot use
// it independently, and anything a dependency happens to register lands in the
// service's exposition without a decision having been made about it.
type Metrics struct {
	registry *prometheus.Registry

	// policies is the closed set of accepted policy label values.
	policies map[string]struct{}

	authRequests *prometheus.CounterVec
	authDuration *prometheus.HistogramVec

	ldapRequests *prometheus.CounterVec
	ldapDuration *prometheus.HistogramVec

	redisDuration prometheus.Histogram

	httpRequests *prometheus.CounterVec
	httpDuration *prometheus.HistogramVec
}

// New builds the metric set.
func New(opts Options) (*Metrics, error) {
	buckets := bucketsFor(opts.Timeouts...)

	policies := make(map[string]struct{}, len(opts.Policies))
	for _, name := range opts.Policies {
		policies[name] = struct{}{}
	}

	m := &Metrics{
		registry: prometheus.NewRegistry(),
		policies: policies,

		authRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "requests_total",
			Help:      "Authentication requests by policy, coarse result and specific reason.",
		}, []string{"policy", "result", "reason"}),

		authDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "request_duration_seconds",
			Help:      "Time to reach an authentication decision.",
			Buckets:   buckets,
		}, []string{"policy"}),

		ldapRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "ldap_requests_total",
			Help:      "Directory operations by kind and result.",
		}, []string{"operation", "result"}),

		ldapDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "ldap_duration_seconds",
			Help:      "Time spent on directory operations.",
			Buckets:   buckets,
		}, []string{"operation"}),

		redisDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "redis_duration_seconds",
			Help:      "Time spent on Redis operations.",
			Buckets:   buckets,
		}),

		httpRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "http_requests_total",
			Help:      "HTTP requests by handler and status code.",
		}, []string{"handler", "code"}),

		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request duration by handler.",
			Buckets:   buckets,
		}, []string{"handler"}),
	}

	info := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "info",
		Help:      "Build information. The value is always 1; the labels carry the data.",
	}, []string{"version", "go_version"})

	info.WithLabelValues(opts.Version, runtime.Version()).Set(1)

	toRegister := []prometheus.Collector{
		m.authRequests, m.authDuration,
		m.ldapRequests, m.ldapDuration,
		m.redisDuration,
		m.httpRequests, m.httpDuration,
		info,

		// The process collector is what makes uptime derivable, via
		// process_start_time_seconds. project.md §10 drops a
		// self-maintained uptime gauge for exactly that reason: a gauge
		// counting up from process start is a counter that silently
		// resets, and this one is maintained by the kernel.
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		collectors.NewGoCollector(),
	}

	for _, collector := range toRegister {
		if err := m.registry.Register(collector); err != nil {
			return nil, fmt.Errorf("register collector: %w", err)
		}
	}

	return m, nil
}

// Registry exposes the registry, for tests and for registering the pull-based
// collectors.
func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}

// Handler returns the exposition handler.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{
		// A collector that fails should not take the scrape down with
		// it; the error is reported through promhttp_metric_handler_errors_total.
		ErrorHandling: promhttp.ContinueOnError,
	})
}

// ObserveAuth records one authentication decision. It satisfies
// server.Observer.
//
// The status is mapped to a coarse result and the reason is kept alongside it,
// because the two answer different questions. Collapsing them would lose the
// distinction between a user who is not in the required group and an nginx
// location naming a policy that does not exist: both are 403, and only one of
// them is somebody's mistake to fix.
func (m *Metrics) ObserveAuth(policy string, status auth.Status, reason string, elapsed time.Duration) {
	policy = m.policyLabel(policy)

	m.authRequests.WithLabelValues(policy, resultFor(status, reason), reasonLabel(reason)).Inc()
	m.authDuration.WithLabelValues(policy).Observe(elapsed.Seconds())
}

// ReasonPolicyUnresolved is the one reason that changes the coarse result.
const ReasonPolicyUnresolved = "policy_unresolved"

// resultFor maps an authentication status onto the coarse result label.
//
// The label classifies the cause, not the HTTP status. The two agree except in
// one case, and that case is the reason the parameter exists: a request naming
// a policy that is not configured is answered 403, but it is not an
// authorization outcome — it is a fault in somebody's nginx configuration, and
// the user it was refused for cannot do anything about it.
//
// Recording it as "unauthorized" would bury it in the same series as users
// failing a group check, which is ordinary traffic on any protected site. An
// alert on unauthorized would then have to be tuned to tolerate it, and the
// misconfiguration would never be noticed.
//
// An unrecognised status becomes an error rather than a new label value. A
// status this layer does not know about is one nobody has decided how to alert
// on, and treating it as success would hide it.
func resultFor(status auth.Status, reason string) string {
	if reason == ReasonPolicyUnresolved {
		return ResultError
	}

	switch status {
	case auth.StatusAllow:
		return ResultSuccess
	case auth.StatusUnauthenticated:
		return ResultInvalidCredentials
	case auth.StatusForbidden:
		return ResultUnauthorized
	case auth.StatusThrottled:
		return ResultThrottled
	case auth.StatusError:
		return ResultError
	default:
		return ResultError
	}
}

// ObserveLDAP records one directory operation. It satisfies ldap.Observer.
func (m *Metrics) ObserveLDAP(operation, result string, elapsed time.Duration) {
	m.ldapRequests.WithLabelValues(operation, result).Inc()
	m.ldapDuration.WithLabelValues(operation).Observe(elapsed.Seconds())
}

// ObserveRedis records the duration of one Redis operation.
func (m *Metrics) ObserveRedis(elapsed time.Duration) {
	m.redisDuration.Observe(elapsed.Seconds())
}

// ObserveHTTP records one HTTP request.
func (m *Metrics) ObserveHTTP(handler string, code int, elapsed time.Duration) {
	m.httpRequests.WithLabelValues(handler, strconv.Itoa(code)).Inc()
	m.httpDuration.WithLabelValues(handler).Observe(elapsed.Seconds())
}

// RegisterState registers the pull-based collector over the cache and throttle.
//
// Their counters are already maintained; mirroring them into Prometheus
// counters would mean two sources of the same truth that can drift. Reading
// them at scrape time cannot drift.
func (m *Metrics) RegisterState(decisionCache cache.Cache, throttle ratelimit.Throttle) error {
	return m.registry.Register(&stateCollector{cache: decisionCache, throttle: throttle})
}

// policyLabel bounds the policy label to the configured set.
func (m *Metrics) policyLabel(policy string) string {
	if _, configured := m.policies[policy]; configured {
		return policy
	}

	return PolicyUnknown
}

// reasonLabel bounds the reason label to the closed set.
func reasonLabel(reason string) string {
	if _, known := knownReasons[reason]; known {
		return reason
	}

	return ReasonOther
}
