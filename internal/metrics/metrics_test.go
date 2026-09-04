package metrics

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"bodsch.me/nginx-ldap-auth/internal/auth"
	"bodsch.me/nginx-ldap-auth/internal/cache"
	"bodsch.me/nginx-ldap-auth/internal/ratelimit"
)

func newTestMetrics(t *testing.T, timeouts ...time.Duration) *Metrics {
	t.Helper()

	m, err := New(Options{
		Version:  "test",
		Policies: []string{"intranet", "monitoring"},
		Timeouts: timeouts,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return m
}

// scrape renders the exposition, the way Prometheus would read it.
func scrape(t *testing.T, m *Metrics) string {
	t.Helper()

	recorder := httptest.NewRecorder()
	m.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, Path, nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("scrape status = %d, want 200", recorder.Code)
	}

	return recorder.Body.String()
}

// TestUnknownPolicyIsNotUsedAsALabel is the project.md §10 requirement that
// makes the policy label safe to have at all.
//
// The header value comes from a request. Recording it verbatim would be one
// time series per made-up policy name — an attacker choosing the cardinality of
// the exposition, until the scrape times out and monitoring goes dark for every
// other metric too.
func TestUnknownPolicyIsNotUsedAsALabel(t *testing.T) {
	m := newTestMetrics(t)

	hostile := "../../etc/passwd" + strings.Repeat("x", 500)

	// The authentication path reports an empty policy when resolution
	// failed; it never passes the received value on. This asserts the
	// metrics layer would not use one even if it did.
	m.ObserveAuth("", auth.StatusForbidden, ReasonPolicyUnresolved, time.Millisecond)
	m.ObserveAuth(hostile, auth.StatusForbidden, ReasonPolicyUnresolved, time.Millisecond)

	exposition := scrape(t, m)

	if strings.Contains(exposition, "etc/passwd") {
		t.Errorf("a request-supplied policy name became a label value:\n%s", exposition)
	}

	if !strings.Contains(exposition, `policy="`+PolicyUnknown+`"`) {
		t.Errorf("the unresolved policy was not recorded as %q:\n%s", PolicyUnknown, exposition)
	}
}

// TestUnknownReasonIsBounded closes the same hole from the other side.
//
// The reason strings are constants in internal/auth today. This asserts that a
// value the metrics layer does not recognise cannot become a series — because
// "the reasons are all constants" is a property of another package that this
// one must not depend on staying true.
func TestUnknownReasonIsBounded(t *testing.T) {
	m := newTestMetrics(t)

	m.ObserveAuth("intranet", auth.StatusError, "a_reason_invented_later", time.Millisecond)

	exposition := scrape(t, m)

	if strings.Contains(exposition, "a_reason_invented_later") {
		t.Errorf("an unrecognised reason became a label value:\n%s", exposition)
	}

	if !strings.Contains(exposition, `reason="`+ReasonOther+`"`) {
		t.Errorf("the unrecognised reason was not folded into %q:\n%s", ReasonOther, exposition)
	}
}

// TestUnresolvedPolicyCountsAsAFault documents the one place where the coarse
// result deliberately disagrees with the HTTP status.
//
// An unknown policy is answered 403, but it is a fault in somebody's nginx
// configuration rather than an authorization outcome. Filed under
// "unauthorized" it would sit in the same series as users failing a group
// check — ordinary traffic on any protected site — and an alert tuned to
// tolerate that would never fire on the misconfiguration.
func TestUnresolvedPolicyCountsAsAFault(t *testing.T) {
	m := newTestMetrics(t)

	m.ObserveAuth("", auth.StatusForbidden, ReasonPolicyUnresolved, time.Millisecond)
	m.ObserveAuth("intranet", auth.StatusForbidden, "group_required", time.Millisecond)

	faults := testutil.ToFloat64(m.authRequests.WithLabelValues(
		PolicyUnknown, ResultError, ReasonPolicyUnresolved))
	if faults != 1 {
		t.Errorf("policy_unresolved counted as result=%q %v times, want it as an error once",
			ResultError, faults)
	}

	refusals := testutil.ToFloat64(m.authRequests.WithLabelValues(
		"intranet", ResultUnauthorized, "group_required"))
	if refusals != 1 {
		t.Errorf("a group refusal counted %v times as result=%q, want once", refusals, ResultUnauthorized)
	}
}

func TestAuthResultMapping(t *testing.T) {
	tests := map[auth.Status]string{
		auth.StatusAllow:           ResultSuccess,
		auth.StatusUnauthenticated: ResultInvalidCredentials,
		auth.StatusForbidden:       ResultUnauthorized,
		auth.StatusThrottled:       ResultThrottled,
		auth.StatusError:           ResultError,
	}

	for status, want := range tests {
		if got := resultFor(status, "authenticated"); got != want {
			t.Errorf("resultFor(%s) = %q, want %q", status, got, want)
		}
	}

	// A status added later must not be silently filed as a success.
	if got := resultFor(auth.Status(99), "authenticated"); got != ResultError {
		t.Errorf("resultFor(unknown status) = %q, want %q", got, ResultError)
	}
}

// TestTimeoutIsAHistogramBoundary is the project.md §10 requirement that makes
// the duration histograms able to answer the question they were added for.
//
// Without the configured timeout as a boundary, an operation that times out
// lands in +Inf together with everything else that was merely slow, and
// "are we hitting the timeout?" cannot be asked of the data at all.
func TestTimeoutIsAHistogramBoundary(t *testing.T) {
	const timeout = 3 * time.Second

	m := newTestMetrics(t, timeout)

	// Just under and just over the timeout.
	m.ObserveLDAP("search", "success", timeout-time.Millisecond)
	m.ObserveLDAP("search", "error", timeout+time.Millisecond)

	exposition := scrape(t, m)

	if !strings.Contains(exposition, `nginx_ldap_auth_ldap_duration_seconds_bucket{operation="search",le="3"} 1`) {
		t.Errorf("no le=\"3\" bucket, or the wrong count in it:\n%s", exposition)
	}

	// The slow one has to be visible as the difference between the timeout
	// bucket and the total.
	if !strings.Contains(exposition, `nginx_ldap_auth_ldap_duration_seconds_count{operation="search"} 2`) {
		t.Errorf("unexpected observation count:\n%s", exposition)
	}
}

func TestBucketsAreSortedAndDeduplicated(t *testing.T) {
	// Several directories with the same timeout is the normal case, and a
	// duplicate boundary makes the histogram invalid.
	buckets := bucketsFor(5*time.Second, 5*time.Second, 3*time.Second, 0, -time.Second)

	for i := 1; i < len(buckets); i++ {
		if buckets[i] <= buckets[i-1] {
			t.Fatalf("buckets are not strictly increasing at %d: %v", i, buckets)
		}
	}

	found := 0

	for _, bucket := range buckets {
		if bucket == 3 || bucket == 5 {
			found++
		}
	}

	if found != 2 {
		t.Errorf("configured timeouts missing from %v", buckets)
	}
}

// TestStateIsReadAtScrapeTime is why the cache and throttle counters are not
// mirrored into Prometheus counters.
//
// Two counters for one fact drift the first time somebody adds an early
// return. Reading the authoritative one at scrape time cannot drift, and this
// asserts the reading actually happens rather than being captured once at
// registration.
func TestStateIsReadAtScrapeTime(t *testing.T) {
	m := newTestMetrics(t)

	memory, err := cache.NewMemory(4)
	if err != nil {
		t.Fatalf("cache.NewMemory: %v", err)
	}

	throttle, err := ratelimit.New(ratelimit.Config{
		Window:                time.Minute,
		BlockDuration:         time.Minute,
		MaxFailuresPerUser:    1,
		MaxFailuresPerAddress: 0,
		MaxEntries:            8,
	})
	if err != nil {
		t.Fatalf("ratelimit.New: %v", err)
	}

	if err := m.RegisterState(memory, throttle); err != nil {
		t.Fatalf("RegisterState: %v", err)
	}

	if got := scrape(t, m); !strings.Contains(got, `nginx_ldap_auth_cache_entries{backend="memory"} 0`) {
		t.Fatalf("expected an empty cache at first scrape:\n%s", got)
	}

	// Change the state *after* registration.
	ctx := t.Context()

	if err := memory.Set(ctx, "k", cache.Decision{Outcome: cache.OutcomeAllow}, time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if _, _, err := memory.Get(ctx, "k"); err != nil {
		t.Fatalf("Get: %v", err)
	}

	throttle.RecordFailure("alice", "10.0.0.1")
	throttle.Check("alice", "10.0.0.1")

	exposition := scrape(t, m)

	for _, want := range []string{
		`nginx_ldap_auth_cache_entries{backend="memory"} 1`,
		`nginx_ldap_auth_cache_requests_total{backend="memory",result="hit"} 1`,
		`nginx_ldap_auth_throttle_entries 1`,
		`nginx_ldap_auth_throttle_trips_total 1`,
		`nginx_ldap_auth_throttle_blocked_total 1`,
	} {
		if !strings.Contains(exposition, want) {
			t.Errorf("scrape does not reflect the current state, missing %q:\n%s", want, exposition)
		}
	}
}

// TestUptimeIsNotAGauge: project.md §10 drops a self-maintained uptime metric
// because the process collector already exports the process start time, and a
// gauge counting up from start is a counter that silently resets.
func TestUptimeIsNotAGauge(t *testing.T) {
	exposition := scrape(t, newTestMetrics(t))

	if strings.Contains(exposition, "nginx_ldap_auth_uptime_seconds") {
		t.Error("a self-maintained uptime metric is exported")
	}

	if !strings.Contains(exposition, "process_start_time_seconds") {
		t.Error("process_start_time_seconds is missing, so uptime is not derivable at all")
	}
}

// TestRegistryIsNotTheDefaultOne keeps the exposition a decision rather than a
// side effect.
//
// The client library's default registry is global mutable state. Anything a
// dependency registers into it appears in this service's exposition without
// anybody having chosen that, and two tests cannot use it independently.
func TestRegistryIsNotTheDefaultOne(t *testing.T) {
	// Building the metric set twice must work. Against the default
	// registry the second call would fail with a duplicate registration.
	first := newTestMetrics(t)
	second := newTestMetrics(t)

	first.ObserveHTTP("auth", http.StatusOK, time.Millisecond)

	if got := testutil.ToFloat64(second.httpRequests.WithLabelValues("auth", "200")); got != 0 {
		t.Errorf("the two metric sets share state: second counter = %v, want 0", got)
	}
}

func TestObserveHTTPRecordsTheCode(t *testing.T) {
	m := newTestMetrics(t)

	for _, code := range []int{http.StatusOK, http.StatusUnauthorized, http.StatusBadGateway} {
		m.ObserveHTTP("auth", code, 2*time.Millisecond)
	}

	exposition := scrape(t, m)

	for _, code := range []int{200, 401, 502} {
		want := fmt.Sprintf(`nginx_ldap_auth_http_requests_total{code="%d",handler="auth"} 1`, code)
		if !strings.Contains(exposition, want) {
			t.Errorf("missing %q:\n%s", want, exposition)
		}
	}
}

// TestExpositionCarriesNoCredentialMaterial is the §10 label-hygiene list,
// asserted rather than trusted.
//
// The exposition is scraped by a monitoring system and usually stored for
// months. Anything that reaches a label reaches long-term storage that nobody
// audits for secrets.
func TestExposedLabelsCarryNoCredentialMaterial(t *testing.T) {
	m := newTestMetrics(t)

	if err := m.RegisterState(cache.Disabled{}, ratelimit.Disabled{}); err != nil {
		t.Fatalf("RegisterState: %v", err)
	}

	m.ObserveAuth("intranet", auth.StatusAllow, "authenticated", time.Millisecond)
	m.ObserveLDAP("bind", "success", time.Millisecond)
	m.ObserveHTTP("auth", http.StatusOK, time.Millisecond)

	exposition := scrape(t, m)

	// The metrics layer is never handed a username, a password or a DN, so
	// there is no filtering to test — the assertion is that no such
	// argument exists to pass. These are the values the surrounding tests
	// use, and none of them may appear.
	for _, forbidden := range []string{"alice", "s3cret", "uid=", "dc=example", "Basic "} {
		if strings.Contains(exposition, forbidden) {
			t.Errorf("the exposition carries %q:\n%s", forbidden, exposition)
		}
	}
}
