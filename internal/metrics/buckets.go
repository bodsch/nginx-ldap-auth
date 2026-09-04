package metrics

import (
	"slices"
	"time"
)

// baseBuckets is the range worth resolving for a directory operation.
//
// The client_golang defaults stop at 10 s but start at 5 ms, which puts every
// cached decision and every local rejection into the first bucket — and those
// are the majority of requests. A bind against a directory on the same network
// is a low single-digit millisecond operation, so the resolution has to start
// an order of magnitude lower.
var baseBuckets = []float64{
	0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
}

// bucketsFor returns the histogram buckets, with every configured timeout
// present as a boundary.
//
// project.md §10 requires the bucket set to extend past the configured
// timeouts. Without that, an operation that times out at 7 s lands in the
// +Inf bucket together with every other slow outcome, and the one question the
// histogram was added to answer — "are we hitting the timeout?" — cannot be
// asked of it.
//
// The timeout itself becomes a boundary rather than something just below it, so
// that a timed-out operation falls in the bucket *above* it and is visible as
// the difference between le="<timeout>" and +Inf.
func bucketsFor(timeouts ...time.Duration) []float64 {
	buckets := make([]float64, len(baseBuckets))
	copy(buckets, baseBuckets)

	for _, timeout := range timeouts {
		if timeout <= 0 {
			continue
		}

		buckets = append(buckets, timeout.Seconds())
	}

	slices.Sort(buckets)

	return slices.Compact(buckets)
}
