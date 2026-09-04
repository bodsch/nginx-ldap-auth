package config

import (
	"fmt"
	"time"
)

// Duration is a time.Duration that decodes from the Go duration strings used
// throughout the configuration file ("5s", "1m", "250ms").
//
// yaml.v3 has no built-in support for time.Duration: it would decode "5s" into
// an int64 and fail. Wrapping the type keeps the configuration readable instead
// of forcing operators to write nanoseconds.
type Duration time.Duration

// UnmarshalYAML decodes a Go duration string.
func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return fmt.Errorf("duration must be a string such as \"5s\": %w", err)
	}

	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}

	*d = Duration(parsed)

	return nil
}

// MarshalYAML re-encodes the duration in the same string form it was read from,
// so a round-trip through the configuration structs stays human-readable.
func (d Duration) MarshalYAML() (any, error) {
	return d.String(), nil
}

// Duration returns the wrapped standard library value.
func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// String implements fmt.Stringer.
func (d Duration) String() string {
	return time.Duration(d).String()
}
