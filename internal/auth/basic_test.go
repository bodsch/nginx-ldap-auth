package auth

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// basicHeader builds an Authorization header for a credential pair.
func basicHeader(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

func TestParseBasic(t *testing.T) {
	user, password, err := ParseBasic(basicHeader("alice", "s3cret"))
	if err != nil {
		t.Fatalf("ParseBasic: %v", err)
	}

	if user != "alice" || password != "s3cret" {
		t.Errorf("got %q/%q, want alice/s3cret", user, password)
	}
}

func TestParseBasicSchemeIsCaseInsensitive(t *testing.T) {
	// RFC 7235 makes the scheme name case-insensitive, and clients vary.
	for _, scheme := range []string{"Basic", "basic", "BASIC", "bAsIc"} {
		encoded := base64.StdEncoding.EncodeToString([]byte("alice:s3cret"))

		if _, _, err := ParseBasic(scheme + " " + encoded); err != nil {
			t.Errorf("scheme %q was rejected: %v", scheme, err)
		}
	}
}

// TestParseBasicRejectsEmptyPassword is the single most important test in this
// package.
//
// A bind with an empty password is an anonymous bind, and many directories
// answer it with success. Without this check, "Authorization: Basic dXNlcjo="
// would be a valid login for every username that exists.
func TestParseBasicRejectsEmptyPassword(t *testing.T) {
	tests := map[string]string{
		"empty":           basicHeader("alice", ""),
		"single space":    basicHeader("alice", " "),
		"tabs and spaces": basicHeader("alice", " \t "),
		"newline":         basicHeader("alice", "\n"),
		"the classic":     "Basic " + base64.StdEncoding.EncodeToString([]byte("user:")),
	}

	for name, header := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, err := ParseBasic(header)
			if !errors.Is(err, ErrEmptyPassword) {
				t.Fatalf("err = %v, want ErrEmptyPassword", err)
			}
		})
	}
}

// TestParseBasicReturnsUsernameWithEmptyPassword is a regression test.
//
// The username parsed cleanly, and the throttle needs it: an empty-password
// attempt is aimed at one specific account. An earlier version discarded it,
// which left the per-username limit with nothing to count and made the attempt
// entirely free wherever max_failures_per_ip was 0.
func TestParseBasicReturnsUsernameWithEmptyPassword(t *testing.T) {
	user, password, err := ParseBasic(basicHeader("alice", ""))

	if !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("err = %v, want ErrEmptyPassword", err)
	}

	if user != "alice" {
		t.Errorf("user = %q, want alice so the attempt can be charged to the account", user)
	}

	if password != "" {
		t.Errorf("password = %q, want it not returned", password)
	}
}

// TestParseBasicWithholdsUsernameOnMalformedInput is the other half: a header
// that could not be parsed has no trustworthy username in it, and counting one
// would let unrelated clients block each other.
func TestParseBasicWithholdsUsernameOnMalformedInput(t *testing.T) {
	for name, header := range map[string]string{
		"not base64": "Basic !!!",
		"no colon":   "Basic " + base64.StdEncoding.EncodeToString([]byte("alice")),
		"no header":  "",
	} {
		t.Run(name, func(t *testing.T) {
			user, _, err := ParseBasic(header)
			if err == nil {
				t.Fatal("expected an error")
			}

			if user != "" {
				t.Errorf("user = %q, want it withheld", user)
			}
		})
	}
}

func TestParseBasicPreservesColonsInPassword(t *testing.T) {
	// A colon is forbidden in the username and perfectly legal in a
	// password, so only the first one separates the two.
	_, password, err := ParseBasic(basicHeader("alice", "a:b:c"))
	if err != nil {
		t.Fatalf("ParseBasic: %v", err)
	}

	if password != "a:b:c" {
		t.Errorf("password = %q, want a:b:c", password)
	}
}

func TestParseBasicRejections(t *testing.T) {
	tests := map[string]struct {
		header string
		want   error
	}{
		"no header": {
			header: "",
			want:   ErrNoCredentials,
		},
		"whitespace only": {
			header: "   ",
			want:   ErrNoCredentials,
		},
		"no scheme": {
			header: "dXNlcjpwYXNz",
			want:   ErrMalformedCredentials,
		},
		"wrong scheme": {
			header: "Bearer dXNlcjpwYXNz",
			want:   ErrMalformedCredentials,
		},
		"not base64": {
			header: "Basic not-base64!!",
			want:   ErrMalformedCredentials,
		},
		"unpadded base64": {
			// Strict decoding: two header values must not be able to
			// produce the same credentials. "alice:s3cr" is ten
			// bytes, so its encoding carries padding to strip.
			header: "Basic " + strings.TrimRight(base64.StdEncoding.EncodeToString([]byte("alice:s3cr")), "="),
			want:   ErrMalformedCredentials,
		},
		"no colon": {
			header: "Basic " + base64.StdEncoding.EncodeToString([]byte("alice")),
			want:   ErrMalformedCredentials,
		},
		"empty username": {
			header: basicHeader("", "s3cret"),
			want:   ErrMalformedCredentials,
		},
		"newline in username": {
			// The username reaches a filter and a response header.
			// A control character in it is not a login attempt.
			header: basicHeader("alice\nX-Injected: yes", "s3cret"),
			want:   ErrMalformedCredentials,
		},
		"null byte in username": {
			header: basicHeader("alice\x00bob", "s3cret"),
			want:   ErrMalformedCredentials,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, err := ParseBasic(test.header)
			if !errors.Is(err, test.want) {
				t.Fatalf("err = %v, want %v", err, test.want)
			}
		})
	}
}

// TestParseBasicHandlesNonUTF8 checks that a client using a legacy charset
// gets a decision rather than a panic. RFC 7617 leaves the encoding open, so
// the bytes are passed through and the directory decides.
func TestParseBasicHandlesNonUTF8(t *testing.T) {
	raw := []byte{0xe4, 0x6c, 0x69, 0x63, 0x65, ':', 's', '3'} // latin-1 "älice:s3"

	user, password, err := ParseBasic("Basic " + base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatalf("ParseBasic: %v", err)
	}

	if password != "s3" {
		t.Errorf("password = %q, want s3", password)
	}

	if user == "" {
		t.Error("username was dropped")
	}
}

func TestCredentialReason(t *testing.T) {
	// The reasons are stable log identifiers, so a failure can be
	// distinguished from an outage by grepping rather than by reading prose.
	tests := map[error]string{
		ErrNoCredentials:        "no_credentials",
		ErrEmptyPassword:        "empty_password",
		ErrMalformedCredentials: "malformed_credentials",
	}

	for err, want := range tests {
		if got := credentialReason(err); got != want {
			t.Errorf("credentialReason(%v) = %q, want %q", err, got, want)
		}
	}
}
