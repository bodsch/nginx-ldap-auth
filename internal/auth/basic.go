package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Errors returned by ParseBasic.
var (
	// ErrNoCredentials means the request carried no Authorization header.
	ErrNoCredentials = errors.New("no credentials")

	// ErrMalformedCredentials means the header was present but unusable.
	ErrMalformedCredentials = errors.New("malformed credentials")

	// ErrUnsupportedUsername means the username contains characters that
	// are only meaningful as LDAP filter metacharacters.
	//
	// Escaping already stops these from changing a filter's meaning. This
	// rejects them anyway, because escaping is not the whole problem: a
	// directory that decodes the escapes and reparses — GLAuth does — turns
	// the escaped filter back into a malformed one and answers with a
	// protocol error. That is not an authentication failure, so it is not
	// counted against the throttle, so it can be repeated indefinitely, and
	// every repetition costs a search on the single pooled service
	// connection that every other request is queued behind.
	//
	// No directory permits these characters in a login name, so rejecting
	// them costs nothing and removes the amplification entirely.
	ErrUnsupportedUsername = errors.New("unsupported username")

	// ErrEmptyPassword means the header carried a username and no password.
	//
	// This is its own error because it is the one failure mode that would
	// otherwise become an authentication bypass: a bind with an empty
	// password is an anonymous bind, and many directories — GLAuth among
	// them, depending on configuration — answer it with success. Every
	// known username would then be a valid login.
	ErrEmptyPassword = errors.New("empty password")
)

// basicScheme is the authentication scheme this service accepts.
const basicScheme = "basic"

// ParseBasic decodes an HTTP Basic Authorization header.
//
// On ErrEmptyPassword the username is returned alongside the error. The name
// parsed cleanly, and the caller needs it: an empty-password attempt is aimed
// at a specific account, and counting it only against the source address would
// leave the per-username limit — the one that catches a distributed attempt at
// one account — with nothing to count.
func ParseBasic(header string) (user, password string, err error) {
	if strings.TrimSpace(header) == "" {
		return "", "", ErrNoCredentials
	}

	scheme, encoded, found := strings.Cut(header, " ")
	if !found {
		return "", "", fmt.Errorf("%w: header has no scheme", ErrMalformedCredentials)
	}

	// RFC 7235 makes the scheme name case-insensitive, and clients do vary.
	if !strings.EqualFold(scheme, basicScheme) {
		return "", "", fmt.Errorf("%w: scheme %q is not Basic", ErrMalformedCredentials, redactScheme(scheme))
	}

	// Strict decoding: a padded, standard-alphabet encoding is what the
	// specification requires, and accepting sloppier input here would mean
	// two different header values could produce the same credentials.
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return "", "", fmt.Errorf("%w: credentials are not valid base64", ErrMalformedCredentials)
	}

	// Split on the first colon only. A colon is forbidden in the username
	// and perfectly legal in a password.
	user, password, found = strings.Cut(string(decoded), ":")
	if !found {
		return "", "", fmt.Errorf("%w: decoded credentials contain no colon", ErrMalformedCredentials)
	}

	return ValidateCredentials(user, password)
}

// ValidateCredentials applies the rules a login name and password have to
// satisfy before either reaches the directory.
//
// It is split out of ParseBasic because the login form arrives with the two
// values already separated. Re-encoding them into a Basic header just to parse
// them back would put the rules for what a username may contain in one place
// and the form in another, and the day they disagree is the day the form
// becomes the way around them.
func ValidateCredentials(user, password string) (string, string, error) {
	if user == "" {
		if password == "" {
			return "", "", ErrNoCredentials
		}

		return "", "", fmt.Errorf("%w: username is empty", ErrMalformedCredentials)
	}

	// The username travels onward into an LDAP filter and, on success, into
	// a response header. Escaping handles the filter and header sanitising
	// handles the response, but a control character in a username is not a
	// login attempt worth passing on either way.
	if i := strings.IndexFunc(user, isControl); i >= 0 {
		return "", "", fmt.Errorf("%w: username contains a control character", ErrMalformedCredentials)
	}

	if i := strings.IndexAny(user, filterMetacharacters); i >= 0 {
		return user, "", fmt.Errorf("%w: %q is not valid in a login name",
			ErrUnsupportedUsername, user[i:i+1])
	}

	// Checked here as well as in the LDAP client, because this is where the
	// distinction between "no password" and "wrong password" is still
	// available: further down it would have to be reconstructed from a
	// directory's answer.
	if strings.TrimSpace(password) == "" {
		return user, "", ErrEmptyPassword
	}

	return user, password, nil
}

// filterMetacharacters are the characters RFC 4515 requires to be escaped in a
// filter value. NUL is covered by the control-character check above.
const filterMetacharacters = `*()\`

// isControl reports whether r is a C0 or C1 control character.
func isControl(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f)
}

// redactScheme bounds an unrecognised scheme name before it reaches a log.
func redactScheme(scheme string) string {
	const max = 16

	if len(scheme) > max {
		return scheme[:max] + "…"
	}

	return scheme
}
