// Package session turns a successful authentication into a cookie that expires.
//
// HTTP Basic Authentication has no logout and no expiry: the browser holds the
// credentials and replays them on every request until it is closed, which in
// practice means for days. A session cookie is what puts an end to that — it
// carries the decision rather than the credentials, and it stops being valid on
// its own.
//
// The cookie is signed rather than stored. There is no server-side session
// table, so nothing has to be replicated between instances and nothing is lost
// on a restart; the trade-off is that a cookie cannot be revoked before it
// expires, which is why the absolute lifetime is a security setting and not
// only a convenience one.
package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Errors returned when a cookie cannot be turned back into a session.
//
// They are deliberately fine-grained even though every one of them ends in the
// same 401: the difference between "expired" and "forged" is the difference
// between a user whose day is over and an attack, and only the log can tell
// them apart.
var (
	// ErrNoCookie means the request carried no session cookie.
	ErrNoCookie = errors.New("no session cookie")

	// ErrMalformed means the cookie is not in the expected form.
	ErrMalformed = errors.New("malformed session cookie")

	// ErrSignature means the signature did not verify. The value was
	// tampered with, or it was issued under a secret this instance no
	// longer has.
	ErrSignature = errors.New("session signature does not verify")

	// ErrExpiredAbsolute means the session reached its maximum lifetime.
	ErrExpiredAbsolute = errors.New("session reached its absolute lifetime")

	// ErrExpiredIdle means the session was not used within the idle window.
	ErrExpiredIdle = errors.New("session idle for too long")

	// ErrPolicyMismatch means the cookie was issued for another policy.
	ErrPolicyMismatch = errors.New("session was issued for another policy")
)

// minSecretBytes is the minimum accepted length of the signing secret.
//
// The secret is the only thing standing between a visitor and a self-issued
// cookie naming any user in any group. It is held to the same length as the
// cache pepper, and for the same reason: below this a leaked or guessed value
// is brute-forceable offline.
const minSecretBytes = 32

// version prefixes every cookie value.
//
// It is part of the signed input, so a future format cannot be produced by
// re-labelling an old cookie. An unknown version is rejected outright rather
// than guessed at — the alternative is a parser that tries formats until one
// verifies, which is how a downgrade becomes possible.
const version = "1"

// Session is what the cookie carries: a decision, not a credential.
//
// The password appears nowhere in it. Everything here was already sent to the
// upstream application in a response header, so a cookie an attacker can read
// tells them nothing the application did not already receive — what it does
// give them is the ability to replay it, which is what the signature and the
// two timeouts bound.
type Session struct {
	// User is the canonical login name as the directory spells it.
	User string `json:"u"`

	// Policy is the policy the login was evaluated under. A cookie is only
	// valid for that policy: one instance serves several applications, and
	// a session for the intranet must not open the monitoring UI.
	Policy string `json:"p"`

	// Groups are the resolved group names, carried so that the identity
	// headers can be rebuilt without a directory lookup on every request.
	Groups []string `json:"g,omitempty"`

	// IssuedAt is when the credentials were verified. The absolute lifetime
	// runs from here and is never extended, which is what stops a session
	// that is in constant use from lasting forever.
	IssuedAt time.Time `json:"-"`

	// SeenAt is when the session was last used. The idle timeout runs from
	// here and moves forward as the user browses.
	SeenAt time.Time `json:"-"`
}

// wire is the JSON form. The timestamps are Unix seconds rather than RFC 3339
// strings because every byte here is a byte in a header that is sent on every
// single request, including the ones for static assets.
type wire struct {
	Session

	IssuedAt int64 `json:"i"`
	SeenAt   int64 `json:"s"`
}

// Signer produces and verifies cookie values.
type Signer struct {
	key []byte
}

// NewSigner returns a Signer keyed with secret.
func NewSigner(secret []byte) (*Signer, error) {
	if len(secret) < minSecretBytes {
		return nil, fmt.Errorf("session secret is %d bytes, at least %d are required", len(secret), minSecretBytes)
	}

	key := make([]byte, len(secret))
	copy(key, secret)

	return &Signer{key: key}, nil
}

// encoding is unpadded base64url: the value goes into a cookie, where "+", "/"
// and "=" are either forbidden or force quoting.
var encoding = base64.RawURLEncoding

// Encode renders a session as a signed cookie value.
func (s *Signer) Encode(sess Session) (string, error) {
	payload, err := json.Marshal(wire{
		Session:  sess,
		IssuedAt: sess.IssuedAt.Unix(),
		SeenAt:   sess.SeenAt.Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("encode session: %w", err)
	}

	signed := version + "." + encoding.EncodeToString(payload)

	return signed + "." + encoding.EncodeToString(s.mac(signed)), nil
}

// Decode verifies a cookie value and returns the session it carries.
//
// It checks the signature before it parses anything, so malformed JSON from an
// unsigned value never reaches the decoder.
func (s *Signer) Decode(value string) (Session, error) {
	signed, mac, found := cutLast(value, ".")
	if !found {
		return Session{}, fmt.Errorf("%w: no signature", ErrMalformed)
	}

	if !strings.HasPrefix(signed, version+".") {
		return Session{}, fmt.Errorf("%w: unsupported format version", ErrMalformed)
	}

	provided, err := encoding.DecodeString(mac)
	if err != nil {
		return Session{}, fmt.Errorf("%w: signature is not valid base64", ErrMalformed)
	}

	// Constant time, because a comparison that returns early on the first
	// wrong byte tells a patient attacker how much of a forged signature
	// was right.
	if !hmac.Equal(provided, s.mac(signed)) {
		return Session{}, ErrSignature
	}

	payload, err := encoding.DecodeString(strings.TrimPrefix(signed, version+"."))
	if err != nil {
		return Session{}, fmt.Errorf("%w: payload is not valid base64", ErrMalformed)
	}

	var decoded wire
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return Session{}, fmt.Errorf("%w: payload is not valid JSON", ErrMalformed)
	}

	if decoded.User == "" || decoded.Policy == "" || decoded.IssuedAt <= 0 || decoded.SeenAt <= 0 {
		return Session{}, fmt.Errorf("%w: payload is incomplete", ErrMalformed)
	}

	sess := decoded.Session
	sess.IssuedAt = time.Unix(decoded.IssuedAt, 0)
	sess.SeenAt = time.Unix(decoded.SeenAt, 0)

	// A session cannot have been used before it was issued. This is only
	// reachable with the signing secret, so it is not a defence against an
	// attacker — it is a defence against a clock that moved backwards
	// between two instances, which would otherwise produce a session whose
	// idle window outlives its absolute one.
	if sess.SeenAt.Before(sess.IssuedAt) {
		sess.SeenAt = sess.IssuedAt
	}

	return sess, nil
}

// mac computes the signature over the version-prefixed payload.
func (s *Signer) mac(signed string) []byte {
	sum := hmac.New(sha256.New, s.key)
	sum.Write([]byte(signed))

	return sum.Sum(nil)
}

// cutLast splits around the last occurrence of sep.
//
// The payload is base64url, which never contains a dot, but splitting from the
// right rather than the left means a future format with more segments stays
// verifiable by this code path instead of failing in a way that looks like
// tampering.
func cutLast(s, sep string) (before, after string, found bool) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return s, "", false
	}

	return s[:i], s[i+len(sep):], true
}
