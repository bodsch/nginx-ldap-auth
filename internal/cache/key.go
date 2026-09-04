package cache

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// KeyPrefix marks the service's keys in a shared Redis database.
const KeyPrefix = "nla:"

// MinPepperBytes is the shortest pepper the Keyer accepts.
const MinPepperBytes = 32

// fieldSeparator separates the key's components.
//
// A NUL byte cannot occur in a policy name, and a username containing one is
// rejected long before this point, so no combination of inputs can be made to
// collide with another by shifting the boundary between them — "ab" + "c" must
// never key the same entry as "a" + "bc".
const fieldSeparator = "\x00"

// Keyer derives cache keys from credentials.
//
// The key is an HMAC over policy, username and password, keyed with a secret
// pepper. Two properties follow from that, and both are the point:
//
//   - The key cannot be reversed into a password.
//   - A leaked cache is useless without the pepper. With an unkeyed hash, a
//     dump would be crackable against a wordlist at the cost of the passwords
//     alone.
//
// The policy is part of the input so that the same credentials evaluated under
// two policies with different group requirements cannot share one entry.
type Keyer struct {
	pepper []byte
}

// NewKeyer returns a Keyer using pepper as the HMAC key.
func NewKeyer(pepper []byte) (*Keyer, error) {
	if len(pepper) < MinPepperBytes {
		return nil, fmt.Errorf("pepper is %d bytes, at least %d are required", len(pepper), MinPepperBytes)
	}

	// Copied so that a caller zeroing its own buffer cannot silently change
	// every key this Keyer will produce.
	own := make([]byte, len(pepper))
	copy(own, pepper)

	return &Keyer{pepper: own}, nil
}

// Key returns the cache key for one credential set under one policy.
func (k *Keyer) Key(policy, user, password string) string {
	mac := hmac.New(sha256.New, k.pepper)

	// Writes to an hmac.Hash never fail, so the errors are not checkable
	// into anything actionable.
	mac.Write([]byte(policy))
	mac.Write([]byte(fieldSeparator))
	mac.Write([]byte(user))
	mac.Write([]byte(fieldSeparator))
	mac.Write([]byte(password))

	return KeyPrefix + hex.EncodeToString(mac.Sum(nil))
}
