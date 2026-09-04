package cache

import (
	"strings"
	"testing"
)

const testPepper = "0123456789abcdef0123456789abcdef"

func newTestKeyer(t *testing.T, pepper string) *Keyer {
	t.Helper()

	keyer, err := NewKeyer([]byte(pepper))
	if err != nil {
		t.Fatalf("NewKeyer: %v", err)
	}

	return keyer
}

func TestKeyIsStable(t *testing.T) {
	keyer := newTestKeyer(t, testPepper)

	first := keyer.Key("intranet", "alice", "s3cret")
	second := keyer.Key("intranet", "alice", "s3cret")

	if first != second {
		t.Fatalf("the same credentials produced two keys:\n%s\n%s", first, second)
	}

	if !strings.HasPrefix(first, KeyPrefix) {
		t.Errorf("key %q is missing the %q prefix", first, KeyPrefix)
	}
}

// TestKeyDoesNotLeakCredentials is the property the whole design exists for.
func TestKeyDoesNotLeakCredentials(t *testing.T) {
	keyer := newTestKeyer(t, testPepper)

	key := keyer.Key("intranet", "alice", "s3cret")

	for _, secret := range []string{"alice", "s3cret", testPepper} {
		if strings.Contains(key, secret) {
			t.Errorf("key %q contains %q", key, secret)
		}
	}
}

func TestKeyDependsOnPepper(t *testing.T) {
	// Without this property a leaked cache would be crackable offline
	// against a wordlist at the cost of the passwords alone.
	first := newTestKeyer(t, testPepper).Key("intranet", "alice", "s3cret")
	second := newTestKeyer(t, strings.Repeat("z", 32)).Key("intranet", "alice", "s3cret")

	if first == second {
		t.Fatal("two different peppers produced the same key")
	}
}

func TestKeyDependsOnPolicy(t *testing.T) {
	// Two policies with different group requirements must not share an
	// entry, or the first decision would answer for the second policy too.
	keyer := newTestKeyer(t, testPepper)

	if keyer.Key("intranet", "alice", "s3cret") == keyer.Key("monitoring", "alice", "s3cret") {
		t.Fatal("the policy is not part of the key")
	}
}

// TestKeyFieldBoundariesAreUnambiguous checks the separator does its job.
//
// Concatenating the fields without one would make ("ab", "c") and ("a", "bc")
// hash the same input — so a username could be chosen to make one password's
// entry answer for another.
func TestKeyFieldBoundariesAreUnambiguous(t *testing.T) {
	keyer := newTestKeyer(t, testPepper)

	pairs := [][3]string{
		{"p", "ab", "c"},
		{"p", "a", "bc"},
		{"pa", "b", "c"},
	}

	seen := make(map[string][3]string, len(pairs))

	for _, fields := range pairs {
		key := keyer.Key(fields[0], fields[1], fields[2])

		if previous, collision := seen[key]; collision {
			t.Fatalf("%v and %v produced the same key", previous, fields)
		}

		seen[key] = fields
	}
}

func TestNewKeyerRejectsShortPepper(t *testing.T) {
	if _, err := NewKeyer([]byte(strings.Repeat("a", MinPepperBytes-1))); err == nil {
		t.Fatal("expected a pepper below the minimum length to be refused")
	}

	if _, err := NewKeyer(nil); err == nil {
		t.Fatal("expected a nil pepper to be refused")
	}
}

// TestKeyerCopiesPepper checks the Keyer cannot be changed from underneath.
func TestKeyerCopiesPepper(t *testing.T) {
	pepper := []byte(testPepper)

	keyer, err := NewKeyer(pepper)
	if err != nil {
		t.Fatalf("NewKeyer: %v", err)
	}

	before := keyer.Key("intranet", "alice", "s3cret")

	for i := range pepper {
		pepper[i] = 0
	}

	if after := keyer.Key("intranet", "alice", "s3cret"); before != after {
		t.Fatal("zeroing the caller's buffer changed every key the Keyer produces")
	}
}
