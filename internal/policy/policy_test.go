package policy

import (
	"errors"
	"strings"
	"testing"

	"git.boone-schulz.de/go/nginx-ldap-auth/internal/config"
	"git.boone-schulz.de/go/nginx-ldap-auth/internal/ldap"
)

func testSet(t *testing.T, defaultPolicy string) *Set {
	t.Helper()

	cfg := &config.Config{
		DefaultPolicy: defaultPolicy,
		Policies: map[string]*config.Policy{
			"intranet": {
				Name:          "intranet",
				Realm:         "Intranet",
				LDAP:          "primary",
				RequireGroups: []string{"cn=web-users,ou=groups,dc=example,dc=org"},
			},
			"staging": {
				Name:         "staging",
				Realm:        "Staging",
				LDAP:         "primary",
				AllowAnyUser: true,
			},
		},
	}

	set, err := NewSet(cfg)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}

	return set
}

func TestResolveNamedPolicy(t *testing.T) {
	set := testSet(t, "")

	entry, err := set.Resolve("intranet")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if entry.Name() != "intranet" {
		t.Errorf("policy = %q, want intranet", entry.Name())
	}

	if entry.Realm() != "Intranet" {
		t.Errorf("realm = %q, want Intranet", entry.Realm())
	}
}

func TestResolveTrimsWhitespace(t *testing.T) {
	// nginx configurations pick up a trailing space more often than anyone
	// would like, and the resulting 403 says nothing about why.
	set := testSet(t, "")

	if _, err := set.Resolve("  intranet\t"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
}

func TestResolveFallsBackToDefault(t *testing.T) {
	set := testSet(t, "staging")

	entry, err := set.Resolve("")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if entry.Name() != "staging" {
		t.Errorf("policy = %q, want the configured default", entry.Name())
	}
}

func TestResolveWithoutHeaderOrDefault(t *testing.T) {
	set := testSet(t, "")

	_, err := set.Resolve("")
	if !errors.Is(err, ErrNoPolicySelected) {
		t.Fatalf("err = %v, want ErrNoPolicySelected", err)
	}
}

// TestResolveRejectsUnknownPolicy is the property that keeps a header value
// from selecting rules nobody configured. Falling back to some other policy
// would mean guessing which access rules an operator meant.
func TestResolveRejectsUnknownPolicy(t *testing.T) {
	set := testSet(t, "staging")

	_, err := set.Resolve("does-not-exist")
	if !errors.Is(err, ErrUnknownPolicy) {
		t.Fatalf("err = %v, want ErrUnknownPolicy", err)
	}

	// Specifically not the default: an unknown name is a fault in the nginx
	// configuration, and answering it with the permissive staging policy
	// would be an authorization bypass.
	if !strings.Contains(err.Error(), "does-not-exist") {
		t.Errorf("err = %v, want it to name the rejected value", err)
	}
}

func TestRedactBoundsRejectedInput(t *testing.T) {
	long := strings.Repeat("x", 200)

	redacted := Redact(long)
	if len(redacted) > maxRedactedLength+len("…") {
		t.Errorf("redacted length = %d, want it bounded", len(redacted))
	}

	// Control characters would otherwise travel from a request into a
	// terminal reading the journal.
	if got := Redact("a\rb\nc\x00d"); strings.ContainsAny(got, "\r\n\x00") {
		t.Errorf("Redact left control characters in %q", got)
	}
}

func TestMatcherAllowAnyUser(t *testing.T) {
	matcher, err := NewMatcher(&config.Policy{Name: "staging", AllowAnyUser: true})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}

	authorized, matched := matcher.Authorized(nil)
	if !authorized {
		t.Fatal("allow_any_user did not authorize a user with no groups")
	}

	if matched != "" {
		t.Errorf("matched group = %q, want empty when no group was required", matched)
	}
}

func TestMatcherRejectsPolicyThatDecidesNothing(t *testing.T) {
	if _, err := NewMatcher(&config.Policy{Name: "broken"}); err == nil {
		t.Fatal("a policy with neither required groups nor allow_any_user was accepted")
	}
}

func TestMatcherByDistinguishedName(t *testing.T) {
	matcher, err := NewMatcher(&config.Policy{
		Name:          "intranet",
		RequireGroups: []string{"cn=web-users,ou=groups,dc=example,dc=org"},
	})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}

	tests := map[string]struct {
		group ldap.Group
		want  bool
	}{
		"exact": {
			group: ldap.Group{DN: "cn=web-users,ou=groups,dc=example,dc=org", Name: "web-users"},
			want:  true,
		},
		"different case": {
			// A directory is free to answer in any case, and denying
			// access over capitalisation would be a support case
			// with no security benefit.
			group: ldap.Group{DN: "CN=Web-Users,OU=Groups,DC=Example,DC=Org", Name: "Web-Users"},
			want:  true,
		},
		"spaces after commas": {
			group: ldap.Group{DN: "cn=web-users, ou=groups, dc=example, dc=org", Name: "web-users"},
			want:  true,
		},
		"different group": {
			group: ldap.Group{DN: "cn=admins,ou=groups,dc=example,dc=org", Name: "admins"},
			want:  false,
		},
		"same name in another subtree": {
			// The policy named a full DN, so a group of the same
			// name elsewhere in the tree is a different group.
			group: ldap.Group{DN: "cn=web-users,ou=other,dc=example,dc=org", Name: "web-users"},
			want:  false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			authorized, _ := matcher.Authorized([]ldap.Group{test.group})
			if authorized != test.want {
				t.Errorf("Authorized(%+v) = %v, want %v", test.group, authorized, test.want)
			}
		})
	}
}

func TestMatcherByShortName(t *testing.T) {
	// A bare name is what people write by hand, and it is also all a
	// memberOf attribute carries in some schemas.
	matcher, err := NewMatcher(&config.Policy{
		Name:          "intranet",
		RequireGroups: []string{"web-users"},
	})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}

	tests := map[string]struct {
		group ldap.Group
		want  bool
	}{
		"name only":       {group: ldap.Group{Name: "web-users"}, want: true},
		"different case":  {group: ldap.Group{Name: "Web-Users"}, want: true},
		"name from a dn":  {group: ldap.Group{DN: "cn=web-users,ou=groups,dc=example,dc=org", Name: "web-users"}, want: true},
		"different group": {group: ldap.Group{Name: "admins"}, want: false},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			authorized, _ := matcher.Authorized([]ldap.Group{test.group})
			if authorized != test.want {
				t.Errorf("Authorized(%+v) = %v, want %v", test.group, authorized, test.want)
			}
		})
	}
}

// TestMatcherAnyRequiredGroupSuffices documents require_groups as a list of
// alternatives rather than a set that all have to be held.
func TestMatcherAnyRequiredGroupSuffices(t *testing.T) {
	matcher, err := NewMatcher(&config.Policy{
		Name:          "intranet",
		RequireGroups: []string{"admins", "web-users"},
	})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}

	authorized, matched := matcher.Authorized([]ldap.Group{{Name: "web-users"}})
	if !authorized {
		t.Fatal("holding one of two alternatives did not authorize")
	}

	if matched != "web-users" {
		t.Errorf("matched group = %q, want the group that granted access", matched)
	}
}

func TestMatcherDeniesEmptyGroupList(t *testing.T) {
	matcher, err := NewMatcher(&config.Policy{
		Name:          "intranet",
		RequireGroups: []string{"web-users"},
	})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}

	if authorized, _ := matcher.Authorized(nil); authorized {
		t.Fatal("a user with no groups was authorized against a group requirement")
	}
}
