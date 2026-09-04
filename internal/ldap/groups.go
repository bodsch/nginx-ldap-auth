package ldap

import (
	"errors"
	"fmt"
	"time"

	goldap "github.com/go-ldap/ldap/v3"

	"bodsch.me/nginx-ldap-auth/internal/config"
)

// ErrTooManyGroups means the group search hit its size limit.
var ErrTooManyGroups = errors.New("group search returned more entries than the size limit allows")

// resolveGroups collects the user's group membership.
//
// Group resolution runs only after a successful bind. Doing it earlier would
// spend directory work on wrong passwords and would let the timing of a failed
// request say something about whether the account exists.
func (c *Client) resolveGroups(entry *goldap.Entry, identity *Identity) ([]Group, error) {
	switch c.cfg.GroupSource {
	case config.GroupSourceNone:
		return nil, nil

	case config.GroupSourceAttribute:
		// memberOf style: the membership is already on the entry that the
		// user search fetched, so this costs no extra round trip.
		values := entry.GetAttributeValues(c.cfg.GroupAttribute)

		groups := make([]Group, 0, len(values))
		for _, value := range values {
			groups = append(groups, groupFromValue(value))
		}

		return groups, nil

	case config.GroupSourceFilter:
		return c.groupsFromFilter(identity)

	default:
		// Unreachable: configuration validation rejects any other value.
		return nil, fmt.Errorf("unsupported group source %q", c.cfg.GroupSource)
	}
}

// groupsFromFilter searches the group base for entries listing the user as a
// member, for member/memberUid style schemas.
func (c *Client) groupsFromFilter(identity *Identity) ([]Group, error) {
	filter := c.groupFilter(identity)

	var entries []*goldap.Entry

	started := time.Now()

	err := c.withService(func(conn *goldap.Conn) error {
		result, err := conn.Search(
			c.searchRequest(c.cfg.GroupBaseDN, filter, []string{c.cfg.GroupNameAttribute}, maxGroupEntries))
		if err != nil {
			return err
		}

		entries = result.Entries

		return nil
	})

	c.observe(OperationSearch, started, err)

	// Truncating instead would be worse than failing. The dropped entries
	// could include the one group the policy requires, and the user would
	// get a 403 that looks like a deliberate authorization decision. An
	// error at least says what happened.
	if goldap.IsErrorWithCode(err, goldap.LDAPResultSizeLimitExceeded) {
		return nil, fmt.Errorf("%w (%d) for %s", ErrTooManyGroups, maxGroupEntries, filter)
	}

	if err != nil {
		return nil, fmt.Errorf("search for groups in %s: %w", c.cfg.GroupBaseDN, err)
	}

	groups := make([]Group, 0, len(entries))

	for _, entry := range entries {
		group := Group{
			DN:   entry.DN,
			Name: entry.GetAttributeValue(c.cfg.GroupNameAttribute),
		}

		if group.Name == "" {
			group.Name = firstRDNValue(entry.DN)
		}

		groups = append(groups, group)
	}

	return groups, nil
}

// groupFilter builds the group search filter with the interpolated value
// escaped.
//
// Extracted from groupsFromFilter so that the escaping is assertable without a
// directory to search. The user filter had a test for this from the start and
// this one did not, which is the whole difference between a rule that holds and
// a rule that is written down.
func (c *Client) groupFilter(identity *Identity) string {
	value := identity.User
	if c.cfg.GroupFilterValue == config.GroupFilterValueDN {
		value = identity.DN
	}

	return fmt.Sprintf(c.cfg.GroupFilter, goldap.EscapeFilter(value))
}

// groupFromValue interprets one value of a memberOf style attribute.
//
// Directories put a full DN there; some schemas and some test fixtures put a
// bare name. Whether the value parses as a DN is the discriminator, since a DN
// has to contain at least one type=value pair.
func groupFromValue(value string) Group {
	if parsed, err := goldap.ParseDN(value); err == nil && len(parsed.RDNs) > 0 {
		return Group{
			DN:   value,
			Name: rdnValue(parsed),
		}
	}

	return Group{Name: value}
}

// firstRDNValue returns the value of a DN's leftmost attribute, which for a
// group entry is its short name.
func firstRDNValue(dn string) string {
	parsed, err := goldap.ParseDN(dn)
	if err != nil {
		return dn
	}

	return rdnValue(parsed)
}

func rdnValue(dn *goldap.DN) string {
	if len(dn.RDNs) == 0 || len(dn.RDNs[0].Attributes) == 0 {
		return ""
	}

	return dn.RDNs[0].Attributes[0].Value
}
