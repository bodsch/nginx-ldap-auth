// Package ldap authenticates users against one directory and resolves their
// group membership.
//
// Two properties of this package matter more than its shape:
//
//   - Every value that reaches a filter is escaped per RFC 4515. Interpolating
//     a raw username into "(uid=%s)" is an injection: "*)(uid=*" turns a lookup
//     into a match-anything search.
//   - A bind changes the authentication state of a connection, so a connection
//     is never reused across users. Searches run on a pooled service-account
//     connection, each user bind gets a fresh connection that is closed
//     immediately afterwards.
package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"

	goldap "github.com/go-ldap/ldap/v3"

	"bodsch.me/nginx-ldap-auth/internal/config"
)

// ErrInvalidCredentials means the directory refused the credentials, or the
// user does not exist.
//
// The two cases are deliberately one error. Reporting them separately would
// turn the authentication endpoint into a username oracle, and the client has
// no use for the difference either way.
var ErrInvalidCredentials = errors.New("invalid credentials")

// maxUserEntries is the size limit of a user search.
//
// It is 2 rather than 1 on purpose: with a limit of 1 an ambiguous filter looks
// like a unique match, and the service would bind as whichever entry the
// directory happened to return first.
const maxUserEntries = 2

// maxGroupEntries is the size limit of a group search. See resolveGroups for
// why exceeding it is an error rather than a truncation.
const maxGroupEntries = 256

// ErrAmbiguousUser means the user filter matched more than one entry. This is a
// configuration fault, not an authentication failure: the service cannot know
// which of the entries the client meant, and picking one would be a guess about
// who is logging in.
var ErrAmbiguousUser = errors.New("user filter matched more than one entry")

// Operation names for the Observer, and the closed set of results.
//
// The service bind is reported separately from a user bind even though both are
// binds. They answer different questions: a user bind happens once per
// uncached authentication, while a service bind happens only on connect and on
// reconnect. Counting them together would make the bind rate meaningless and
// hide a directory that is closing connections.
const (
	OperationBind        = "bind"
	OperationServiceBind = "service_bind"
	OperationSearch      = "search"

	// ResultSuccess means the operation completed.
	ResultSuccess = "success"

	// ResultFailure means the directory answered and said no. A rejected
	// password is a failure; so is a refused search.
	ResultFailure = "failure"

	// ResultError means the operation never got an answer: a broken
	// transport, a timeout, a TLS handshake that could not be verified.
	ResultError = "error"
)

// Observer receives one report per directory operation.
//
// The interface lives here rather than in internal/metrics so that this package
// keeps no dependency on a metrics library, and so that what is reported is
// decided by the code that knows what it did.
type Observer interface {
	ObserveLDAP(operation, result string, elapsed time.Duration)
}

// Option adjusts a Client at construction.
type Option func(*Client)

// WithObserver attaches an observer.
func WithObserver(observer Observer) Option {
	return func(c *Client) { c.observer = observer }
}

// Group is one resolved group membership.
//
// Both forms are kept because a policy may name either. Configurations in the
// wild use the full DN, and people writing them by hand use the short name.
type Group struct {
	// DN is the group's distinguished name, empty when the directory only
	// reported a name.
	DN string

	// Name is the short name, typically the cn.
	Name string
}

// String renders the group for logs and for the identity header, preferring the
// short name.
func (g Group) String() string {
	if g.Name != "" {
		return g.Name
	}

	return g.DN
}

// Identity is the result of a successful authentication.
type Identity struct {
	// DN is the entry the service bound as.
	DN string

	// User is the canonical login name as the directory spells it, which is
	// not necessarily what the client typed.
	User string

	Groups []Group
}

// Client talks to one directory.
type Client struct {
	cfg *config.LDAP
	log *slog.Logger
	tls *tls.Config

	observer Observer

	// serviceMu guards the pooled service-account connection.
	//
	// One connection means searches are serialised. For the deployment this
	// targets — a single service in front of a cached authentication path,
	// where a search costs well under a millisecond — that is not the
	// bottleneck, and it keeps the invariant that matters obvious: this
	// connection is bound as the service account and as nothing else.
	serviceMu   sync.Mutex
	serviceConn *goldap.Conn
}

// New returns a Client for one configured directory.
func New(cfg *config.LDAP, log *slog.Logger, opts ...Option) (*Client, error) {
	tlsConfig, err := tlsConfigFor(cfg)
	if err != nil {
		return nil, err
	}

	client := &Client{
		cfg: cfg,
		log: log.With(slog.String("directory", cfg.Name)),
		tls: tlsConfig,
	}

	for _, opt := range opts {
		opt(client)
	}

	return client, nil
}

// observe reports one completed operation.
func (c *Client) observe(operation string, started time.Time, err error) {
	if c.observer == nil {
		return
	}

	c.observer.ObserveLDAP(operation, resultFor(err), time.Since(started))
}

// resultFor classifies an operation's outcome.
//
// The distinction that matters is between an answer and no answer. "The
// directory rejected this password" is normal traffic; "the directory could not
// be reached" is an outage, and an alert that cannot tell them apart will fire
// on users mistyping their passwords.
func resultFor(err error) string {
	switch {
	case err == nil:
		return ResultSuccess
	case isConnectionError(err):
		return ResultError
	default:
		return ResultFailure
	}
}

// Name returns the directory's configured name.
func (c *Client) Name() string {
	return c.cfg.Name
}

// Authenticate looks the user up, binds as the entry that was found, and
// resolves the group membership.
//
// It returns ErrInvalidCredentials for a rejected or unknown user, and any
// other error for an infrastructure fault. Callers must keep the two apart: the
// first is a 401, the second must never be.
func (c *Client) Authenticate(ctx context.Context, user, password string) (*Identity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Defence in depth. The authentication path rejects empty passwords
	// before it gets here, but a bind with an empty password is an
	// anonymous bind, and many directories answer it with success. That
	// would make "Authorization: Basic dXNlcjo=" a valid login for any
	// known username, so the check is repeated at the only layer that
	// actually issues the bind.
	if strings.TrimSpace(password) == "" {
		return nil, fmt.Errorf("%w: empty password", ErrInvalidCredentials)
	}

	entry, err := c.findUser(user)
	if err != nil {
		return nil, err
	}

	if err := c.bindAs(entry.DN, password); err != nil {
		return nil, err
	}

	identity := &Identity{
		DN:   entry.DN,
		User: entry.GetAttributeValue(c.cfg.UserAttribute),
	}

	// A directory that matched the filter but reports no value for the
	// login attribute would otherwise produce an empty identity header.
	if identity.User == "" {
		identity.User = user
	}

	identity.Groups, err = c.resolveGroups(entry, identity)
	if err != nil {
		return nil, err
	}

	return identity, nil
}

// Close releases the pooled connection.
func (c *Client) Close() {
	c.serviceMu.Lock()
	defer c.serviceMu.Unlock()

	if c.serviceConn != nil {
		_ = c.serviceConn.Close()
		c.serviceConn = nil
	}
}

// findUser resolves the login name to a single directory entry.
func (c *Client) findUser(user string) (*goldap.Entry, error) {
	filter := c.userFilter(user)

	attributes := []string{c.cfg.UserAttribute}
	if c.cfg.GroupSource == config.GroupSourceAttribute {
		attributes = append(attributes, c.cfg.GroupAttribute)
	}

	var entries []*goldap.Entry

	started := time.Now()

	err := c.withService(func(conn *goldap.Conn) error {
		result, err := conn.Search(c.searchRequest(c.cfg.BaseDN, filter, attributes, maxUserEntries))
		if err != nil {
			return err
		}

		entries = result.Entries

		return nil
	})

	c.observe(OperationSearch, started, err)

	switch {
	case goldap.IsErrorWithCode(err, goldap.LDAPResultSizeLimitExceeded):
		return nil, fmt.Errorf("%w: %s", ErrAmbiguousUser, filter)
	case err != nil:
		return nil, fmt.Errorf("search for user in %s: %w", c.cfg.BaseDN, err)
	case len(entries) == 0:
		return nil, fmt.Errorf("%w: no entry matched", ErrInvalidCredentials)
	case len(entries) > 1:
		return nil, fmt.Errorf("%w: %s", ErrAmbiguousUser, filter)
	}

	return entries[0], nil
}

// bindAs verifies a password by binding as the entry that was found.
//
// The connection is created for this bind and closed straight after it. It is
// never returned to the pool: a bound connection carries that user's identity,
// and a later search on it would run as them.
func (c *Client) bindAs(dn, password string) error {
	started := time.Now()

	conn, err := c.dial()
	if err != nil {
		c.observe(OperationBind, started, err)

		return fmt.Errorf("connect for user bind: %w", err)
	}

	defer conn.Close()

	err = conn.Bind(dn, password)

	c.observe(OperationBind, started, err)

	if err != nil {
		if goldap.IsErrorWithCode(err, goldap.LDAPResultInvalidCredentials) {
			return fmt.Errorf("%w: directory rejected the password", ErrInvalidCredentials)
		}

		// An entry the service account can see but nobody may bind as —
		// a disabled account, a group, a computer object — is an
		// authentication failure, not an outage.
		if goldap.IsErrorWithCode(err, goldap.LDAPResultInappropriateAuthentication) ||
			goldap.IsErrorWithCode(err, goldap.LDAPResultUnwillingToPerform) {
			return fmt.Errorf("%w: directory refused to authenticate this entry", ErrInvalidCredentials)
		}

		return fmt.Errorf("user bind: %w", err)
	}

	return nil
}

// userFilter builds the user search filter with the login name escaped.
func (c *Client) userFilter(user string) string {
	return fmt.Sprintf(c.cfg.UserFilter, goldap.EscapeFilter(user))
}

// searchRequest builds a search bounded by sizeLimit and by the configured
// operation timeout.
func (c *Client) searchRequest(baseDN, filter string, attributes []string, sizeLimit int) *goldap.SearchRequest {
	return goldap.NewSearchRequest(
		baseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		sizeLimit,
		timeLimitSeconds(c.cfg.OperationTimeout.Duration()),
		false,
		filter,
		attributes,
		nil,
	)
}

// timeLimitSeconds converts the operation timeout into the whole seconds the
// LDAP protocol allows, rounding up. Rounding down would send 0, which means
// "no limit" and would leave the server free to run longer than configured.
func timeLimitSeconds(timeout time.Duration) int {
	if timeout <= 0 {
		return 1
	}

	return int(math.Ceil(timeout.Seconds()))
}
