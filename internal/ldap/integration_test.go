package ldap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"bodsch.me/nginx-ldap-auth/internal/config"
)

// The integration suite runs against a real directory.
//
// GLAuth is a single static binary with a plain configuration file, which is
// why it is the backend this service targets: the suite needs no container, no
// shared test environment, and no fixture that only resembles LDAP. Everything
// here goes over a socket and through the real protocol.
//
// Install it with:
//
//	go install github.com/glauth/glauth/v2@latest
//
// Without the binary the suite skips rather than failing. A developer without
// it still gets a green run of everything else; what they do not get is any
// claim about the paths only a directory can exercise, and the skip message
// says so.
const (
	// EnvGLAuth overrides the binary location.
	EnvGLAuth = "NGINX_LDAP_AUTH_GLAUTH"

	// Credentials from testdata/glauth/glauth.cfg. Fixtures, not secrets:
	// nothing authenticates against them but this suite.
	testServiceDN       = "cn=svc,ou=service,dc=example,dc=org"
	testServicePassword = "servicepw"
	testBaseDN          = "dc=example,dc=org"
	testGroupBaseDN     = "ou=groups,dc=example,dc=org"
)

// directory is a running GLAuth instance.
type directory struct {
	address string
	cmd     *exec.Cmd

	mu      sync.Mutex
	stopped bool
}

// glauthBinary locates the GLAuth binary, or reports why the suite cannot run.
func glauthBinary() (string, error) {
	if override := os.Getenv(EnvGLAuth); override != "" {
		return override, nil
	}

	if path, err := exec.LookPath("glauth"); err == nil {
		return path, nil
	}

	// go install puts it here, and GOPATH/bin is frequently not on PATH.
	gopath, err := exec.Command("go", "env", "GOPATH").Output()
	if err == nil {
		candidate := filepath.Join(strings.TrimSpace(string(gopath)), "bin", "glauth")
		if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("glauth not found in PATH or GOPATH/bin; "+
		"install it with `go install github.com/glauth/glauth/v2@latest`, or set %s", EnvGLAuth)
}

// startDirectory boots GLAuth on a free port with the fixture configuration.
func startDirectory(t *testing.T) *directory {
	t.Helper()

	binary, err := glauthBinary()
	if err != nil {
		t.Skipf("skipping the integration suite: %v", err)
	}

	address := freeLoopbackAddress(t)

	// The fixture's listen address is a placeholder; the port is chosen at
	// run time so that two test binaries can run at once and neither
	// collides with a developer's own directory.
	fixture, err := os.ReadFile(filepath.Join("..", "..", "testdata", "glauth", "glauth.cfg"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	rewritten := strings.Replace(string(fixture), "127.0.0.1:3893", address, 1)

	configPath := filepath.Join(t.TempDir(), "glauth.cfg")
	if err := os.WriteFile(configPath, []byte(rewritten), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	logPath := filepath.Join(t.TempDir(), "glauth.log")

	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create log: %v", err)
	}

	cmd := exec.Command(binary, "-c", configPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		t.Fatalf("start glauth: %v", err)
	}

	dir := &directory{address: address, cmd: cmd}

	t.Cleanup(func() {
		dir.Stop()
		_ = logFile.Close()

		// The directory's own log is the only place that says why a
		// request was refused, so it is surfaced when something failed.
		if t.Failed() {
			if contents, readErr := os.ReadFile(logPath); readErr == nil {
				t.Logf("glauth log:\n%s", contents)
			}
		}
	})

	dir.waitUntilListening(t)

	return dir
}

// waitUntilListening polls the port rather than sleeping.
func (d *directory) waitUntilListening(t *testing.T) {
	t.Helper()

	deadline := time.Now().Add(15 * time.Second)

	for {
		conn, err := net.DialTimeout("tcp", d.address, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()

			return
		}

		if time.Now().After(deadline) {
			t.Fatalf("glauth never listened on %s: %v", d.address, err)
		}

		time.Sleep(10 * time.Millisecond)
	}
}

// Stop terminates the directory. Safe to call twice, because a test that stops
// it mid-run also has the cleanup call it.
func (d *directory) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.stopped {
		return
	}

	d.stopped = true

	if d.cmd.Process != nil {
		_ = d.cmd.Process.Kill()
	}

	_ = d.cmd.Wait()
}

// freeLoopbackAddress returns an address nothing is listening on.
func freeLoopbackAddress(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	address := listener.Addr().String()

	if err := listener.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	return address
}

// clientFor builds a client against the running directory.
//
// The defaults mirror the group configuration that actually works against
// GLAuth, which is not the one an intuitive reading of the schema suggests —
// see TestGLAuthSchemaAssumptions.
func clientFor(t *testing.T, dir *directory, mutate func(*config.LDAP)) (*Client, *recordingObserver) {
	t.Helper()

	cfg := &config.LDAP{
		Name:               "glauth",
		URL:                "ldap://" + dir.address,
		BaseDN:             testBaseDN,
		UserFilter:         "(uid=%s)",
		UserAttribute:      "uid",
		GroupSource:        config.GroupSourceFilter,
		GroupBaseDN:        testGroupBaseDN,
		GroupFilter:        "(&(objectClass=groupOfUniqueNames)(uniqueMember=%s))",
		GroupFilterValue:   config.GroupFilterValueDN,
		GroupNameAttribute: "cn",
		BindDN:             testServiceDN,
		BindPassword:       testServicePassword,
		BindTimeout:        config.Duration(5 * time.Second),
		OperationTimeout:   config.Duration(5 * time.Second),
	}

	if mutate != nil {
		mutate(cfg)
	}

	observer := &recordingObserver{}

	client, err := New(cfg, discardLogger(), WithObserver(observer))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t.Cleanup(client.Close)

	return client, observer
}

func TestIntegrationValidCredentials(t *testing.T) {
	dir := startDirectory(t)
	client, observer := clientFor(t, dir, nil)

	identity, err := client.Authenticate(t.Context(), "alice", "s3cret")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if identity.User != "alice" {
		t.Errorf("user = %q, want alice", identity.User)
	}

	if !strings.HasPrefix(identity.DN, "cn=alice,") {
		t.Errorf("dn = %q, want the entry the directory actually holds", identity.DN)
	}

	if len(identity.Groups) == 0 {
		t.Fatal("no groups resolved")
	}

	found := false

	for _, group := range identity.Groups {
		if group.Name == "web-users" {
			found = true
		}
	}

	if !found {
		t.Errorf("groups = %v, want web-users among them", identity.Groups)
	}

	// A search on the service connection, then a bind on a fresh one.
	operations := observer.snapshot()

	binds := 0
	searches := 0

	for _, op := range operations {
		switch op.operation {
		case OperationBind:
			binds++
		case OperationSearch:
			searches++
		}
	}

	if binds != 1 {
		t.Errorf("binds = %d, want exactly one user bind: %+v", binds, operations)
	}

	if searches != 2 {
		t.Errorf("searches = %d, want the user lookup and the group lookup: %+v", searches, operations)
	}
}

func TestIntegrationWrongPassword(t *testing.T) {
	dir := startDirectory(t)
	client, _ := clientFor(t, dir, nil)

	_, err := client.Authenticate(t.Context(), "alice", "not-her-password")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
}

// TestIntegrationUnknownUserIsIndistinguishable keeps the endpoint from
// becoming a username oracle.
func TestIntegrationUnknownUserIsIndistinguishable(t *testing.T) {
	dir := startDirectory(t)
	client, _ := clientFor(t, dir, nil)

	_, unknownErr := client.Authenticate(t.Context(), "nobody-here", "whatever")
	if !errors.Is(unknownErr, ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", unknownErr)
	}

	_, wrongErr := client.Authenticate(t.Context(), "alice", "wrong")
	if !errors.Is(wrongErr, ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials", wrongErr)
	}
}

// TestIntegrationEmptyPasswordDoesNotBind is the anonymous-bind bypass against
// a real directory.
//
// The unit test asserts the check happens; this asserts what the check
// prevents. Without it the bind below is an unauthenticated bind, and whether
// that succeeds is up to the directory rather than up to us.
func TestIntegrationEmptyPasswordDoesNotBind(t *testing.T) {
	dir := startDirectory(t)
	client, observer := clientFor(t, dir, nil)

	for _, password := range []string{"", " ", "\t"} {
		_, err := client.Authenticate(t.Context(), "alice", password)
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("password %q: err = %v, want ErrInvalidCredentials", password, err)
		}
	}

	if operations := observer.snapshot(); len(operations) != 0 {
		t.Errorf("the directory was contacted %d times: %+v", len(operations), operations)
	}
}

// TestIntegrationFilterInjectionIsRefusedWithoutASearch is the injection test
// with a real directory behind it, and it is the test that found why escaping
// alone is not enough.
//
// Escaping works: `*)(uid=*` goes out as `(uid=\2a\29\28uid=\2a)` and matches
// nothing. But GLAuth decodes the escapes and recompiles the filter, so it
// answers with a protocol error instead of a refusal. That is an infrastructure
// error, which means it is deliberately *not* counted against the throttle —
// and every attempt costs a search on the single pooled service connection that
// every other request queues behind. An attacker could repeat it indefinitely.
//
// So these usernames are now refused before any directory work happens, and the
// assertion is both halves: the request is a credential failure, and the
// directory was never contacted.
func TestIntegrationFilterInjectionIsRefusedWithoutASearch(t *testing.T) {
	dir := startDirectory(t)
	client, observer := clientFor(t, dir, nil)

	for _, username := range []string{"*", "*)(uid=*", "alice)(|(uid=*", `back\slash`} {
		_, err := client.Authenticate(t.Context(), username, "s3cret")

		if err == nil {
			t.Errorf("username %q authenticated", username)

			continue
		}

		if !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("username %q: err = %v, want ErrInvalidCredentials", username, err)
		}
	}

	if operations := observer.snapshot(); len(operations) != 0 {
		t.Errorf("the directory was contacted %d times by injection attempts: %+v",
			len(operations), operations)
	}
}

// TestIntegrationOrdinaryUsernamesStillWork is the guard on the previous test's
// fix.
//
// Rejecting characters outright is only safe if the rejected set contains
// nothing a real login name uses. These are names that must keep working.
func TestIntegrationOrdinaryUsernamesStillWork(t *testing.T) {
	dir := startDirectory(t)
	client, _ := clientFor(t, dir, nil)

	// alice is the only one the fixture can authenticate; the rest have to
	// reach the directory and be refused there rather than being rejected
	// as malformed.
	if _, err := client.Authenticate(t.Context(), "alice", "s3cret"); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	for _, username := range []string{
		"first.last", "user-name", "user_name", "user+tag", "USER", "üser", "a@example.org",
	} {
		_, err := client.Authenticate(t.Context(), username, "whatever")

		if !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("username %q: err = %v, want it to reach the directory and be refused there",
				username, err)
		}
	}
}

// TestIntegrationAmbiguousUserIsRefused provokes the condition rather than
// constructing it.
//
// Two fixture entries share a uidNumber. A filter on that attribute matches
// both, and the service must refuse: it cannot know which of the two the client
// meant, and picking one is a guess about who is logging in.
func TestIntegrationAmbiguousUserIsRefused(t *testing.T) {
	dir := startDirectory(t)

	client, _ := clientFor(t, dir, func(cfg *config.LDAP) {
		cfg.UserFilter = "(uidNumber=%s)"
	})

	_, err := client.Authenticate(t.Context(), "5005", "irrelevant")
	if !errors.Is(err, ErrAmbiguousUser) {
		t.Fatalf("err = %v, want ErrAmbiguousUser", err)
	}

	// Specifically not an authentication failure: a 401 would tell the user
	// their password is wrong when the actual problem is a filter that
	// cannot identify them.
	if errors.Is(err, ErrInvalidCredentials) {
		t.Error("an ambiguous filter was reported as invalid credentials")
	}
}

// TestIntegrationGroupsFromMemberOf covers the other group source against the
// real schema.
func TestIntegrationGroupsFromMemberOf(t *testing.T) {
	dir := startDirectory(t)

	client, _ := clientFor(t, dir, func(cfg *config.LDAP) {
		cfg.GroupSource = config.GroupSourceAttribute
		cfg.GroupAttribute = "memberOf"
		cfg.GroupFilter = ""
		cfg.GroupBaseDN = ""
	})

	identity, err := client.Authenticate(t.Context(), "alice", "s3cret")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if len(identity.Groups) == 0 {
		t.Fatal("memberOf resolved no groups")
	}

	// GLAuth writes memberOf values as ou=<group>,ou=groups,... rather than
	// cn=<group>,... The short name has to come out the same either way, or
	// a policy written against one group source would not match the other.
	for _, group := range identity.Groups {
		if group.Name == "web-users" {
			return
		}
	}

	t.Errorf("groups = %+v, want the short name web-users among them", identity.Groups)
}

// TestIntegrationUserWithoutGroupsAuthenticates separates the two concepts
// against a real directory: carol's password is correct and her group
// membership is not what a policy requires.
func TestIntegrationUserWithoutGroupsAuthenticates(t *testing.T) {
	dir := startDirectory(t)
	client, _ := clientFor(t, dir, nil)

	identity, err := client.Authenticate(t.Context(), "carol", "c4rol")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	for _, group := range identity.Groups {
		if group.Name == "web-users" {
			t.Errorf("carol resolved into web-users: %+v", identity.Groups)
		}
	}
}

// TestIntegrationDirectoryOutage is the §18 row "LDAP unavailable → 5xx",
// provoked by stopping the directory rather than by pointing at a closed port.
//
// The difference matters: a closed port fails at connect, while a directory
// that goes away mid-session fails on an established connection that the
// service believes is usable. The second is what actually happens during a
// restart of the directory.
func TestIntegrationDirectoryOutage(t *testing.T) {
	dir := startDirectory(t)
	client, _ := clientFor(t, dir, nil)

	if _, err := client.Authenticate(t.Context(), "alice", "s3cret"); err != nil {
		t.Fatalf("Authenticate before the outage: %v", err)
	}

	dir.Stop()

	_, err := client.Authenticate(t.Context(), "alice", "s3cret")
	if err == nil {
		t.Fatal("authentication succeeded against a stopped directory")
	}

	// Never a credential failure. A 401 during an outage tells every user
	// their password is wrong, and they will change it.
	if errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("err = %v, want an infrastructure error", err)
	}
}

// TestIntegrationServiceConnectionIsReusedAcrossRequests is the pooling half of
// the connection contract.
func TestIntegrationServiceConnectionIsReusedAcrossRequests(t *testing.T) {
	dir := startDirectory(t)
	client, observer := clientFor(t, dir, nil)

	for range 3 {
		if _, err := client.Authenticate(t.Context(), "alice", "s3cret"); err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
	}

	// One service bind for the whole run: the search connection is pooled.
	// A service bind per request would mean the pool is not working, and a
	// directory with a bind rate limit would start refusing.
	serviceBinds := 0

	for _, op := range observer.snapshot() {
		if op.operation == OperationServiceBind {
			serviceBinds++
		}
	}

	if serviceBinds != 1 {
		t.Errorf("service binds = %d across three authentications, want 1", serviceBinds)
	}
}

// TestIntegrationUserBindNeverRunsOnTheServiceConnection is the property that
// keeps one request from inheriting another's identity.
//
// A successful bind changes the authentication state of a connection. If the
// user bind ran on the pooled connection, every subsequent search would run as
// that user — and in this fixture ordinary users have no search capability at
// all, so the next request would fail with an access error. That is what makes
// the property observable from outside: authenticating as a user with no search
// rights must not break the following authentication.
func TestIntegrationUserBindNeverRunsOnTheServiceConnection(t *testing.T) {
	dir := startDirectory(t)
	client, _ := clientFor(t, dir, nil)

	// bob can bind but cannot search.
	if _, err := client.Authenticate(t.Context(), "bob", "hunter2"); err != nil {
		t.Fatalf("Authenticate bob: %v", err)
	}

	// If bob's bind had landed on the pooled connection, this search would
	// now run as bob and be refused.
	if _, err := client.Authenticate(t.Context(), "alice", "s3cret"); err != nil {
		t.Fatalf("the next authentication failed, so the user bind reused the service connection: %v", err)
	}
}

// TestIntegrationReconnectsAfterTheDirectoryDropsTheConnection is the retry
// contract from §5.
//
// Directories close idle connections. The first request after a quiet period
// finds a dead one, and failing it would turn an idle timeout into a 500 for a
// user who did nothing wrong. Restarting the directory under a live client is
// the same situation, arrived at faster.
func TestIntegrationReconnectsAfterTheDirectoryDropsTheConnection(t *testing.T) {
	binary, err := glauthBinary()
	if err != nil {
		t.Skipf("skipping the integration suite: %v", err)
	}

	_ = binary

	dir := startDirectory(t)
	client, _ := clientFor(t, dir, nil)

	if _, err := client.Authenticate(t.Context(), "alice", "s3cret"); err != nil {
		t.Fatalf("Authenticate before the restart: %v", err)
	}

	// Restart on the same port, so the client's pooled connection is dead
	// but a new one will succeed.
	address := dir.address
	dir.Stop()

	restarted := restartDirectoryOn(t, binary, address)
	defer restarted.Stop()

	if _, err := client.Authenticate(t.Context(), "alice", "s3cret"); err != nil {
		t.Fatalf("the client did not recover from a dropped connection: %v", err)
	}
}

// restartDirectoryOn boots GLAuth on a specific address.
func restartDirectoryOn(t *testing.T, binary, address string) *directory {
	t.Helper()

	fixture, err := os.ReadFile(filepath.Join("..", "..", "testdata", "glauth", "glauth.cfg"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	rewritten := strings.Replace(string(fixture), "127.0.0.1:3893", address, 1)

	configPath := filepath.Join(t.TempDir(), "glauth-restart.cfg")
	if err := os.WriteFile(configPath, []byte(rewritten), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	cmd := exec.Command(binary, "-c", configPath)

	if err := cmd.Start(); err != nil {
		t.Fatalf("restart glauth: %v", err)
	}

	dir := &directory{address: address, cmd: cmd}
	dir.waitUntilListening(t)

	return dir
}

// TestIntegrationContextCancellation checks the one cancellation point the
// client has. go-ldap 3.4 has no context-aware operations, so this is the
// extent of it, and the test exists to keep that honest rather than to claim
// more.
func TestIntegrationContextCancellation(t *testing.T) {
	dir := startDirectory(t)
	client, observer := clientFor(t, dir, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := client.Authenticate(ctx, "alice", "s3cret"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}

	if operations := observer.snapshot(); len(operations) != 0 {
		t.Errorf("a cancelled request still reached the directory: %+v", operations)
	}
}
