# nginx-ldap-auth

An LDAP authentication service for nginx's `auth_request` module. It protects
websites or single nginx locations with LDAP credentials without introducing a
full identity-management stack, and without rebuilding nginx or adding a
third-party module.

```text
Browser ──HTTPS──► nginx ──auth_request──► nginx-ldap-auth ──► GLAuth / LDAP
```

nginx keeps doing HTTP and access enforcement. This service only answers one
question: may this request through?

## Status

Milestone 1 complete. Milestone 2 complete except the Arch Linux PKGBUILD.

Working and covered by tests: authentication, authorization, the in-process and
the shared Redis cache, throttling, Prometheus metrics, and an integration suite
against a real GLAuth directory. See [project.md](project.md) §21.

## Install

### Arch Linux

```sh
updpkgsums          # fills in the release checksum
makepkg -si
```

The package creates the system user, sets the modes on
`/etc/nginx-ldap-auth`, and generates the cache pepper on first install — all
of it declaratively, through `sysusers.d` and `tmpfiles.d` fragments, except
the pepper, which cannot be in the package. See
[packaging/README.md](packaging/README.md) for why.

### From a release archive

Each release carries a `linux/amd64` and a `linux/arm64` archive containing the
binary, the systemd unit, the `sysusers.d` fragment, the example configuration
and the nginx snippet. Those binaries are statically linked and run on any
distribution.

### From source

```sh
make build
sudo make install    # honours DESTDIR, PREFIX, SYSCONFDIR, UNITDIR
```

`make install` places the same ten files the package does, under `/usr/local`
by default. It does not create the system user or generate the pepper, because
neither belongs to a build:

```sh
# The unit runs as this user. The sysusers fragment is the declarative form,
# for a system where systemd applies it.
sudo systemd-sysusers /usr/lib/sysusers.d/nginx-ldap-auth.conf

# Keys the HMAC that derives cache keys from credentials. Without it a leaked
# cache would be crackable offline against a wordlist.
sudo make pepper

# The service account the user and group searches run as, if the directory
# needs one.
sudo sh -c 'printf %s "the-service-password" > /etc/nginx-ldap-auth/ldap-bind.secret'
sudo chown root:nginx-ldap-auth /etc/nginx-ldap-auth/ldap-bind.secret
sudo chmod 0640 /etc/nginx-ldap-auth/ldap-bind.secret
```

### Either way: check the configuration first

```sh
sudo -u nginx-ldap-auth nginx-ldap-auth --check --config /etc/nginx-ldap-auth/config.yaml
```

It reports every problem it finds at once, so a config file takes one pass to
fix rather than one restart per mistake. The unit runs the same check as
`ExecStartPre`, which is what turns a typo into a refused start instead of a
running service with surprising access rules.

```sh
sudo systemctl enable --now nginx-ldap-auth
```

## nginx

[`nginx/auth.conf`](nginx/auth.conf) is a complete server block. The short
version:

```nginx
location / {
    auth_request /_auth;

    auth_request_set $auth_user $upstream_http_x_auth_user;
    proxy_set_header X-Remote-User $auth_user;

    proxy_pass http://127.0.0.1:3000;
}

location = /_auth {
    internal;

    proxy_pass http://127.0.0.1:8080/auth;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";

    proxy_set_header X-Auth-Policy  intranet;
    proxy_set_header Authorization  $http_authorization;
    proxy_set_header X-Real-IP      $remote_addr;
}
```

Three things about this are load-bearing:

- **`X-Real-IP` is not optional.** Behind nginx every request arrives from the
  proxy, so without it the per-address throttle counts the whole internet as one
  client.
- **`X-Auth-Policy` picks the rules.** Omit it and the service falls back to
  `default_policy`, or refuses the request when none is configured. A name that
  matches no policy is always refused — never silently replaced with the
  default.
- **Basic Authentication needs HTTPS.** The password travels on every single
  request.

### What nginx does with the answer

`ngx_http_auth_request_module` only interprets `2xx`, `401` and `403`. The
`429` and `502` this service can return both reach the browser as `500`. That is
the intended fail-closed behaviour; the real status stays in the logs, which is
where it is useful.

| Service answers | Meaning | Browser sees |
|---|---|---|
| `200` | authenticated and authorized | the application |
| `401` | missing, malformed or wrong credentials, or an empty password | a password prompt |
| `403` | valid credentials, group requirement not met — or an unknown policy | `403` |
| `429` | too many failures for this username or address | `500` |
| `502` | the directory could not be reached | `500` |

## Policies

A policy bundles a realm, a directory and the authorization rules for one
application. That is what lets one instance serve several virtual hosts: the
shared endpoint has to be told which rules apply.

```yaml
default_policy: intranet

policies:
  intranet:
    realm: "Intranet"
    ldap: primary
    require_groups:
      - cn=web-users,ou=groups,dc=example,dc=org

  monitoring:
    realm: "Monitoring"
    ldap: primary
    require_groups: [ops]
```

`require_groups` is a list of alternatives: holding any one of them is enough.
Both full DNs and short names are accepted, compared case-insensitively.

Authentication without authorization has to be spelled out:

```yaml
  staging:
    realm: "Staging"
    ldap: primary
    allow_any_user: true
```

Leaving `require_groups` out without that key is refused at startup. "Anyone
who can log in may enter" is a decision, and it should not be reachable by
forgetting a line.

## Configuration

See [`config.example.yaml`](config.example.yaml) — every key is documented
there with the value used when it is omitted. The parts worth knowing before
reading it:

- **The cache is not an optimisation.** nginx issues an `auth_request` for every
  HTTP request, including every image. Without the cache a single page view is
  dozens of LDAP binds. It is on by default with a 60 second TTL.
- **`cache.pepper_file` is required while the cache is on.** Cache keys are
  `HMAC-SHA256(pepper, policy ‖ user ‖ password)`. The pepper is what makes a
  leaked cache useless; an unkeyed hash of a password is not.
- **Negative caching is off.** Turning it on reduces the load a brute-force
  attempt puts on the directory, and delays a corrected password by the same
  amount.
- **Group changes take effect after the TTL.** Membership is part of the cached
  decision.
- **A misspelled key is refused, not ignored.** Silently dropping
  `requre_groups` would produce a policy that lets every authenticated user
  through.

## Security properties

The ones that are deliberate rather than incidental:

- **An empty password is refused before any LDAP operation.** A bind with an
  empty password is an anonymous bind, and many directories answer it with
  success — which would make `Authorization: Basic dXNlcjo=` a valid login for
  every username that exists. The check sits both at the parser and at the layer
  that issues the bind.
- **Every value reaching a filter is escaped per RFC 4515.** A username of
  `*)(uid=*` would otherwise turn a lookup into a match-anything search.
- **A connection is never reused across users.** A bind changes the
  authentication state of a connection. Searches run on a pooled service-account
  connection; each user bind gets a fresh connection that is closed immediately
  after.
- **A directory outage is never an authentication failure.** It is answered
  `502`, and it is not counted against the user — throttling on infrastructure
  errors would lock out every account for the block duration after the outage
  ended.
- **Usernames containing filter metacharacters are refused before any directory
  operation.** Escaping them is correct and not sufficient: a directory that
  decodes the escapes and reparses — GLAuth does — answers with a protocol
  error, which is an infrastructure error, which is deliberately not throttled,
  which makes it repeatable for free. Each repetition costs a search on the one
  pooled connection every other request queues behind.
- **A failing cache is a miss, never a decision.** A read error falls through to
  the directory in both directions: if it denied, a Redis restart would log
  everybody out of every protected site; if it granted, a Redis restart would
  open them. A backend that reports a hit *and* an error is treated as a miss —
  the error alone disqualifies the entry.
- **A decision nobody set denies.** The zero value of a cached decision is
  "invalid credentials", so a struct produced by a failed deserialisation or a
  field added later refuses access instead of granting it.
- **The throttle fails closed on its own exhaustion.** If every tracked identity
  is an active block, further requests are refused rather than served
  uncounted. Making room by evicting an active block would let an attacker clear
  their own block on demand.
- **A username's case is one budget.** LDAP matches `uid` case-insensitively, so
  counting `alice` and `ALICE` separately would multiply an attacker's budget by
  the number of ways a name can be spelled.
- **A successful login clears the username's failure count, never the
  address's.** Otherwise anyone holding one valid account could keep their
  address budget fresh between guesses at everyone else's passwords.
- **Passwords, `Authorization` headers and the pepper never reach the log.**
  Verified by a test that greps its own log output.
- **Successful authentications are logged at debug.** At info they would put one
  line in the journal per HTTP request, and bury the failures that matter.

## Endpoints

On the authentication listener (`server.listen`, loopback):

| Path | Purpose |
|---|---|
| `/auth` | the decision, called by nginx. Not for clients. |
| `/healthz` | liveness. Deliberately independent of LDAP: a failing probe means a restart, and a restart discards the cache that was absorbing the outage. |
| `/readyz` | readiness, plus cache and throttle counters as JSON. |

On its own listener (`metrics.address`), so the two can be firewalled apart:

| Path | Purpose |
|---|---|
| `/metrics` | Prometheus/OpenMetrics exposition. |

### The four metrics worth alerting on

```promql
# The directory is unreachable — not users mistyping passwords.
rate(nginx_ldap_auth_ldap_requests_total{result="error"}[5m]) > 0

# Somebody's nginx names a policy that does not exist. Answered 403, but
# recorded as an error, because the user it was refused for cannot fix it.
rate(nginx_ldap_auth_requests_total{reason="policy_unresolved"}[5m]) > 0

# The throttle ran out of room to count and started refusing. Not a state
# normal traffic produces.
rate(nginx_ldap_auth_throttle_capacity_denied_total[5m]) > 0

# The cache is too small for the working set, so every page view is paying
# for LDAP binds again.
rate(nginx_ldap_auth_cache_evictions_total[5m]) > 0
```

`nginx_ldap_auth_requests_total` carries both a coarse `result` and a specific
`reason`: build ratios on the first, diagnose with the second. Uptime comes from
`process_start_time_seconds`, which the process collector provides — there is
deliberately no uptime gauge of our own, because a gauge counting up from
process start is a counter that silently resets.

## Development

```sh
make help              # every target, with a one-line description
make ci                # exactly what CI runs
make test              # tests with the race detector
make test-integration  # the GLAuth suite (see below)
make check-example     # verify the shipped example configuration loads
make cover             # coverage summary
make sec               # golangci-lint (incl. gosec) + govulncheck
```

Every CI step is one `make` invocation, and a test asserts it. A check that
cannot be reproduced locally is a check nobody can act on — and the linter
version lives in the Makefile for the same reason: pinned separately in the
workflow, it drifted, and a linter older than the Go toolchain does not report
findings, it crashes.

`make fmt` **fails** on unformatted code rather than rewriting it — a CI step
that silently fixes what it was asked to check is not a check. Run
`gofmt -w cmd internal` to fix.

Bump `GOLANGCI_VERSION` in the Makefile together with the Go version in
`go.mod`, not separately.

Pipelines: `.forgejo/workflows/` is the full gate and the release; Forgejo is
primary. `.github/workflows/` is the mirror — a smoke build plus the release
archives.

### The integration suite

```sh
go install github.com/glauth/glauth/v2@latest
make integration
```

It starts a real GLAuth per test on a free port, using the fixture in
`testdata/glauth/`. No container, no shared environment. Without the binary it
skips and says how to get it — so a run without GLAuth is still green, it just
makes no claim about the paths only a directory can settle.

That suite is what verifies the three properties nothing else could: that a
filter matching two entries is refused rather than guessed, that a dropped
service connection is retried once, and that a user bind never lands on the
pooled connection. The last one is observable because an ordinary user in the
fixture has no search capability — so a leaked bind breaks the *next* request.

It also found a defect no unit test could: escaping the username correctly is
not sufficient, because a directory that decodes the escapes and reparses
answers with a protocol error rather than a refusal — an unthrottled request
that costs a search on the pooled connection every time.

The Redis backend is tested against a real RESP server on a real socket.
`NGINX_LDAP_AUTH_REDIS_ADDR=127.0.0.1:6379` runs the same assertions against a
real Redis.

## Design

[project.md](project.md) is the specification: architecture, the reasoning
behind each decision, the operational behaviour table, and what is explicitly
out of scope. Read §12 before changing anything in the authentication path.
