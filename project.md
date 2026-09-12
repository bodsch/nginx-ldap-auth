# nginx-ldap-auth

A small, native authentication gateway for nginx using LDAP, a short-lived decision cache, and Prometheus/OpenMetrics.

## 1. Overview

`nginx-ldap-auth` provides a simple LDAP-backed authentication service for nginx.

The primary use case is protecting websites or selected nginx locations with LDAP credentials without introducing a full identity-management stack such as Keycloak.

The service is designed for Linux installations where nginx is already installed and should not need to be rebuilt or extended with third-party nginx modules.

### Design goals

- Native Linux/systemd deployment
- Go implementation
- No Docker requirement
- No Node.js
- No nginx rebuild
- No third-party nginx module
- LDAP authentication
- GLAuth-compatible LDAP backend
- In-process authentication cache by default; optional Redis for multi-instance setups
- Prometheus/OpenMetrics metrics
- Health and readiness endpoints
- Small dependency footprint
- Secure defaults
- Named policies, so one instance can serve multiple nginx virtual hosts/applications
- Configuration via YAML
- No external process execution at runtime

## 2. Architecture

```text
                         HTTPS
Browser ─────────────────────────────► nginx
                                      │
                                      │ auth_request
                                      ▼
                              ┌─────────────────┐
                              │ nginx-ldap-auth │
                              │                 │
                              │ /auth           │
                              │ /healthz        │
                              │ /readyz         │
                              │ /metrics        │
                              │                 │
                              │ in-process      │
                              │ decision cache  │
                              └───────┬─────────┘
                                      │
                         ┌────────────┼────────────┐
                         │                         │
                         ▼                         ▼
                      GLAuth                    Redis
                       LDAP           optional shared cache
```

nginx remains responsible for HTTP handling and access control.

`nginx-ldap-auth` is responsible only for authentication and authorization decisions.

LDAP credentials are validated against GLAuth. Successful decisions are cached in-process for a short, configurable period. Redis is an optional replacement for that cache when several instances should share decisions — it is not part of the default deployment.

## 3. nginx integration

The Arch Linux nginx package already provides the required `auth_request` module.

The intended integration is:

```nginx
location / {
    auth_request /_auth;

    proxy_pass http://backend;
}

location = /_auth {
    internal;

    proxy_pass http://127.0.0.1:8080/auth;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Auth-Policy intranet;
    proxy_set_header Authorization $http_authorization;
    proxy_set_header X-Real-IP $remote_addr;
}
```

`X-Real-IP` is not decoration. Behind nginx every request arrives from the proxy, so the peer address is the same loopback address for all of them, and a per-address throttle keyed on it would count the whole internet as one client. The header is what carries the original address across, and `server.client_ip_header` is where the service is told which header was used.

The value is trusted, and that is only safe while the endpoint is unreachable by clients — a client that can reach it directly could spread its failures over as many fictional addresses as it likes. Configuration validation refuses the combination of a trusted address header and a listener bound to anything other than loopback.

The authentication service returns:

- `200` for an authenticated request
- `401` for invalid or missing credentials
- `403` for authenticated users that are not authorized

### Status codes nginx understands

`ngx_http_auth_request_module` only interprets `2xx`, `401` and `403`. Every other status — including the `429` and `5xx` responses described in section 9 — is turned into a `500` for the browser.

That is the intended fail-closed behavior, but it means the original status is only visible in the nginx error log and in the service's own logs and metrics, never to the client. The status table in section 9 describes what the service emits, not what the browser sees.

### Authentication challenge

For HTTP Basic Authentication, a `401` response must include:

```http
WWW-Authenticate: Basic realm="..."
```

The realm comes from the selected policy (section 7).

### Passing identity upstream

The service may additionally return authenticated identity information through response headers, allowing nginx to pass the user identity to an upstream application.

Example:

```nginx
location / {
    auth_request /_auth;

    auth_request_set $auth_user $upstream_http_x_auth_user;
    proxy_set_header X-Remote-User $auth_user;

    proxy_pass http://backend;
}
```

The upstream must be prevented from receiving a client-supplied `X-Remote-User`; `proxy_set_header` overwrites it, but any location that forwards headers without setting it explicitly is a spoofing path.

### Rate limiting in nginx

nginx sends an `auth_request` for every single HTTP request, so an unprotected instance is a high-rate password oracle against the directory. The service throttles failures itself (section 12), but the cheaper first line of defense belongs in nginx:

```nginx
limit_req_zone $binary_remote_addr zone=auth:10m rate=20r/s;

location / {
    limit_req zone=auth burst=50 nodelay;

    auth_request /_auth;

    proxy_pass http://backend;
}
```

This limits all traffic to the location, not just failed authentications, so the rate has to be tuned to the application's normal request volume — an asset-heavy page can easily issue dozens of requests per view. The two mechanisms are complementary: nginx limits per address, the service limits per address *and* per username.

## 4. Authentication flow

The service accepts credentials in two forms: HTTP Basic Authentication, and a login form that issues a signed session cookie (section 4a). Both reach the same decision path — the same policy resolution, throttle, cache and directory — because a second path is a second set of rules to keep in step, and the one that drifts is always the one nobody is looking at.

Basic Authentication alone has no logout and no expiry: the browser keeps sending the credentials until it is closed, which in practice means for days. That was accepted for the first milestone and is no longer the default answer; it remains the right one for clients that cannot hold a cookie.

```text
Browser
   │
   │ Authorization: Basic ...
   ▼
nginx
   │
   │ internal auth_request
   ▼
nginx-ldap-auth
   │
   ├── select policy (X-Auth-Policy, or default_policy)
   │
   ├── parse Authorization header  (keeps the username even when it rejects)
   │
   ├── check failure throttle ──► 429, no LDAP
   │
   ├── act on a parse failure ──► 401, no LDAP
   │     └── empty / whitespace-only password counts as a failure
   │
   ├── check cache (in-process, optionally Redis)
   │
   └── LDAP search + bind, then group check
            │
            ▼
          GLAuth
```

### Empty passwords

A bind with an empty password is an unauthenticated (anonymous) bind. Many directories, including common GLAuth configurations, answer it with `success` — which would turn `Authorization: Basic dXNlcjo=` into a valid login for any known username.

The service must therefore reject empty or whitespace-only passwords before it touches LDAP, and must record them as authentication failures rather than as infrastructure errors.

### Credential handling

The service must never store plaintext passwords.

Cache entries must not permit password recovery; the key derivation is specified in section 6.

Cache entries must have a short configurable TTL.

## 4a. Sessions

Basic Authentication cannot expire, and that is not a detail an operator can work around: there is no logout, closing a tab does nothing, and the browser replays the credentials for as long as it is open. Section 19 listed a login form with a signed session cookie as a future extension; it is now implemented, and this section is what it has to do.

Sessions are off by default. Enabling them changes how every protected location behaves and needs a secret file and an nginx change to go with it, so it must be a decision rather than something that happens on upgrade.

### The cookie

The session is stateless: the cookie carries the decision and its own signature, and there is no server-side session table. That is what makes it work across instances and across restarts without Redis, and it is also its one weakness — see "revocation" below.

```text
value  = "1." + base64url(payload) + "." + base64url(HMAC-SHA256(secret, "1." + base64url(payload)))
payload = { "u": user, "p": policy, "g": [groups], "i": issued_at, "s": last_seen }
```

Requirements:

- The signature is verified before the payload is parsed, so malformed JSON from an unsigned value never reaches the decoder, and it is compared in constant time.
- The format carries a version, and the version is part of the signed input. An unknown version is rejected rather than guessed at: a parser that tries formats until one verifies is a parser that can be downgraded.
- The payload holds no password. Everything in it was already sent to the upstream application in a response header.
- The signing secret is a file, at least 32 bytes, held to the same standard as the cache pepper. Without one the cookie is a request parameter and a visitor can name any user in any group.
- The cookie is `HttpOnly` and `SameSite=Lax`, and `Secure` unless the operator explicitly turns it off for a test setup — which validation warns about.
- A cookie is valid only for the policy it was issued for. One instance serves several applications, and a session for the intranet must not open the monitoring UI.

### The two timeouts

| | Runs from | Extended by use | Default |
|---|---|---|---|
| absolute | the login | never | 8h |
| idle | the last request | yes | 30m |

The absolute timeout is the only bound on a cookie that has been copied, which is why it must not be extendable by using the session — a browser left open on a dashboard would otherwise never log out.

The idle window slides, but not on every request: nginx makes one auth subrequest per HTTP request, so re-issuing the cookie every time would put a `Set-Cookie` on every asset. The cookie is re-issued once its last-seen stamp is older than `refresh_interval`, which must stay below the idle timeout — a longer one would let a session expire in the browser while the service still accepts it, and configuration validation clamps it to half the idle window rather than allowing that.

### Revocation

A stateless cookie cannot be withdrawn before it expires. This is the deliberate trade-off against a session store, and it has to be stated rather than discovered:

- Disabling an account in the directory stops new logins at once and the existing session at its next expiry, up to the absolute timeout later.
- Replacing the signing secret and restarting invalidates every session at once. That is the only "log everybody out" this design has.
- `/logout` clears the cookie in one browser.

An operator for whom the first point is unacceptable shortens the absolute timeout; the alternative — a server-side session store — is a section 19 item.

### The login form

`/login` and `/logout` are served by this service and proxied by nginx as ordinary locations. Unlike `/auth` they are reached by the browser directly.

- The form posts `username`, `password`, `csrf_token` and `next`. It is protected by a signed double-submit token in a `SameSite=Strict` cookie: a cross-site POST does not carry that cookie, so the check fails before the values are compared. Without it, an attacker cannot read the response but can make a visitor's browser submit *the attacker's* credentials, and everything the visitor then does happens in the attacker's session.
- `next` is client-controlled and must be reduced to a same-site path. An absolute URL, a scheme-relative `//host`, a backslash form, or anything with a control character in it falls back to `/`. A login page that follows it unchanged is an open redirect on the one page that takes a password.
- Failure messages must not distinguish "no such user" from "wrong password". A form that does is a form that confirms which accounts exist.
- A CSRF failure is not an authentication failure: the credentials were never evaluated, so it must not count against the throttle.
- The page must be self-contained — no external stylesheet, script, font or image. A login page that depends on an asset from elsewhere is a login page that fails while the site behind it is up.
- The built-in form may be replaced by a template, parsed at startup so that a broken one is a service that does not start rather than a 500 at the first login.

### Interaction with Basic Authentication

While sessions are enabled the `401` must not carry `WWW-Authenticate`. The browser would open its own password dialog instead of following nginx's redirect to the form, and the credentials it caches there never expire — which is the problem this whole section exists to remove.

Basic Authentication is still accepted from a client that sends it unprompted, which is every client that cannot hold a cookie: curl, monitoring checks, API consumers. It can be turned off with `allow_basic: false`.

The `401` carries the address of the login form in a response header, so that nginx can redirect to it without the path being configured in two places.

## 5. LDAP

The LDAP layer should support:

- LDAP
- LDAPS
- StartTLS where practical
- configurable connection and operation timeouts
- configurable bind/search behavior
- user lookup by configurable attribute
- configurable user search base
- optional group authorization
- TLS certificate verification

Directories are configured as a named map and referenced by a policy:

```yaml
ldap:
  primary:
    url: ldaps://glauth.example.org:636
    base_dn: dc=example,dc=org
    user_filter: "(uid=%s)"
    bind_dn: cn=serviceuser,dc=example,dc=org
    bind_password_file: /etc/nginx-ldap-auth/ldap-bind.secret
    bind_timeout: 5s
    operation_timeout: 5s
    tls:
      verify: true
```

Each policy references exactly one directory. The earlier list form was dropped on purpose: a list implies ordering and failover, and neither was defined. Multiple backends are a section 19 item, and when they arrive the configuration must state explicitly what "try the next backend" means — an invalid password must never cause a retry against another directory, only a connection or timeout failure may.

### Filter escaping

`user_filter` is a template with a single `%s`. Interpolating the raw username is an LDAP filter injection: a username of `*)(uid=*` changes the meaning of the filter and can turn a lookup into a match-anything search.

All user-supplied values must be escaped with `ldap.EscapeFilter` before interpolation. The same applies to values interpolated into `group_filter` or into any DN template.

Escaping is necessary and not sufficient. A directory that decodes the escapes and recompiles the filter — GLAuth does — turns the correctly escaped filter back into a malformed one and answers with a protocol error rather than a refusal. A protocol error is an infrastructure error, so it is deliberately not counted against the throttle (section 12), so it can be repeated indefinitely, and every repetition costs a search on the single pooled service connection that every other request queues behind.

A username containing any of `*`, `(`, `)`, `\` or a NUL byte is therefore rejected before any directory work happens, and counted as a failure. No directory permits these in a login name, so the restriction costs nothing; the escaping stays as defence in depth, and because group filters legitimately interpolate DNs, which do contain backslashes.

This was found by the integration suite, not by reasoning about the code. The unit test asserted the escaped string was correct, and it was.

### Connection handling

A successful bind changes the authentication state of the connection, so a connection must never be reused across users without an intervening rebind.

The intended split is:

- one pooled connection bound as the service account, used for user and group searches
- one fresh connection per user bind, closed immediately afterwards

This keeps pooling where it is safe and avoids the class of bug where one request inherits the previous request's identity. `go-ldap` provides no connection pool, so the pooling is the service's own responsibility, including revalidation of an idle connection before use.

The implementation must not assume a particular GLAuth schema beyond what is explicitly configured.

### The GLAuth schema, as it actually is

GLAuth compatibility is a design goal in section 1, and the integration suite established what that requires. Recorded here because it is not what an intuitive reading of the schema suggests, and two of these were wrong in the example configuration until the suite ran:

- Users live at `cn=<name>,ou=<primary group>,ou=users,<base>` and carry both `cn` and `uid`.
- Groups are `groupOfUniqueNames` with a `uniqueMember` attribute holding full DNs. GLAuth exposes neither `posixGroup` nor `memberUid`, so the filter most examples use — `(&(objectClass=posixGroup)(memberUid=%s))` — matches nothing against it. The working filter is `(&(objectClass=groupOfUniqueNames)(uniqueMember=%s))` with `group_filter_value: dn`.
- Group DNs use `ou=` as the RDN attribute, not `cn=`: `ou=web-users,ou=groups,<base>`. A `require_groups` entry written as a full `cn=...` DN therefore does not match. Short names match either spelling and are the portable choice.
- `memberOf` is exposed on the user entry and carries the same `ou=`-prefixed DNs, so both group sources work and both resolve to the same short name.
- Searching requires an explicit `capabilities` entry on the user. An ordinary user cannot search, which is the same split a real deployment has — and what makes the pooled-service-connection design observable from outside.

## 6. Caching

Caching is not an optimisation, it is a requirement. nginx issues an `auth_request` for every request, including every static asset, so without a cache a single page view becomes dozens of LDAP binds.

### In-process cache (default)

The default cache is in-process: a TTL map with a bounded entry count. For a single systemd service on one host this is strictly better than Redis — no network hop, no second service to keep alive, no credential-derived key leaving the process.

```yaml
cache:
  enabled: true
  ttl: 60s
  negative_ttl: 0s
  max_entries: 10000
  pepper_file: /etc/nginx-ldap-auth/cache-pepper.secret
```

`max_entries` is a security control, not just a memory setting: a spray of invalid usernames must not be able to grow the process indefinitely. Eviction is LRU.

### Redis (optional)

Redis is only useful when several instances should share decisions. It is disabled by default, and it replaces the in-process cache rather than sitting behind it: a memory tier in front of Redis would keep serving a decision another instance had already revoked, which defeats the only reason to share them.

```yaml
redis:
  enabled: false
  address: 127.0.0.1:6379
  database: 3
  timeout: 1s
  password_file: /etc/nginx-ldap-auth/redis.secret
```

The timeout must stay well below the directory's `operation_timeout`. A cache slower than the lookup it spares costs the timeout and then does the lookup anyway; startup warns when the two are the wrong way round.

An unreachable Redis is reported at startup and never refuses it. The cost of a cache outage is LDAP binds, and refusing to start would turn it into a site outage.

The stored value carries the outcome **by name**, not by its numeric value. The numbers exist only so that the zero value denies, and their order has already changed once — with the number on the wire, that change would have reinterpreted every entry written by an instance still running the older build, turning stored denials into grants for as long as the two versions overlapped. An entry that cannot be decoded, for any reason including an outcome name this build does not know, is treated as a miss.

### Key derivation

A cache key must not allow recovery of the password, and a leaked Redis dump must not allow cheap offline verification of password guesses.

```text
key   = "nla:" + hex(HMAC-SHA256(pepper, policy + "\0" + user + "\0" + password))
value = decision + resolved groups + expiry
```

The pepper is a random 32-byte secret loaded from a file outside the main configuration (`pepper_file`). It is never written to Redis, never logged, and never included in a diagnostic dump. With an unkeyed hash a leaked dump would be trivially crackable against a wordlist; with the pepper it is useless without also compromising the host.

The pepper is generated once at installation. Rotating it invalidates all cache entries, which is acceptable given the short TTL.

### Negative caching

Caching failed authentications is disabled by default (`negative_ttl: 0s`). It reduces LDAP load during a brute-force attempt, but it also delays a legitimate password change from taking effect. If enabled, the negative TTL should stay well below the positive TTL.

### Failure behavior

```text
Cache available
    │
    ├── hit  ──► use cached decision
    │
    └── miss ──► LDAP ──► cache result

Cache unavailable (Redis down)
    │
    └────────► LDAP directly
```

A cache miss, a cache error and an unreachable Redis all fall through to LDAP. Only LDAP grants access. Cache failures must not make the authentication service unusable, and must never cause it to fail open.

## 7. Policies, authorization and groups

Authentication and authorization are separate concepts.

One instance is meant to serve multiple virtual hosts, and that only works if the request states which ruleset applies — `/auth` otherwise cannot tell whether it is answering for the intranet or for the monitoring UI.

### Policy selection

A policy is a named bundle of realm, directory and authorization rules. nginx selects it with a header:

```nginx
proxy_set_header X-Auth-Policy intranet;
```

Rules:

- The header value must match a configured policy name exactly. It is never used to construct a filter, a path, a DN or a metric label.
- An unknown policy name is a configuration error on the nginx side. The service responds `403` and logs the rejected value. It must never fall back to a more permissive policy.
- `default_policy` may be configured for single-application setups. When set, a missing header selects it; an unknown header value is still rejected.

`/auth` is `internal`, so the header is not attacker-controlled — but it is validated anyway, because "internal" is a configuration promise and not an enforcement.

### Group authorization

```yaml
policies:
  intranet:
    realm: "Intranet"
    ldap: primary
    require_groups:
      - cn=web-users,ou=groups,dc=example,dc=org
```

LDAP group handling must be configurable because schemas differ. At minimum the group source must be selectable between:

- a filter evaluated against a group base, for `member`/`memberUid` style schemas
- an attribute on the user entry, for `memberOf` style schemas

`require_groups` is satisfied when the user is a member of at least one listed group. An empty or absent `require_groups` means authentication alone is sufficient, and that must be an explicit configuration choice rather than a silent default.

A user that authenticates successfully but does not satisfy the policy receives HTTP `403`.

Group membership is part of the cached decision, so a group change also only takes effect after the cache TTL expires.

## 8. Configuration

Configuration should be YAML-based.

Example:

```yaml
server:
  listen: 127.0.0.1:8080
  client_ip_header: X-Real-IP
  read_timeout: 5s
  write_timeout: 5s
  idle_timeout: 30s
  shutdown_timeout: 10s
  max_header_bytes: 8192

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
    require_groups:
      - cn=ops,ou=groups,dc=example,dc=org

ldap:
  primary:
    url: ldaps://127.0.0.1:636
    base_dn: dc=example,dc=org
    user_filter: "(uid=%s)"
    group_base_dn: ou=groups,dc=example,dc=org
    group_filter: "(&(objectClass=posixGroup)(memberUid=%s))"
    bind_dn: cn=serviceuser,dc=example,dc=org
    bind_password_file: /etc/nginx-ldap-auth/ldap-bind.secret
    bind_timeout: 5s
    operation_timeout: 5s
    tls:
      verify: true

cache:
  enabled: true
  ttl: 60s
  negative_ttl: 0s
  max_entries: 10000
  pepper_file: /etc/nginx-ldap-auth/cache-pepper.secret

redis:
  enabled: false
  address: 127.0.0.1:6379
  database: 3
  timeout: 2s

rate_limit:
  enabled: true
  window: 1m
  max_failures_per_user: 10
  max_failures_per_ip: 30
  block_duration: 5m

logging:
  level: info
  format: json
  log_username: true

metrics:
  enabled: true
  address: 127.0.0.1:9931
```

### Secrets

Secrets must not be hard-coded into the configuration example, and not inlined into the configuration file itself.

Credentials are referenced by path (`bind_password_file`, `pepper_file`) or supplied through the environment. This keeps the main configuration file readable for debugging while the secrets stay in separate, tightly permissioned files.

Intended modes:

```text
/etc/nginx-ldap-auth/config.yaml          0640 root:nginx-ldap-auth
/etc/nginx-ldap-auth/ldap-bind.secret     0640 root:nginx-ldap-auth
/etc/nginx-ldap-auth/cache-pepper.secret  0640 root:nginx-ldap-auth
```

Startup must fail with a clear error if a referenced secret file is missing, empty or unreadable. A secret file accessible to *other* — readable, writable or executable — produces a warning rather than a refusal, so a misconfigured permission does not take down a running site on restart.

Group access is not a misconfiguration and must not warn. Root-owned and group-readable by the service user is the intended arrangement: it is what lets the unit run unprivileged without the secrets being writable by it, and it is what the `tmpfiles.d` fragment sets. An earlier implementation warned on any group-readable file, which meant it fired on every correct installation and advised `chmod 0640` on files that were already `0640` — a warning that fires on the intended setup teaches operators to ignore warnings.

## 9. HTTP API

### `GET /auth`

Internal authentication endpoint used by nginx.

Expected input:

```http
Authorization: Basic <credentials>
X-Auth-Policy: intranet
X-Original-URI: /some/path
```

Responses:

| Status | Meaning |
|---|---|
| `200` | Authentication successful |
| `401` | Missing, malformed or invalid credentials; empty password |
| `403` | Authenticated but not authorized; unknown policy |
| `429` | Throttled after repeated failures |
| `5xx` | Authentication infrastructure failure |

nginx forwards only `2xx`, `401` and `403`; `429` and `5xx` both reach the browser as `500` (section 3). The distinction still matters, because it is what logs, metrics and alerting are based on. A throttled client deliberately does not get a friendly retry prompt.

The endpoint must not be directly exposed to untrusted clients. Binding to `127.0.0.1` is the default; a Unix domain socket would be stronger and is a section 19 item.

### `GET /login`, `POST /login`, `GET /logout`

Present only while `session.enabled` is set. Reached by the browser through an ordinary nginx location, not through `auth_request`.

`GET /login` renders the form and sets the CSRF token cookie. A visitor who already holds a valid session is redirected to `next` instead of being offered a form that would start a second one.

`POST /login` verifies the token, evaluates the credentials through the normal decision path, and on success sets the session cookie and answers `303` to `next`. A failure re-renders the form with the status the decision produced — `401`, `403`, `429` or `502` — so that the outcome is visible to a monitoring system as well as to the user.

`GET /logout` clears the session and the token cookie and redirects to the form. `GET` is accepted alongside `POST`: the worst a forged logout can do is end a session the user can start again, where refusing `GET` would mean every application embedding a logout link has to grow a form.

### `GET /healthz`

Liveness endpoint.

It verifies that the process and HTTP server are operational.

It must not depend on LDAP or Redis availability — otherwise a directory outage turns into a restart loop that also discards the cache.

Expected response:

```http
HTTP/1.1 200 OK
```

### `GET /readyz`

Readiness endpoint.

It reports whether the listener is up. A valid configuration and readable secrets are implied rather than re-checked: startup refuses without them, so a process that got far enough to answer this endpoint already has both.

Backend connectivity should be handled carefully. A transient LDAP outage must not cause unnecessary restarts. For a single-instance systemd deployment there is no load balancer acting on readiness at all, so this endpoint is a diagnostic aid — it should not grow into a health-check framework.

### `GET /metrics`

Prometheus/OpenMetrics endpoint.

It listens on its own address so it can be firewalled separately, and should normally only be reachable from a trusted monitoring network or localhost.

## 10. Metrics

The service should use the official Prometheus Go client rather than implementing the exposition format manually.

Recommended metrics:

### Authentication

```text
nginx_ldap_auth_requests_total{policy, result, reason}
nginx_ldap_auth_request_duration_seconds{policy}
```

`result` is one of `success`, `invalid_credentials`, `unauthorized`, `throttled`, `error`.

One counter with a `result` label replaces the earlier `requests_total` / `success_total` / `failure_total` triple, which was redundant and could not be aggregated cleanly.

`reason` carries the specific cause, from a closed set: `authenticated`, `invalid_credentials`, `group_required`, `no_credentials`, `empty_password`, `malformed_credentials`, `policy_unresolved`, `throttled_user`, `throttled_address`, `throttled_capacity`, `directory_error`, `directory_missing`.

The second label is there because the five coarse values cannot express the distinction section 11 requires of the logs. A user who is not in the required group and an nginx location naming a policy that does not exist both produce a `403`; only one of them is somebody's mistake to fix. `result` is what an alert or a ratio is built on, `reason` is what answers why. A value outside the closed set is recorded as `other` — the set is made of constants in `internal/auth`, and the metrics layer must not depend on that staying true.

`result` classifies the cause and not the HTTP status, and the two disagree in exactly one case: `policy_unresolved` is answered `403` but recorded as `error`. It is a configuration fault rather than an authorization outcome, and filed under `unauthorized` it would sit in the same series as group refusals — ordinary traffic on any protected site — so an alert tuned to tolerate those would never fire on the misconfiguration.

`policy` is safe as a label because its value set is defined by the configuration, and the metrics layer is given that set rather than trusting its caller. Any other value, including a `X-Auth-Policy` that matches no policy, is recorded as the constant `unknown` — never as the received string, which would be cardinality chosen by whoever can set a header.

### LDAP

```text
nginx_ldap_auth_ldap_requests_total{operation="bind|service_bind|search", result="success|failure|error"}
nginx_ldap_auth_ldap_duration_seconds{operation}
```

A separate `ldap_errors_total` is dropped; it is `ldap_requests_total{result="error"}`.

`service_bind` is separate from `bind` although both are binds. A user bind happens once per uncached authentication; a service bind happens only on connect and reconnect. Counting them together makes the bind rate meaningless and hides a directory that is closing connections.

`failure` means the directory answered and said no — a rejected password, a refused search. `error` means it never answered: a broken transport, a timeout, a certificate that could not be verified. An alert that cannot separate the two fires on users mistyping passwords, gets tuned to tolerate that, and then does not fire on the outage.

A `search` observation spans the connection attempt that preceded it. That is the work the request paid for, and a connect that never completes is a search that never happened.

### Cache

```text
nginx_ldap_auth_cache_requests_total{backend="memory|redis", result="hit|miss|error"}
nginx_ldap_auth_cache_entries{backend}
nginx_ldap_auth_cache_evictions_total{backend}
nginx_ldap_auth_cache_expired_total{backend}
nginx_ldap_auth_redis_duration_seconds
```

`expired` separates a cold lookup from one whose entry had aged out: subtract it from `miss` to see how much of the miss rate is TTL rather than new traffic. A rising `evictions` means `cache.max_entries` is too small for the working set — or that something is spraying invalid usernames.

These are read from the cache at scrape time rather than incremented alongside the cache's own counters. Two counters for one fact drift the first time somebody adds an early return; one authoritative counter read on demand cannot.

### Throttle

```text
nginx_ldap_auth_throttle_entries
nginx_ldap_auth_throttle_blocked_total
nginx_ldap_auth_throttle_trips_total
nginx_ldap_auth_throttle_capacity_denied_total
```

`trips` counts identities reaching their limit, `blocked` counts requests refused because of one. `capacity_denied` being anything other than zero means the throttle ran out of room to count and started refusing (section 12) — that is not a state normal traffic produces, and it deserves an alert of its own.

### HTTP

```text
nginx_ldap_auth_http_requests_total{handler, code}
nginx_ldap_auth_http_request_duration_seconds{handler}
```

### Service

```text
nginx_ldap_auth_info{version, go_version}
```

`uptime_seconds` is dropped: the `client_golang` process collector already exports `process_start_time_seconds`, from which uptime is derivable in the query, and a self-maintained uptime gauge is just a counter that resets.

### Histogram buckets

All `_duration_seconds` metrics are histograms with explicitly configured buckets. The `client_golang` defaults are a poor fit for LDAP binds; the interesting range is roughly 1 ms to 5 s, and the bucket set must extend past the configured timeouts so a timeout shows up as a bucket boundary rather than only in `+Inf`.

### Label hygiene

Labels must be deliberately limited.

Do not expose:

- usernames
- passwords
- authorization headers
- arbitrary URLs
- raw `X-Auth-Policy` header values
- LDAP distinguished names supplied by users
- other high-cardinality or sensitive request data

Suitable labels are those with a small, configuration-defined value set:

```text
result="success|invalid_credentials|unauthorized|throttled|error"
operation="bind|service_bind|search"
backend="memory|redis"
```

Every one of these is bounded inside the metrics layer rather than by whoever calls it, against a closed set of permitted values. The exposition is scraped and usually kept for months, so a label value is long-term storage that nobody audits — and cardinality is a denial of service against the scrape, which takes every other metric down with it.

The values are all constants in the packages that report them, so the bounding is in principle redundant. It is there because that is a property of another package: this layer cannot enforce it, and the cost of being wrong is not a missing data point but unbounded cardinality. A value outside its set is recorded as `other` rather than dropped, because a metric that silently loses observations is worse than one with a visible bucket that prompts someone to look.

The `code` label is bounded too. It is an integer and so cannot carry an arbitrary string, but a handler bug can make it carry an arbitrary number, and one series per invented code is the same problem. Anything outside 100-599 is recorded as `0`.

## 11. Logging

Structured JSON logging should be supported.

Example:

```json
{
  "level": "info",
  "msg": "authentication successful",
  "policy": "intranet",
  "result": "success",
  "remote_addr": "127.0.0.1",
  "duration_ms": 12,
  "cache": "hit"
}
```

Logs must never contain:

- passwords
- Authorization headers
- session credentials
- the cache pepper
- cache keys derived from credential material
- sensitive LDAP attributes

Usernames are a special case: they are needed to investigate a lockout or a throttle, but users do type passwords into the username field by accident. `logging.log_username` controls this and defaults to on, since a directory administrator can see usernames anyway.

Authentication failures, authorization failures, throttled requests and infrastructure failures must be distinguishable from one another — an operator has to be able to tell "someone is guessing passwords" from "LDAP is down" without reading the code.

### Dependencies that log on their own

A library that writes to the standard `log` package writes to stderr: unstructured, and unaffected by `logging.level`. That has to be redirected into the service's logger, or the promise of structured logging holds only for the records this service writes itself.

`go-redis` is the case in point. Against an unreachable Redis it emits roughly three lines per operation, and nginx issues one authentication request per HTTP request — so a single page view with thirty assets produced about a hundred unparseable lines, at `logging.level: error`. Measured: five authentication requests produced twenty-five log lines, twenty of them unstructured.

Its diagnostics now go through `redis.SetLogger` at debug level. Debug, because the failure is already reported where it matters — the cache error counter, and one structured record from the startup probe. What is left is per-operation detail: useful when looking for it, noise otherwise.

## 12. Security requirements

Security is a primary design requirement.

### Mandatory

- Never log credentials.
- Never store plaintext passwords.
- Never fail open when LDAP or Redis is unavailable.
- Empty or whitespace-only passwords are rejected before any LDAP operation.
- All user-supplied values are escaped per RFC 4515 before filter interpolation.
- Usernames containing `*`, `(`, `)`, `\` or NUL are rejected before any directory operation, and counted as a failure. Escaping alone leaves an unthrottled amplification path against directories that decode the escapes and reparse — see section 5.
- Never reuse an LDAP connection across users without an intervening rebind.
- Reject requests whose `X-Auth-Policy` does not name a configured policy.
- Throttle repeated authentication failures per username and per source address.
- Keep the cache pepper out of the main configuration file, out of Redis and out of all logs.
- Bound the in-process cache and throttle state so invalid input cannot grow the process.
- Trust the client-address header only while the listener is bound to loopback.
- Validate LDAP TLS certificates by default.
- Apply strict network and HTTP timeouts.
- Limit request body/header sizes where applicable.
- Reject malformed Basic Authentication headers.
- Verify a session cookie's signature before parsing its payload, in constant time, and reject an unknown format version rather than guessing at it.
- Keep the session signing secret out of the main configuration file and out of all logs, hold it to at least 32 bytes, and never let a session cookie carry a password.
- Bind a session cookie to the policy it was issued for.
- Never send `WWW-Authenticate` while the login form is enabled: the browser's own dialog caches credentials that cannot expire, which is what the session exists to prevent.
- Reduce the login form's redirect target to a same-site path. It is client-supplied, and following it unchanged is an open redirect on the page that takes a password.
- Protect the login form against cross-site submission, and do not count a failed CSRF check against the throttle — the credentials were never evaluated.
- Never compare a secret locally. This replaces an earlier requirement to "use constant-time comparisons where applicable", which was wrong to state: nothing in the service compares a secret, so there was nothing for it to apply to and no way to verify it. A password is emptiness-checked, fed to an HMAC, and sent to the directory — never matched against a stored value. The property to preserve is the absence of such a comparison, not a timing-safe way to perform one; adding a local password check would be the change that makes constant-time comparison necessary, and it should not be made.
- A decision nobody set must deny. The zero value of the cached decision is "invalid credentials", so a struct produced by a failed deserialisation, a partial write, or a field added later refuses access rather than granting it.
- A cache that returns an error is a cache miss, whatever else it reports. A backend may return a hit and an error together; the error alone disqualifies the entry.
- Avoid high-cardinality Prometheus labels.
- Do not expose internal authentication endpoints unnecessarily.
- Run as an unprivileged system user.
- Restrict access to configuration files containing credentials.
- Support systemd hardening.

### Brute-force protection

Because nginx calls `/auth` for every request, an unprotected instance is a high-rate password oracle against the directory, and it can trip account lockout in directories that implement it.

The initial milestone therefore includes a minimal in-process throttle:

- failure counters per username and per source address over a sliding window
- once the configured limit is reached, requests are answered `429` without touching LDAP
- a successful authentication resets the counter for that username, and never the counter for the address — otherwise one valid account would keep an attacker's address budget permanently fresh between guesses at everyone else's passwords
- usernames are normalised before they are counted, because LDAP matches `uid` case-insensitively and `alice` and `ALICE` must not be two budgets
- state is in-process only and bounded; sharing it across instances is a section 19 item
- the throttle fails closed on its own exhaustion: if every tracked identity is an active block, further requests are refused rather than served uncounted, because making room by evicting an active block would let an attacker clear their own block on demand

Two ordering details decide whether it works at all.

The throttle is consulted **after** the Authorization header is parsed, because it needs the username to charge an attempt to an account — but **before** a parse failure is answered. Checking it only on well-formed requests would leave the cheapest attempt of all, a header carrying a username and no password, as the one attempt that is never blocked.

An empty password therefore counts as a failure against that username, not only against the source address. Where the per-address limit is disabled, charging it to the address alone would be charging it to nothing.

This does not replace `limit_req` in nginx (section 3): nginx limits request volume per address, the throttle limits failures per identity.

### Basic Authentication

HTTP Basic Authentication must only be used over HTTPS.

The authentication service itself may run on localhost because nginx terminates TLS.

## 13. systemd

The service should be deployed as a native systemd unit.

Example:

```ini
[Unit]
Description=nginx LDAP Authentication Service
After=network.target

[Service]
Type=simple
User=nginx-ldap-auth
Group=nginx-ldap-auth
ExecStart=/usr/local/bin/nginx-ldap-auth --config /etc/nginx-ldap-auth/config.yaml
Restart=on-failure
RestartSec=2s

NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectProc=invisible
ProcSubset=pid
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictSUIDSGID=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
ReadOnlyPaths=/etc/nginx-ldap-auth
UMask=0077

[Install]
WantedBy=multi-user.target
```

Notes on the individual options:

- `After=network-online.target` / `Wants=network-online.target` were removed. The service listens on loopback and connects to LDAP lazily on the first request, so waiting for full network configuration buys nothing and slows boot.
- `CapabilityBoundingSet=` empty requires a listen port above 1024, which is the case.
- `MemoryDenyWriteExecute=true` is safe for a `CGO_ENABLED=0` Go binary. It breaks if cgo or a JIT is ever introduced.
- `RestrictAddressFamilies` includes `AF_UNIX` so that the future Unix-socket listener and logging to the journal keep working.
- `DynamicUser=yes` is an alternative that removes user creation from the package entirely, but it complicates ownership of the secret files. A static system user is the simpler default.

The exact hardening options should be validated against the application's runtime requirements rather than copied blindly. `systemd-analyze security nginx-ldap-auth.service` is the check, not this list.

## 14. Package / installation

Native installation, three ways in: an Arch package, a release archive, or `make install`. All three place the same set of files.

```text
/usr/bin/nginx-ldap-auth                        (/usr/local/bin from make install)
/etc/nginx-ldap-auth/config.yaml
/usr/lib/systemd/system/nginx-ldap-auth.service
/usr/lib/sysusers.d/nginx-ldap-auth.conf
/usr/lib/tmpfiles.d/nginx-ldap-auth.conf
/usr/share/doc/nginx-ldap-auth/...
/usr/share/licenses/nginx-ldap-auth/LICENSE
```

A package must not install or modify nginx itself. nginx is an `optdepends`, not a dependency: the service is useful without it while a configuration is being written, the nginx package needs no modification to work with it, and a package that pulls in a web server because it can be used behind one decides too much.

### One installer, and the unit's path

The Makefile's `install-files` target is the only place that knows the layout. The `PKGBUILD` delegates to it rather than repeating it, and the release archives ship the same tree.

That is not tidiness. The unit names the binary by absolute path, and the prefix is not known until install time: a source install goes to `/usr/local` by convention and a distribution package must go to `/usr`. The first version had the path baked into the unit and a separate install sequence in the `PKGBUILD` — so the package installed cleanly to `/usr/bin` and shipped a unit pointing at `/usr/local/bin`. Every `systemctl start` would have failed on `ExecStartPre` with "No such file or directory", on every machine, and nothing in the repository was wrong enough for the compiler, the linter or any other test to notice.

`install-files` rewrites both `Exec` lines to `$PREFIX/bin`. A test installs into a throwaway directory at three different prefixes and asserts the unit points at the binary that was actually placed — a real install rather than a parse, because what matters is the tree that ends up on disk.

The same test file asserts the rest of the cross-file agreements, for the same reason: each of these files is consumed by a different tool on a different machine, so a mismatch between them is invisible to everything else.

- The unit's `User=`/`Group=` matches the user the `sysusers` fragment creates. If they diverge, systemd refuses to start with "Failed to determine user credentials".
- Every secret path the example configuration names is managed by the `tmpfiles` fragment. One that is not stays root-only and the service cannot read it.
- The pepper path is the same in the install hook, the `tmpfiles` fragment and the example configuration.
- The workflows only call `make` targets that exist, and only bundle files that exist. The release job runs once per tag; a missing file fails it after the tag is already pushed.

### What is declarative and what cannot be

The system user comes from a `sysusers.d` fragment and the modes on `/etc/nginx-ldap-auth` from a `tmpfiles.d` fragment, rather than from `useradd` and `chown` in a post-install script. Both are idempotent, both apply on first boot of an image as well as on package installation, and neither can be half-applied. The modes in particular cannot be baked into the package at all: the group does not exist while the package is being built.

The cache pepper is the exception, and the reason is the point of the pepper. It must not exist in the package — every installation would then share one secret, and a cache leaked from any of them would be crackable against all the others. So it is generated on the target machine, on first install, and never regenerated on upgrade. Installation must generate it if it does not exist yet, with restrictive permissions, and must not overwrite an existing one.

### Static or hardened, not both

The release archives are built without `-buildmode=pie` and are statically linked: one build runs on any distribution, which is what a downloadable archive is for.

The Arch package adds `-buildmode=pie`, which with cgo disabled still produces a dynamically linked binary wanting the glibc loader — hence `depends=('glibc')`. That is the right trade for a distribution package, where the loader is present by definition and ASLR is worth having, and the wrong one for an archive that has to run anywhere.

Neither build enables cgo, because the systemd unit sets `MemoryDenyWriteExecute=true` and says in its own comment that this is safe for a binary built without it.

## 15. Project structure

Recommended structure:

```text
nginx-ldap-auth/
├── cmd/
│   └── nginx-ldap-auth/
│       └── main.go
├── internal/
│   ├── auth/
│   ├── cache/          # in-process TTL cache + optional Redis backend
│   ├── config/
│   ├── ldap/
│   ├── metrics/
│   ├── policy/
│   ├── ratelimit/
│   └── server/         # HTTP listener and handlers
├── systemd/
│   └── nginx-ldap-auth.service
├── nginx/
│   └── auth.conf
├── packaging/
│   ├── nginx-ldap-auth.sysusers    # creates the system user
│   ├── nginx-ldap-auth.tmpfiles    # modes on /etc/nginx-ldap-auth
│   └── nginx-ldap-auth.install     # generates the cache pepper, once
├── testdata/
│   └── glauth/         # GLAuth fixture config for integration tests
├── .forgejo/workflows/ # the full gate and the release; primary
├── .github/workflows/  # the mirror: smoke build and release archives
├── PKGBUILD
├── config.example.yaml
├── go.mod
├── go.sum
├── LICENSE
├── README.md
└── Makefile
```

A separate `internal/redis` package was folded into `internal/cache`: the cache interface is the abstraction and Redis is one implementation of it. That keeps "Redis is optional" a property of the type system instead of a scattering of `if redisEnabled` branches.

The HTTP package is `internal/server` rather than `internal/http`, because a package named `http` forces every file in it to import the standard library under an alias.

The public API should remain small.

Internal implementation details should remain under `internal/`.

## 16. Dependencies

The intended external dependencies are deliberately limited:

```text
github.com/go-ldap/ldap/v3
github.com/redis/go-redis/v9
github.com/prometheus/client_golang
gopkg.in/yaml.v3
```

Everything else should use the Go standard library. In particular the in-process cache, the failure throttle, the HMAC key derivation and the JSON logging need no third-party package — `crypto/hmac`, `crypto/sha256` and `log/slog` cover all of it.

One further module, `github.com/alicebob/miniredis/v2`, is imported only from test files and is not linked into the binary — `go version -m` on the built artefact lists neither it nor its own dependencies. It is a real RESP server rather than a mock of the Redis client, which is what makes the shared-cache tests exercise the protocol instead of exercising a stub. `go.mod` cannot express "test only", so it appears in the require block; the property that matters is verifiable from the binary.

GLAuth is not a module dependency at all. The integration suite runs it as a separate process, and skips when it is absent.

No subprocess execution should be required at runtime.

No Node.js runtime should be required.

No container runtime should be required.

## 17. Testing

The project should provide unit and integration tests.

### Unit tests

At minimum:

- configuration parsing and validation, including refusal of invalid configurations
- secret file loading: missing, empty, unreadable
- Basic Authentication parsing, including malformed and non-UTF-8 input
- empty and whitespace-only password rejection
- LDAP filter construction with metacharacters in the username
- policy selection: valid name, unknown name, missing header with and without `default_policy`
- authorization decisions for each supported group schema
- cache behavior: hit, miss, expiry, eviction at `max_entries`
- cache key derivation: same credentials produce the same key, a different pepper does not
- throttle behavior: trigger, reset on success, window expiry
- HTTP status mapping for every row of the section 18 table
- metric labels never contain user-supplied strings
- timeout handling

### Integration tests

GLAuth is a single static binary with a plain configuration file, which is why it is the backend this service targets. The suite starts it per test on a free port using the fixture in `testdata/glauth/`, so it needs no container, no shared test environment, and no fixture that merely resembles LDAP.

```sh
go install github.com/glauth/glauth/v2@latest
make integration
```

Without the binary the suite skips rather than failing, and the skip message says how to get it. A developer without GLAuth still gets a green run of everything else; what they do not get is any claim about the paths only a directory can exercise.

The cases that only a real directory can settle, and what each one is for:

| Case | Why a fake could not answer it |
|---|---|
| Valid credentials, wrong password, unknown user | The refusals have to be indistinguishable to the client, and that is the directory's answer, not ours |
| Empty password | Whether an anonymous bind succeeds is the directory's decision; the assertion is that it is never asked |
| Filter injection | Escaping can be correct and still not be enough — see section 5 |
| Ambiguous user filter | Two entries sharing an attribute is provoked from the fixture, not constructed |
| Group resolution, both sources | The real schema is not the one its documentation suggests |
| Directory stopped mid-run | An established connection going away is not the same failure as a closed port |
| Service connection reuse | One service bind across three authentications is only observable from the directory's side |
| User bind isolation | An ordinary user in the fixture cannot search, so a bind leaking onto the pooled connection breaks the *next* request — which is how the property becomes testable at all |
| Reconnect after a drop | Directories close idle connections; restarting GLAuth under a live client reaches that state faster |

The Redis backend is covered separately, against a real RESP server on a real socket rather than a mocked client. `NGINX_LDAP_AUTH_REDIS_ADDR` points the same assertions at a real Redis.

The "no external process execution" design goal in section 1 applies to the running service, not to the test harness.

## 18. Operational behavior

Important failure cases:

| Condition | Expected behavior |
|---|---|
| Valid LDAP credentials | `200` |
| Invalid LDAP credentials | `401` |
| Missing or malformed credentials | `401` |
| Empty or whitespace-only password | `401`, no LDAP operation |
| User not authorized by policy | `403` |
| Unknown `X-Auth-Policy` value | `403`, no LDAP operation |
| Repeated failures for user or address | `429`, no LDAP operation |
| LDAP unavailable | `5xx` |
| Redis unavailable | Continue with LDAP |
| Cache hit | Skip LDAP |
| Invalid configuration | Refuse startup |
| Missing or unreadable secret file | Refuse startup |
| TLS certificate validation failure | Authentication fails safely |

The service must prefer denying access over accidentally granting access.

## 19. Future extensions

The initial implementation should remain deliberately small.

Named policies, group authorization and failure throttling were moved out of this list and into the initial scope: without them the service either cannot serve more than one application or ships as an unprotected password oracle.

Potential future features:

- multiple LDAP backends with explicitly defined failover semantics
- a short-lived memory tier in front of Redis, if the per-request round trip ever matters more than seeing a revocation immediately
- LDAP group-to-role mapping
- Unix domain socket support
- configuration reload without restart
- administrative cache invalidation
- throttle state shared across instances
- a server-side session store, for sessions that can be revoked before they expire (section 4a)
- audit logging
- optional client certificate authentication
- OIDC support only if there is a compelling requirement

OIDC and full identity-provider functionality are explicitly outside the initial scope.

## 20. Non-goals

The project is not intended to become:

- Keycloak
- a general-purpose identity provider
- an OAuth2 authorization server
- an OIDC provider
- a user management application
- a replacement for GLAuth
- an nginx module
- a web application framework

The goal is a small authentication component that fills the gap between nginx and an LDAP directory.

## 21. Milestones

### Milestone 1 — correct and safe

1. Go service skeleton, `Makefile`, linting
2. YAML configuration with validation; refuse startup on invalid configuration or missing secrets
3. HTTP server with timeouts and header size limits
4. Basic Authentication parsing, including empty-password rejection
5. Named policies and policy selection via `X-Auth-Policy`
6. LDAP search and bind against GLAuth, with RFC 4515 escaping and the split connection model
7. Group authorization
8. In-process cache with pepper-derived keys
9. Failure throttling
10. `/healthz`, `/readyz`, structured JSON logging
11. systemd unit, example nginx configuration, README
12. Unit tests covering all of the above

### Milestone 2 — operability

1. ~~Prometheus metrics and `/metrics`~~
2. ~~Redis cache backend~~
3. ~~Integration tests against a GLAuth binary~~
4. ~~Arch Linux PKGBUILD~~

### Milestone 3 — a login that expires

1. ~~Signed session cookie with an absolute and an idle timeout (section 4a)~~
2. ~~Login form with CSRF protection, and `/logout`~~
3. ~~`session` configuration section, validation, and the secret file~~
4. ~~nginx example that redirects to the form and carries the sliding cookie back~~

This was a section 19 item, brought forward because the alternative it was compared against — Basic Authentication with no logout — turned out to be the first thing an operator notices in production: a login that survives days of inactivity.

Metrics, Redis and the integration suite were moved out of the first milestone deliberately. None of them changes whether the service authenticates correctly, and the original seventeen-point milestone was not the "intentionally small" first step it claimed to be.

The implementation should remain intentionally small and production-oriented.

## 22. Rationale

A dedicated authentication service is preferable to rebuilding nginx with a third-party LDAP module in this environment.

The existing Arch Linux nginx already contains `ngx_http_auth_request_module`, so LDAP-specific functionality can remain completely outside nginx.

This results in a clean separation:

```text
nginx
  = HTTP reverse proxy / access enforcement

nginx-ldap-auth
  = authentication / authorization / decision cache

GLAuth
  = identity directory

Redis
  = optional shared cache for multi-instance setups

Prometheus
  = monitoring
```

This architecture avoids unnecessary platform coupling while remaining simple enough to operate as a single native systemd service.
