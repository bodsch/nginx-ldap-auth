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

The initial implementation uses HTTP Basic Authentication.

Basic Authentication has no logout: the browser keeps sending the credentials until it is closed. This is accepted for the initial milestone — the alternative, a login form plus a signed session cookie as used by the original nginx reference daemon, is deliberately out of scope (section 19). It must be stated in the README so operators are not surprised by it.

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

### Connection handling

A successful bind changes the authentication state of the connection, so a connection must never be reused across users without an intervening rebind.

The intended split is:

- one pooled connection bound as the service account, used for user and group searches
- one fresh connection per user bind, closed immediately afterwards

This keeps pooling where it is safe and avoids the class of bug where one request inherits the previous request's identity. `go-ldap` provides no connection pool, so the pooling is the service's own responsibility, including revalidation of an idle connection before use.

The implementation must not assume a particular GLAuth schema beyond what is explicitly configured.

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

Redis is only useful when several instances should share decisions. It is disabled by default.

```yaml
redis:
  enabled: false
  address: 127.0.0.1:6379
  database: 3
  timeout: 2s
```

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

Startup must fail with a clear error if a referenced secret file is missing, empty or unreadable. A world-readable secret file should produce a warning rather than a refusal, so a misconfigured permission does not take down a running site on restart.

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
nginx_ldap_auth_requests_total{policy, result}
nginx_ldap_auth_request_duration_seconds{policy}
```

`result` is one of `success`, `invalid_credentials`, `unauthorized`, `throttled`, `error`.

One counter with a `result` label replaces the earlier `requests_total` / `success_total` / `failure_total` triple, which was redundant and could not be aggregated cleanly.

`policy` is safe as a label because its value set is defined by the configuration. A `X-Auth-Policy` value that matches no policy must be recorded as the constant `unknown`, never as the received string — otherwise the label becomes attacker-controlled cardinality.

### LDAP

```text
nginx_ldap_auth_ldap_requests_total{operation="bind|search", result="success|failure|error"}
nginx_ldap_auth_ldap_duration_seconds{operation}
```

A separate `ldap_errors_total` is dropped; it is `ldap_requests_total{result="error"}`.

### Cache

```text
nginx_ldap_auth_cache_requests_total{backend="memory|redis", result="hit|miss|error"}
nginx_ldap_auth_cache_entries{backend="memory"}
nginx_ldap_auth_redis_duration_seconds
```

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
operation="bind|search"
backend="memory|redis"
```

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

## 12. Security requirements

Security is a primary design requirement.

### Mandatory

- Never log credentials.
- Never store plaintext passwords.
- Never fail open when LDAP or Redis is unavailable.
- Empty or whitespace-only passwords are rejected before any LDAP operation.
- All user-supplied values are escaped per RFC 4515 before filter interpolation.
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

The first implementation should support a straightforward native installation.

Target paths:

```text
/usr/local/bin/nginx-ldap-auth
/etc/nginx-ldap-auth/config.yaml
/usr/lib/systemd/system/nginx-ldap-auth.service
```

An Arch Linux PKGBUILD may be added later.

A package should not install or modify nginx itself.

Installation must generate the cache pepper if it does not exist yet, with restrictive permissions, and must not overwrite an existing one.

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
├── testdata/
│   └── glauth/         # GLAuth fixture config for integration tests
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

GLAuth is a single static binary with a plain configuration file. Integration tests start it from `TestMain` on a random port using the fixture in `testdata/glauth/`, which covers the real LDAP path without Docker and without a shared test environment.

Cases:

- valid and invalid credentials against GLAuth
- empty password rejected before a bind reaches GLAuth
- username containing LDAP filter metacharacters
- group authorization, allow and deny
- unknown policy name
- LDAP outage: GLAuth stopped mid-test
- cache hit skips LDAP, asserted through the LDAP request counter
- Redis outage falls through to LDAP
- throttle engages after the configured failure count
- nginx `auth_request` integration where an nginx binary is available, skipped otherwise

The "no external process execution" design goal in section 1 applies to the running service, not to the test harness. A dedicated test environment may use containers if useful, but containers must not be a runtime requirement.

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
- LDAP group-to-role mapping
- Unix domain socket support
- configuration reload without restart
- administrative cache invalidation
- throttle state shared across instances
- login form with a signed session cookie, to get a real logout
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

1. Prometheus metrics and `/metrics`
2. Redis cache backend
3. Integration tests against a GLAuth binary
4. Arch Linux PKGBUILD

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
