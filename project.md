# nginx-ldap-auth

A small, native authentication gateway for nginx using LDAP, Redis, and Prometheus/OpenMetrics.

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
- Optional Redis-backed authentication cache
- Prometheus/OpenMetrics metrics
- Health and readiness endpoints
- Small dependency footprint
- Secure defaults
- Suitable for multiple nginx virtual hosts/applications
- Configuration via YAML
- No external process execution

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
                              └───────┬─────────┘
                                      │
                         ┌────────────┼────────────┐
                         │                         │
                         ▼                         ▼
                      GLAuth                    Redis
                       LDAP                  auth cache
```

nginx remains responsible for HTTP handling and access control.

`nginx-ldap-auth` is responsible only for authentication and authorization decisions.

LDAP credentials are validated against GLAuth. Redis may be used to cache successful authentication decisions for a short, configurable period.

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
    proxy_set_header Authorization $http_authorization;
}
```

The authentication service returns:

- `200` for an authenticated request
- `401` for invalid or missing credentials
- `403` for authenticated users that are not authorized

For HTTP Basic Authentication, a `401` response must include:

```http
WWW-Authenticate: Basic realm="..."
```

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

## 4. Authentication flow

The initial implementation uses HTTP Basic Authentication.

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
   ├── validate request
   │
   ├── check Redis cache
   │
   └── LDAP bind/search
            │
            ▼
          GLAuth
```

The service must never store plaintext passwords.

Redis entries must contain only data that is safe to cache, preferably derived from the credential material using a secure keyed hash or another design that does not permit password recovery.

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
- LDAP connection reuse where safe

Example configuration:

```yaml
ldap:
  - name: localhost
    url: ldaps://glauth.example.org:636
    base_dn: dc=example,dc=org
    user_filter: "(uid=%s)"
    bind_timeout: 5s
    operation_timeout: 5s
    tls:
      verify: true
```

The implementation must not assume a particular GLAuth schema beyond what is explicitly configured.

## 6. Redis

Redis is optional.

Its primary purpose is short-lived caching of authentication decisions to reduce repeated LDAP binds.

Example:

```yaml
redis:
  enabled: true
  address: 127.0.0.1:6379
  database: 3
  timeout: 2s
```

Redis failures must not make the authentication service unusable.

The recommended behavior is:

```text
Redis available
    │
    ├── cache hit  ──► authenticate
    │
    └── cache miss ──► LDAP ──► cache result

Redis unavailable
    │
    └───────────────► LDAP directly
```

The service must never fail open because Redis is unavailable.

## 7. Authorization and groups

Authentication and authorization are separate concepts.

The service should support optional group-based authorization.

Example:

```yaml
authorization:
  groups:
    - web-users
```

LDAP group handling must be configurable because LDAP schemas differ.

Possible future configuration:

```yaml
authorization:
  require_groups:
    - cn=web-users,ou=groups,dc=example,dc=org
```

A user that authenticates successfully but does not satisfy the configured authorization policy receives HTTP `403`.

## 8. Configuration

Configuration should be YAML-based.

Example:

```yaml
server:
  listen: 127.0.0.1:8080

ldap:
  - name: localhost
    url: ldaps://127.0.0.1:636
    base_dn: dc=example,dc=org
    user_filter: "(uid=%s)"
    bind_timeout: 5s
    operation_timeout: 5s

redis:
  enabled: true
  address: 127.0.0.1:6379
  database: 3
  timeout: 2s

authentication:
  cache_enabled: true
  cache_ttl: 60s
  realm: "Restricted"

logging:
  level: info
  format: json
  
metrics:
  enabled: true
  address: 127.0.0.1:9931
```

Secrets must not be hard-coded into the configuration example.

Where possible, credentials should be supplied through protected configuration files or environment variables.

File permissions for configuration containing secrets should be restrictive.

## 9. HTTP API

### `GET /auth`

Internal authentication endpoint used by nginx.

Expected input:

```http
Authorization: Basic <credentials>
```

Responses:

| Status | Meaning |
|---|---|
| `200` | Authentication successful |
| `401` | Missing or invalid credentials |
| `403` | Authenticated but not authorized |
| `5xx` | Authentication infrastructure failure |

The endpoint must not be directly exposed to untrusted clients.

### `GET /healthz`

Liveness endpoint.

It verifies that the process and HTTP server are operational.

It should not depend on LDAP or Redis availability.

Expected response:

```http
HTTP/1.1 200 OK
```

### `GET /readyz`

Readiness endpoint.

It verifies that the service has loaded a valid configuration and is able to serve authentication requests.

Backend connectivity should be handled carefully. A transient LDAP outage should not cause unnecessary service restart loops.

### `GET /metrics`

Prometheus/OpenMetrics endpoint.

This endpoint should normally only be accessible from a trusted monitoring network or localhost.

## 10. Metrics

The service should use the official Prometheus Go client rather than implementing the exposition format manually.

Recommended metrics:

### Authentication

```text
nginx_ldap_auth_requests_total
nginx_ldap_auth_success_total
nginx_ldap_auth_failure_total
```

### LDAP

```text
nginx_ldap_auth_ldap_requests_total
nginx_ldap_auth_ldap_errors_total
nginx_ldap_auth_ldap_duration_seconds
```

### Redis

```text
nginx_ldap_auth_redis_requests_total
nginx_ldap_auth_redis_errors_total
nginx_ldap_auth_redis_duration_seconds
```

### Cache

```text
nginx_ldap_auth_cache_hits_total
nginx_ldap_auth_cache_misses_total
```

### HTTP

```text
nginx_ldap_auth_http_requests_total
nginx_ldap_auth_http_request_duration_seconds
```

### Service

```text
nginx_ldap_auth_info
nginx_ldap_auth_uptime_seconds
```

Labels must be deliberately limited.

Do not expose:

- usernames
- passwords
- authorization headers
- arbitrary URLs
- LDAP distinguished names supplied by users
- other high-cardinality or sensitive request data

Suitable labels include values such as:

```text
result="success|failure"
operation="bind|search"
```

## 11. Logging

Structured JSON logging should be supported.

Example:

```json
{
  "level": "info",
  "msg": "authentication successful",
  "remote_addr": "127.0.0.1"
}
```

Logs must never contain:

- passwords
- Authorization headers
- session credentials
- Redis cache keys containing credential-derived secrets
- sensitive LDAP attributes

Authentication failures should be distinguishable from infrastructure failures.

## 12. Security requirements

Security is a primary design requirement.

### Mandatory

- Never log credentials.
- Never store plaintext passwords.
- Never fail open when LDAP or Redis is unavailable.
- Validate LDAP TLS certificates by default.
- Apply strict network and HTTP timeouts.
- Limit request body/header sizes where applicable.
- Reject malformed Basic Authentication headers.
- Use constant-time comparisons where applicable.
- Avoid high-cardinality Prometheus labels.
- Do not expose internal authentication endpoints unnecessarily.
- Run as an unprivileged system user.
- Restrict access to configuration files containing credentials.
- Support systemd hardening.

### Basic Authentication

HTTP Basic Authentication must only be used over HTTPS.

The authentication service itself may run on localhost because nginx terminates TLS.

## 13. systemd

The service should be deployed as a native systemd unit.

Example:

```ini
[Unit]
Description=nginx LDAP Authentication Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nginx-ldap-auth
Group=nginx-ldap-auth
ExecStart=/usr/local/bin/nginx-ldap-auth --config /etc/nginx-ldap-auth/config.yaml
Restart=on-failure
RestartSec=2s

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
```

The exact hardening options should be validated against the application's runtime requirements rather than copied blindly.

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

## 15. Project structure

Recommended structure:

```text
nginx-ldap-auth/
├── cmd/
│   └── nginx-ldap-auth/
│       └── main.go
├── internal/
│   ├── auth/
│   ├── config/
│   ├── http/
│   ├── ldap/
│   ├── metrics/
│   └── redis/
├── systemd/
│   └── nginx-ldap-auth.service
├── nginx/
│   └── auth.conf
├── config.example.yaml
├── go.mod
├── go.sum
├── LICENSE
├── README.md
└── Makefile
```

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

Everything else should use the Go standard library.

No subprocess execution should be required.

No Node.js runtime should be required.

No container runtime should be required.

## 17. Testing

The project should provide unit and integration tests.

### Unit tests

At minimum:

- configuration parsing
- configuration validation
- Basic Authentication parsing
- malformed credentials
- LDAP filter construction
- authorization decisions
- cache behavior
- HTTP status mapping
- metrics
- timeout handling

### Integration tests

Where practical:

- LDAP authentication against GLAuth
- Redis cache behavior
- LDAP outage
- Redis outage
- invalid credentials
- group authorization
- nginx `auth_request` integration

Integration tests should be runnable without requiring Docker as part of the production architecture. A dedicated test environment may use containers if useful, but containers must not be a runtime requirement.

## 18. Operational behavior

Important failure cases:

| Condition | Expected behavior |
|---|---|
| Valid LDAP credentials | `200` |
| Invalid LDAP credentials | `401` |
| Missing credentials | `401` |
| User not authorized | `403` |
| LDAP unavailable | `5xx` |
| Redis unavailable | Continue with LDAP |
| Redis cache hit | Skip LDAP |
| Invalid configuration | Refuse startup |
| TLS certificate validation failure | Authentication fails safely |

The service must prefer denying access over accidentally granting access.

## 19. Future extensions

The initial implementation should remain deliberately small.

Potential future features:

- multiple LDAP backends / failover
- LDAP group-to-role mapping
- per-application authorization policies
- multiple authentication realms
- Unix domain socket support
- configuration reload
- administrative cache invalidation
- rate limiting / brute-force protection
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

## 21. Initial milestone

The first milestone should implement:

1. Go service skeleton
2. YAML configuration
3. HTTP server
4. Basic Authentication parsing
5. LDAP authentication
6. GLAuth compatibility
7. nginx `auth_request` integration
8. Redis authentication cache
9. Prometheus metrics
10. `/healthz`
11. `/readyz`
12. structured logging
13. systemd unit
14. unit tests
15. integration tests
16. documentation
17. example nginx configuration

The implementation should remain intentionally small and production-oriented.

## 22. Rationale

A dedicated authentication service is preferable to rebuilding nginx with a third-party LDAP module in this environment.

The existing Arch Linux nginx already contains `ngx_http_auth_request_module`, so LDAP-specific functionality can remain completely outside nginx.

This results in a clean separation:

```text
nginx
  = HTTP reverse proxy / access enforcement

nginx-ldap-auth
  = authentication / authorization

GLAuth
  = identity directory

Redis
  = short-lived authentication cache

Prometheus
  = monitoring
```

This architecture avoids unnecessary platform coupling while remaining simple enough to operate as a single native systemd service.
