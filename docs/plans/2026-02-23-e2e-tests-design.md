# E2E Tests Design — Docker Compose Based

**Date**: 2026-02-23
**Status**: Approved

## Goal

Add Docker Compose based e2e tests that validate JA4 (TLS fingerprinting) and JA4H (HTTP fingerprinting) through real TLS/HTTP traffic, covering both hash mode and raw mode output.

## Architecture

Two-container Docker Compose setup:

1. **nginx** — OpenResty with self-signed TLS cert, lua modules loaded, JA4/JA4H wired up
2. **tests** — Python 3 + pytest making real TLS/HTTP requests and asserting response headers

Fingerprints are exposed as `X-JA4` and `X-JA4H` response headers.

## File Layout

```
e2e/
├── docker-compose.e2e.yml      # Orchestration
├── Dockerfile.nginx             # OpenResty + certs + config + lua modules
├── Dockerfile.tests             # Python 3.12 + pytest
├── nginx.conf                   # Two server blocks: hash (443) + raw (8443)
├── conftest.py                  # pytest fixtures (SSL contexts, request helpers)
├── test_ja4.py                  # JA4 TLS fingerprinting tests
└── test_ja4h.py                 # JA4H HTTP fingerprinting tests
```

## Nginx Configuration

Two server blocks to test both modes:

- **Port 443**: Hash mode (default) — JA4/JA4H produce SHA256-truncated fingerprints
- **Port 8443**: Raw mode — JA4/JA4H produce plain CSV output

Both blocks use:
- `ssl_client_hello_by_lua_block` — calls `ja4.compute()`, stores in `ngx.ctx`
- `header_filter_by_lua_block` — retrieves JA4 from ctx, computes JA4H, sets response headers

Endpoints:
- `/health` — healthcheck (returns 200)
- `/` — default endpoint (returns 200)

## Test Cases

### JA4 (TLS Fingerprinting) — `test_ja4.py`

| Test | Mode | Validates |
|------|------|-----------|
| TLS 1.3 → X-JA4 present | hash | Header exists, matches `t13d\d{4}h[12]_[a-f0-9]{12}_[a-f0-9]{12}` |
| TLS 1.2 → version in fingerprint | hash | Version section shows "12" |
| Deterministic hash | hash | Same ciphers always produce same fingerprint |
| Raw mode → CSV output | raw | Comma-separated hex values instead of hashes |
| Raw mode section structure | raw | Format: `section_a_csv_ciphers_csv_extensions` |

### JA4H (HTTP Fingerprinting) — `test_ja4h.py`

| Test | Mode | Validates |
|------|------|-----------|
| GET → X-JA4H present | hash | Header exists, 4 underscore-separated sections |
| Method detection (GET vs POST) | hash | Section A starts with "ge" or "po" |
| Cookie flag detection | hash | With/without Cookie header changes flag |
| Accept-Language parsing | hash | Language code in section A |
| Header count accuracy | hash | Section A reflects correct header count |
| Raw mode → full header names | raw | Section B has actual header names, not hash |

## Python Test Client

Uses stdlib `ssl` + `http.client` for TLS control:

```python
import ssl
import http.client

def make_tls_request(host, port, path="/", headers=None, ctx=None):
    if ctx is None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection(host, port, context=ctx)
    conn.request("GET", path, headers=headers or {})
    resp = conn.getresponse()
    return dict(resp.getheaders()), resp.read()
```

Fixtures provide pinned SSL contexts:
- `ssl_context_tls13()` — TLS 1.3 with specific cipher list
- `ssl_context_tls12()` — TLS 1.2 with specific cipher list

## Docker Compose

```yaml
services:
  nginx:
    build:
      context: .
      dockerfile: e2e/Dockerfile.nginx
    healthcheck:
      test: ["CMD", "curl", "-k", "https://localhost/health"]
      interval: 2s
      retries: 5

  tests:
    build:
      context: .
      dockerfile: e2e/Dockerfile.tests
    depends_on:
      nginx:
        condition: service_healthy
    environment:
      - NGINX_HOST=nginx
      - NGINX_PORT=443
      - NGINX_RAW_PORT=8443
```

## Makefile Integration

```makefile
e2e:
    docker compose -f e2e/docker-compose.e2e.yml up --build --abort-on-container-exit --exit-code-from tests

e2e-clean:
    docker compose -f e2e/docker-compose.e2e.yml down --rmi local
```

Coexists with existing `make test` (unit tests via Test::Nginx).

## Dependencies

- **nginx container**: OpenResty 1.27.1.1, openssl for cert generation
- **tests container**: Python 3.12-slim, pytest (only external dep)
- No additional Python packages needed (stdlib ssl + http.client)
