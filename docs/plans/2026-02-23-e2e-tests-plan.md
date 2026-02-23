# E2E Tests Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add Docker Compose based e2e tests validating JA4/JA4H fingerprinting through real TLS/HTTP traffic in both hash and raw modes.

**Architecture:** Two-container Docker Compose — OpenResty (nginx with JA4/JA4H wired up via response headers) and a Python pytest client making real TLS connections. Two server blocks (port 443 hash, port 8443 raw) with explicit `configure()` calls to avoid shared module-level state leakage. `worker_processes 1` + sequential tests = no concurrency issues.

**Tech Stack:** OpenResty 1.27.1.1, Python 3.12, pytest, stdlib ssl + http.client

**Design doc:** `docs/plans/2026-02-23-e2e-tests-design.md`

---

### Task 1: Create nginx Dockerfile and self-signed cert

**Files:**
- Create: `e2e/Dockerfile.nginx`

**Step 1: Write the Dockerfile**

```dockerfile
FROM openresty/openresty:1.27.1.1-0-bookworm-fat

RUN apt-get update && apt-get install -y curl \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Generate self-signed cert at build time
RUN openssl req -x509 -newkey rsa:2048 -keyout /etc/nginx/server.key \
    -out /etc/nginx/server.crt -days 365 -nodes \
    -subj "/CN=nginx"

WORKDIR /app
COPY lib/ /app/lib/
COPY e2e/nginx.conf /usr/local/openresty/nginx/conf/nginx.conf

EXPOSE 443 8443

CMD ["openresty", "-g", "daemon off;"]
```

**Step 2: Build to verify it works**

Run: `docker build -f e2e/Dockerfile.nginx -t ja4-e2e-nginx .`
Expected: Successful build, no errors

**Step 3: Commit**

```bash
git add e2e/Dockerfile.nginx
git commit -m "feat(e2e): add nginx Dockerfile with self-signed cert"
```

---

### Task 2: Create nginx.conf with hash and raw server blocks

**Files:**
- Create: `e2e/nginx.conf`

**Important context:** Both `ja4.lua` and `ja4h.lua` use a module-level `_hash_mode` variable. Since Lua modules are cached per-worker, both server blocks share the same module instance. Each block MUST call `configure()` explicitly before `compute()` to set the correct mode.

**Step 1: Write nginx.conf**

```nginx
worker_processes 1;
error_log /dev/stderr warn;

events {
    worker_connections 64;
}

http {
    lua_package_path "/app/lib/?.lua;/app/lib/?/init.lua;;";

    # --- Hash mode server (port 443) ---
    server {
        listen 443 ssl;
        server_name _;

        ssl_certificate     /etc/nginx/server.crt;
        ssl_certificate_key /etc/nginx/server.key;
        ssl_protocols TLSv1.2 TLSv1.3;

        ssl_client_hello_by_lua_block {
            local ja4 = require "resty.ja4"
            ja4.configure({ hash = true })
            ja4.compute()
        }

        header_filter_by_lua_block {
            local ja4 = require "resty.ja4"
            local ja4h = require "resty.ja4h"
            ja4h.configure({ hash = true })

            local tls_fp = ja4.get()
            if tls_fp then
                ngx.header["X-JA4"] = tls_fp
            end

            local http_fp = ja4h.compute()
            if http_fp then
                ngx.header["X-JA4H"] = http_fp
            end
        }

        location /health {
            return 200 "ok";
        }

        location / {
            return 200 "hello";
        }
    }

    # --- Raw mode server (port 8443) ---
    server {
        listen 8443 ssl;
        server_name _;

        ssl_certificate     /etc/nginx/server.crt;
        ssl_certificate_key /etc/nginx/server.key;
        ssl_protocols TLSv1.2 TLSv1.3;

        ssl_client_hello_by_lua_block {
            local ja4 = require "resty.ja4"
            ja4.configure({ hash = false })
            ja4.compute()
        }

        header_filter_by_lua_block {
            local ja4 = require "resty.ja4"
            local ja4h = require "resty.ja4h"
            ja4h.configure({ hash = false })

            local tls_fp = ja4.get()
            if tls_fp then
                ngx.header["X-JA4"] = tls_fp
            end

            local http_fp = ja4h.compute()
            if http_fp then
                ngx.header["X-JA4H"] = http_fp
            end
        }

        location /health {
            return 200 "ok";
        }

        location / {
            return 200 "hello";
        }
    }
}
```

**Step 2: Rebuild and test nginx starts**

Run: `docker build -f e2e/Dockerfile.nginx -t ja4-e2e-nginx . && docker run --rm -d --name ja4-test ja4-e2e-nginx && sleep 2 && docker logs ja4-test && docker stop ja4-test`
Expected: No Lua errors in logs, nginx starts cleanly

**Step 3: Commit**

```bash
git add e2e/nginx.conf
git commit -m "feat(e2e): add nginx.conf with hash and raw mode server blocks"
```

---

### Task 3: Create pytest Dockerfile and conftest.py

**Files:**
- Create: `e2e/Dockerfile.tests`
- Create: `e2e/conftest.py`

**Step 1: Write the test Dockerfile**

```dockerfile
FROM python:3.12-slim

RUN pip install --no-cache-dir pytest

WORKDIR /app
COPY e2e/conftest.py e2e/test_ja4.py e2e/test_ja4h.py /app/

CMD ["pytest", "-v", "--tb=short"]
```

**Step 2: Write conftest.py with fixtures**

```python
import os
import ssl
import http.client

import pytest


NGINX_HOST = os.environ.get("NGINX_HOST", "nginx")
HASH_PORT = int(os.environ.get("NGINX_PORT", "443"))
RAW_PORT = int(os.environ.get("NGINX_RAW_PORT", "8443"))


def _make_ssl_context(max_version=None, min_version=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if max_version:
        ctx.maximum_version = max_version
    if min_version:
        ctx.minimum_version = min_version
    return ctx


@pytest.fixture
def ssl_ctx_tls13():
    return _make_ssl_context(
        min_version=ssl.TLSVersion.TLSv1_3,
        max_version=ssl.TLSVersion.TLSv1_3,
    )


@pytest.fixture
def ssl_ctx_tls12():
    return _make_ssl_context(
        min_version=ssl.TLSVersion.TLSv1_2,
        max_version=ssl.TLSVersion.TLSv1_2,
    )


@pytest.fixture
def ssl_ctx_default():
    return _make_ssl_context()


def make_request(port, path="/", method="GET", headers=None, ctx=None):
    """Make an HTTPS request and return (response_headers_dict, body_bytes)."""
    if ctx is None:
        ctx = _make_ssl_context()
    conn = http.client.HTTPSConnection(NGINX_HOST, port, context=ctx)
    conn.request(method, path, headers=headers or {})
    resp = conn.getresponse()
    resp_headers = {k.lower(): v for k, v in resp.getheaders()}
    body = resp.read()
    conn.close()
    return resp_headers, body


@pytest.fixture
def hash_request():
    """Make a request to the hash-mode server (port 443)."""
    def _request(path="/", method="GET", headers=None, ctx=None):
        return make_request(HASH_PORT, path, method, headers, ctx)
    return _request


@pytest.fixture
def raw_request():
    """Make a request to the raw-mode server (port 8443)."""
    def _request(path="/", method="GET", headers=None, ctx=None):
        return make_request(RAW_PORT, path, method, headers, ctx)
    return _request
```

**Step 3: Commit**

```bash
git add e2e/Dockerfile.tests e2e/conftest.py
git commit -m "feat(e2e): add pytest Dockerfile and conftest with SSL fixtures"
```

---

### Task 4: Create docker-compose.e2e.yml

**Files:**
- Create: `e2e/docker-compose.e2e.yml`

**Step 1: Write the compose file**

```yaml
services:
  nginx:
    build:
      context: ..
      dockerfile: e2e/Dockerfile.nginx
    healthcheck:
      test: ["CMD", "curl", "-kf", "https://localhost/health"]
      interval: 2s
      timeout: 5s
      retries: 10
      start_period: 5s

  tests:
    build:
      context: ..
      dockerfile: e2e/Dockerfile.tests
    depends_on:
      nginx:
        condition: service_healthy
    environment:
      - NGINX_HOST=nginx
      - NGINX_PORT=443
      - NGINX_RAW_PORT=8443
```

**Note:** `context: ..` because compose file is inside `e2e/` but Dockerfiles need project root as context (to COPY `lib/`).

**Step 2: Test compose builds**

Run: `docker compose -f e2e/docker-compose.e2e.yml build`
Expected: Both images build successfully

**Step 3: Commit**

```bash
git add e2e/docker-compose.e2e.yml
git commit -m "feat(e2e): add docker-compose orchestration"
```

---

### Task 5: Write JA4 e2e tests (TLS fingerprinting)

**Files:**
- Create: `e2e/test_ja4.py`

**Step 1: Write the test file**

```python
import re


# JA4 hash format: t<ver>d<cc><ec><alpn>_<12hex>_<12hex>
# Section A is 10 chars: 1 protocol + 2 version + 1 sni + 2 cipher_count + 2 ext_count + 2 alpn
JA4_HASH_RE = re.compile(
    r"^t(?:13|12|11|10|s3|s2|00)[di]\d{2}\d{2}[a-z0-9]{2}_[a-f0-9]{12}_[a-f0-9]{12}$"
)

# JA4 raw format: section_a_csv_ciphers_csv_extensions (possibly with trailing _sig_algs)
JA4_RAW_RE = re.compile(
    r"^t(?:13|12|11|10|s3|s2|00)[di]\d{2}\d{2}[a-z0-9]{2}_[a-f0-9,]*_[a-f0-9,_]*$"
)


class TestJA4Hash:
    """JA4 TLS fingerprinting — hash mode (port 443)."""

    def test_ja4_header_present(self, hash_request, ssl_ctx_default):
        headers, _ = hash_request(ctx=ssl_ctx_default)
        assert "x-ja4" in headers, f"X-JA4 header missing. Headers: {headers}"

    def test_ja4_hash_format_tls13(self, hash_request, ssl_ctx_tls13):
        headers, _ = hash_request(ctx=ssl_ctx_tls13)
        ja4 = headers["x-ja4"]
        assert JA4_HASH_RE.match(ja4), f"JA4 '{ja4}' doesn't match hash format"
        assert ja4[1:3] == "13", f"Expected TLS 1.3 version '13', got '{ja4[1:3]}'"

    def test_ja4_hash_format_tls12(self, hash_request, ssl_ctx_tls12):
        headers, _ = hash_request(ctx=ssl_ctx_tls12)
        ja4 = headers["x-ja4"]
        assert JA4_HASH_RE.match(ja4), f"JA4 '{ja4}' doesn't match hash format"
        assert ja4[1:3] == "12", f"Expected TLS 1.2 version '12', got '{ja4[1:3]}'"

    def test_ja4_deterministic(self, hash_request, ssl_ctx_tls13):
        h1, _ = hash_request(ctx=ssl_ctx_tls13)
        h2, _ = hash_request(ctx=ssl_ctx_tls13)
        assert h1["x-ja4"] == h2["x-ja4"], "JA4 should be deterministic for same TLS context"

    def test_ja4_sni_flag_is_domain(self, hash_request, ssl_ctx_default):
        headers, _ = hash_request(ctx=ssl_ctx_default)
        ja4 = headers["x-ja4"]
        # Python's http.client sends SNI (the hostname), so flag should be 'd'
        assert ja4[3] == "d", f"Expected SNI flag 'd', got '{ja4[3]}'"

    def test_ja4_different_tls_versions_differ(self, hash_request, ssl_ctx_tls13, ssl_ctx_tls12):
        h13, _ = hash_request(ctx=ssl_ctx_tls13)
        h12, _ = hash_request(ctx=ssl_ctx_tls12)
        # At minimum the version portion differs
        assert h13["x-ja4"][:3] != h12["x-ja4"][:3], \
            "TLS 1.3 and 1.2 should produce different version sections"


class TestJA4Raw:
    """JA4 TLS fingerprinting — raw mode (port 8443)."""

    def test_ja4_raw_header_present(self, raw_request, ssl_ctx_default):
        headers, _ = raw_request(ctx=ssl_ctx_default)
        assert "x-ja4" in headers, f"X-JA4 header missing. Headers: {headers}"

    def test_ja4_raw_format(self, raw_request, ssl_ctx_tls13):
        headers, _ = raw_request(ctx=ssl_ctx_tls13)
        ja4 = headers["x-ja4"]
        # Raw mode: section_a has same 10-char prefix, but sections B/C are CSV hex
        assert JA4_RAW_RE.match(ja4), f"JA4 raw '{ja4}' doesn't match raw format"

    def test_ja4_raw_contains_commas(self, raw_request, ssl_ctx_default):
        headers, _ = raw_request(ctx=ssl_ctx_default)
        ja4 = headers["x-ja4"]
        # Raw mode sections B and C should have comma-separated hex values
        parts = ja4.split("_", 1)
        assert len(parts) >= 2, "Raw JA4 should have underscore separators"
        rest = parts[1]
        assert "," in rest, f"Raw mode should contain commas in cipher/ext sections: '{rest}'"

    def test_ja4_raw_longer_than_hash(self, raw_request, ssl_ctx_default):
        headers, _ = raw_request(ctx=ssl_ctx_default)
        ja4 = headers["x-ja4"]
        # Hash mode is always 36 chars; raw mode is typically much longer
        assert len(ja4) > 36, f"Raw JA4 should be longer than 36 chars, got {len(ja4)}"
```

**Step 2: Run e2e to verify tests execute (expect pass)**

Run: `docker compose -f e2e/docker-compose.e2e.yml up --build --abort-on-container-exit --exit-code-from tests`
Expected: All JA4 tests pass

**Step 3: Commit**

```bash
git add e2e/test_ja4.py
git commit -m "feat(e2e): add JA4 TLS fingerprinting tests (hash + raw)"
```

---

### Task 6: Write JA4H e2e tests (HTTP fingerprinting)

**Files:**
- Create: `e2e/test_ja4h.py`

**Context for JA4H section A format (12 chars):**
- Chars 0-1: method code ("ge", "po", "he", etc.)
- Chars 2-3: HTTP version ("11", "20")
- Char 4: cookie flag ("c" or "n")
- Char 5: referer flag ("r" or "n")
- Chars 6-7: header count (2-digit decimal)
- Chars 8-11: accept-language (4 chars, e.g. "enus", "0000")

**Step 1: Write the test file**

```python
import re


# JA4H hash: 12-char section_a + 3x _<12hex> = 12 + 3*(1+12) = 51 chars
JA4H_HASH_RE = re.compile(
    r"^[a-z]{2}(?:11|10|20|30|00)[cnr]{2}\d{2}[a-z0-9]{4}"
    r"_[a-f0-9]{12}_[a-f0-9]{12}_[a-f0-9]{12}$"
)


class TestJA4HHash:
    """JA4H HTTP fingerprinting — hash mode (port 443)."""

    def test_ja4h_header_present(self, hash_request):
        headers, _ = hash_request()
        assert "x-ja4h" in headers, f"X-JA4H header missing. Headers: {headers}"

    def test_ja4h_hash_format(self, hash_request):
        headers, _ = hash_request()
        ja4h = headers["x-ja4h"]
        assert JA4H_HASH_RE.match(ja4h), f"JA4H '{ja4h}' doesn't match hash format"

    def test_ja4h_get_method(self, hash_request):
        headers, _ = hash_request(method="GET")
        ja4h = headers["x-ja4h"]
        assert ja4h[:2] == "ge", f"Expected method code 'ge', got '{ja4h[:2]}'"

    def test_ja4h_head_method(self, hash_request):
        headers, _ = hash_request(method="HEAD")
        ja4h = headers["x-ja4h"]
        assert ja4h[:2] == "he", f"Expected method code 'he', got '{ja4h[:2]}'"

    def test_ja4h_cookie_flag_absent(self, hash_request):
        headers, _ = hash_request()
        ja4h = headers["x-ja4h"]
        assert ja4h[4] == "n", f"Expected cookie flag 'n' (no cookie), got '{ja4h[4]}'"

    def test_ja4h_cookie_flag_present(self, hash_request):
        headers, _ = hash_request(headers={"Cookie": "session=abc123"})
        ja4h = headers["x-ja4h"]
        assert ja4h[4] == "c", f"Expected cookie flag 'c', got '{ja4h[4]}'"

    def test_ja4h_referer_flag_absent(self, hash_request):
        headers, _ = hash_request()
        ja4h = headers["x-ja4h"]
        assert ja4h[5] == "n", f"Expected referer flag 'n', got '{ja4h[5]}'"

    def test_ja4h_referer_flag_present(self, hash_request):
        headers, _ = hash_request(headers={"Referer": "https://example.com"})
        ja4h = headers["x-ja4h"]
        assert ja4h[5] == "r", f"Expected referer flag 'r', got '{ja4h[5]}'"

    def test_ja4h_accept_language(self, hash_request):
        headers, _ = hash_request(headers={"Accept-Language": "en-US,en;q=0.9"})
        ja4h = headers["x-ja4h"]
        lang = ja4h[8:12]
        assert lang == "enus", f"Expected language 'enus', got '{lang}'"

    def test_ja4h_no_language_defaults(self, hash_request):
        headers, _ = hash_request()
        ja4h = headers["x-ja4h"]
        lang = ja4h[8:12]
        assert lang == "0000", f"Expected default language '0000', got '{lang}'"

    def test_ja4h_deterministic(self, hash_request):
        h1, _ = hash_request(headers={"Accept-Language": "fr-FR"})
        h2, _ = hash_request(headers={"Accept-Language": "fr-FR"})
        assert h1["x-ja4h"] == h2["x-ja4h"], "JA4H should be deterministic"


class TestJA4HRaw:
    """JA4H HTTP fingerprinting — raw mode (port 8443)."""

    def test_ja4h_raw_header_present(self, raw_request):
        headers, _ = raw_request()
        assert "x-ja4h" in headers, f"X-JA4H header missing. Headers: {headers}"

    def test_ja4h_raw_contains_header_names(self, raw_request):
        headers, _ = raw_request(headers={"Accept-Language": "en-US"})
        ja4h = headers["x-ja4h"]
        # In raw mode, section B contains actual header names (comma-separated)
        parts = ja4h.split("_")
        assert len(parts) >= 2, f"Raw JA4H should have underscore separators: '{ja4h}'"
        section_b = parts[1]
        # http.client sends Host header; Accept-Language was added by us
        assert "Host" in section_b or "host" in section_b or "Accept-Language" in section_b, \
            f"Raw section B should contain header names: '{section_b}'"

    def test_ja4h_raw_cookie_names_visible(self, raw_request):
        headers, _ = raw_request(headers={"Cookie": "alpha=1; beta=2"})
        ja4h = headers["x-ja4h"]
        parts = ja4h.split("_")
        # Section C should contain sorted cookie names
        assert len(parts) >= 3, f"Expected at least 3 sections: '{ja4h}'"
        section_c = parts[2]
        assert "alpha" in section_c and "beta" in section_c, \
            f"Raw section C should contain cookie names: '{section_c}'"

    def test_ja4h_raw_longer_than_hash(self, raw_request):
        headers, _ = raw_request(headers={
            "Accept-Language": "en-US",
            "Cookie": "session=abc123",
        })
        ja4h = headers["x-ja4h"]
        # Hash mode is always 51 chars; raw mode is typically longer
        assert len(ja4h) > 51, f"Raw JA4H should be longer than 51 chars, got {len(ja4h)}"
```

**Step 2: Run full e2e suite**

Run: `docker compose -f e2e/docker-compose.e2e.yml up --build --abort-on-container-exit --exit-code-from tests`
Expected: All JA4 + JA4H tests pass

**Step 3: Commit**

```bash
git add e2e/test_ja4h.py
git commit -m "feat(e2e): add JA4H HTTP fingerprinting tests (hash + raw)"
```

---

### Task 7: Add Makefile targets and final verification

**Files:**
- Modify: `Makefile`

**Step 1: Add e2e targets to Makefile**

Append after the existing `test-verbose` target (line 10), before the Performance Analysis section (line 12):

```makefile

# --- E2E Tests ---
.PHONY: e2e e2e-clean

e2e:
	docker compose -f e2e/docker-compose.e2e.yml up --build --abort-on-container-exit --exit-code-from tests

e2e-clean:
	docker compose -f e2e/docker-compose.e2e.yml down --rmi local --volumes --remove-orphans
```

**Step 2: Run `make e2e` to verify the full pipeline**

Run: `make e2e`
Expected: All tests pass, clean exit code 0

**Step 3: Run existing unit tests still work**

Run: `make test`
Expected: All 87 unit tests still pass

**Step 4: Commit**

```bash
git add Makefile
git commit -m "feat(e2e): add make e2e and e2e-clean targets"
```

---

### Task 8: Add .dockerignore for e2e and cleanup

**Files:**
- Modify: `.dockerignore` (if needed — check if existing one excludes e2e test files from nginx image)

**Step 1: Verify .dockerignore doesn't break e2e builds**

Read `.dockerignore` and ensure it doesn't exclude `e2e/` or `lib/`. If it does, add exceptions.

**Step 2: Run full e2e one final time**

Run: `make e2e`
Expected: Clean pass

**Step 3: Final commit if changes were needed**

```bash
git add .dockerignore
git commit -m "chore: update .dockerignore for e2e test support"
```
