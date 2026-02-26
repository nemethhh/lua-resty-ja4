# JA4H HTTP/2 Support — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix JA4H crash on HTTP/2 by adding an FFI-based header extraction path alongside the existing raw_header() path for HTTP/1.x.

**Architecture:** Dual-path in `compute()` — HTTP/1.x uses `raw_header()` (unchanged), HTTP/2+ uses `ngx_http_lua_ffi_req_get_headers()` directly for ordered header iteration. Single-pass FFI buffer walk extracts header names, cookie values, and accept-language simultaneously. Cookie values from multiple HTTP/2 headers are joined via FFI buffer (one allocation).

**Tech Stack:** LuaJIT FFI, OpenResty lua-resty-core, Test::Nginx, pytest + httpx

**Design doc:** `docs/plans/2026-02-26-ja4h-http2-design.md`

---

## Task 1: FFI header extraction function + unit tests

Add `get_headers_ffi()` internal function to `ja4h.lua` and test it against HTTP/1.1 requests (the FFI function reads `headers_in` which works for all HTTP versions).

**Files:**
- Modify: `lib/resty/ja4h.lua`
- Create: `t/006-ja4h-ffi-headers.t`

**Step 1: Write the unit test file**

Create `t/006-ja4h-ffi-headers.t`:

```perl
use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

repeat_each(1);
plan tests => repeat_each() * 2 * 8;

no_shuffle();

my $pwd = cwd();

our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;$pwd/lib/?/init.lua;;";
};

no_long_string();
log_level('warn');
run_tests();

__DATA__

=== TEST 1: get_headers_ffi returns ordered header names
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            local names, count = ja4h._get_headers_ffi()
            ngx.say("count: ", count)
            -- Host is always present; custom headers in order
            local found_host = false
            for i = 1, count do
                if names[i] == "Host" or names[i] == "host" then
                    found_host = true
                end
            end
            ngx.say("has_host: ", found_host and "yes" or "no")
        }
    }
--- request
GET /t
--- response_body_like
count: \d+
has_host: yes

=== TEST 2: get_headers_ffi excludes cookie and referer
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            local names, count, has_cookie, has_referer = ja4h._get_headers_ffi()
            ngx.say("has_cookie: ", has_cookie and "yes" or "no")
            ngx.say("has_referer: ", has_referer and "yes" or "no")
            -- Verify cookie/referer NOT in names
            for i = 1, count do
                local lname = names[i]:lower()
                if lname == "cookie" then ngx.say("ERROR: cookie in names") end
                if lname == "referer" then ngx.say("ERROR: referer in names") end
            end
            ngx.say("ok")
        }
    }
--- request
GET /t
--- more_headers
Cookie: a=1; b=2
Referer: http://example.com
--- response_body
has_cookie: yes
has_referer: yes
ok

=== TEST 3: get_headers_ffi collects cookie values
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            local names, count, has_cookie, has_referer, cookie_values = ja4h._get_headers_ffi()
            ngx.say("has_cookie: ", has_cookie and "yes" or "no")
            ngx.say("cookie_count: ", cookie_values and #cookie_values or 0)
            if cookie_values and #cookie_values > 0 then
                ngx.say("cookie_val: ", cookie_values[1])
            end
        }
    }
--- request
GET /t
--- more_headers
Cookie: session=abc; user=john
--- response_body
has_cookie: yes
cookie_count: 1
cookie_val: session=abc; user=john

=== TEST 4: get_headers_ffi extracts accept-language
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            local names, count, has_cookie, has_referer, cookie_values, accept_lang = ja4h._get_headers_ffi()
            ngx.say("lang: ", accept_lang or "nil")
        }
    }
--- request
GET /t
--- more_headers
Accept-Language: fr-FR,en;q=0.5
--- response_body
lang: fr-FR,en;q=0.5

=== TEST 5: get_headers_ffi with no cookie no referer
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            local names, count, has_cookie, has_referer, cookie_values, accept_lang = ja4h._get_headers_ffi()
            ngx.say("has_cookie: ", has_cookie and "yes" or "no")
            ngx.say("has_referer: ", has_referer and "yes" or "no")
            ngx.say("cookie_values: ", cookie_values and #cookie_values or "nil")
            ngx.say("accept_lang: ", accept_lang or "nil")
        }
    }
--- request
GET /t
--- response_body
has_cookie: no
has_referer: no
cookie_values: nil
accept_lang: nil

=== TEST 6: get_headers_ffi preserves header order
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            local names, count = ja4h._get_headers_ffi()
            -- Print all header names to verify order
            for i = 1, count do
                ngx.say(names[i])
            end
        }
    }
--- request
GET /t
--- more_headers
X-First: 1
X-Second: 2
X-Third: 3
--- response_body_like
.*X-First.*
.*X-Second.*
.*X-Third.*

=== TEST 7: get_headers_ffi result matches raw_header path
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            local utils = require "resty.ja4.utils"

            -- FFI path
            local ffi_names, ffi_count = ja4h._get_headers_ffi()

            -- raw_header path
            local raw = ngx.req.raw_header(true)
            local raw_names, raw_count = utils.parse_raw_header_names(raw)

            ngx.say("ffi_count: ", ffi_count)
            ngx.say("raw_count: ", raw_count)
            ngx.say("match: ", ffi_count == raw_count and "yes" or "no")

            -- Compare header names (case-insensitive since HTTP/1.1 may differ)
            local all_match = true
            for i = 1, ffi_count do
                if ffi_names[i]:lower() ~= raw_names[i]:lower() then
                    ngx.say("MISMATCH at ", i, ": ffi=", ffi_names[i], " raw=", raw_names[i])
                    all_match = false
                end
            end
            ngx.say("names_match: ", all_match and "yes" or "no")
        }
    }
--- request
GET /t
--- more_headers
Accept: text/html
Accept-Language: en-US
User-Agent: TestBot/1.0
--- response_body_like
ffi_count: \d+
raw_count: \d+
match: yes
names_match: yes

=== TEST 8: get_headers_ffi handles many headers
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            local names, count = ja4h._get_headers_ffi()
            ngx.say("count: ", count)
            ngx.say("ok: ", count >= 10 and "yes" or "no")
        }
    }
--- request
GET /t
--- more_headers
X-H1: v1
X-H2: v2
X-H3: v3
X-H4: v4
X-H5: v5
X-H6: v6
X-H7: v7
X-H8: v8
X-H9: v9
X-H10: v10
--- response_body_like
count: \d+
ok: yes
```

**Step 2: Run tests to verify they fail**

```bash
make test-verbose 2>&1 | grep -A2 "006-ja4h-ffi"
```

Expected: FAIL because `_get_headers_ffi` doesn't exist.

**Step 3: Implement `get_headers_ffi()` in ja4h.lua**

Add the following to `lib/resty/ja4h.lua`. Insert the FFI imports after the existing imports (line 9), the helper functions before `build()`, and expose `_get_headers_ffi` for testing.

After line 9 (`local utils = require "resty.ja4.utils"`), add:

```lua
-- FFI header extraction for HTTP/2+ (reads headers_in via lua-resty-core FFI)
local base = require "resty.core.base"
local get_request = base.get_request
require "resty.core.request"  -- ensures header FFI types are cdef'd

local C = ffi.C
local table_elt_ct = ffi.typeof("ngx_http_lua_ffi_table_elt_t[?]")
local MAX_HDR = 100
local _hdr_buf = ffi_new(table_elt_ct, MAX_HDR)
local _hdr_truncated = ffi_new("int[1]")
local _ck_join = ffi_new("uint8_t[4096]")
```

Add the byte-matching helper (after the `_ck_join` line):

```lua
-- Case-insensitive byte match: compare FFI char* against Lua string (lowercase expected)
local function match_header(data, expected, len)
    for j = 0, len - 1 do
        local b = data[j]
        if b >= 0x41 and b <= 0x5A then b = b + 32 end  -- fold to lowercase
        if b ~= byte(expected, j + 1) then return false end
    end
    return true
end
```

Add the main FFI function (before `function _M.build(data)`):

```lua
-- Extract headers in order via FFI. Works for all HTTP versions.
-- Returns: names[], count, has_cookie, has_referer, cookie_values[], accept_lang
local function get_headers_ffi()
    local r = get_request()
    if not r then
        return {}, 0, false, false, nil, nil
    end

    local n = C.ngx_http_lua_ffi_req_get_headers_count(r, MAX_HDR, _hdr_truncated)
    if n <= 0 then
        return {}, 0, false, false, nil, nil
    end

    local buf
    if n <= MAX_HDR then
        buf = _hdr_buf
    else
        buf = ffi_new(table_elt_ct, n)
    end

    C.ngx_http_lua_ffi_req_get_headers(r, buf, n, 1)  -- raw=1: preserve original case

    local names = new_tab(n, 0)
    local name_count = 0
    local has_cookie = false
    local has_referer = false
    local cookie_values = nil
    local cookie_count = 0
    local accept_lang = nil

    for i = 0, n - 1 do
        local key_len = buf[i].key.len
        local key_data = buf[i].key.data

        if key_len == 6 and (key_data[0] == 0x43 or key_data[0] == 0x63) then
            if match_header(key_data, "cookie", 6) then
                has_cookie = true
                if not cookie_values then cookie_values = new_tab(4, 0) end
                cookie_count = cookie_count + 1
                cookie_values[cookie_count] = ffi_string(buf[i].value.data, buf[i].value.len)
            else
                name_count = name_count + 1
                names[name_count] = ffi_string(key_data, key_len)
            end
        elseif key_len == 7 and (key_data[0] == 0x52 or key_data[0] == 0x72) then
            if match_header(key_data, "referer", 7) then
                has_referer = true
            else
                name_count = name_count + 1
                names[name_count] = ffi_string(key_data, key_len)
            end
        else
            if key_len == 15 and not accept_lang
                and match_header(key_data, "accept-language", 15) then
                accept_lang = ffi_string(buf[i].value.data, buf[i].value.len)
            end
            name_count = name_count + 1
            names[name_count] = ffi_string(key_data, key_len)
        end
    end

    return names, name_count, has_cookie, has_referer, cookie_values, accept_lang
end
```

Expose for testing (after `_M.get = ...`):

```lua
_M._get_headers_ffi = get_headers_ffi
```

**Step 4: Run tests to verify they pass**

```bash
make test-verbose 2>&1 | tail -20
```

Expected: all 8 tests in `t/006-ja4h-ffi-headers.t` PASS. All existing tests still PASS.

**Step 5: Commit**

```bash
git add lib/resty/ja4h.lua t/006-ja4h-ffi-headers.t
git commit -m "feat(ja4h): add FFI header extraction for HTTP/2+ support

Single-pass iteration of ngx_http_lua_ffi_req_get_headers() buffer.
Extracts ordered header names, cookie values, and accept-language.
Byte-level case-insensitive matching avoids string allocations."
```

---

## Task 2: Dual-path compute() + cookie join

Wire up `compute()` to use `get_headers_ffi()` for HTTP/2+ while keeping the `raw_header()` path for HTTP/1.x. Add a JIT-friendly cookie value joiner for multi-header HTTP/2 cookies.

**Files:**
- Modify: `lib/resty/ja4h.lua:186-212` (compute function)
- Create: `t/007-ja4h-compute-h2-path.t`

**Step 1: Write the unit test file**

Create `t/007-ja4h-compute-h2-path.t`. We can't send real HTTP/2 in Test::Nginx, but we CAN test that:
- The FFI path produces the same fingerprint as the raw_header path for identical HTTP/1.1 requests
- The `_compute_ffi_path()` function (exposed for testing) works correctly

```perl
use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

repeat_each(1);
plan tests => repeat_each() * 2 * 5;

no_shuffle();

my $pwd = cwd();

our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;$pwd/lib/?/init.lua;;";
};

no_long_string();
log_level('warn');
run_tests();

__DATA__

=== TEST 1: FFI path matches raw_header path for simple GET
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            ja4h.configure({ hash = true })
            local normal = ja4h.compute()
            local ffi_result = ja4h._compute_ffi_path()
            ngx.say("normal: ", normal)
            ngx.say("ffi:    ", ffi_result)
            -- Section A may differ in case (raw_header preserves original,
            -- FFI preserves original), but hashes should match
            local norm_hash = normal:match("_(.+)")
            local ffi_hash = ffi_result:match("_(.+)")
            ngx.say("hashes_match: ", norm_hash == ffi_hash and "yes" or "no")
        }
    }
--- request
GET /t
--- more_headers
Accept: text/html
Accept-Language: en-US
User-Agent: TestBot/1.0
--- response_body_like
normal: ge11.*
ffi:    ge11.*
hashes_match: yes

=== TEST 2: FFI path with cookies produces correct fingerprint
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            ja4h.configure({ hash = true })
            local normal = ja4h.compute()
            local ffi_result = ja4h._compute_ffi_path()
            ngx.say("normal:  ", normal)
            ngx.say("ffi:     ", ffi_result)
            -- Cookie/referer sections should be identical
            local norm_parts = {}
            for p in normal:gmatch("[^_]+") do norm_parts[#norm_parts+1] = p end
            local ffi_parts = {}
            for p in ffi_result:gmatch("[^_]+") do ffi_parts[#ffi_parts+1] = p end
            ngx.say("cookie_hash_match: ", norm_parts[3] == ffi_parts[3] and "yes" or "no")
            ngx.say("pair_hash_match: ", norm_parts[4] == ffi_parts[4] and "yes" or "no")
        }
    }
--- request
GET /t
--- more_headers
Accept-Language: en-US
Cookie: beta=2; alpha=1
Referer: http://example.com
--- response_body_like
normal:  ge11cr.*
ffi:     ge11cr.*
cookie_hash_match: yes
pair_hash_match: yes

=== TEST 3: FFI path raw mode matches
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            ja4h.configure({ hash = false })
            local normal = ja4h.compute()
            local ffi_result = ja4h._compute_ffi_path()
            -- In raw mode, section B lists header names
            local norm_parts = {}
            for p in normal:gmatch("[^_]+") do norm_parts[#norm_parts+1] = p end
            local ffi_parts = {}
            for p in ffi_result:gmatch("[^_]+") do ffi_parts[#ffi_parts+1] = p end
            -- Cookie sections (C, D) should match (sorting is deterministic)
            ngx.say("cookie_raw_match: ", norm_parts[3] == ffi_parts[3] and "yes" or "no")
            ngx.say("pair_raw_match: ", norm_parts[4] == ffi_parts[4] and "yes" or "no")
        }
    }
--- request
GET /t
--- more_headers
Accept-Language: en-US
Cookie: z=3; a=1
--- response_body
cookie_raw_match: yes
pair_raw_match: yes

=== TEST 4: compute() with no cookies no referer
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            ja4h.configure({ hash = true })
            local normal = ja4h.compute()
            local ffi_result = ja4h._compute_ffi_path()
            ngx.say("normal_flags: ", normal:sub(5, 6))
            ngx.say("ffi_flags:    ", ffi_result:sub(5, 6))
            -- Both should have "nn" (no cookie, no referer)
            ngx.say("match: ", normal:sub(5, 6) == ffi_result:sub(5, 6) and "yes" or "no")
        }
    }
--- request
GET /t
--- response_body
normal_flags: nn
ffi_flags:    nn
match: yes

=== TEST 5: compute stores result in ngx.ctx
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            ja4h.configure({ hash = true })
            local result = ja4h.compute()
            local stored = ja4h.get()
            ngx.say("match: ", result == stored and "yes" or "no")
            ngx.say("len: ", #result)
        }
    }
--- request
GET /t
--- more_headers
Accept-Language: en-US
--- response_body
match: yes
len: 51
```

**Step 2: Run tests to verify they fail**

```bash
make test-verbose 2>&1 | grep -A2 "007-ja4h-compute"
```

Expected: FAIL because `_compute_ffi_path` doesn't exist.

**Step 3: Add the cookie joiner and modify compute()**

In `lib/resty/ja4h.lua`, add the cookie joiner helper (after `get_headers_ffi` function):

```lua
-- Join multiple cookie values with "; " via FFI buffer (one allocation).
-- HTTP/2 may send separate cookie: headers instead of one semicolon-separated value.
local function join_cookie_values(values, count)
    if not values or count == 0 then return nil end
    if count == 1 then return values[1] end
    local pos = 0
    for i = 1, count do
        if i > 1 then
            _ck_join[pos] = 0x3B      -- ';'
            _ck_join[pos + 1] = 0x20  -- ' '
            pos = pos + 2
        end
        local s = values[i]
        local slen = #s
        ffi_copy(_ck_join + pos, s, slen)
        pos = pos + slen
    end
    return ffi_string(_ck_join, pos)
end
```

Replace the existing `compute()` function (lines 186-212) with the dual-path version:

```lua
-- Internal: compute via FFI path (used for HTTP/2+, exposed for testing)
local function compute_ffi_path()
    local method = ngx.req.get_method()
    local version = get_http_version()

    local header_names, header_count, has_cookie, has_referer,
          cookie_values, accept_language = get_headers_ffi()

    local cookie_str = join_cookie_values(cookie_values, cookie_values and #cookie_values or 0)

    return _M.build({
        method          = method,
        version         = version,
        has_cookie      = has_cookie,
        has_referer     = has_referer,
        header_names    = header_names,
        accept_language = accept_language,
        cookie_str      = cookie_str,
    })
end

-- Compute JA4H from current HTTP request context.
-- Dual-path: raw_header() for HTTP/1.x, FFI for HTTP/2+.
-- Returns: fingerprint string (or nil, err)
function _M.compute()
    local version = get_http_version()
    local result

    if version == "20" or version == "30" then
        result = compute_ffi_path()
    else
        -- HTTP/1.x path (unchanged)
        local req = ngx.req
        local method = req.get_method()
        local raw_header = req.raw_header(true)
        local header_names, header_count = utils.parse_raw_header_names(raw_header)
        local headers = req.get_headers(100)

        result = _M.build({
            method          = method,
            version         = version,
            has_cookie      = headers["cookie"] ~= nil,
            has_referer     = headers["referer"] ~= nil,
            header_names    = header_names,
            accept_language = headers["accept-language"],
            cookie_str      = headers["cookie"],
        })
    end

    _M.store(result)
    return result
end

-- Exposed for testing
_M._compute_ffi_path = compute_ffi_path
```

**Step 4: Run ALL tests**

```bash
make test
```

Expected: ALL tests pass (existing 003, 004, 005 + new 006, 007).

**Step 5: Commit**

```bash
git add lib/resty/ja4h.lua t/007-ja4h-compute-h2-path.t
git commit -m "feat(ja4h): dual-path compute() for HTTP/1.x and HTTP/2+

HTTP/1.x: raw_header() path unchanged (proven, zero regression risk).
HTTP/2+: FFI path via get_headers_ffi() + cookie value join.
Version detected via ngx.var.server_protocol."
```

---

## Task 3: E2E HTTP/2 infrastructure

Enable HTTP/2 in the e2e nginx config and add an HTTP/2 Python client to the test container.

**Files:**
- Modify: `e2e/nginx.conf` — add `http2 on;` to both server blocks
- Modify: `e2e/Dockerfile.tests` — add `httpx[http2]` dependency
- Modify: `e2e/conftest.py` — add HTTP/2 request fixture

**Step 1: Add `http2 on;` to nginx.conf**

In `e2e/nginx.conf`, add `http2 on;` to both server blocks, after the `ssl_protocols` line:

For the hash mode server (port 443), after line 18 (`ssl_protocols TLSv1.2 TLSv1.3;`):
```nginx
        http2 on;
```

For the raw mode server (port 8443), after line 58 (`ssl_protocols TLSv1.2 TLSv1.3;`):
```nginx
        http2 on;
```

**Step 2: Add httpx to Dockerfile.tests**

Replace line 3 in `e2e/Dockerfile.tests`:

```dockerfile
RUN pip install --no-cache-dir pytest httpx[http2]
```

Update the COPY line (line 6) to include the new test file:

```dockerfile
COPY e2e/conftest.py e2e/test_ja4.py e2e/test_ja4h.py e2e/test_ja4h_http2.py /app/
```

**Step 3: Add HTTP/2 fixtures to conftest.py**

Add to the end of `e2e/conftest.py`:

```python
import httpx

H2_HASH_PORT = HASH_PORT
H2_RAW_PORT = RAW_PORT


def make_h2_request(port, path="/", method="GET", headers=None):
    """Make an HTTP/2 request and return (response_headers_dict, body_bytes)."""
    url = f"https://{NGINX_HOST}:{port}{path}"
    with httpx.Client(http2=True, verify=False) as client:
        resp = client.request(method, url, headers=headers or {})
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        return resp_headers, resp.content


@pytest.fixture
def h2_hash_request():
    """Make an HTTP/2 request to the hash-mode server (port 443)."""
    def _request(path="/", method="GET", headers=None):
        return make_h2_request(H2_HASH_PORT, path, method, headers)
    return _request


@pytest.fixture
def h2_raw_request():
    """Make an HTTP/2 request to the raw-mode server (port 8443)."""
    def _request(path="/", method="GET", headers=None):
        return make_h2_request(H2_RAW_PORT, path, method, headers)
    return _request
```

**Step 4: Verify existing tests still pass**

```bash
make e2e
```

Expected: all 25 existing tests pass on both OpenResty 1.27 and 1.29. HTTP/1.1 clients are unaffected by `http2 on;`.

**Step 5: Commit**

```bash
git add e2e/nginx.conf e2e/Dockerfile.tests e2e/conftest.py
git commit -m "build(e2e): enable HTTP/2 and add httpx client for h2 tests"
```

---

## Task 4: E2E HTTP/2 tests

Write e2e tests that send real HTTP/2 requests and verify JA4H fingerprints.

**Files:**
- Create: `e2e/test_ja4h_http2.py`

**Step 1: Write the e2e test file**

Create `e2e/test_ja4h_http2.py`:

```python
import re


# JA4H hash: 12-char section_a + 3x _<12hex> = 51 chars
JA4H_HASH_RE = re.compile(
    r"^[a-z]{2}(?:11|10|20|30|00)[cnr]{2}\d{2}[a-z0-9]{4}"
    r"_[a-f0-9]{12}_[a-f0-9]{12}_[a-f0-9]{12}$"
)


class TestJA4HHttp2Hash:
    """JA4H HTTP/2 fingerprinting — hash mode."""

    def test_h2_ja4h_header_present(self, h2_hash_request):
        headers, _ = h2_hash_request()
        assert "x-ja4h" in headers, f"X-JA4H header missing. Headers: {dict(headers)}"

    def test_h2_ja4h_hash_format(self, h2_hash_request):
        headers, _ = h2_hash_request()
        ja4h = headers["x-ja4h"]
        assert JA4H_HASH_RE.match(ja4h), f"JA4H '{ja4h}' doesn't match hash format"

    def test_h2_version_is_20(self, h2_hash_request):
        headers, _ = h2_hash_request()
        ja4h = headers["x-ja4h"]
        version = ja4h[2:4]
        assert version == "20", f"Expected HTTP/2 version '20', got '{version}'"

    def test_h2_get_method(self, h2_hash_request):
        headers, _ = h2_hash_request(method="GET")
        ja4h = headers["x-ja4h"]
        assert ja4h[:2] == "ge", f"Expected method 'ge', got '{ja4h[:2]}'"

    def test_h2_head_method(self, h2_hash_request):
        headers, _ = h2_hash_request(method="HEAD")
        ja4h = headers["x-ja4h"]
        assert ja4h[:2] == "he", f"Expected method 'he', got '{ja4h[:2]}'"

    def test_h2_cookie_flag_absent(self, h2_hash_request):
        headers, _ = h2_hash_request()
        ja4h = headers["x-ja4h"]
        assert ja4h[4] == "n", f"Expected cookie flag 'n', got '{ja4h[4]}'"

    def test_h2_cookie_flag_present(self, h2_hash_request):
        headers, _ = h2_hash_request(headers={"Cookie": "session=abc123"})
        ja4h = headers["x-ja4h"]
        assert ja4h[4] == "c", f"Expected cookie flag 'c', got '{ja4h[4]}'"

    def test_h2_referer_flag_absent(self, h2_hash_request):
        headers, _ = h2_hash_request()
        ja4h = headers["x-ja4h"]
        assert ja4h[5] == "n", f"Expected referer flag 'n', got '{ja4h[5]}'"

    def test_h2_referer_flag_present(self, h2_hash_request):
        headers, _ = h2_hash_request(headers={"Referer": "https://example.com"})
        ja4h = headers["x-ja4h"]
        assert ja4h[5] == "r", f"Expected referer flag 'r', got '{ja4h[5]}'"

    def test_h2_accept_language(self, h2_hash_request):
        headers, _ = h2_hash_request(headers={"Accept-Language": "en-US,en;q=0.9"})
        ja4h = headers["x-ja4h"]
        lang = ja4h[8:12]
        assert lang == "enus", f"Expected language 'enus', got '{lang}'"

    def test_h2_no_language_defaults(self, h2_hash_request):
        headers, _ = h2_hash_request()
        ja4h = headers["x-ja4h"]
        lang = ja4h[8:12]
        assert lang == "0000", f"Expected default language '0000', got '{lang}'"

    def test_h2_deterministic(self, h2_hash_request):
        h1, _ = h2_hash_request(headers={"Accept-Language": "fr-FR"})
        h2, _ = h2_hash_request(headers={"Accept-Language": "fr-FR"})
        assert h1["x-ja4h"] == h2["x-ja4h"], "JA4H should be deterministic"

    def test_h2_fingerprint_length(self, h2_hash_request):
        headers, _ = h2_hash_request()
        ja4h = headers["x-ja4h"]
        assert len(ja4h) == 51, f"Hash JA4H should be 51 chars, got {len(ja4h)}"


class TestJA4HHttp2Raw:
    """JA4H HTTP/2 fingerprinting — raw mode."""

    def test_h2_raw_header_present(self, h2_raw_request):
        headers, _ = h2_raw_request()
        assert "x-ja4h" in headers, f"X-JA4H header missing. Headers: {dict(headers)}"

    def test_h2_raw_version_is_20(self, h2_raw_request):
        headers, _ = h2_raw_request()
        ja4h = headers["x-ja4h"]
        version = ja4h[2:4]
        assert version == "20", f"Expected HTTP/2 version '20', got '{version}'"

    def test_h2_raw_contains_header_names(self, h2_raw_request):
        headers, _ = h2_raw_request(headers={"Accept-Language": "en-US"})
        ja4h = headers["x-ja4h"]
        parts = ja4h.split("_")
        assert len(parts) >= 2, f"Raw JA4H should have underscore separators: '{ja4h}'"
        section_b = parts[1]
        # HTTP/2 headers are lowercase; should contain accept-language
        assert "accept-language" in section_b.lower(), \
            f"Raw section B should contain header names: '{section_b}'"

    def test_h2_raw_cookie_names_sorted(self, h2_raw_request):
        headers, _ = h2_raw_request(headers={"Cookie": "zebra=3; alpha=1; mango=2"})
        ja4h = headers["x-ja4h"]
        parts = ja4h.split("_")
        assert len(parts) >= 3, f"Expected at least 3 sections: '{ja4h}'"
        section_c = parts[2]
        assert "alpha" in section_c and "mango" in section_c and "zebra" in section_c, \
            f"Raw section C should contain sorted cookie names: '{section_c}'"
        # Verify alphabetical order
        names = section_c.split(",")
        assert names == sorted(names), f"Cookie names should be sorted: {names}"
```

**Step 2: Run e2e tests**

```bash
make e2e
```

Expected: all existing 25 tests + 17 new HTTP/2 tests pass on both OpenResty versions.

**Step 3: Debug if needed**

Common issues:
- **`http2 on;` not supported on OpenResty 1.27**: May need `listen 443 ssl http2;` syntax instead. Check nginx version. OpenResty 1.27 uses nginx 1.27 core which supports `http2 on;`.
- **httpx not negotiating HTTP/2**: Verify with `h2` extra (`httpx[http2]`). Check that the response `headers` actually come over HTTP/2.
- **Version shows "11" instead of "20"**: Check `ngx.var.server_protocol` — may return "HTTP/2.0" or "HTTP/2". Both are handled in `get_http_version()`.
- **JA4H missing from response**: Check nginx error log for Lua errors. The old `raw_header()` call should NOT run for HTTP/2 requests.

**Step 4: Commit**

```bash
git add e2e/test_ja4h_http2.py
git commit -m "test(e2e): add HTTP/2 JA4H fingerprinting tests

17 tests covering hash/raw modes via httpx HTTP/2 client.
Verifies version=20, method codes, cookie/referer flags,
accept-language, determinism, and raw mode header visibility."
```

---

## Task 5: Final verification + test count update

Run the complete test suite, update test counts, and verify no regressions.

**Files:**
- Verify: all test files

**Step 1: Run unit tests**

```bash
make test
```

Expected: all tests pass (existing 192 + new 13 = 205 unit tests).

**Step 2: Run e2e tests**

```bash
make e2e
```

Expected: all tests pass (existing 25 + new 17 = 42 e2e tests) on both OpenResty 1.27 and 1.29.

**Step 3: Verify test counts in plan headers match**

Update `plan tests` in new test files if counts changed during implementation.

**Step 4: Final commit if any adjustments**

```bash
git add -A
git commit -m "test: finalize test counts for JA4H HTTP/2 support"
```

---

## Future Work (documented, not implemented)

- **`JA4H_ro` mode**: Raw fingerprint with original cookie order. Python reference has `JA4H_r` (sorted) and `JA4H_ro` (original). Would need a third mode in `configure()`.
- **HTTP/3 e2e testing**: The FFI path handles HTTP/3 (C function synthesizes host from `:authority`). `get_http_version()` returns "30". Needs QUIC e2e tests.
- **Performance benchmarking**: Add HTTP/2 path to `bench/microbench.lua` to verify JIT compilation and measure overhead vs HTTP/1.x path.
