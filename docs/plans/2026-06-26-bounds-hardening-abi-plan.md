# Bounds Hardening + ABI Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the remotely-triggerable FFI buffer overflows and the O(n²) sort DoS in `lua-resty-ja4`, and migrate the JA4 TLS extraction from hand-rolled OpenSSL FFI to the official `ngx.ssl.clienthello` getters.

**Architecture:** Input lists are clamped to named per-field caps before they reach the fixed FFI buffers; buffers are resized from those caps so overflow is impossible by construction; the CSV writers gain a capacity backstop. The JA4 live path drops raw OpenSSL FFI (and the `CRYPTO_free` hazard) for the platform getters, which already GREASE-filter and cap ciphers at 128. Over-cap inputs are truncated to a deterministic fingerprint and logged at WARN — the request never fails.

**Tech Stack:** LuaJIT + FFI, OpenResty, lua-resty-core (`ngx.ssl.clienthello`), Test::Nginx::Socket::Lua (`t/`), pytest + scapy (`e2e/`), Docker.

## Global Constraints

- **Minimum OpenResty: 1.29.2.1** (bundles lua-resty-core 0.1.32R1, which has the getters). Drop 1.27.
- **Per-field caps (named constants in `utils.lua`):** `MAX_CIPHERS = 128`, `MAX_EXTENSIONS = 128`, `MAX_SIG_ALGS = 128`, `MAX_HEADERS = 100`, `MAX_COOKIES = 128`.
- **Overflow behavior:** clamp to cap + one `ngx.log(ngx.WARN, ...)` of the form `"ja4: <field> truncated <orig>-><cap>"`. Never fail the request.
- **No new per-request heap allocation** on the common path — keep the module-level reused-buffer design.
- Little-endian only (existing assertion in `utils.lua` stays).
- Real clients (always under every cap) MUST keep producing byte-identical fingerprints — caps only affect pathological inputs.

---

## File Structure

- `lib/resty/ja4/utils.lua` — cap constants, buffer-size constant, capacity-aware CSV writers, cookie-count cap. (Task 1)
- `lib/resty/ja4.lua` — `build()` count-clamping + buffer resize + warn (Task 2); `compute()` ABI migration to official getters (Task 4).
- `lib/resty/ja4h.lua` — `build()` header/cookie clamping + buffer resize + warn. (Task 3)
- `t/001-utils.t` — unit tests for capacity-aware writers + cookie cap. (Task 1)
- `t/002-ja4-algo.t` — fix overflowing tests + add >cap JA4 tests. (Task 2)
- `t/003-ja4h-algo.t` — add >cap JA4H tests. (Task 3)
- `Dockerfile.test`, `e2e/docker-compose.e2e.yml` — bump base image to 1.29.2.x. (Task 4)
- `e2e/test_ja4_scapy.py` — oversized-ClientHello robustness test. (Task 5)
- `README.md` — version floor + dependency note. (Task 6)

---

## Task 1: Caps and capacity-aware writers in `utils.lua`

**Files:**
- Modify: `lib/resty/ja4/utils.lua`
- Test: `t/001-utils.t`

**Interfaces:**
- Consumes: nothing.
- Produces (used by Tasks 2 & 3):
  - `utils.MAX_CIPHERS = 128`, `utils.MAX_EXTENSIONS = 128`, `utils.MAX_SIG_ALGS = 128`, `utils.MAX_HEADERS = 100`, `utils.MAX_COOKIES = 128` (integers)
  - `utils.CSV_BUF_SIZE = 2048` (integer; the size of the shared `csv_buf`)
  - `write_u16_hex_csv(arr, n, buf, offset, cap)` — new trailing `cap` (max byte offset); `nil` cap = unbounded (back-compat)
  - `write_hex4_csv_at(hex_array, n, buf, pos, cap)` — new trailing `cap`
  - `write_str_csv_at(str_array, n, buf, pos, cap)` — new trailing `cap`
  - `parse_cookies_into(cookie_str, names, pairs_list, max_cookies)` — new trailing `max_cookies`; returns `n, truncated` (second value `true` when clamped)

- [ ] **Step 1: Write failing tests**

Append these three blocks to `t/001-utils.t` (before `run_tests()` is not needed — blocks go after `__DATA__`; add at end of file). Then bump the plan count: change the `plan tests => repeat_each() * 2 * N;` line, increasing `N` by 3.

```
=== TEST: write_u16_hex_csv respects cap (no overflow)
--- http_config eval: $::HttpConfig
--- lua_code
local ffi = require "ffi"
local utils = require "resty.ja4.utils"
local buf = ffi.new("uint8_t[16]")
local arr = ffi.new("uint16_t[10]")
for i = 0, 9 do arr[i] = 0x1234 end
local pos = utils.write_u16_hex_csv(arr, 10, buf, 0, 16)
ngx.say("within_cap: ", tostring(pos <= 16))
--- response_body
within_cap: true

=== TEST: write_str_csv_at respects cap (no overflow)
--- http_config eval: $::HttpConfig
--- lua_code
local ffi = require "ffi"
local utils = require "resty.ja4.utils"
local buf = ffi.new("uint8_t[16]")
local arr = {}
for i = 1, 20 do arr[i] = "longheadername" end
local pos = utils.write_str_csv_at(arr, 20, buf, 0, 16)
ngx.say("within_cap: ", tostring(pos <= 16))
--- response_body
within_cap: true

=== TEST: parse_cookies_into caps cookie count and reports truncation
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
local names, pairs_list = {}, {}
local parts = {}
for i = 1, 300 do parts[i] = "k" .. i .. "=v" end
local cookie_str = table.concat(parts, "; ")
local n, truncated = utils.parse_cookies_into(cookie_str, names, pairs_list, 128)
ngx.say("n: ", n, " truncated: ", tostring(truncated))
--- response_body
n: 128 truncated: true
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
make test-build
docker run --rm --init lua-resty-ja4-test prove -v t/001-utils.t
```
Expected: the three new blocks FAIL (cap arg ignored / `truncated` is `nil` / `parse_cookies_into` returns 300).

- [ ] **Step 3: Add cap constants and buffer-size constant**

In `lib/resty/ja4/utils.lua`, just after the `_M.EMPTY_HASH = "000000000000"` line (~line 25), add:

```lua
-- Per-field safety caps. Real clients are far below these; pathological or
-- malicious inputs are clamped to a deterministic, bounded fingerprint.
_M.MAX_CIPHERS    = 128   -- matches the platform ngx.ssl.clienthello getter
_M.MAX_EXTENSIONS = 128
_M.MAX_SIG_ALGS   = 128
_M.MAX_HEADERS    = 100   -- nginx NGX_HTTP_LUA_MAX_HEADERS default
_M.MAX_COOKIES    = 128
```

- [ ] **Step 4: Resize `csv_buf` and export its size**

In `lib/resty/ja4/utils.lua`, replace the `csv_buf` definition (currently `local csv_buf = ffi_new("uint8_t[512]")`, ~line 143) with:

```lua
-- FFI buffer for building comma-separated hex values (ja4 hash inputs).
-- Worst case section C: 128 exts*5 (640) + '_' + 128 sig_algs*5 (640) = 1281 -> 2048.
local CSV_BUF_SIZE = 2048
local csv_buf = ffi_new("uint8_t[" .. CSV_BUF_SIZE .. "]")
_M.csv_buf = csv_buf
_M.CSV_BUF_SIZE = CSV_BUF_SIZE
```

- [ ] **Step 5: Add `cap` to the three CSV writers**

Replace `write_u16_hex_csv` (~lines 147-163) with:

```lua
-- Write uint16 FFI array as comma-separated 4-char hex into buf at offset.
-- Stops before exceeding `cap` bytes if cap is given (backstop; sizing prevents this).
local function write_u16_hex_csv(arr, n, buf, offset, cap)
    if n == 0 then return offset end
    local pos = offset
    for i = 0, n - 1 do
        if cap and pos + 5 > cap then break end
        if i > 0 then
            buf[pos] = 0x2C  -- ','
            pos = pos + 1
        end
        local val = arr[i]
        buf[pos]     = hex_chars[rshift(val, 12)]
        buf[pos + 1] = hex_chars[band(rshift(val, 8), 0x0f)]
        buf[pos + 2] = hex_chars[band(rshift(val, 4), 0x0f)]
        buf[pos + 3] = hex_chars[band(val, 0x0f)]
        pos = pos + 4
    end
    return pos
end
_M.write_u16_hex_csv = write_u16_hex_csv
```

Replace `write_hex4_csv_at` (~lines 167-182) with:

```lua
-- Write array of 4-char hex strings as CSV into arbitrary buffer at pos.
local function write_hex4_csv_at(hex_array, n, buf, pos, cap)
    if n == 0 then return pos end
    for i = 1, n do
        if cap and pos + 5 > cap then break end
        if i > 1 then
            buf[pos] = 0x2C  -- ','
            pos = pos + 1
        end
        local s = hex_array[i]
        buf[pos]     = byte(s, 1)
        buf[pos + 1] = byte(s, 2)
        buf[pos + 2] = byte(s, 3)
        buf[pos + 3] = byte(s, 4)
        pos = pos + 4
    end
    return pos
end
_M.write_hex4_csv_at = write_hex4_csv_at
```

Replace `write_str_csv_at` (~lines 186-199) with:

```lua
-- Write array of variable-length Lua strings as CSV into buffer at pos.
local function write_str_csv_at(str_array, n, buf, pos, cap)
    if n == 0 then return pos end
    for i = 1, n do
        local s = str_array[i]
        local slen = #s
        local need = (i > 1 and 1 or 0) + slen
        if cap and pos + need > cap then break end
        if i > 1 then
            buf[pos] = 0x2C  -- ','
            pos = pos + 1
        end
        ffi_copy(buf + pos, s, slen)
        pos = pos + slen
    end
    return pos
end
_M.write_str_csv_at = write_str_csv_at
```

- [ ] **Step 6: Add `max_cookies` cap to `parse_cookies_into`**

In `lib/resty/ja4/utils.lua`, change the signature and loop of `parse_cookies_into` (~lines 300-340). Replace the function header line:

```lua
function _M.parse_cookies_into(cookie_str, names, pairs_list, max_cookies)
```

Add `local truncated = false` next to the existing `local n = 0` line. Inside the `while pos <= len do` loop, immediately after `if pos > len then break end`, add the cap check:

```lua
        if max_cookies and n >= max_cookies then
            truncated = true
            break
        end
```

Change the final `return n` to:

```lua
    return n, truncated
```

(The existing leftover-clearing loops before the return stay unchanged.)

- [ ] **Step 7: Run tests to verify they pass**

Run:
```bash
make test-build
docker run --rm --init lua-resty-ja4-test prove -v t/001-utils.t
```
Expected: all blocks PASS (including the 3 new ones). If `prove` reports "planned N but ran M", set the `plan tests =>` multiplier so the planned total equals M.

- [ ] **Step 8: Commit**

```bash
git add lib/resty/ja4/utils.lua t/001-utils.t
git commit -m "feat(utils): add per-field caps and capacity-aware CSV writers"
```

---

## Task 2: Bounds-harden `ja4.build()`

**Files:**
- Modify: `lib/resty/ja4.lua`
- Test: `t/002-ja4-algo.t`

**Interfaces:**
- Consumes: `utils.MAX_CIPHERS`, `utils.MAX_EXTENSIONS`, `utils.MAX_SIG_ALGS`, `utils.CSV_BUF_SIZE`, and the cap-aware `write_u16_hex_csv` / `write_hex4_csv_at` from Task 1.
- Produces: a `build()` that never writes past its buffers and warns on truncation. Public signature unchanged.

- [ ] **Step 1: Write failing tests**

Append to `t/002-ja4-algo.t` (after `__DATA__`, at end of file), then bump the plan count: change `plan tests => repeat_each() * 2 * 16;` to `plan tests => repeat_each() * 2 * 19;`.

```
=== TEST: JA4 hash mode survives 200 ciphers and warns
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
local ciphers = {}
for i = 1, 200 do ciphers[i] = i end
local result = ja4.build({
    protocol = "t", version = "13", sni = "d",
    ciphers = ciphers, extensions = {0x000a}, alpn = "h2", sig_algs = nil,
})
ngx.say("cc: ", result:sub(5, 6))
ngx.say("len: ", #result)
--- response_body
cc: 99
len: 36
--- error_log
ja4: ciphers truncated 200->128

=== TEST: JA4 hash mode survives 200 extensions and warns
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
local extensions = {}
for i = 1, 200 do extensions[i] = i + 0x0100 end
local result = ja4.build({
    protocol = "t", version = "13", sni = "d",
    ciphers = {0x1301}, extensions = extensions, alpn = "h2", sig_algs = nil,
})
ngx.say("len: ", #result)
--- response_body
len: 36
--- error_log
ja4: extensions truncated 200->128

=== TEST: JA4 raw mode survives 300 ciphers without overflow
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
ja4.configure({ hash = false })
local ciphers = {}
for i = 1, 300 do ciphers[i] = i end
local result = ja4.build({
    protocol = "t", version = "13", sni = "d",
    ciphers = ciphers, extensions = {0x000a}, alpn = "h2", sig_algs = nil,
})
ja4.configure({ hash = true })
ngx.say("bounded: ", tostring(#result < 4096 and #result > 0))
--- response_body
bounded: true
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
make test-build
docker run --rm --init lua-resty-ja4-test prove -v t/002-ja4-algo.t
```
Expected: the 3 new blocks FAIL (no warn logged; raw-mode block may segfault/abort the worker — that IS the bug).

- [ ] **Step 3: Wire caps + buffer-size constants into the module**

In `lib/resty/ja4.lua`, after the existing `local NUM2 = utils.NUM2` line (~line 21), add:

```lua
local MAX_CIPHERS    = utils.MAX_CIPHERS
local MAX_EXTENSIONS = utils.MAX_EXTENSIONS
local MAX_SIG_ALGS   = utils.MAX_SIG_ALGS
local CSV_BUF_SIZE   = utils.CSV_BUF_SIZE
local ngx_log = ngx.log
local ngx_WARN = ngx.WARN
```

- [ ] **Step 4: Resize the module buffers to the caps**

In `lib/resty/ja4.lua`, replace lines 23-27 (`cipher_u16`, `ext_u16`, the comment, `out_buf`) with:

```lua
local cipher_u16 = ffi_new("uint16_t[" .. MAX_CIPHERS .. "]")
local ext_u16 = ffi_new("uint16_t[" .. MAX_EXTENSIONS .. "]")
-- Raw mode worst case: 10 (section_a) + 1 + 640 (128 ciphers) + 1 + 640 (128 exts)
-- + 1 + 640 (128 sig_algs) ~= 1934B. Hash mode: fixed 36B. 4096B covers all cases.
local OUT_BUF_SIZE = 4096
local out_buf = ffi_new("uint8_t[" .. OUT_BUF_SIZE .. "]")
```

- [ ] **Step 5: Clamp the copy/filter helpers to their caps**

In `lib/resty/ja4.lua`, replace `copy_ciphers` (~lines 59-65) with:

```lua
-- Copy cipher uint16 values from Lua table to FFI array (clamped to cap).
-- Separate function gives JIT a clean trace boundary.
local function copy_ciphers(ciphers, arr, cap)
    local n = #ciphers
    if n > cap then n = cap end
    for i = 1, n do
        arr[i - 1] = ciphers[i]
    end
    return n
end
```

Replace `filter_extensions_u16` (~lines 69-79) with:

```lua
-- Copy extension uint16 values to FFI array (clamped to cap), excluding SNI
-- (0x0000) and ALPN (0x0010). Separate function eliminates a JIT abort.
local function filter_extensions_u16(extensions, arr, cap)
    local total = #extensions
    if total > cap then total = cap end
    local n = 0
    for i = 1, total do
        local ext = extensions[i]
        if ext ~= 0x0000 and ext ~= 0x0010 then
            arr[n] = ext
            n = n + 1
        end
    end
    return n
end
```

- [ ] **Step 6: Clamp + warn in `build()`, pass caps to copy/filter and writers**

In `lib/resty/ja4.lua` `build()`, replace lines 133-134:

```lua
    local cipher_count = math_min(#data.ciphers, 99)
    local ext_count = math_min(#data.extensions, 99)
```

with:

```lua
    local raw_cipher_n = #data.ciphers
    local raw_ext_n = #data.extensions
    local cipher_count = math_min(raw_cipher_n, 99)
    local ext_count = math_min(raw_ext_n, 99)
    if raw_cipher_n > MAX_CIPHERS then
        ngx_log(ngx_WARN, "ja4: ciphers truncated ", raw_cipher_n, "->", MAX_CIPHERS)
    end
    if raw_ext_n > MAX_EXTENSIONS then
        ngx_log(ngx_WARN, "ja4: extensions truncated ", raw_ext_n, "->", MAX_EXTENSIONS)
    end
    local sig_n = data.sig_algs and #data.sig_algs or 0
    if sig_n > MAX_SIG_ALGS then
        ngx_log(ngx_WARN, "ja4: sig_algs truncated ", sig_n, "->", MAX_SIG_ALGS)
        sig_n = MAX_SIG_ALGS
    end
```

Replace the two copy/filter call sites (~lines 152, 155):

```lua
    local cn = copy_ciphers(data.ciphers, cipher_u16)
```
→
```lua
    local cn = copy_ciphers(data.ciphers, cipher_u16, MAX_CIPHERS)
```

and
```lua
    local ext_n = filter_extensions_u16(data.extensions, ext_u16)
```
→
```lua
    local ext_n = filter_extensions_u16(data.extensions, ext_u16, MAX_EXTENSIONS)
```

In the hash-mode branch, replace the section B/C writer calls (~lines 163, 171-174):

```lua
            local csv_len = write_u16_hex_csv(cipher_u16, cn, csv_buf, 0)
```
→
```lua
            local csv_len = write_u16_hex_csv(cipher_u16, cn, csv_buf, 0, CSV_BUF_SIZE)
```

and
```lua
        local sc_len = write_u16_hex_csv(ext_u16, ext_n, csv_buf, 0)
        if data.sig_algs and #data.sig_algs > 0 then
            csv_buf[sc_len] = 0x5F  -- '_'
            sc_len = write_hex4_csv_at(data.sig_algs, #data.sig_algs, csv_buf, sc_len + 1)
        end
        if ext_n == 0 and (not data.sig_algs or #data.sig_algs == 0) then
```
→
```lua
        local sc_len = write_u16_hex_csv(ext_u16, ext_n, csv_buf, 0, CSV_BUF_SIZE)
        if sig_n > 0 then
            csv_buf[sc_len] = 0x5F  -- '_'
            sc_len = write_hex4_csv_at(data.sig_algs, sig_n, csv_buf, sc_len + 1, CSV_BUF_SIZE)
        end
        if ext_n == 0 and sig_n == 0 then
```

In the raw-mode branch, replace the writer calls (~lines 184, 189-192):

```lua
        pos = write_u16_hex_csv(cipher_u16, cn, out_buf, pos)
```
→
```lua
        pos = write_u16_hex_csv(cipher_u16, cn, out_buf, pos, OUT_BUF_SIZE)
```

and
```lua
        pos = write_u16_hex_csv(ext_u16, ext_n, out_buf, pos)
        if data.sig_algs and #data.sig_algs > 0 then
            out_buf[pos] = 0x5F; pos = pos + 1
            pos = write_hex4_csv_at(data.sig_algs, #data.sig_algs, out_buf, pos)
        end
```
→
```lua
        pos = write_u16_hex_csv(ext_u16, ext_n, out_buf, pos, OUT_BUF_SIZE)
        if sig_n > 0 then
            out_buf[pos] = 0x5F; pos = pos + 1
            pos = write_hex4_csv_at(data.sig_algs, sig_n, out_buf, pos, OUT_BUF_SIZE)
        end
```

- [ ] **Step 7: Run tests to verify they pass**

Run:
```bash
make test-build
docker run --rm --init lua-resty-ja4-test prove -v t/002-ja4-algo.t
```
Expected: all blocks PASS, including TEST 8/9 (now within the resized buffers) and the 3 new ones. Adjust the `plan tests =>` multiplier if `prove` reports a planned/ran mismatch.

- [ ] **Step 8: Commit**

```bash
git add lib/resty/ja4.lua t/002-ja4-algo.t
git commit -m "fix(ja4): clamp ciphers/extensions/sig_algs to caps; resize buffers"
```

---

## Task 3: Bounds-harden `ja4h.build()`

**Files:**
- Modify: `lib/resty/ja4h.lua`
- Test: `t/003-ja4h-algo.t`

**Interfaces:**
- Consumes: `utils.MAX_HEADERS`, `utils.MAX_COOKIES`, the cap-aware `write_str_csv_at`, and `parse_cookies_into(..., max_cookies) -> n, truncated` from Task 1.
- Produces: a `build()` that never overflows `hash_buf`/`out_buf` and warns on truncation. Public signature unchanged.

- [ ] **Step 1: Write failing tests**

Append to `t/003-ja4h-algo.t` (after `__DATA__`, at end), then change `plan tests => repeat_each() * 2 * 18;` to `plan tests => repeat_each() * 2 * 20;`.

```
=== TEST: JA4H survives 200 header names and warns
--- http_config eval: $::HttpConfig
--- lua_code
local ja4h = require "resty.ja4h"
local names = {}
for i = 1, 200 do names[i] = "x-custom-header-" .. i end
local result = ja4h.build({
    method = "GET", version = "20",
    has_cookie = false, has_referer = false,
    header_names = names, accept_language = nil, cookie_str = nil,
})
ngx.say("bounded: ", tostring(#result > 0 and #result < 16384))
--- response_body
bounded: true
--- error_log
ja4: header_names truncated 200->100

=== TEST: JA4H survives 500 cookies and warns
--- http_config eval: $::HttpConfig
--- lua_code
local ja4h = require "resty.ja4h"
local parts = {}
for i = 1, 500 do parts[i] = "k" .. i .. "=" .. string.rep("v", 40) end
local cookie_str = table.concat(parts, "; ")
local result = ja4h.build({
    method = "GET", version = "20",
    has_cookie = true, has_referer = false,
    header_names = {"accept"}, accept_language = nil, cookie_str = cookie_str,
})
ngx.say("bounded: ", tostring(#result > 0 and #result < 16384))
--- response_body
bounded: true
--- error_log
ja4: cookies truncated to 128
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
make test-build
docker run --rm --init lua-resty-ja4-test prove -v t/003-ja4h-algo.t
```
Expected: the 2 new blocks FAIL (no warn; cookie block may overflow the 4096 `hash_buf` and corrupt/abort — that IS the bug).

- [ ] **Step 3: Wire caps + resize buffers**

In `lib/resty/ja4h.lua`, after `local NUM2 = utils.NUM2` (~line 28), add:

```lua
local MAX_HEADERS = utils.MAX_HEADERS
local MAX_COOKIES = utils.MAX_COOKIES
local ngx_log = ngx.log
local ngx_WARN = ngx.WARN
```

Replace the buffer definitions (~lines 21, 34-35):

```lua
local _ck_join = ffi_new("uint8_t[4096]")
```
→
```lua
local CK_JOIN_SIZE = 16384
local _ck_join = ffi_new("uint8_t[" .. CK_JOIN_SIZE .. "]")
```

and
```lua
local out_buf = ffi_new("uint8_t[4096]")
local hash_buf = ffi_new("uint8_t[4096]")  -- SHA256 input buffer for hash mode
```
→
```lua
-- Cookies/headers are bounded by nginx large_client_header_buffers (~8K default);
-- 16K ensures real requests never truncate, with count caps as backstop.
local BUF_SIZE = 16384
local out_buf = ffi_new("uint8_t[" .. BUF_SIZE .. "]")
local hash_buf = ffi_new("uint8_t[" .. BUF_SIZE .. "]")  -- SHA256 input buffer
```

Then delete the now-duplicated `local CK_JOIN_SIZE = 4096` line (~line 133) — it is replaced by the `16384` constant defined above. Verify `join_cookie_values` still references `CK_JOIN_SIZE` (it does).

- [ ] **Step 4: Clamp header names + warn, pass cap to writer**

In `lib/resty/ja4h.lua` `build()`, replace line 180:

```lua
    local header_count = math_min(#data.header_names, 99)
```
with:
```lua
    local raw_header_n = #data.header_names
    local header_count = math_min(raw_header_n, 99)
    local hn = math_min(raw_header_n, MAX_HEADERS)
    if raw_header_n > MAX_HEADERS then
        ngx_log(ngx_WARN, "ja4: header_names truncated ", raw_header_n, "->", MAX_HEADERS)
    end
```

In the hash-mode Section B (~lines 201-205), replace:

```lua
        if #data.header_names == 0 then
            ffi_copy(out_buf + pos, EMPTY_HASH, 12)
        else
            local hlen = write_str_csv_at(data.header_names, #data.header_names, hash_buf, 0)
            sha256_to_buf(hash_buf, hlen, out_buf, pos)
        end
```
with:
```lua
        if hn == 0 then
            ffi_copy(out_buf + pos, EMPTY_HASH, 12)
        else
            local hlen = write_str_csv_at(data.header_names, hn, hash_buf, 0, BUF_SIZE)
            sha256_to_buf(hash_buf, hlen, out_buf, pos)
        end
```

In the raw-mode Section B (~line 244), replace:

```lua
        pos = write_str_csv_at(data.header_names, #data.header_names, out_buf, pos)
```
with:
```lua
        pos = write_str_csv_at(data.header_names, hn, out_buf, pos, BUF_SIZE)
```

- [ ] **Step 5: Clamp cookies + warn, pass cap to writers**

In `lib/resty/ja4h.lua`, there are two cookie-parsing sites (hash mode ~line 213, raw mode ~line 250). The parser stops once it reaches the cap, so the client's true cookie count is unknown — the warn reports the cap only. In **both** sites, replace:

```lua
            local cn = utils.parse_cookies_into(data.cookie_str, _cookie_names, _cookie_pairs)
```
with:
```lua
            local cn, ck_trunc = utils.parse_cookies_into(data.cookie_str, _cookie_names, _cookie_pairs, MAX_COOKIES)
            if ck_trunc then
                ngx_log(ngx_WARN, "ja4: cookies truncated to ", MAX_COOKIES)
            end
```

In the **hash-mode** cookie branch, pass the cap to the two writers (~lines 217, 225):

```lua
                local nlen = write_str_csv_at(_cookie_names, cn, hash_buf, 0)
```
→ `write_str_csv_at(_cookie_names, cn, hash_buf, 0, BUF_SIZE)`

```lua
                local plen = write_str_csv_at(_cookie_pairs, cn, hash_buf, 0)
```
→ `write_str_csv_at(_cookie_pairs, cn, hash_buf, 0, BUF_SIZE)`

In the **raw-mode** cookie branch, pass the cap (~lines 253, 258):

```lua
                pos = write_str_csv_at(_cookie_names, cn, out_buf, pos)
```
→ `pos = write_str_csv_at(_cookie_names, cn, out_buf, pos, BUF_SIZE)`

```lua
                pos = write_str_csv_at(_cookie_pairs, cn, out_buf, pos)
```
→ `pos = write_str_csv_at(_cookie_pairs, cn, out_buf, pos, BUF_SIZE)`

(Only one of the two cookie branches runs per call — hash or raw — so the warn fires at most once per request. Editing both keeps the two modes consistent.)

- [ ] **Step 6: Run tests to verify they pass**

Run:
```bash
make test-build
docker run --rm --init lua-resty-ja4-test prove -v t/003-ja4h-algo.t
```
Expected: all blocks PASS. Adjust the `plan tests =>` multiplier if `prove` reports a mismatch.

- [ ] **Step 7: Commit**

```bash
git add lib/resty/ja4h.lua t/003-ja4h-algo.t
git commit -m "fix(ja4h): clamp header/cookie counts to caps; resize buffers"
```

---

## Task 4: Migrate JA4 live path to official `ngx.ssl.clienthello` getters + bump test images

**Files:**
- Modify: `lib/resty/ja4.lua`
- Modify: `Dockerfile.test`
- Modify: `e2e/docker-compose.e2e.yml`

**Interfaces:**
- Consumes: `ssl_clt.get_client_hello_ciphers()` (returns GREASE-filtered, ≤128 cipher array, or `nil[, err]`) and `ssl_clt.get_client_hello_ext_present()` (returns GREASE-filtered extension-type array incl. SNI/ALPN, or `nil[, err]`).
- Produces: a `compute()` with no raw OpenSSL cipher/extension FFI and no manual `CRYPTO_free`. `build()` is unchanged.

- [ ] **Step 1: Bump the unit-test image to a getter-capable OpenResty**

In `Dockerfile.test`, change line 1:

```dockerfile
FROM openresty/openresty:1.27.1.1-0-bookworm-fat
```
→
```dockerfile
FROM openresty/openresty:1.29.2.1-0-bookworm-fat
```

- [ ] **Step 2: Verify the getters exist in the new image**

Run:
```bash
make test-build
docker run --rm lua-resty-ja4-test resty -e '
  local ch = require "ngx.ssl.clienthello"
  print("ciphers_getter:", ch.get_client_hello_ciphers ~= nil)
  print("ext_getter:", ch.get_client_hello_ext_present ~= nil)'
```
Expected:
```
ciphers_getter: true
ext_getter: true
```
If either prints `false`, bump the tag to `1.29.2.5-0-bookworm-fat` and re-run.

- [ ] **Step 3: Remove the raw OpenSSL cipher/extension FFI**

In `lib/resty/ja4.lua`, replace the `ffi.cdef` block (lines 34-40) with the legacy-version-only version:

```lua
-- OpenSSL FFI: only the ClientHello legacy_version (no official wrapper exists).
-- Ciphers and extensions now come from ngx.ssl.clienthello (OpenResty >= 1.29.2.1).
pcall(ffi.cdef, [[
    unsigned int SSL_client_hello_get0_legacy_version(void *ssl);
]])
```

Delete the now-unused module-level pointers (lines 42-45):

```lua
-- Module-level FFI buffers (reused per-call, no allocation)
local ciphers_out_ptr = ffi_new("const unsigned char*[1]")
local ext_out_ptr = ffi_new("int*[1]")
local ext_len_ptr = ffi_new("size_t[1]")
```

Delete the entire `get_ciphers_ffi` function (lines 81-97) and the entire `get_extensions_ffi` function (lines 99-116).

- [ ] **Step 4: Add a getter-availability flag**

In `lib/resty/ja4.lua`, just after the `ok_ssl, ngx_ssl = pcall(...)` lines (~line 32), add:

```lua
local _have_getters = ok_clt
    and ssl_clt.get_client_hello_ciphers ~= nil
    and ssl_clt.get_client_hello_ext_present ~= nil
```

- [ ] **Step 5: Use the official getters in `compute()`**

In `lib/resty/ja4.lua` `compute()`, after the existing `if not ok_ssl then ... end` guard (~line 229), add:

```lua
    if not _have_getters then
        return nil, "ja4.compute requires OpenResty >= 1.29.2.1 "
            .. "(ngx.ssl.clienthello cipher/extension getters)"
    end
```

Replace the cipher/extension extraction calls (~lines 264-268):

```lua
    -- Ciphers (GREASE filtered by get_ciphers_ffi)
    local ciphers = get_ciphers_ffi(ssl_ptr)

    -- Extensions (GREASE filtered by get_extensions_ffi)
    local extensions = get_extensions_ffi(ssl_ptr)
```
with:
```lua
    -- Ciphers: official getter (GREASE filtered, capped at 128, no manual free)
    local ciphers = ssl_clt.get_client_hello_ciphers() or {}

    -- Extensions: official getter (GREASE filtered, pool-allocated, no manual free);
    -- includes SNI/ALPN, which build() counts in section A and excludes from the hash.
    local extensions = ssl_clt.get_client_hello_ext_present() or {}
```

- [ ] **Step 6: Bump the default e2e image to 1.31**

This gives the two supported majors coverage: unit tests run on the 1.29.2.1 floor (Step 1), the default e2e on 1.31, and `make e2e-1.29` on the 1.29.2.1 source build.

In `e2e/docker-compose.e2e.yml`, change line 3:

```yaml
    image: openresty/openresty:1.27.1.2-11-jammy
```
→
```yaml
    image: openresty/openresty:1.31.1.1-2-jammy
```

Verify the tag exists and has the getters:
```bash
docker run --rm openresty/openresty:1.31.1.1-2-jammy resty -e '
  local ch = require "ngx.ssl.clienthello"
  print(ch.get_client_hello_ciphers ~= nil and ch.get_client_hello_ext_present ~= nil)'
```
Expected: `true`. If the tag is not found on the registry, list available tags with
`docker run --rm quay.io/skopeo/stable list-tags docker://openresty/openresty | grep '1.31.1.1.*jammy'`
and use the newest `1.31.1.1-N-jammy`.

- [ ] **Step 7: Run the full unit suite + both e2e suites**

Run:
```bash
make test       # unit tests on the 1.29.2.1 floor image
make e2e        # default e2e on 1.31
make e2e-1.29   # e2e on the 1.29.2.1 source build
```
Expected: `make test` — all `t/` pass. Both e2e runs — all existing scapy/JA4/JA4H vectors pass (fingerprints unchanged after the migration). The bench/microbench paths are unaffected (they call `build()` directly).

- [ ] **Step 8: Commit**

```bash
git add lib/resty/ja4.lua Dockerfile.test e2e/docker-compose.e2e.yml
git commit -m "refactor(ja4): use official ngx.ssl.clienthello getters; floor 1.29.2.1"
```

---

## Task 5: e2e robustness test for oversized ClientHello

**Files:**
- Modify: `e2e/test_ja4_scapy.py`

**Interfaces:**
- Consumes: `connect_and_get_ja4(host, port, ciphers, ext_types, alpn, sig_algs)` (existing) and `NGINX_HOST`, `HASH_PORT` (existing module globals).
- Produces: a regression test proving the worker survives a >128-cipher handshake and still serves traffic.

- [ ] **Step 1: Write the failing test**

Append to `e2e/test_ja4_scapy.py`:

```python
def test_ja4_oversized_clienthello_no_crash():
    """A ClientHello with >128 ciphers must not crash the worker.
    The platform getter caps ciphers at 128; we assert a valid JA4 hash
    comes back and (via a second request) that the worker is still alive."""
    many_ciphers = list(range(0x0001, 0x0001 + 300))  # 300 cipher IDs
    ja4 = connect_and_get_ja4(
        NGINX_HOST, HASH_PORT, many_ciphers, [0x002b, 0x000a], "h2", [0x0403]
    )
    # hash-mode JA4 is exactly 36 chars; section A cipher count caps at "99"
    assert ja4 is not None and len(ja4) == 36
    assert ja4[4:6] == "99"

    # Worker still alive: a normal handshake afterwards still returns a JA4.
    ja4_after = connect_and_get_ja4(
        NGINX_HOST, HASH_PORT, [0x1301, 0x1302, 0x1303], [0x002b, 0x000a], "h2", [0x0403]
    )
    assert ja4_after is not None and len(ja4_after) == 36
```

- [ ] **Step 2: Run it against the (pre-fix) baseline to confirm it catches the bug**

This step is informational — on a hardened build it should pass; the value is the regression guard. Run:
```bash
make e2e-1.29
```
Expected: `test_ja4_oversized_clienthello_no_crash` PASSES on the hardened build (Tasks 2 & 4 applied). If run against an unhardened `ja4.lua`, the oversized handshake would abort the worker and the test would error on connection.

- [ ] **Step 3: Commit**

```bash
git add e2e/test_ja4_scapy.py
git commit -m "test(e2e): oversized ClientHello does not crash the worker"
```

---

## Task 6: Documentation + version floor

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: nothing.
- Produces: accurate requirements/support documentation.

- [ ] **Step 1: Update the Requirements section**

In `README.md`, replace the requirements bullets:

```markdown
- For live JA4 `compute()`: OpenResty with `ngx.ssl.get_req_ssl_pointer()` available (tested on OpenResty 1.27+)

Tested in this repo against:
- OpenResty 1.27.1.2
- OpenResty 1.29.2.1
```
with:
```markdown
- For live JA4 `compute()`: **OpenResty >= 1.29.2.1**, which bundles
  lua-resty-core >= 0.1.32 (provides `ngx.ssl.clienthello.get_client_hello_ciphers()`
  and `get_client_hello_ext_present()`). Earlier versions (e.g. 1.27) lack these
  getters and are not supported.

Tested in this repo against:
- OpenResty 1.29.2.x
- OpenResty 1.31.1.1
```

- [ ] **Step 2: Document the input caps**

In `README.md`, under the Features list, add a bullet:

```markdown
- Hardened against pathological inputs: cipher/extension/sig-alg lists are
  capped at 128, header names at 100, and cookies at 128. Over-cap inputs are
  truncated to a deterministic fingerprint and logged at `warn`; real clients
  are unaffected and remain byte-identical to canonical JA4/JA4H.
```

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: OpenResty 1.29.2.1 floor and input-cap behavior"
```

---

## Final verification

- [ ] Run the complete suite:

```bash
make test       # unit tests on the 1.29.2.1 floor image
make e2e        # e2e on 1.31, incl. the oversized-ClientHello regression test
make e2e-1.29   # e2e on the 1.29.2.1 source build
```
Expected: everything green. `make test` covers `t/001`–`t/007`; both e2e runs cover JA4/JA4H scapy vectors plus the new robustness test on each supported major.

- [ ] Confirm no raw cipher/extension OpenSSL FFI or `CRYPTO_free` remains:

```bash
grep -nE "SSL_client_hello_get0_ciphers|SSL_client_hello_get1_extensions_present|CRYPTO_free|get_ciphers_ffi|get_extensions_ffi" lib/resty/ja4.lua
```
Expected: no output (only `SSL_client_hello_get0_legacy_version` should remain, which this grep does not match).
