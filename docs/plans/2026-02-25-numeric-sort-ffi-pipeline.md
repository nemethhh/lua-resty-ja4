# Numeric-Sort FFI Pipeline Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the string-based sort+write pipeline with a numeric uint16 FFI pipeline to maximize JIT compilation, reduce per-request latency, and cut allocations in ja4h.

**Architecture:** Current hot path converts uint16 cipher/extension values to hex strings, sorts strings (non-JIT string comparison), then copies string bytes to CSV buffer. New pipeline keeps values as uint16 in FFI arrays, sorts numerically (single machine instruction per comparison, fully JIT-inlined), and converts to hex via nibble extraction at write time. For ja4h, pre-allocated module-level tables eliminate per-request cookie/header allocations.

**Tech Stack:** LuaJIT FFI, OpenResty, Test::Nginx (prove), Docker benchmarks

**Key Insight:** LuaJIT string comparison calls `lj_str_cmp` (a C function) which breaks JIT traces. Numeric comparison on FFI uint16_t arrays compiles to a single `cmp` instruction. This targets the 15% CPU spent in `isort` (per jit.p profile).

**Current Baselines (typical profile):**
- ja4.build() hash: 270.6K ops/s
- ja4h.build() hash: 230.0K ops/s
- ja4.build() raw: 681.8K ops/s
- ja4h.build() raw: 999.0K ops/s
- ja4h alloc heavy: 553 bytes/call

---

### Task 1: Add isort_u16 and write_u16_hex_csv to utils.lua

**Files:**
- Modify: `lib/resty/ja4/utils.lua` (after line 176 for isort_u16, after line 238 for write_u16_hex_csv)
- Modify: `t/001-utils.t` (add TEST 34, TEST 35; update plan count from 33 to 35)

**Step 1: Write failing tests in 001-utils.t**

Add after TEST 33 (line 529):

```lua
=== TEST 34: isort_u16 sorts FFI uint16 array (matches hex string sort)
--- http_config eval: $::HttpConfig
--- lua_code
local ffi = require "ffi"
local utils = require "resty.ja4.utils"
-- Same values as TEST 13 string sort: c02b, 002f, 1301, 0035, cca9
local arr = ffi.new("uint16_t[5]", 0xc02b, 0x002f, 0x1301, 0x0035, 0xcca9)
utils.isort_u16(arr, 5)
local result = {}
for i = 0, 4 do result[i+1] = utils.to_hex4(arr[i]) end
ngx.say("sorted: ", table.concat(result, ","))
-- Edge cases
local one = ffi.new("uint16_t[1]", 0x1301)
utils.isort_u16(one, 1)
ngx.say("one: ", utils.to_hex4(one[0]))
utils.isort_u16(one, 0)
ngx.say("empty: ok")
-- Already sorted
local pre = ffi.new("uint16_t[3]", 0x0001, 0x0002, 0x0003)
utils.isort_u16(pre, 3)
ngx.say("pre: ", utils.to_hex4(pre[0]), ",", utils.to_hex4(pre[1]), ",", utils.to_hex4(pre[2]))
--- response_body
sorted: 002f,0035,1301,c02b,cca9
one: 1301
empty: ok
pre: 0001,0002,0003

=== TEST 35: write_u16_hex_csv matches write_hex4_csv output
--- http_config eval: $::HttpConfig
--- lua_code
local ffi = require "ffi"
local utils = require "resty.ja4.utils"
local buf = ffi.new("uint8_t[256]")
-- Compare: new uint16 path vs old hex string path
local arr = ffi.new("uint16_t[5]", 0x002f, 0x0035, 0x009c, 0x1301, 0x1302)
local pos = utils.write_u16_hex_csv(arr, 5, buf, 0)
local new_result = ffi.string(buf, pos)
local hexes = {"002f", "0035", "009c", "1301", "1302"}
local len = utils.write_hex4_csv(hexes, 5)
local old_result = ffi.string(utils.csv_buf, len)
ngx.say("match: ", new_result == old_result and "yes" or "no")
ngx.say("value: ", new_result)
-- Single element
pos = utils.write_u16_hex_csv(ffi.new("uint16_t[1]", 0xcca9), 1, buf, 0)
ngx.say("single: ", ffi.string(buf, pos))
-- Empty
pos = utils.write_u16_hex_csv(arr, 0, buf, 5)
ngx.say("empty_pos: ", pos)
-- At offset
pos = utils.write_u16_hex_csv(ffi.new("uint16_t[2]", 0x000a, 0x000d), 2, buf, 10)
ngx.say("offset: ", ffi.string(buf + 10, pos - 10))
--- response_body
match: yes
value: 002f,0035,009c,1301,1302
single: cca9
empty_pos: 5
offset: 000a,000d
```

Update test plan count at line 5:
```perl
plan tests => repeat_each() * 2 * 35;
```

**Step 2: Run tests to verify they fail**

Run: `make test-verbose`
Expected: TEST 34, TEST 35 fail (isort_u16 and write_u16_hex_csv not defined)

**Step 3: Implement isort_u16 and write_u16_hex_csv in utils.lua**

Add after `isort` (after line 176):

```lua
-- 0-based insertion sort for FFI uint16_t arrays.
-- Pure numeric comparison — fully JIT-inlined (single cmp instruction),
-- unlike isort's string comparison which calls lj_str_cmp (C function, breaks traces).
local function isort_u16(arr, n)
    for i = 1, n - 1 do
        local val = arr[i]
        local j = i - 1
        while j >= 0 and arr[j] > val do
            arr[j + 1] = arr[j]
            j = j - 1
        end
        arr[j + 1] = val
    end
end
_M.isort_u16 = isort_u16
```

Add after `write_hex4_csv_at` (after line 238):

```lua
-- Write uint16 FFI array as comma-separated 4-char hex into buf at offset.
-- Converts each value to hex via nibble extraction from hex_chars[].
-- No HEX4 table lookup, no intermediate strings, no byte() calls.
-- Returns: new offset after last byte written.
local function write_u16_hex_csv(arr, n, buf, offset)
    if n == 0 then return offset end
    local pos = offset
    for i = 0, n - 1 do
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

Note: `hex_chars` (line 66), `rshift`, `band` are already in scope at module level.

**Step 4: Run tests to verify they pass**

Run: `make test-verbose`
Expected: All 35 tests pass (including TEST 34, TEST 35)

**Step 5: Commit**

```bash
git add lib/resty/ja4/utils.lua t/001-utils.t
git commit -m "feat(utils): add isort_u16 and write_u16_hex_csv FFI primitives

Numeric sort on uint16_t[] arrays compiles to single cmp instructions
in JIT traces, unlike string comparison which calls lj_str_cmp (C func).
write_u16_hex_csv converts values to hex via nibble extraction at write
time, eliminating HEX4 table lookups and intermediate string creation."
```

---

### Task 2: Rewrite ja4.lua build() with numeric sort pipeline

**Files:**
- Modify: `lib/resty/ja4.lua` (lines 11-13 imports, lines 23-24 buffers, lines 59-82 helpers, lines 131-203 build)

**Step 1: Verify existing tests pass (baseline)**

Run: `make test-verbose`
Expected: All 35 tests pass. This is our safety net — all 16 tests in 002-ja4-algo.t must still pass after changes.

**Step 2: Update imports and module-level buffers in ja4.lua**

Replace lines 11-24 (imports and buffers):

```lua
-- OLD (remove these lines):
local new_tab = utils.new_tab
local isort = utils.isort
...
local write_hex4_csv = utils.write_hex4_csv
...
local cipher_hexes = new_tab(40, 0)
local ext_hexes = new_tab(30, 0)

-- NEW (replace with):
local new_tab = utils.new_tab          -- still needed for get_ciphers_ffi/get_extensions_ffi
local isort_u16 = utils.isort_u16
local is_grease = utils.is_grease
local LEGACY_VERSION_MAP = utils.LEGACY_VERSION_MAP
local csv_buf = utils.csv_buf
local write_u16_hex_csv = utils.write_u16_hex_csv
local append_hex4_csv = utils.append_hex4_csv   -- still needed for sig_algs (hex strings)
local sha256_to_buf = utils.sha256_to_buf
local EMPTY_HASH = utils.EMPTY_HASH
local NUM2 = utils.NUM2

local cipher_u16 = ffi_new("uint16_t[100]")
local ext_u16 = ffi_new("uint16_t[100]")
```

**Step 3: Replace helper functions**

Remove `fill_cipher_hexes` (lines 61-67) and `filter_extensions` (lines 72-82). Replace with:

```lua
-- Copy cipher uint16 values from Lua table to FFI array.
-- Separate function gives JIT a clean trace boundary.
local function copy_ciphers(ciphers, arr)
    local n = #ciphers
    for i = 1, n do
        arr[i - 1] = ciphers[i]
    end
    return n
end

-- Copy extension uint16 values to FFI array, excluding SNI (0x0000) and ALPN (0x0010).
-- Separate function eliminates JIT abort ("leaving loop in root trace").
local function filter_extensions_u16(extensions, arr)
    local n = 0
    for i = 1, #extensions do
        local ext = extensions[i]
        if ext ~= 0x0000 and ext ~= 0x0010 then
            arr[n] = ext
            n = n + 1
        end
    end
    return n
end
```

**Step 4: Rewrite build() function**

Replace the sorting and writing sections of `build()` (lines 131-203):

```lua
function _M.build(data)
    if not data then
        return nil, "no data"
    end

    local cipher_count = math_min(#data.ciphers, 99)
    local ext_count = math_min(#data.extensions, 99)

    -- Section A: 10 bytes directly into out_buf via byte writes + NUM2 lookup
    out_buf[0] = byte(data.protocol)
    local ver = data.version
    out_buf[1] = byte(ver, 1); out_buf[2] = byte(ver, 2)
    out_buf[3] = byte(data.sni)
    local cc = NUM2[cipher_count]
    out_buf[4] = byte(cc, 1); out_buf[5] = byte(cc, 2)
    local ec = NUM2[ext_count]
    out_buf[6] = byte(ec, 1); out_buf[7] = byte(ec, 2)
    local alp = data.alpn
    out_buf[8] = byte(alp, 1); out_buf[9] = byte(alp, 2)

    out_buf[10] = 0x5F  -- '_'
    local pos = 11

    -- Copy to FFI arrays and sort numerically (fully JIT-inlined)
    local cn = copy_ciphers(data.ciphers, cipher_u16)
    isort_u16(cipher_u16, cn)

    local ext_n = filter_extensions_u16(data.extensions, ext_u16)
    isort_u16(ext_u16, ext_n)

    if _hash_mode then
        -- Section B: sorted ciphers -> csv_buf -> SHA256 -> 12 hex bytes to out_buf
        if cn == 0 then
            ffi_copy(out_buf + pos, EMPTY_HASH, 12)
        else
            local csv_len = write_u16_hex_csv(cipher_u16, cn, csv_buf, 0)
            sha256_to_buf(csv_buf, csv_len, out_buf, pos)
        end
        pos = pos + 12  -- 23

        out_buf[pos] = 0x5F; pos = pos + 1  -- 24

        -- Section C: sorted exts + sig_algs -> csv_buf -> SHA256 -> 12 hex bytes
        local sc_len = write_u16_hex_csv(ext_u16, ext_n, csv_buf, 0)
        if data.sig_algs and #data.sig_algs > 0 then
            csv_buf[sc_len] = 0x5F  -- '_'
            sc_len = append_hex4_csv(data.sig_algs, #data.sig_algs, sc_len + 1)
        end
        if ext_n == 0 and (not data.sig_algs or #data.sig_algs == 0) then
            ffi_copy(out_buf + pos, EMPTY_HASH, 12)
        else
            sha256_to_buf(csv_buf, sc_len, out_buf, pos)
        end
        pos = pos + 12  -- 36
    else
        -- Section B raw: hex CSV directly into out_buf
        pos = write_u16_hex_csv(cipher_u16, cn, out_buf, pos)

        out_buf[pos] = 0x5F; pos = pos + 1

        -- Section C raw: exts CSV + '_' + sig_algs CSV
        pos = write_u16_hex_csv(ext_u16, ext_n, out_buf, pos)
        if data.sig_algs and #data.sig_algs > 0 then
            out_buf[pos] = 0x5F; pos = pos + 1
            pos = utils.write_hex4_csv_at(data.sig_algs, #data.sig_algs, out_buf, pos)
        end
    end

    return ffi_string(out_buf, pos)
end
```

**Step 5: Run all tests to verify no regression**

Run: `make test-verbose`
Expected: All 35 tests pass. Critical: all 16 tests in 002-ja4-algo.t produce identical output.

Key verification points:
- TEST 1 (002-ja4-algo.t): `t13d1516h1_8daaf6152771_e5627efa2ab1` (Chrome vector, hash mode)
- TEST 5 (002-ja4-algo.t): Raw output with sorted ciphers/extensions (raw mode)
- TEST 8 (002-ja4-algo.t): 105 ciphers, count capped at 99
- TEST 11 (002-ja4-algo.t): Extensions all filtered (SNI+ALPN only), sig_algs present

**Step 6: Commit**

```bash
git add lib/resty/ja4.lua
git commit -m "perf(ja4): numeric sort pipeline with FFI uint16_t arrays

Replace string-based sort+write pipeline with numeric uint16 FFI arrays.
Ciphers and extensions are now sorted as numbers (single cmp instruction
in JIT traces) instead of hex strings (lj_str_cmp C call). Hex conversion
happens at write time via nibble extraction, eliminating HEX4 table lookups
and intermediate string creation from the hot path.

No API or output changes. All existing tests pass identically."
```

---

### Task 3: Add parse_cookies_into and parse_raw_header_names_into to utils.lua

**Files:**
- Modify: `lib/resty/ja4/utils.lua` (after parse_cookies ~line 382, after parse_raw_header_names ~line 432)
- Modify: `t/001-utils.t` (add TEST 36, TEST 37; update plan count from 35 to 37)

**Step 1: Write failing tests**

Add after TEST 35 in 001-utils.t:

```lua
=== TEST 36: parse_cookies_into fills pre-allocated tables
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
-- Pre-allocate tables
local names = {}
local pairs_list = {}
-- First call
local n = utils.parse_cookies_into("session=abc123; user=john; theme=dark", names, pairs_list)
ngx.say("count: ", n)
table.sort(names)
table.sort(pairs_list)
ngx.say("names: ", table.concat(names, ","))
ngx.say("pairs: ", table.concat(pairs_list, ","))
-- Second call with fewer cookies (verifies stale entry cleanup)
n = utils.parse_cookies_into("a=1", names, pairs_list)
ngx.say("count2: ", n)
ngx.say("len: ", #names)
ngx.say("name2: ", names[1])
-- nil/empty input
n = utils.parse_cookies_into(nil, names, pairs_list)
ngx.say("nil: ", n)
n = utils.parse_cookies_into("", names, pairs_list)
ngx.say("empty: ", n)
--- response_body
count: 3
names: session,theme,user
pairs: session=abc123,theme=dark,user=john
count2: 1
len: 1
name2: a
nil: 0
empty: 0

=== TEST 37: parse_raw_header_names_into fills pre-allocated table
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
local names = {}
local raw = "Host: example.com\r\nCookie: a=1\r\nUser-Agent: Mozilla\r\nReferer: http://x.com\r\nAccept: */*\r\n\r\n"
local n = utils.parse_raw_header_names_into(raw, names)
ngx.say("count: ", n)
ngx.say("names: ", table.concat(names, ",", 1, n))
-- Second call with fewer headers (stale cleanup)
n = utils.parse_raw_header_names_into("Host: x\r\n\r\n", names)
ngx.say("count2: ", n)
ngx.say("len: ", #names)
-- nil/empty
n = utils.parse_raw_header_names_into(nil, names)
ngx.say("nil: ", n)
--- response_body
count: 3
names: Host,User-Agent,Accept
count2: 1
len: 1
nil: 0
```

Update test plan count:
```perl
plan tests => repeat_each() * 2 * 37;
```

**Step 2: Run tests to verify they fail**

Run: `make test-verbose`
Expected: TEST 36, TEST 37 fail

**Step 3: Implement parse_cookies_into and parse_raw_header_names_into**

Add after `parse_cookies` (after line 382 in utils.lua):

```lua
-- Like parse_cookies but fills pre-allocated tables instead of allocating new ones.
-- Nils out stale entries from previous calls. Returns count.
function _M.parse_cookies_into(cookie_str, names, pairs_list)
    if not cookie_str or cookie_str == "" then
        -- Clear any stale entries
        for i = 1, #names do names[i] = nil end
        for i = 1, #pairs_list do pairs_list[i] = nil end
        return 0
    end

    local n = 0
    local len = #cookie_str
    local pos = 1

    while pos <= len do
        while pos <= len and byte(cookie_str, pos) == 0x20 do
            pos = pos + 1
        end
        if pos > len then break end

        local semi = str_find(cookie_str, "; ", pos, true)
        local seg_end = semi and (semi - 1) or len

        while seg_end >= pos and byte(cookie_str, seg_end) == 0x20 do
            seg_end = seg_end - 1
        end

        if seg_end >= pos then
            local eq = str_find(cookie_str, "=", pos, true)
            if eq and eq <= seg_end then
                local name_end = eq - 1
                while name_end >= pos and byte(cookie_str, name_end) == 0x20 do
                    name_end = name_end - 1
                end
                if name_end >= pos then
                    n = n + 1
                    names[n] = str_sub(cookie_str, pos, name_end)
                    pairs_list[n] = str_sub(cookie_str, pos, seg_end)
                end
            end
        end

        pos = semi and (semi + 2) or (len + 1)
    end

    -- Clear stale entries from previous calls
    local old_len = #names
    for i = n + 1, old_len do names[i] = nil end
    old_len = #pairs_list
    for i = n + 1, old_len do pairs_list[i] = nil end

    return n
end
```

Add after `parse_raw_header_names` (after line 432 in utils.lua):

```lua
-- Like parse_raw_header_names but fills pre-allocated table instead of allocating.
-- Nils out stale entries from previous calls. Returns count.
function _M.parse_raw_header_names_into(raw, names)
    if not raw or raw == "" then
        for i = 1, #names do names[i] = nil end
        return 0
    end

    local n = 0
    local pos = 1
    local len = #raw

    while pos <= len do
        local cr = str_find(raw, "\r\n", pos, true)
        if not cr or cr == pos then
            break
        end

        local colon = str_find(raw, ":", pos, true)
        if colon and colon < cr then
            local name_len = colon - pos
            local skip = false
            if name_len == 6 then
                local b = byte(raw, pos)
                if b == 0x43 or b == 0x63 then
                    skip = (str_lower(str_sub(raw, pos, colon - 1)) == "cookie")
                end
            elseif name_len == 7 then
                local b = byte(raw, pos)
                if b == 0x52 or b == 0x72 then
                    skip = (str_lower(str_sub(raw, pos, colon - 1)) == "referer")
                end
            end
            if not skip then
                n = n + 1
                names[n] = str_sub(raw, pos, colon - 1)
            end
        end

        pos = cr + 2
    end

    -- Clear stale entries
    local old_len = #names
    for i = n + 1, old_len do names[i] = nil end

    return n
end
```

**Step 4: Run tests to verify they pass**

Run: `make test-verbose`
Expected: All 37 tests pass

**Step 5: Commit**

```bash
git add lib/resty/ja4/utils.lua t/001-utils.t
git commit -m "feat(utils): add parse_cookies_into and parse_raw_header_names_into

Pre-allocated table variants that fill caller-owned tables instead of
allocating new ones each call. Stale entries from previous calls are
niled out. Reduces ja4h per-request allocation from ~553 to ~50 bytes
for heavy cookie profiles."
```

---

### Task 4: Rewrite ja4h.lua build() with pre-allocated tables

**Files:**
- Modify: `lib/resty/ja4h.lua` (add module-level tables, update build() cookie section, update compute())

**Step 1: Verify existing tests pass (baseline)**

Run: `make test-verbose`
Expected: All 37 tests pass. Safety net: all 18 tests in 003-ja4h-algo.t and 10 in 004-ja4h-compute.t.

**Step 2: Add module-level pre-allocated tables**

After line 19 (`local ngx = ngx`) in ja4h.lua, add:

```lua
local _cookie_names = new_tab(100, 0)
local _cookie_pairs = new_tab(100, 0)
```

**Step 3: Update build() hash mode cookie section**

Replace the cookie parsing in hash mode (lines 97-126):

```lua
        -- Sections C/D: cookie names and pairs
        if data.cookie_str and data.cookie_str ~= "" then
            local cn = utils.parse_cookies_into(data.cookie_str, _cookie_names, _cookie_pairs)
            if cn > 0 then
                -- Section C: sorted cookie names -> hash
                isort(_cookie_names, cn)
                local nlen = write_str_csv_at(_cookie_names, cn, hash_buf, 0)
                sha256_to_buf(hash_buf, nlen, out_buf, pos)
                pos = pos + 12

                out_buf[pos] = 0x5F; pos = pos + 1

                -- Section D: sorted cookie pairs -> hash
                isort(_cookie_pairs, cn)
                local plen = write_str_csv_at(_cookie_pairs, cn, hash_buf, 0)
                sha256_to_buf(hash_buf, plen, out_buf, pos)
                pos = pos + 12
            else
                ffi_copy(out_buf + pos, EMPTY_HASH, 12)
                pos = pos + 12
                out_buf[pos] = 0x5F; pos = pos + 1
                ffi_copy(out_buf + pos, EMPTY_HASH, 12)
                pos = pos + 12
            end
        else
            ffi_copy(out_buf + pos, EMPTY_HASH, 12)
            pos = pos + 12
            out_buf[pos] = 0x5F; pos = pos + 1
            ffi_copy(out_buf + pos, EMPTY_HASH, 12)
            pos = pos + 12
        end
```

**Step 4: Update build() raw mode cookie section**

Replace the cookie parsing in raw mode (lines 134-151):

```lua
        -- Sections C/D raw: sorted cookie names, sorted cookie pairs
        if data.cookie_str and data.cookie_str ~= "" then
            local cn = utils.parse_cookies_into(data.cookie_str, _cookie_names, _cookie_pairs)
            if cn > 0 then
                isort(_cookie_names, cn)
                pos = write_str_csv_at(_cookie_names, cn, out_buf, pos)

                out_buf[pos] = 0x5F; pos = pos + 1

                isort(_cookie_pairs, cn)
                pos = write_str_csv_at(_cookie_pairs, cn, out_buf, pos)
            else
                -- Empty section C, separator, empty section D
                out_buf[pos] = 0x5F; pos = pos + 1
            end
        else
            -- Empty section C, separator, empty section D
            out_buf[pos] = 0x5F; pos = pos + 1
        end
```

**Step 5: Run all tests to verify no regression**

Run: `make test-verbose`
Expected: All 37 tests pass. Critical: all 18 tests in 003-ja4h-algo.t and 10 in 004-ja4h-compute.t produce identical output.

Key verification points:
- TEST 1 (003-ja4h-algo.t): `he11nn05enus_6f8992deff94_000000000000_000000000000`
- TEST 3 (003-ja4h-algo.t): Hash with cookies+referer
- TEST 6 (003-ja4h-algo.t): Raw mode output
- TEST 10 (003-ja4h-algo.t): Cookie sorting order

**Step 6: Commit**

```bash
git add lib/resty/ja4h.lua
git commit -m "perf(ja4h): pre-allocated cookie tables eliminate per-request allocation

Module-level _cookie_names and _cookie_pairs tables (100 slots each)
are reused across calls via parse_cookies_into(). Stale entries cleared
automatically. Overflow beyond 100 cookies handled by automatic Lua
table growth. Reduces heavy-profile allocation from ~553 to ~50 bytes/call."
```

---

### Task 5: Benchmark comparison and final verification

**Files:**
- None modified (benchmarks exercise build() which already uses new code)

**Step 1: Rebuild benchmark Docker image**

Run: `make bench-build`
Expected: Image builds successfully with updated lib/ code

**Step 2: Run full benchmark suite**

Run: `make jit-all`
Expected: Output for all four analyses (bench, alloc, trace, profile)

**Step 3: Compare results against baselines**

| Metric | Baseline | Target | Notes |
|--------|----------|--------|-------|
| ja4.build() hash typical | 270.6K | > 300K | SHA256 floor limits gains |
| ja4.build() raw typical | 681.8K | > 1.0M | Full benefit, no SHA256 |
| ja4h.build() hash typical | 230.0K | > 250K | Cookie alloc savings |
| ja4h.build() raw typical | 999.0K | > 1.2M | Cookie alloc savings |
| ja4h alloc heavy | 553 B/call | < 100 B | Pre-allocated tables |
| JIT trace aborts | 2 | <= 2 | Should not increase |

**Step 4: Run e2e tests**

Run: `make e2e`
Expected: All 25 e2e tests pass on both OpenResty 1.27 and 1.29

**Step 5: Save benchmark report**

Run: `make jit-report`
Results saved to: `bench/reports/bench.txt`, `bench/reports/alloc.txt`, `bench/reports/trace.txt`, `bench/reports/profile.txt`

**Step 6: Final commit with benchmark results**

```bash
git add bench/reports/
git commit -m "bench: capture post-optimization benchmark results

Numeric sort FFI pipeline: ja4.build() raw XK->YK, hash XK->YK
Pre-allocated tables: ja4h alloc heavy 553->Z bytes/call"
```

---

## Summary of Changes

| File | Lines Changed | What Changes |
|------|---------------|-------------|
| `lib/resty/ja4/utils.lua` | +~80 lines | isort_u16, write_u16_hex_csv, parse_cookies_into, parse_raw_header_names_into |
| `lib/resty/ja4.lua` | ~40 lines rewritten | Imports, FFI arrays, helper functions, build() pipeline |
| `lib/resty/ja4h.lua` | ~30 lines rewritten | Module-level tables, build() cookie sections |
| `t/001-utils.t` | +~70 lines | 4 new tests (TEST 34-37), plan count 33→37 |

## What Does NOT Change

- Public API: build() input/output format identical
- Output fingerprints: numeric sort = hex lexicographic sort for uint16
- Existing functions: isort, write_hex4_csv, parse_cookies, parse_raw_header_names all remain (used by tests and external callers)
- HEX4 table: still loaded, used by parse_sig_algs, parse_alpn, to_hex4
- SHA256 pipeline: same EVP_Digest calls
- E2E behavior: identical fingerprints
