# lib/ Code Cleanup Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Remove dead code, consolidate duplicates, and restructure utils.lua into logical sections.

**Architecture:** Bottom-up cleanup — first make dead functions truly unreferenced (rewrite dependent tests), then delete dead code, restructure utils.lua, update consumers (ja4.lua, ja4h.lua, benchmarks).

**Tech Stack:** Lua (LuaJIT FFI), Test::Nginx::Socket::Lua (Perl), Docker

---

### Task 1: Rewrite tests that reference soon-to-be-deleted functions

**Files:**
- Modify: `t/001-utils.t` (tests 18, 34, 35)
- Modify: `t/002-ja4-algo.t` (tests 10, 11)

These 5 tests use deleted functions only to compute expected values. Rewrite them to be self-contained.

**Step 1: Rewrite TEST 18 in `t/001-utils.t`**

TEST 18 ("sha256_to_buf writes same result as sha256_hex12") uses `write_hex4_csv` and `sha256_hex12_buf` to create expected values. Rewrite to use `write_u16_hex_csv` and hardcoded expected hash:

```lua
=== TEST 18: sha256_to_buf produces correct hash
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
local ffi = require "ffi"
-- Build cipher CSV via write_u16_hex_csv
local arr = ffi.new("uint16_t[15]", 0x002f,0x0035,0x009c,0x009d,0x1301,0x1302,0x1303,0xc013,0xc014,0xc02b,0xc02c,0xc02f,0xc030,0xcca8,0xcca9)
local buf = ffi.new("uint8_t[256]")
local len = utils.write_u16_hex_csv(arr, 15, buf, 0)
-- Hash via sha256_to_buf
local target = ffi.new("uint8_t[64]")
utils.sha256_to_buf(buf, len, target, 5)
local result = ffi.string(target + 5, 12)
ngx.say("result: ", result)
-- Known SHA256 of "002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"
ngx.say("expected: 8daaf6152771")
ngx.say("match: ", result == "8daaf6152771")
-- Empty input
utils.sha256_to_buf(buf, 0, target, 0)
local empty = ffi.string(target, 12)
ngx.say("empty: ", empty)
--- response_body
result: 8daaf6152771
expected: 8daaf6152771
match: true
empty: e3b0c44298fc
```

**Step 2: Rewrite TEST 34 in `t/001-utils.t`**

TEST 34 ("isort_u16 sorts FFI uint16 array") uses `to_hex4()` to format output. Replace with `string.format`:

```lua
=== TEST 34: isort_u16 sorts FFI uint16 array
--- http_config eval: $::HttpConfig
--- lua_code
local ffi = require "ffi"
local utils = require "resty.ja4.utils"
local fmt = string.format
-- Same values as TEST 13 string sort: c02b, 002f, 1301, 0035, cca9
local arr = ffi.new("uint16_t[5]", 0xc02b, 0x002f, 0x1301, 0x0035, 0xcca9)
utils.isort_u16(arr, 5)
local result = {}
for i = 0, 4 do result[i+1] = fmt("%04x", arr[i]) end
ngx.say("sorted: ", table.concat(result, ","))
-- Edge cases
local one = ffi.new("uint16_t[1]", 0x1301)
utils.isort_u16(one, 1)
ngx.say("one: ", fmt("%04x", one[0]))
utils.isort_u16(one, 0)
ngx.say("empty: ok")
-- Already sorted
local pre = ffi.new("uint16_t[3]", 0x0001, 0x0002, 0x0003)
utils.isort_u16(pre, 3)
ngx.say("pre: ", fmt("%04x", pre[0]), ",", fmt("%04x", pre[1]), ",", fmt("%04x", pre[2]))
--- response_body
sorted: 002f,0035,1301,c02b,cca9
one: 1301
empty: ok
pre: 0001,0002,0003
```

**Step 3: Rewrite TEST 35 in `t/001-utils.t`**

TEST 35 ("write_u16_hex_csv matches write_hex4_csv output") uses `write_hex4_csv` as reference. Rewrite to use hardcoded expected strings:

```lua
=== TEST 35: write_u16_hex_csv writes correct hex CSV
--- http_config eval: $::HttpConfig
--- lua_code
local ffi = require "ffi"
local utils = require "resty.ja4.utils"
local buf = ffi.new("uint8_t[256]")
-- 5 elements
local arr = ffi.new("uint16_t[5]", 0x002f, 0x0035, 0x009c, 0x1301, 0x1302)
local pos = utils.write_u16_hex_csv(arr, 5, buf, 0)
ngx.say("value: ", ffi.string(buf, pos))
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
value: 002f,0035,009c,1301,1302
single: cca9
empty_pos: 5
offset: 000a,000d
```

**Step 4: Rewrite TEST 10 and TEST 11 in `t/002-ja4-algo.t`**

Replace `utils.sha256_hex12(...)` calls with hardcoded expected hashes:

In TEST 10 (~line 208), replace:
```lua
local expected_c = utils.sha256_hex12("000a,000d")
```
with:
```lua
-- SHA256("000a,000d") truncated to 12 hex chars
local expected_c = "1b6e0e2c7e28"
```

In TEST 11 (~line 231), replace:
```lua
local expected_c = utils.sha256_hex12("_0403")
```
with:
```lua
-- SHA256("_0403") truncated to 12 hex chars
local expected_c = "e7e1c7b0b28d"
```

Also remove the `local utils = require "resty.ja4.utils"` line from these two test blocks if it's only used for the sha256_hex12 call.

**Important:** Before hardcoding, verify the expected hashes by running the current tests first to confirm they pass, then read the actual values from the test output.

**Step 5: Run tests to verify rewrites are correct**

Run: `make test`
Expected: All 37 tests pass (same as before)

**Step 6: Commit**

```
refactor(test): rewrite tests to not depend on soon-to-be-deleted utils
```

---

### Task 2: Delete dead test blocks from `t/001-utils.t`

**Files:**
- Modify: `t/001-utils.t`

**Step 1: Delete these test blocks**

Delete the following 14 test blocks entirely (header + all content):
- TEST 2: sha256_hex12 with empty string
- TEST 3: sha256_hex12 with JA4 cipher test vector
- TEST 4: sha256_hex12 with extension+sigalg test vector
- TEST 5: to_hex4 formats values
- TEST 9: parse_cookies with standard cookie header
- TEST 10: parse_cookies with nil
- TEST 14: write_hex4_csv builds comma-separated hex into buffer
- TEST 15: sha256_hex12_buf produces same hash as sha256_hex12
- TEST 16: hex_pair produces correct hex byte-pairs
- TEST 24: parse_cookies with trailing semicolon
- TEST 25: parse_cookies with missing value
- TEST 26: parse_cookies with leading/trailing spaces
- TEST 27: parse_cookies with single cookie
- TEST 37: parse_raw_header_names_into fills pre-allocated table

**Step 2: Renumber all remaining tests sequentially (TEST 1 through TEST 23)**

Remaining tests in order:
1. utils module loads (was 1)
2. tls_version_code maps versions (was 6)
3. parse_alpn extracts first+last char (was 7)
4. parse_sig_algs extracts algorithms in order (was 8)
5. parse_raw_header_names preserves ORIGINAL CASE (was 11)
6. parse_accept_language (was 12)
7. isort sorts small arrays (was 13)
8. NUM2 produces zero-padded decimal strings (was 17)
9. sha256_to_buf produces correct hash (was 18, rewritten in Task 1)
10. write_hex4_csv_at writes CSV into arbitrary buffer (was 19)
11. write_str_csv_at writes variable-length strings (was 20)
12. parse_alpn with single-byte alphanumeric protocol (was 21)
13. parse_alpn with non-alphanumeric bytes (was 22)
14. parse_alpn with empty/short input (was 23)
15. parse_raw_header_names with header containing multiple colons (was 28)
16. parse_raw_header_names with only excluded headers (was 29)
17. parse_raw_header_names with nil and empty input (was 30)
18. parse_accept_language with quality value on first tag (was 31)
19. parse_accept_language with single char (was 32)
20. parse_accept_language with 3-char code (was 33)
21. isort_u16 sorts FFI uint16 array (was 34, rewritten in Task 1)
22. write_u16_hex_csv writes correct hex CSV (was 35, rewritten in Task 1)
23. parse_cookies_into fills pre-allocated tables (was 36)

**Step 3: Update test plan count**

Change line 5 from:
```perl
plan tests => repeat_each() * 2 * 37;
```
to:
```perl
plan tests => repeat_each() * 2 * 23;
```

**Step 4: Run tests**

Run: `make test`
Expected: All 23 tests in 001-utils.t pass. All other test files unchanged.

**Step 5: Commit**

```
refactor(test): remove tests for deleted utils functions
```

---

### Task 3: Restructure `lib/resty/ja4/utils.lua`

**Files:**
- Rewrite: `lib/resty/ja4/utils.lua`

This is the core change. Rewrite utils.lua with:
- 6 dead functions removed
- `append_hex4_csv` removed (consolidated into `write_hex4_csv_at`)
- `hex_pair` no longer exported
- `to_hex4` no longer exported
- Functions organized into logical sections

**Step 1: Write the restructured utils.lua**

The new file should contain exactly these sections in order:

```
-- Section 1: FFI imports & constants
local ffi, ffi_new, ffi_string, ffi_copy, ffi_cast, bit, band, rshift, byte, char
local str_lower, str_sub, str_find
local new_tab (with pcall fallback)
local EMPTY_TAB = {}

local _M = { _VERSION = "0.1.0" }
_M.new_tab = new_tab
_M.EMPTY_HASH = "000000000000"

-- LE assertion

-- Section 2: Lookup tables
-- HEX4 (internal, not exported)
-- hex_pair (internal, not exported)
-- hex_chars (internal, used by write_u16_hex_csv)
-- NUM2 (exported)
-- LEGACY_VERSION_MAP (exported)
-- TLS_VERSION_MAP (internal, used by tls_version_code)

-- Section 3: SHA256
-- EVP cdef
-- md_buf, md_len, sha256_md, evp_digest locals
-- sha256_to_buf (exported) — the ONLY SHA function

-- Section 4: Sorting
-- isort (exported) — string, 1-based
-- isort_u16 (exported) — uint16, 0-based

-- Section 5: CSV serialization
-- csv_buf (exported)
-- write_u16_hex_csv (exported)
-- write_hex4_csv_at (exported)
-- write_str_csv_at (exported)

-- Section 6: GREASE detection
-- is_grease (exported)

-- Section 7: TLS parsing
-- tls_version_code (exported)
-- is_alnum (internal)
-- parse_alpn (exported)
-- parse_sig_algs (exported)

-- Section 8: HTTP parsing
-- parse_accept_language (exported)
-- parse_cookies_into (exported)
-- parse_raw_header_names (exported)

return _M
```

**Key rules:**
- Every function and lookup table must be preserved exactly as-is (byte-identical logic)
- Only the ORDER changes, plus deletions
- `_M.hex_pair = hex_pair` line is removed
- `_M.to_hex4 = to_hex4` and the `to_hex4` function are removed
- `_M.sha256_hex12`, `_M.sha256_hex12_buf` functions are removed
- `_M.write_hex4_csv` and the `write_hex4_csv` function are removed
- `_M.append_hex4_csv` and the `append_hex4_csv` function are removed
- `_M.parse_cookies` function is removed
- `_M.parse_raw_header_names_into` function is removed

**Step 2: Run tests**

Run: `make test`
Expected: All tests pass (001-utils.t should have 23 passing tests)

**Step 3: Commit**

```
refactor(utils): restructure into logical sections and remove dead code
```

---

### Task 4: Update `lib/resty/ja4.lua`

**Files:**
- Modify: `lib/resty/ja4.lua`

**Step 1: Replace `append_hex4_csv` with `write_hex4_csv_at`**

In the imports at top (~line 18), change:
```lua
local append_hex4_csv = utils.append_hex4_csv
```
to:
```lua
local write_hex4_csv_at = utils.write_hex4_csv_at
```

In the build function (~line 176), change:
```lua
sc_len = append_hex4_csv(data.sig_algs, #data.sig_algs, sc_len + 1)
```
to:
```lua
sc_len = write_hex4_csv_at(data.sig_algs, #data.sig_algs, csv_buf, sc_len + 1)
```

**Step 2: Use shared `_VERSION`**

Change:
```lua
local _M = {
    _VERSION = "0.1.0"
}
```
to:
```lua
local _M = {
    _VERSION = utils._VERSION
}
```

**Step 3: Remove stale import**

The line `local write_hex4_csv_at = utils.write_hex4_csv_at` should already exist from Step 1, but also remove the raw-mode call at line 194 that already uses `utils.write_hex4_csv_at` — ensure both usages use the local alias.

**Step 4: Run tests**

Run: `make test`
Expected: All tests pass

**Step 5: Commit**

```
refactor(ja4): consolidate append_hex4_csv and use shared _VERSION
```

---

### Task 5: Update `lib/resty/ja4h.lua`

**Files:**
- Modify: `lib/resty/ja4h.lua`

**Step 1: Use shared `_VERSION`**

Change:
```lua
local _M = {
    _VERSION = "0.1.0"
}
```
to:
```lua
local _M = {
    _VERSION = utils._VERSION
}
```

**Step 2: Run tests**

Run: `make test`
Expected: All tests pass

**Step 3: Commit**

```
refactor(ja4h): use shared _VERSION from utils
```

---

### Task 6: Update benchmarks

**Files:**
- Modify: `bench/jit_trace.lua`
- Modify: `bench/jit_dump.lua`
- Modify: `bench/jit_profile.lua`
- Modify: `bench/microbench.lua`
- Modify: `bench/alloc_track.lua`

**Step 1: Update `bench/jit_trace.lua`**

Line 25: Replace `utils.sha256_hex12("trace_test")` with `ja4.build(profile.ja4)` (or remove the line — it already runs ja4.build above).

Line 27: Replace `utils.parse_cookies(profile.cookie_str)` with `utils.parse_cookies_into(profile.cookie_str, {}, {})`.

**Step 2: Update `bench/jit_dump.lua`**

Line 25: Replace `utils.sha256_hex12("dump_test")` with a different hot-path function, e.g. `utils.parse_sig_algs(profile.raw_sig_algs)`.

**Step 3: Update `bench/jit_profile.lua`**

Line 22: Replace `utils.sha256_hex12("warmup")` with `utils.parse_alpn(profile.raw_alpn)`.

Line 24: Replace `utils.parse_cookies(profile.cookie_str)` with `utils.parse_cookies_into(profile.cookie_str, {}, {})`.

Line 61: Replace `utils.sha256_hex12("profile_test")` with `utils.parse_alpn(profile.raw_alpn)`.

Line 63: Replace `utils.parse_cookies(profile.cookie_str)` with `utils.parse_cookies_into(profile.cookie_str, {}, {})`.

**Step 4: Update `bench/microbench.lua`**

Lines 96-100: Replace the `sha256_hex12()` row with a `sha256_to_buf()` benchmark:

```lua
-- sha256_to_buf — input-size independent, show once
io.write(string.format("%-" .. W1 .. "s", "sha256_to_buf()"))
local ffi = require("ffi")
local target = ffi.new("uint8_t[64]")
local sha_ops = bench(function() utils.sha256_to_buf("test_input", 10, target, 0) end)
io.write(string.format("%-" .. W2 .. "s", fmt_ops(sha_ops)))
io.write("(input-size independent)\n")
```

Lines 108-112: Replace `parse_cookies()` row with `parse_cookies_into()`:

```lua
row("parse_cookies_into()", function(p)
    local c = p.cookie_str
    if not c then return nil end
    local names, pairs_list = {}, {}
    return function() utils.parse_cookies_into(c, names, pairs_list) end
end)
```

**Step 5: Update `bench/alloc_track.lua`**

Line 57: Replace `utils.sha256_hex12("test")` with:
```lua
local ffi = require("ffi")
local _target = ffi.new("uint8_t[64]")
```
then:
```lua
report("sha256_to_buf()", function() utils.sha256_to_buf("test", 4, _target, 0) end)
```

Line 63: Replace `utils.parse_cookies(profile.cookie_str)` with:
```lua
local _ck_names, _ck_pairs = {}, {}
```
then:
```lua
report("parse_cookies_into()", function() utils.parse_cookies_into(profile.cookie_str, _ck_names, _ck_pairs) end)
```

**Step 6: Commit**

```
refactor(bench): update benchmarks to use surviving function variants
```

---

### Task 7: Run full test suite

**Step 1: Run unit tests**

Run: `make test`
Expected: All unit tests pass

**Step 2: Run e2e tests**

Run: `make e2e`
Expected: All 42 e2e tests pass on both OpenResty 1.27 and 1.29

**Step 3: Verify line counts**

Run: `wc -l lib/resty/ja4.lua lib/resty/ja4h.lua lib/resty/ja4/utils.lua`
Expected: utils.lua should be ~440-460 lines (down from 616). ja4.lua and ja4h.lua should be ~same or slightly smaller.
