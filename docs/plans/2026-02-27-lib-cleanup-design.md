# lib/ Code Cleanup Design

**Date:** 2026-02-27
**Scope:** Dead code removal, consolidation, utils.lua restructure

## 1. Dead Code Removal

Delete 6 functions from `utils.lua` that are not used by any production code (`ja4.lua`, `ja4h.lua`):

| Function | Lines | Replacement |
|---|---|---|
| `sha256_hex12` | 102-116 | `sha256_to_buf` (zero-alloc, writes directly to target) |
| `sha256_hex12_buf` | 120-134 | `sha256_to_buf` |
| `write_hex4_csv` | 196-213 | `write_u16_hex_csv` + `write_hex4_csv_at` |
| `to_hex4` | 156-159 | Internal `HEX4[val]` lookup (never used externally) |
| `parse_cookies` | 369-421 | `parse_cookies_into` (pre-allocated tables) |
| `parse_raw_header_names_into` | 528-573 | Not used (ja4h.lua uses allocating `parse_raw_header_names`) |

Also stop exporting `hex_pair` — internal to `sha256_to_buf`.

## 2. Consolidation

### `append_hex4_csv` → `write_hex4_csv_at`

`append_hex4_csv(hex_array, n, offset)` is identical to `write_hex4_csv_at(hex_array, n, buf, pos)` except it hardcodes `csv_buf`. Delete `append_hex4_csv` and update ja4.lua:

```lua
-- Before:
sc_len = append_hex4_csv(data.sig_algs, #data.sig_algs, sc_len + 1)

-- After:
sc_len = write_hex4_csv_at(data.sig_algs, #data.sig_algs, csv_buf, sc_len + 1)
```

### `_VERSION`

Define `_VERSION = "0.1.0"` once in `utils.lua`. Reference from ja4 and ja4h:

```lua
local _M = { _VERSION = utils._VERSION }
```

## 3. utils.lua Section Reorder

Reorganize ~440 remaining lines into logical sections:

```
1. FFI imports & constants
   - ffi requires, local aliases, LE assertion
   - EMPTY_HASH, EMPTY_TAB, new_tab, _VERSION

2. Lookup tables (built at module load)
   - HEX4 (internal), hex_pair (internal), hex_chars, NUM2
   - LEGACY_VERSION_MAP, TLS_VERSION_MAP

3. SHA256
   - EVP cdef + sha256_to_buf (sole remaining SHA function)

4. Sorting
   - isort (string, 1-based), isort_u16 (uint16, 0-based)

5. CSV serialization
   - csv_buf (exported)
   - write_u16_hex_csv, write_hex4_csv_at, write_str_csv_at

6. GREASE detection
   - is_grease

7. TLS parsing
   - tls_version_code, parse_alpn, parse_sig_algs

8. HTTP parsing
   - parse_accept_language, parse_cookies_into, parse_raw_header_names

9. return _M
```

## 4. Test & Benchmark Impact

### `t/001-utils.t`

Delete test blocks for removed functions:
- `sha256_hex12` tests, `sha256_hex12_buf` test (TEST 15)
- `write_hex4_csv` tests (TEST 14, 18, 19, 35)
- `parse_cookies` tests (TEST 9, 10, 24-27)
- `parse_raw_header_names_into` test (TEST 37)
- `to_hex4` tests (TEST 5), `hex_pair` tests (TEST 16)

All remaining tests exercise functions that are still in production.

### `bench/*.lua`

Update `jit_trace.lua`, `jit_profile.lua`, `microbench.lua`, `alloc_track.lua`, `jit_dump.lua` to remove references to deleted functions.

### E2E tests

No impact — they test via `compute()` which is unchanged.

## 5. Verification

- All 226 unit tests that test surviving functions must pass
- All 42 e2e tests must pass on both OpenResty 1.27 and 1.29
- `make test` and `make e2e` green before merge
