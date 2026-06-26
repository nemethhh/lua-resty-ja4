# Bounds Hardening + ABI Migration Design

**Date:** 2026-06-26
**Scope:** Eliminate remotely-triggerable FFI buffer overflows and an O(n²) sort DoS; migrate the JA4 TLS path from hand-rolled OpenSSL FFI to the official `ngx.ssl.clienthello` getters (minimum OpenResty 1.29.2.1).

## Problem

The library writes client-controlled, unbounded input into fixed-size module-level FFI
buffers with no bounds checking. The 99-cap at `ja4.lua:133-134` only affects the
2-digit count in Section A — the actual data fed to the buffers and the hash is never
clamped. Two distinct, remotely-reachable (pre-auth, during the TLS handshake / before
the request body) defects result:

1. **Buffer overflow.** Concrete, exercised by the repo's own tests:
   - `csv_buf` is `uint8_t[512]` (`utils.lua:143`). `write_u16_hex_csv` writes `5n − 1`
     bytes; 512 is exceeded at **n ≥ 103** ciphers or extensions. `t/002-ja4-algo.t:154`
     (TEST 8) feeds 105 ciphers → **524 bytes into a 512-byte buffer**. It "passes" only
     because LuaJIT FFI does no bounds checking. TEST 9 does the same with 105 extensions.
   - `cipher_u16`/`ext_u16` are `uint16_t[256]` (`ja4.lua:23-24`); `copy_ciphers`
     (`ja4.lua:60-64`) writes `arr[i-1]` for all `i` up to `#ciphers` with no guard. A
     ClientHello can legitimately carry thousands of cipher suites / extensions → OOB
     heap write → worker segfault or silent memory corruption (wrong fingerprints).
   - Raw mode `out_buf[2048]` (`ja4.lua:27`) is sized for "99 ciphers"; more overflows it.
   - JA4H: `hash_buf`/`out_buf` are `uint8_t[4096]` (`ja4h.lua:34-35`); `write_str_csv_at`
     has no bound. Header names are count-capped at 100 but not length-capped, and cookies
     have **no count cap at all** (`parse_cookies_into`, `utils.lua:300`). nginx's default
     header buffers allow well over 4 KB → overflow.

2. **O(n²) sort DoS.** `isort_u16` / `isort` are insertion sorts (`utils.lua:113,127`).
   Even with larger buffers, sorting an attacker-supplied 30,000-element list is ~10⁹
   comparisons per handshake — CPU exhaustion. Any "just grow the buffers" fix re-exposes
   this, which is why the fix must *cap* rather than *grow*.

## Reference findings (OpenResty 1.31.1.1 / lua-resty-core 0.1.34rc3)

Verified against the bundled reference sources in `docs/`:

- **Official clienthello getters exist and are safe** (introduced lua-resty-core 0.1.32,
  May 2025). Verified present at `v0.1.32R1` (bundled by OpenResty **1.29.2.1**),
  `v0.1.34rc2` (1.29.2.5), and `v0.1.34rc3` (1.31.1.1). OpenResty 1.27.x bundles a
  pre-0.1.32 lua-resty-core and does **not** have them:
  - `clienthello.get_client_hello_ciphers()` (`clienthello.lua:184`) — GREASE-filtered;
    the C layer caps at the caller's buffer size and **truncates safely**
    (`ciphers_cnt > ciphers_size ? ciphers_size : ciphers_cnt`,
    `ngx_http_lua_ssl_client_helloby.c`). The Lua wrapper passes `short[128]`, so
    **ciphers are capped at 128 by the platform.**
  - `clienthello.get_client_hello_ext_present()` (`clienthello.lua:147`) — GREASE-filtered;
    the C layer copies extensions into the **nginx request pool** (`ngx_palloc`) and frees
    the OpenSSL buffer itself. No Lua-side memory management.
- **`NGX_HTTP_LUA_MAX_HEADERS = 100`** (`ngx_http_lua_common.h:131`) — matches the lib's
  existing `MAX_HDR = 100`.
- OpenResty 1.31 ships **OpenSSL 3.5.6**. The current `CRYPTO_free(ext_arr, "", 0)`
  (`ja4.lua:114`) is a manual free into OpenSSL's allocator with faked file/line — a real
  corruption hazard across builds. Migrating to the official getter removes it entirely.
- The JA4H header path is **already ABI-stable**: it reuses lua-resty-core's own cdef of
  `ngx_http_lua_ffi_table_elt_t` + `req_get_headers` (`ja4h.lua:12-17`); struct
  (`{ffi_str key; ffi_str value;}`) and signatures are unchanged 1.27→1.31. Only the
  bounds fix is needed there.

## Decisions

1. **Adopt the official `ngx.ssl.clienthello` API; minimum OpenResty floor becomes
   1.29.2.1.** Drops only the 1.27 support claim — 1.29.2.1 bundles lua-resty-core
   0.1.32R1, which has the getters (verified). The getters did not exist in 1.27.
2. **Overflow behavior: clamp + warn.** Over-cap inputs are truncated to a deterministic,
   bounded fingerprint and a single `ngx.log(ngx.WARN, ...)` is emitted. The request never
   fails. This mirrors the platform's own cipher behavior (cap 128, silent truncate) and
   keeps all sections consistent. Real clients are always under the caps and remain
   byte-identical to canonical JA4/JA4H.

## Design

### Caps (named constants in `utils.lua`)

| Constant | Value | Rationale |
|---|---|---|
| `MAX_CIPHERS` | 128 | Matches the platform getter's built-in cap. |
| `MAX_EXTENSIONS` | 128 | Platform returns all; we cap for `csv_buf`/sort. |
| `MAX_SIG_ALGS` | 128 | Extension 13 is client-controlled and uncapped upstream. |
| `MAX_HEADERS` | 100 | nginx `NGX_HTTP_LUA_MAX_HEADERS` default (already used). |
| `MAX_COOKIES` | 128 | `parse_cookies_into` currently has no cap. |

Buffers are sized **from** these constants (with a comment showing the worst-case
arithmetic) so the relationship is explicit and reviewable.

### JA4 (`ja4.lua`)

- Replace `get_ciphers_ffi` → `clienthello.get_client_hello_ciphers()`.
- Replace `get_extensions_ffi` → `clienthello.get_client_hello_ext_present()`.
  Returns all extensions including SNI (0x0000) / ALPN (0x0010) — exactly what `build()`
  expects: Section A count includes them, `filter_extensions_u16` excludes them from the
  hash. That logic is unchanged.
- **Delete** the cdefs and pointers for `SSL_client_hello_get0_ciphers`,
  `SSL_client_hello_get1_extensions_present`, `CRYPTO_free`, and
  `ciphers_out_ptr`/`ext_out_ptr`/`ext_len_ptr`.
- **ABI smoke / floor enforcement:** at load, assert the getters resolve; fail fast with
  a message naming the **1.29.2.1** floor if absent.
- **Keep** one raw symbol: `SSL_client_hello_get0_legacy_version` (read-only, no
  allocation) for the TLS-1.2-only version fallback — no official wrapper exists.
  `get_req_ssl_pointer()` is retained solely to feed that single call.
- Clamp the copy loops (`copy_ciphers`, `filter_extensions_u16`) and `sig_algs` to their
  caps; emit a warn on truncation.

Buffer sizing:
- `cipher_u16` / `ext_u16` → sized to `MAX_*` (clamped copy guarantees no OOB).
- `csv_buf` → **2048** (worst Section C: 128 exts × 5 = 640, `_`, 128 sig_algs × 5 = 640
  ≈ 1281).
- `out_buf` (raw mode) → **4096** (worst ≈ 1934).

### JA4H (`ja4h.lua`)

- Header FFI path unchanged (already ABI-stable).
- Cap header-name count at `MAX_HEADERS` (already 100) and cookie count at `MAX_COOKIES`;
  warn on truncation. `parse_cookies_into` gains a count cap.
- `hash_buf` / `out_buf` → **16384** (cookies/headers are bounded by nginx's
  `large_client_header_buffers`, ~8 KB default; 16 KB ensures real requests never
  truncate, with the count caps + bounds checks as backstop).
- `join_cookie_values` 4096 silent truncate → truncate + warn for consistency.

### `utils.lua` — capacity-aware CSV writers

`write_u16_hex_csv`, `write_hex4_csv_at`, `write_str_csv_at` take a `cap_bytes` argument
and stop at capacity. Analytical buffer sizing already prevents reaching the cap; this is
pure defense-in-depth against future regressions. Insertion sorts are unchanged — bounded
inputs (≤128) keep them O(n²)-but-tiny and JIT-friendly.

## Error handling

- Over-cap input → clamp to cap, compute bounded fingerprint, one `ngx.log(ngx.WARN, ...)`
  with the form `"ja4: <field> truncated <n>-><cap>"`. Off the common path.
- CSV writers refuse to write past `cap_bytes` (backstop, should never trigger given
  sizing).

## Testing

- **Unit (`t/`):** feed `build()` 300 ciphers / 300 extensions / 300 sig_algs / 200 header
  names / 500 cookies with long values. Assert: (a) no crash, (b) output length matches the
  capped expectation, (c) a warn is logged. Repair TEST 8 / TEST 9 in `t/002-ja4-algo.t`
  (currently overflow `csv_buf`; 105 < 128 now fits, plus add a >128 case).
- **e2e:** a scapy ClientHello (`e2e/scapy_tls_client.py`) with >128 ciphers and many
  extensions → worker stays up, returns a valid JA4 header.
- **ABI smoke:** at module load, assert `clienthello.get_client_hello_ciphers` and
  `get_client_hello_ext_present` resolve; fail fast with a clear message naming the
  1.29.2.1 floor if absent.

## Migration / docs

- README requirements: minimum OpenResty **1.29.2.1**; note reliance on the official
  clienthello getters. Drop the 1.27 "tested against" claim; keep 1.29 and 1.31.
- CI matrix: drop 1.27; keep 1.29.2.x and 1.31.

## Out of scope

- Replacing insertion sort with O(n log n): unnecessary once inputs are capped at ≤128.
- Per-request configuration of hash/raw mode (the global `_hash_mode` is a separate
  concern, not a security defect).
- HTTP/3 JA4H correctness (untested path; tracked separately).
