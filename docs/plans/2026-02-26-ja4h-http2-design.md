# JA4H HTTP/2 Support — Design Document

**Date:** 2026-02-26
**Status:** Approved

## Problem

JA4H fingerprinting crashes on HTTP/2 requests because `ngx.req.raw_header()` is not
supported for HTTP/2 in OpenResty. The function throws `"http2 requests not supported yet"`
when `r->stream` is non-NULL (HTTP/2 stream-based requests don't maintain raw header buffers).

## Solution: Dual-Path Architecture

Keep the proven HTTP/1.x path unchanged. Add a new FFI-based path for HTTP/2+ that calls
`ngx_http_lua_ffi_req_get_headers()` directly, iterating the ordered output buffer instead
of going through the Lua wrapper (which loses order by dumping into a hash table).

```
ja4h.compute()
├── detect version via ngx.var.server_protocol
├── HTTP/1.x:  raw_header() → parse_raw_header_names()     [existing, untouched]
└── HTTP/2+:   FFI → ngx_http_lua_ffi_req_get_headers(r, buf, n, raw=1)
               iterate buf[0..n-1] in order
               skip cookie/referer, collect cookie values
               extract accept-language
```

### Why This Works

- `r->headers_in.headers` (ngx_list_t) stores parsed headers in insertion order for
  ALL HTTP versions — HTTP/1.1, HTTP/2, and HTTP/3
- The C function `ngx_http_lua_ffi_req_get_headers()` iterates this list sequentially
  into a flat `ngx_http_lua_ffi_table_elt_t` array
- HTTP/2 pseudo-headers (`:method`, `:path`, `:scheme`, `:authority`) are NOT stored in
  `headers_in.headers` — they go into separate struct fields. No filtering needed.
- `raw=1` parameter preserves original header name case

### FFI Details

Reuse existing FFI functions already compiled into every OpenResty build:

```c
int ngx_http_lua_ffi_req_get_headers_count(void *r, int max, int *truncated);
int ngx_http_lua_ffi_req_get_headers(void *r,
    ngx_http_lua_ffi_table_elt_t *out, int count, int raw);
```

FFI struct (already defined by lua-resty-core, use `pcall` guard for re-declaration):

```c
typedef struct {
    ngx_http_lua_ffi_str_t   key;
    ngx_http_lua_ffi_str_t   value;
} ngx_http_lua_ffi_table_elt_t;
```

### New Function: `utils.get_ordered_header_names_ffi()`

Single-pass extraction from the FFI buffer. Returns:
- `header_names[]` — ordered array of header name strings, excluding cookie/referer
- `header_count` — number of headers
- `has_cookie` — boolean
- `has_referer` — boolean
- `cookie_values[]` — array of raw cookie value strings (may be multiple for HTTP/2)
- `accept_lang` — accept-language header value or nil

### Cookie Handling for HTTP/2

HTTP/2 clients MAY send cookies as multiple `cookie:` headers instead of one
semicolon-separated value (RFC 7540 §8.1.2.5).

During the FFI buffer iteration, all cookie values are collected into `cookie_values[]`.
Then `parse_cookies_into()` is called per entry, appending to shared output tables.
`isort()` sorts the merged result. No string concatenation allocation.

### Changes to ja4h.lua

`compute()` gets a version branch:
- `is_h2_plus = (version == "20" or version == "30")`
- HTTP/2+: calls `utils.get_ordered_header_names_ffi()`
- HTTP/1.x: existing path unchanged

Everything else unchanged: `build_section_a()`, `configure()`, `store()`, `get()`.

### Performance Constraints

- Fully JIT-compilable — no NYI calls in hot path
- Zero intermediate string allocations for header name comparison
- FFI buffer reuse where possible
- Cookie values parsed per-entry into shared tables (no concatenation)
- `byte()` length-first comparison for cookie/referer skip

## Testing

**Unit tests** (`t/006-ja4h-http2-algo.t`):
- FFI header extraction: ordering, cookie/referer skip, multi-cookie, accept-language
- Verify pseudo-headers not present in `headers_in`

**E2e tests** (`e2e/test_ja4h_http2.py`):
- Enable `http2 on;` in nginx.conf server blocks
- Python HTTP/2 client (httpx or h2) sends requests with known headers
- Verify X-JA4H section A version=20, correct header count, deterministic hashes
- Test: cookies, referer, multi-value cookies, no cookies

**Existing tests untouched** — HTTP/1.x path is unchanged.

## Future Work (not implemented)

- **`JA4H_ro` mode**: Raw fingerprint with original cookie order. Python reference has this.
  Would need a third mode in `configure()`. Low priority — no known consumers.
- **HTTP/3 e2e testing**: The FFI path handles HTTP/3 (C function synthesizes host header
  from `:authority`). Version detection returns "30". Should work but needs QUIC e2e tests.
