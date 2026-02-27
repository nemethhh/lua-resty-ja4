# lua-resty-ja4

JA4 and JA4H fingerprinting for OpenResty.

This library provides:
- `resty.ja4` for TLS ClientHello fingerprints (JA4)
- `resty.ja4h` for HTTP request fingerprints (JA4H)

It is implemented with LuaJIT FFI and optimized for low allocation and high throughput.

## Features

- JA4 generation from live TLS handshakes in `ssl_client_hello_by_lua*`
- JA4H generation from live HTTP requests (HTTP/1.x and HTTP/2 path)
- Hash mode (default): truncated SHA256 sections
- Raw mode: full sortable CSV sections
- Direct `build()` APIs when you already have parsed handshake/header data
- Request-local storage helpers via `ngx.ctx` (`store()` / `get()`)

## Requirements

- OpenResty with LuaJIT FFI
- `lua-resty-core` (used by JA4H FFI header extraction path)
- For live JA4 `compute()`: OpenResty with `ngx.ssl.get_req_ssl_pointer()` available (tested on OpenResty 1.27+)

Tested in this repo against:
- OpenResty 1.27.1.2
- OpenResty 1.29.2.1

## Installation

Copy the library into your Lua package path:

```bash
cp -r lib/resty/* /usr/local/openresty/lualib/resty/
```

Or keep it in-repo and add to `lua_package_path`:

```nginx
lua_package_path "/path/to/lua-resty-ja4/lib/?.lua;/path/to/lua-resty-ja4/lib/?/init.lua;;";
```

## Quick Start

Example: compute JA4 during TLS handshake, compute JA4H during request processing, and expose both as response headers.

```nginx
server {
    listen 443 ssl;
    http2 on;

    ssl_certificate     /etc/nginx/server.crt;
    ssl_certificate_key /etc/nginx/server.key;

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

    location / {
        return 200 "ok";
    }
}
```

## API

### `resty.ja4`

- `configure({ hash = boolean })`
- `build(data)`
- `compute()`
- `store(value)`
- `get()`

`compute()` must run in `ssl_client_hello_by_lua*` context.

`build(data)` input:

```lua
{
  protocol   = "t",                    -- "t" (TCP), "q" (QUIC), "d" (DTLS)
  version    = "13",                   -- 13,12,11,10,s3,s2,00
  sni        = "d",                    -- "d" domain or "i" IP
  ciphers    = { 0x1301, 0x1302 },
  extensions = { 0x0000, 0x0010, 0x000d },
  alpn       = "h2",
  sig_algs   = { "0403", "0804" },   -- optional
}
```

Example output (hash mode):

```text
t13d1516h2_8daaf6152771_e5627efa2ab1
```

### `resty.ja4h`

- `configure({ hash = boolean })`
- `build(data)`
- `compute()`
- `store(value)`
- `get()`

`compute()` supports HTTP/1.x and HTTP/2 request paths.

`build(data)` input:

```lua
{
  method          = "GET",
  version         = "11",              -- 10,11,20,30,00
  has_cookie      = true,
  has_referer     = false,
  header_names    = { "Host", "Accept" },
  accept_language = "en-US,en;q=0.9",  -- optional
  cookie_str      = "a=1; b=2",         -- optional
}
```

Example output (hash mode):

```text
he11nn05enus_6f8992deff94_000000000000_000000000000
```

## Hash vs Raw Mode

Default is hash mode (`hash = true`).

Hash mode output lengths:
- JA4: 36 chars (`sectionA_hash_hash`)
- JA4H: 51 chars (`sectionA_hash_hash_hash`)

Raw mode (`hash = false`) emits full CSV sections for debugging and comparisons.

## Notes and Caveats

- `configure()` changes module-level mode per worker. Set it once during startup and avoid toggling per request.
- `store()` / `get()` use `ngx.ctx`, so values are request-local.
- JA4 extension visibility depends on what OpenSSL reports through ClientHello APIs. Some wire extensions may be omitted by OpenSSL and therefore not appear in JA4 section C.
- JA4H excludes `Cookie` and `Referer` from the header-name hash section by design (they are represented by flags and cookie sections).

## Development

Unit tests (Test::Nginx in Docker):

```bash
make test
make test-verbose
```

E2E tests (Docker Compose, OpenResty 1.27 and 1.29):

```bash
make e2e
make e2e-clean
```

Benchmarks and profiling:

```bash
make jit-bench
make jit-alloc
make jit-trace
make jit-profile
make jit-dump
make jit-all
make jit-report
```

## License

MIT. See [LICENSE](LICENSE).
