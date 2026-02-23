# lua-resty-ja4

JA4 and JA4H fingerprinting for OpenResty/nginx. Generates [JA4](https://blog.foxio.io/ja4%2B-network-fingerprinting) TLS client fingerprints and JA4H HTTP request fingerprints.

Built for LuaJIT with FFI-based SHA256 hashing, pre-computed lookup tables, and zero-allocation hot paths.

## Installation

Copy the library into your OpenResty Lua package path:

```bash
cp -r lib/resty/* /usr/local/openresty/lualib/resty/
```

**Requirements:** OpenResty **1.29.2.1** or later with `lua-resty-core` and LuaJIT FFI.

> **Note:** JA4 TLS fingerprinting requires `ssl.clienthello.get_client_hello_ciphers` and
> `get_client_hello_ext_present` APIs, which were added in lua-nginx-module v0.10.29 /
> lua-resty-core v0.1.32. These ship with OpenResty 1.29.2.1, which has not been formally
> released yet — source tarball is available at
> https://openresty.org/download/openresty-1.29.2.1.tar.gz.
> Earlier versions (including 1.27.1.2) bundle older modules that lack these APIs.
> JA4H HTTP fingerprinting works on any OpenResty version.

## Usage

### JA4 — TLS Client Fingerprinting

Compute JA4 fingerprints from the TLS ClientHello. Must be called from `ssl_client_hello_by_lua_block`:

```nginx
server {
    listen 443 ssl;

    ssl_client_hello_by_lua_block {
        local ja4 = require "resty.ja4"
        local fp = ja4.compute()
        ja4.store(fp)
    }

    location / {
        content_by_lua_block {
            local ja4 = require "resty.ja4"
            ngx.say("JA4: ", ja4.get())
        }
    }
}
```

### JA4H — HTTP Request Fingerprinting

Compute JA4H fingerprints from HTTP request headers:

```nginx
location / {
    content_by_lua_block {
        local ja4h = require "resty.ja4h"
        local fp = ja4h.compute()
        ngx.say("JA4H: ", fp)
    }
}
```

### Configuration

Both modules default to hash mode (truncated SHA256). Switch to raw mode to get full CSV values:

```lua
local ja4 = require "resty.ja4"
ja4.configure({ hash = false })  -- raw mode
```

### Building Fingerprints from Custom Data

You can call `build()` directly with pre-extracted data:

```lua
-- JA4
local ja4 = require "resty.ja4"
local fp = ja4.build({
    protocol   = "t",                          -- "t" (TCP), "q" (QUIC), "d" (DTLS)
    version    = "13",                         -- TLS version code
    sni        = "d",                          -- "d" (domain) or "i" (IP)
    ciphers    = { 0x1301, 0x1302, 0x1303 },   -- cipher suite IDs
    extensions = { 0x0033, 0x002b },           -- extension type IDs
    alpn       = "h2",                         -- 2-char ALPN code
    sig_algs   = { "0403", "0804" },           -- signature algorithm hex strings
})

-- JA4H
local ja4h = require "resty.ja4h"
local fp = ja4h.build({
    method          = "GET",
    version         = "11",                    -- HTTP version code
    has_cookie      = true,
    has_referer     = false,
    header_names    = { "Host", "Accept", "User-Agent" },
    accept_language = "en-US,en;q=0.9",
    cookie_str      = "session=abc; theme=dark",
})
```

## Fingerprint Format

**JA4** (TLS): `t13d1516h2_<ciphers_hash>_<extensions_hash>`
- Section A (10 chars): protocol + TLS version + SNI + cipher count + extension count + ALPN
- Section B (12 chars): sorted cipher suites, SHA256-truncated
- Section C (12 chars): sorted extensions + signature algorithms, SHA256-truncated

**JA4H** (HTTP): `ge11cn05enus_<headers_hash>_<cookie_names_hash>_<cookie_pairs_hash>`
- Section A (12 chars): method + HTTP version + cookie flag + referer flag + header count + language
- Section B (12 chars): header names in order, SHA256-truncated
- Section C (12 chars): sorted cookie names, SHA256-truncated
- Section D (12 chars): sorted cookie name=value pairs, SHA256-truncated

## Testing

Tests use [Test::Nginx](https://github.com/openresty/test-nginx) and run in Docker:

```bash
make test            # unit tests
make test-verbose    # verbose output
make e2e             # end-to-end tests (Docker Compose, builds OpenResty 1.29.2.1)
make e2e-clean       # remove e2e containers and images
```

## Benchmarking

```bash
make jit-bench       # micro-benchmarks (ops/sec)
make jit-alloc       # memory allocation tracking
make jit-trace       # JIT trace analysis
make jit-all         # run all analyses
make jit-report      # save reports to bench/reports/
```

## License

MIT — see [LICENSE](LICENSE).
