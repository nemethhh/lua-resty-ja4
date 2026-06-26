local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_string = ffi.string
local ffi_copy = ffi.copy
local C = ffi.C
local bit = require "bit"
local byte = string.byte
local tonumber = tonumber
local math_min = math.min
local utils = require "resty.ja4.utils"
local isort_u16 = utils.isort_u16
local LEGACY_VERSION_MAP = utils.LEGACY_VERSION_MAP
local csv_buf = utils.csv_buf
local write_u16_hex_csv = utils.write_u16_hex_csv
local write_hex4_csv_at = utils.write_hex4_csv_at
local sha256_to_buf = utils.sha256_to_buf
local EMPTY_HASH = utils.EMPTY_HASH
local NUM2 = utils.NUM2
local MAX_CIPHERS    = utils.MAX_CIPHERS
local MAX_EXTENSIONS = utils.MAX_EXTENSIONS
local MAX_SIG_ALGS   = utils.MAX_SIG_ALGS
local CSV_BUF_SIZE   = utils.CSV_BUF_SIZE
local ngx_log = ngx.log
local ngx_WARN = ngx.WARN

local cipher_u16 = ffi_new("uint16_t[" .. MAX_CIPHERS .. "]")
local ext_u16 = ffi_new("uint16_t[" .. MAX_EXTENSIONS .. "]")
-- Raw mode worst case: 10 (section_a) + 1 + 640 (128 ciphers) + 1 + 640 (128 exts)
-- + 1 + 640 (128 sig_algs) ~= 1934B. Hash mode: fixed 36B. 4096B covers all cases.
local OUT_BUF_SIZE = 4096
local out_buf = ffi_new("uint8_t[" .. OUT_BUF_SIZE .. "]")

-- Load ssl.clienthello once at module load (not per-call).
-- pcall here handles non-SSL or non-OpenResty environments gracefully.
local ok_clt, ssl_clt = pcall(require, "ngx.ssl.clienthello")
local ok_ssl, ngx_ssl = pcall(require, "ngx.ssl")

local _have_getters = ok_clt
    and ssl_clt.get_client_hello_ciphers ~= nil
    and ssl_clt.get_client_hello_ext_present ~= nil

-- OpenSSL FFI: only the ClientHello legacy_version (no official wrapper exists).
-- Ciphers and extensions now come from ngx.ssl.clienthello (OpenResty >= 1.29.2.1).
pcall(ffi.cdef, [[
    unsigned int SSL_client_hello_get0_legacy_version(void *ssl);
]])

local _M = {}

local _hash_mode = true

function _M.configure(opts)
    if opts and opts.hash ~= nil then
        _hash_mode = opts.hash
    end
end

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

-- Build JA4 fingerprint from pre-extracted data.
-- Input table fields:
--   protocol: "t" (TCP), "q" (QUIC), "d" (DTLS)
--   version: "13", "12", "11", "10", "s3", "s2", "00"
--   sni: "d" (domain) or "i" (IP)
--   ciphers: array of uint16 cipher suite IDs (GREASE already filtered)
--   extensions: array of uint16 extension type IDs (GREASE already filtered)
--   alpn: 2-char ALPN code (e.g. "h2", "h1", "00")
--   sig_algs: array of 4-char hex strings in original order, or nil
-- Returns: fingerprint string (hash or raw depending on configure), or nil, err
function _M.build(data)
    if not data then
        return nil, "no data"
    end

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
    local cn = copy_ciphers(data.ciphers, cipher_u16, MAX_CIPHERS)
    isort_u16(cipher_u16, cn)

    local ext_n = filter_extensions_u16(data.extensions, ext_u16, MAX_EXTENSIONS)
    isort_u16(ext_u16, ext_n)

    if _hash_mode then
        -- Section B: sorted ciphers -> csv_buf -> SHA256 -> 12 hex bytes to out_buf
        if cn == 0 then
            ffi_copy(out_buf + pos, EMPTY_HASH, 12)
        else
            local csv_len = write_u16_hex_csv(cipher_u16, cn, csv_buf, 0, CSV_BUF_SIZE)
            sha256_to_buf(csv_buf, csv_len, out_buf, pos)
        end
        pos = pos + 12  -- 23

        out_buf[pos] = 0x5F; pos = pos + 1  -- 24

        -- Section C: sorted exts + sig_algs -> csv_buf -> SHA256 -> 12 hex bytes
        local sc_len = write_u16_hex_csv(ext_u16, ext_n, csv_buf, 0, CSV_BUF_SIZE)
        if sig_n > 0 then
            csv_buf[sc_len] = 0x5F  -- '_'
            sc_len = write_hex4_csv_at(data.sig_algs, sig_n, csv_buf, sc_len + 1, CSV_BUF_SIZE)
        end
        if ext_n == 0 and sig_n == 0 then
            ffi_copy(out_buf + pos, EMPTY_HASH, 12)
        else
            sha256_to_buf(csv_buf, sc_len, out_buf, pos)
        end
        pos = pos + 12  -- 36
    else
        -- Section B raw: hex CSV directly into out_buf
        pos = write_u16_hex_csv(cipher_u16, cn, out_buf, pos, OUT_BUF_SIZE)

        out_buf[pos] = 0x5F; pos = pos + 1

        -- Section C raw: exts CSV + '_' + sig_algs CSV
        pos = write_u16_hex_csv(ext_u16, ext_n, out_buf, pos, OUT_BUF_SIZE)
        if sig_n > 0 then
            out_buf[pos] = 0x5F; pos = pos + 1
            pos = write_hex4_csv_at(data.sig_algs, sig_n, out_buf, pos, OUT_BUF_SIZE)
        end
    end

    return ffi_string(out_buf, pos)
end

-- ngx.ctx storage
local CTX_KEY = "ja4_fingerprint"

function _M.store(val)
    ngx.ctx[CTX_KEY] = val
end

function _M.get()
    return ngx.ctx[CTX_KEY]
end

local VERSION_PRIORITY = {
    ["SSLv2"]   = 1,
    ["SSLv3"]   = 2,
    ["TLSv1"]   = 3,
    ["TLSv1.1"] = 4,
    ["TLSv1.2"] = 5,
    ["TLSv1.3"] = 6,
}

-- Compute JA4 from current ssl_client_hello context.
-- Must be called from ssl_client_hello_by_lua_block.
-- Stores result in ngx.ctx automatically.
-- Returns: fingerprint string (or nil, err)
function _M.compute()
    if not ok_clt then
        return nil, "ngx.ssl.clienthello not available"
    end
    if not ok_ssl then
        return nil, "ngx.ssl not available"
    end
    if not _have_getters then
        return nil, "ja4.compute requires OpenResty >= 1.29.2.1 "
            .. "(ngx.ssl.clienthello cipher/extension getters)"
    end
    local ssl_ptr, err = ngx_ssl.get_req_ssl_pointer()
    if not ssl_ptr then
        return nil, "failed to get SSL pointer: " .. (err or "unknown")
    end

    -- Protocol: always TCP in OpenResty
    local protocol = "t"

    -- TLS version: prefer supported_versions extension, fallback
    local version_code = "00"
    local versions = ssl_clt.get_supported_versions()
    if versions and #versions > 0 then
        local best_ver = nil
        local best_pri = 0
        for i = 1, #versions do
            local pri = VERSION_PRIORITY[versions[i]] or 0
            if pri > best_pri then
                best_pri = pri
                best_ver = versions[i]
            end
        end
        version_code = utils.tls_version_code(best_ver)
    end

    -- Fallback: use ClientHello legacy_version for pure TLS 1.2 clients
    if version_code == "00" then
        local legacy = tonumber(C.SSL_client_hello_get0_legacy_version(ssl_ptr))
        version_code = LEGACY_VERSION_MAP[legacy] or "00"
    end

    -- SNI
    local sni_name = ssl_clt.get_client_hello_server_name()
    local sni = sni_name and "d" or "i"

    -- Ciphers: official getter (GREASE filtered, capped at 128, no manual free)
    local ciphers = ssl_clt.get_client_hello_ciphers() or {}

    -- Extensions: official getter (GREASE filtered, pool-allocated, no manual free);
    -- includes SNI/ALPN, which build() counts in section A and excludes from the hash.
    local extensions = ssl_clt.get_client_hello_ext_present() or {}

    -- ALPN: parse raw extension type 16
    local alpn_raw = ssl_clt.get_client_hello_ext(16)
    local alpn = utils.parse_alpn(alpn_raw)

    -- Signature algorithms: parse raw extension type 13
    local sig_algs_raw = ssl_clt.get_client_hello_ext(13)
    local sig_algs = utils.parse_sig_algs(sig_algs_raw)

    local result, err = _M.build({
        protocol   = protocol,
        version    = version_code,
        sni        = sni,
        ciphers    = ciphers,
        extensions = extensions,
        alpn       = alpn,
        sig_algs   = sig_algs,
    })

    if not result then
        return nil, err
    end

    _M.store(result)
    return result
end

return _M
