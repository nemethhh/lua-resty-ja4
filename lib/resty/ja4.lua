local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_string = ffi.string
local ffi_copy = ffi.copy
local C = ffi.C
local bit = require "bit"
local lshift = bit.lshift
local byte = string.byte
local tonumber = tonumber
local math_min = math.min
local utils = require "resty.ja4.utils"
local new_tab = utils.new_tab
local isort_u16 = utils.isort_u16
local is_grease = utils.is_grease
local LEGACY_VERSION_MAP = utils.LEGACY_VERSION_MAP
local csv_buf = utils.csv_buf
local write_u16_hex_csv = utils.write_u16_hex_csv
local write_hex4_csv_at = utils.write_hex4_csv_at
local sha256_to_buf = utils.sha256_to_buf
local EMPTY_HASH = utils.EMPTY_HASH
local NUM2 = utils.NUM2

local cipher_u16 = ffi_new("uint16_t[256]")
local ext_u16 = ffi_new("uint16_t[256]")
-- Raw mode worst case: 10 (section_a) + 1 + 494 (99 ciphers) + 1 + 494 (99 exts)
-- + 1 + ~200 (sig_algs) ≈ 1200B. Hash mode: fixed 36B. 2048B covers all cases.
local out_buf = ffi_new("uint8_t[2048]")

-- Load ssl.clienthello once at module load (not per-call).
-- pcall here handles non-SSL or non-OpenResty environments gracefully.
local ok_clt, ssl_clt = pcall(require, "ngx.ssl.clienthello")
local ok_ssl, ngx_ssl = pcall(require, "ngx.ssl")

-- OpenSSL FFI: direct ClientHello access (works on OpenResty 1.27+)
pcall(ffi.cdef, [[
    size_t SSL_client_hello_get0_ciphers(void *ssl, const unsigned char **out);
    int SSL_client_hello_get1_extensions_present(void *ssl, int **out, size_t *outlen);
    unsigned int SSL_client_hello_get0_legacy_version(void *ssl);
    void CRYPTO_free(void *ptr, const char *file, int line);
]])

-- Module-level FFI buffers (reused per-call, no allocation)
local ciphers_out_ptr = ffi_new("const unsigned char*[1]")
local ext_out_ptr = ffi_new("int*[1]")
local ext_len_ptr = ffi_new("size_t[1]")

local _M = {
    _VERSION = utils._VERSION
}

local _hash_mode = true

function _M.configure(opts)
    if opts and opts.hash ~= nil then
        _hash_mode = opts.hash
    end
end

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

-- Extract cipher suite IDs via OpenSSL FFI (GREASE filtered).
local function get_ciphers_ffi(ssl_ptr)
    local nbytes = C.SSL_client_hello_get0_ciphers(ssl_ptr, ciphers_out_ptr)
    if nbytes == 0 then return {} end
    local ptr = ciphers_out_ptr[0]
    local count = tonumber(nbytes) / 2
    local ciphers = new_tab(count, 0)
    local n = 0
    for i = 0, count - 1 do
        local val = lshift(ptr[i * 2], 8) + ptr[i * 2 + 1]  -- big-endian
        if not is_grease(val) then
            n = n + 1
            ciphers[n] = val
        end
    end
    return ciphers
end

-- Extract extension type IDs via OpenSSL FFI (GREASE filtered).
local function get_extensions_ffi(ssl_ptr)
    local rc = C.SSL_client_hello_get1_extensions_present(ssl_ptr, ext_out_ptr, ext_len_ptr)
    if rc ~= 1 then return {} end
    local ext_arr = ext_out_ptr[0]
    local ext_count = tonumber(ext_len_ptr[0])
    local extensions = new_tab(ext_count, 0)
    local n = 0
    for i = 0, ext_count - 1 do
        local val = ext_arr[i]
        if not is_grease(val) then
            n = n + 1
            extensions[n] = val
        end
    end
    C.CRYPTO_free(ext_arr, "", 0)
    return extensions
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
            sc_len = write_hex4_csv_at(data.sig_algs, #data.sig_algs, csv_buf, sc_len + 1)
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
            pos = write_hex4_csv_at(data.sig_algs, #data.sig_algs, out_buf, pos)
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

    -- Ciphers (GREASE filtered by get_ciphers_ffi)
    local ciphers = get_ciphers_ffi(ssl_ptr)

    -- Extensions (GREASE filtered by get_extensions_ffi)
    local extensions = get_extensions_ffi(ssl_ptr)

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
