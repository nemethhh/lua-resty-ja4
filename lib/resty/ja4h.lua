local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_string = ffi.string
local ffi_copy = ffi.copy
local byte = string.byte
local str_lower = string.lower
local str_sub = string.sub
local math_min = math.min
local utils = require "resty.ja4.utils"

-- FFI header extraction for HTTP/2+ (reads headers_in via lua-resty-core FFI)
local base = require "resty.core.base"
local get_request = base.get_request
require "resty.core.request"  -- ensures header FFI types are cdef'd

local C = ffi.C
local table_elt_ct = ffi.typeof("ngx_http_lua_ffi_table_elt_t[?]")
local MAX_HDR = 100
local _hdr_buf = ffi_new(table_elt_ct, MAX_HDR)
local _hdr_truncated = ffi_new("int[1]")

local new_tab = utils.new_tab
local EMPTY_HASH = utils.EMPTY_HASH
local isort = utils.isort
local sha256_to_buf = utils.sha256_to_buf
local write_str_csv_at = utils.write_str_csv_at
local NUM2 = utils.NUM2
local ngx = ngx

local _cookie_names = new_tab(100, 0)
local _cookie_pairs = new_tab(100, 0)

local out_buf = ffi_new("uint8_t[4096]")
local hash_buf = ffi_new("uint8_t[4096]")  -- SHA256 input buffer for hash mode

local _M = {
    _VERSION = "0.1.0"
}

local _hash_mode = true

function _M.configure(opts)
    if opts and opts.hash ~= nil then
        _hash_mode = opts.hash
    end
end

-- Pre-computed 2-char lowercase method codes for common HTTP methods.
local METHOD_CODE = {
    GET = "ge", POST = "po", PUT = "pu", DELETE = "de",
    PATCH = "pa", HEAD = "he", OPTIONS = "op", CONNECT = "co",
    TRACE = "tr",
}

-- Case-insensitive byte match: compare FFI char* against Lua string (lowercase expected)
local function match_header(data, expected, len)
    for j = 0, len - 1 do
        local b = data[j]
        if b >= 0x41 and b <= 0x5A then b = b + 32 end  -- fold to lowercase
        if b ~= byte(expected, j + 1) then return false end
    end
    return true
end

-- Extract headers in order via FFI. Works for all HTTP versions.
-- Returns: names[], count, has_cookie, has_referer, cookie_values[], accept_lang
local function get_headers_ffi()
    local r = get_request()
    if not r then
        return {}, 0, false, false, nil, nil
    end

    local n = C.ngx_http_lua_ffi_req_get_headers_count(r, MAX_HDR, _hdr_truncated)
    if n <= 0 then
        return {}, 0, false, false, nil, nil
    end

    local buf
    if n <= MAX_HDR then
        buf = _hdr_buf
    else
        buf = ffi_new(table_elt_ct, n)
    end

    C.ngx_http_lua_ffi_req_get_headers(r, buf, n, 1)  -- raw=1: preserve original case

    local names = new_tab(n, 0)
    local name_count = 0
    local has_cookie = false
    local has_referer = false
    local cookie_values = nil
    local cookie_count = 0
    local accept_lang = nil

    for i = 0, n - 1 do
        local key_len = buf[i].key.len
        local key_data = buf[i].key.data

        if key_len == 6 and (key_data[0] == 0x43 or key_data[0] == 0x63) then
            if match_header(key_data, "cookie", 6) then
                has_cookie = true
                if not cookie_values then cookie_values = new_tab(4, 0) end
                cookie_count = cookie_count + 1
                cookie_values[cookie_count] = ffi_string(buf[i].value.data, buf[i].value.len)
            else
                name_count = name_count + 1
                names[name_count] = ffi_string(key_data, key_len)
            end
        elseif key_len == 7 and (key_data[0] == 0x52 or key_data[0] == 0x72) then
            if match_header(key_data, "referer", 7) then
                has_referer = true
            else
                name_count = name_count + 1
                names[name_count] = ffi_string(key_data, key_len)
            end
        else
            if key_len == 15 and not accept_lang
                and match_header(key_data, "accept-language", 15) then
                accept_lang = ffi_string(buf[i].value.data, buf[i].value.len)
            end
            name_count = name_count + 1
            names[name_count] = ffi_string(key_data, key_len)
        end
    end

    return names, name_count, has_cookie, has_referer, cookie_values, accept_lang
end

-- Build JA4H fingerprint from pre-extracted data.
-- Input table fields:
--   method: HTTP method string (e.g. "GET", "POST")
--   version: "10", "11", "20"
--   has_cookie: boolean
--   has_referer: boolean
--   header_names: array of header names in ORIGINAL CASE, in order (excluding Cookie, Referer)
--   accept_language: raw Accept-Language header value or nil
--   cookie_str: raw Cookie header value or nil
-- Returns: fingerprint string (hash or raw depending on configure), or nil, err
function _M.build(data)
    if not data then
        return nil, "no data"
    end

    -- Method: first 2 lowercase chars (table lookup for common methods)
    local method_code = METHOD_CODE[data.method]
    if not method_code then
        if data.method and #data.method >= 2 then
            method_code = str_lower(str_sub(data.method, 1, 2))
        else
            method_code = str_lower(data.method or "??")
        end
    end

    local header_count = math_min(#data.header_names, 99)
    local cookie_flag = data.has_cookie and "c" or "n"
    local referer_flag = data.has_referer and "r" or "n"
    local lang = utils.parse_accept_language(data.accept_language)

    -- Section A: 12 bytes directly into out_buf
    out_buf[0] = byte(method_code, 1); out_buf[1] = byte(method_code, 2)
    local ver = data.version
    out_buf[2] = byte(ver, 1); out_buf[3] = byte(ver, 2)
    out_buf[4] = byte(cookie_flag)
    out_buf[5] = byte(referer_flag)
    local hc = NUM2[header_count]
    out_buf[6] = byte(hc, 1); out_buf[7] = byte(hc, 2)
    out_buf[8] = byte(lang, 1); out_buf[9] = byte(lang, 2)
    out_buf[10] = byte(lang, 3); out_buf[11] = byte(lang, 4)

    out_buf[12] = 0x5F  -- '_'
    local pos = 13

    if _hash_mode then
        -- Section B: header names CSV → hash_buf → SHA256 → 12 hex to out_buf
        if #data.header_names == 0 then
            ffi_copy(out_buf + pos, EMPTY_HASH, 12)
        else
            local hlen = write_str_csv_at(data.header_names, #data.header_names, hash_buf, 0)
            sha256_to_buf(hash_buf, hlen, out_buf, pos)
        end
        pos = pos + 12

        out_buf[pos] = 0x5F; pos = pos + 1

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
    else
        -- Section B raw: header names CSV directly into out_buf
        pos = write_str_csv_at(data.header_names, #data.header_names, out_buf, pos)

        out_buf[pos] = 0x5F; pos = pos + 1

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
    end

    return ffi_string(out_buf, pos)
end

-- ngx.ctx storage
local CTX_KEY = "ja4h_fingerprint"

function _M.store(val)
    ngx.ctx[CTX_KEY] = val
end

function _M.get()
    return ngx.ctx[CTX_KEY]
end

_M._get_headers_ffi = get_headers_ffi

-- HTTP version from server_protocol string
local function get_http_version()
    local proto = ngx.var.server_protocol
    if not proto then
        return "00"
    end
    if proto == "HTTP/1.1" then return "11" end
    if proto == "HTTP/2.0" or proto == "HTTP/2" then return "20" end
    if proto == "HTTP/1.0" then return "10" end
    if proto == "HTTP/3.0" or proto == "HTTP/3" then return "30" end
    return "00"
end

-- Compute JA4H from current HTTP request context.
-- Returns: fingerprint string (or nil, err)
function _M.compute()
    local req = ngx.req
    local method = req.get_method()
    local version = get_http_version()

    local raw_header = req.raw_header(true)
    local header_names, header_count = utils.parse_raw_header_names(raw_header)

    local headers = req.get_headers(100)
    local has_cookie = headers["cookie"] ~= nil
    local has_referer = headers["referer"] ~= nil
    local accept_language = headers["accept-language"]
    local cookie_str = headers["cookie"]

    local result = _M.build({
        method          = method,
        version         = version,
        has_cookie      = has_cookie,
        has_referer     = has_referer,
        header_names    = header_names,
        accept_language = accept_language,
        cookie_str      = cookie_str,
    })

    _M.store(result)
    return result
end

return _M
