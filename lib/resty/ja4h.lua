local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_string = ffi.string
local ffi_copy = ffi.copy
local byte = string.byte
local str_lower = string.lower
local str_sub = string.sub
local math_min = math.min
local utils = require "resty.ja4.utils"
local new_tab = utils.new_tab
local EMPTY_HASH = utils.EMPTY_HASH
local isort = utils.isort
local sha256_to_buf = utils.sha256_to_buf
local write_str_csv_at = utils.write_str_csv_at
local NUM2 = utils.NUM2
local ngx = ngx

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
            local names, pairs_list = utils.parse_cookies(data.cookie_str)
            if names and #names > 0 then
                -- Section C: sorted cookie names → hash
                isort(names, #names)
                local nlen = write_str_csv_at(names, #names, hash_buf, 0)
                sha256_to_buf(hash_buf, nlen, out_buf, pos)
                pos = pos + 12

                out_buf[pos] = 0x5F; pos = pos + 1

                -- Section D: sorted cookie pairs → hash
                isort(pairs_list, #pairs_list)
                local plen = write_str_csv_at(pairs_list, #pairs_list, hash_buf, 0)
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
            local names, pairs_list = utils.parse_cookies(data.cookie_str)
            if names and #names > 0 then
                isort(names, #names)
                pos = write_str_csv_at(names, #names, out_buf, pos)

                out_buf[pos] = 0x5F; pos = pos + 1

                isort(pairs_list, #pairs_list)
                pos = write_str_csv_at(pairs_list, #pairs_list, out_buf, pos)
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
