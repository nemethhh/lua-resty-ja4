-- Section 1: FFI imports & module setup
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_string = ffi.string
local ffi_copy = ffi.copy
local ffi_cast = ffi.cast
local bit = require "bit"
local band = bit.band
local rshift = bit.rshift
local byte = string.byte
local char = string.char
local str_lower = string.lower
local str_sub = string.sub
local str_find = string.find

local ok, new_tab = pcall(require, "table.new")
if not ok then
    new_tab = function() return {} end
end

local EMPTY_TAB = {}

local _M = {
    _VERSION = "0.1.0"
}

_M.new_tab = new_tab
_M.EMPTY_HASH = "000000000000"

-- Section 2: Lookup tables

-- HEX4: uint16 → 4-char hex string (INTERNAL, not exported)
local HEX4 = {}
for i = 0, 65535 do
    HEX4[i] = string.format("%04x", i)
end

-- Little-endian assertion
do
    local le_check = ffi_new("uint16_t[1]", 0x0001)
    assert(ffi.cast("uint8_t*", le_check)[0] == 1,
        "resty.ja4 requires little-endian architecture")
end

-- hex_pair: byte → uint16 hex pair (INTERNAL, used by sha256_to_buf)
local hex_ascii = "0123456789abcdef"
local hex_pair = ffi_new("uint16_t[256]")
for i = 0, 255 do
    local hi = rshift(i, 4) + 1
    local lo = band(i, 0x0f) + 1
    hex_pair[i] = byte(hex_ascii, hi) + byte(hex_ascii, lo) * 256
end

-- hex_chars: for write_u16_hex_csv nibble extraction
local hex_chars = ffi_new("const char[16]", "0123456789abcdef")

-- NUM2: two-digit decimal lookup (exported)
local NUM2 = {}
for i = 0, 99 do
    NUM2[i] = string.format("%02d", i)
end
_M.NUM2 = NUM2

-- Version maps
_M.LEGACY_VERSION_MAP = {
    [0x0304] = "13", [0x0303] = "12", [0x0302] = "11",
    [0x0301] = "10", [0x0300] = "s3", [0x0002] = "s2",
}

local TLS_VERSION_MAP = {
    ["TLSv1.3"] = "13",
    ["TLSv1.2"] = "12",
    ["TLSv1.1"] = "11",
    ["TLSv1"]   = "10",
    ["SSLv3"]   = "s3",
    ["SSLv2"]   = "s2",
}

-- Section 3: SHA256

ffi.cdef[[
typedef struct evp_md_st EVP_MD;
typedef struct engine_st ENGINE;
const EVP_MD *EVP_sha256(void);
int EVP_Digest(const void *data, size_t count,
               unsigned char *md, unsigned int *size,
               const EVP_MD *type, ENGINE *impl);
]]

local md_buf = ffi_new("unsigned char[32]")
local md_len = ffi_new("unsigned int[1]")
local sha256_md = ffi.C.EVP_sha256()
local evp_digest = ffi.C.EVP_Digest

-- SHA256 of FFI buffer → 12 hex bytes written directly into target buffer.
-- Uses hex_pair uint16 lookup: 18 FFI ops vs 36.
-- No intermediate buffer, no ffi_string allocation.
function _M.sha256_to_buf(input_buf, input_len, target_buf, target_pos)
    if input_len == 0 then
        evp_digest("", 0, md_buf, md_len, sha256_md, nil)
    else
        evp_digest(input_buf, input_len, md_buf, md_len, sha256_md, nil)
    end
    local out16 = ffi_cast("uint16_t*", target_buf + target_pos)
    out16[0] = hex_pair[md_buf[0]]
    out16[1] = hex_pair[md_buf[1]]
    out16[2] = hex_pair[md_buf[2]]
    out16[3] = hex_pair[md_buf[3]]
    out16[4] = hex_pair[md_buf[4]]
    out16[5] = hex_pair[md_buf[5]]
end

-- Section 4: Sorting

-- JIT-compilable insertion sort for 1-based Lua arrays (strings).
local function isort(t, n)
    for i = 2, n do
        local val = t[i]
        local j = i - 1
        while j >= 1 and t[j] > val do
            t[j + 1] = t[j]
            j = j - 1
        end
        t[j + 1] = val
    end
end
_M.isort = isort

-- 0-based insertion sort for FFI uint16_t arrays.
local function isort_u16(arr, n)
    for i = 1, n - 1 do
        local val = arr[i]
        local j = i - 1
        while j >= 0 and arr[j] > val do
            arr[j + 1] = arr[j]
            j = j - 1
        end
        arr[j + 1] = val
    end
end
_M.isort_u16 = isort_u16

-- Section 5: CSV serialization

-- FFI buffer for building comma-separated hex values (ja4 hash inputs).
local csv_buf = ffi_new("uint8_t[512]")
_M.csv_buf = csv_buf

-- Write uint16 FFI array as comma-separated 4-char hex into buf at offset.
local function write_u16_hex_csv(arr, n, buf, offset)
    if n == 0 then return offset end
    local pos = offset
    for i = 0, n - 1 do
        if i > 0 then
            buf[pos] = 0x2C  -- ','
            pos = pos + 1
        end
        local val = arr[i]
        buf[pos]     = hex_chars[rshift(val, 12)]
        buf[pos + 1] = hex_chars[band(rshift(val, 8), 0x0f)]
        buf[pos + 2] = hex_chars[band(rshift(val, 4), 0x0f)]
        buf[pos + 3] = hex_chars[band(val, 0x0f)]
        pos = pos + 4
    end
    return pos
end
_M.write_u16_hex_csv = write_u16_hex_csv

-- Write array of 4-char hex strings as CSV into arbitrary buffer at pos.
local function write_hex4_csv_at(hex_array, n, buf, pos)
    if n == 0 then return pos end
    for i = 1, n do
        if i > 1 then
            buf[pos] = 0x2C  -- ','
            pos = pos + 1
        end
        local s = hex_array[i]
        buf[pos]     = byte(s, 1)
        buf[pos + 1] = byte(s, 2)
        buf[pos + 2] = byte(s, 3)
        buf[pos + 3] = byte(s, 4)
        pos = pos + 4
    end
    return pos
end
_M.write_hex4_csv_at = write_hex4_csv_at

-- Write array of variable-length Lua strings as CSV into buffer at pos.
local function write_str_csv_at(str_array, n, buf, pos)
    if n == 0 then return pos end
    for i = 1, n do
        if i > 1 then
            buf[pos] = 0x2C  -- ','
            pos = pos + 1
        end
        local s = str_array[i]
        local slen = #s
        ffi_copy(buf + pos, s, slen)
        pos = pos + slen
    end
    return pos
end
_M.write_str_csv_at = write_str_csv_at

-- Section 6: GREASE detection

-- GREASE detection (RFC 8701): 0x0a0a, 0x1a1a, ..., 0xfafa
local function is_grease(val)
    local hi = rshift(val, 8)
    local lo = band(val, 0xff)
    return hi == lo and band(lo, 0x0f) == 0x0a
end
_M.is_grease = is_grease

-- Section 7: TLS parsing

function _M.tls_version_code(version_str)
    if not version_str then
        return "00"
    end
    return TLS_VERSION_MAP[version_str] or "00"
end

local function is_alnum(b)
    return (b >= 0x30 and b <= 0x39)
        or (b >= 0x41 and b <= 0x5A)
        or (b >= 0x61 and b <= 0x7A)
end

function _M.parse_alpn(raw)
    if not raw or #raw < 4 then
        return "00"
    end
    local proto_len = byte(raw, 3)
    if proto_len < 1 or 3 + proto_len > #raw then
        return "00"
    end
    local first_byte = byte(raw, 4)
    local last_byte = byte(raw, 3 + proto_len)
    if is_alnum(first_byte) and is_alnum(last_byte) then
        return char(first_byte, last_byte)
    else
        return HEX4[first_byte * 256 + last_byte]
    end
end

function _M.parse_sig_algs(raw)
    if not raw or #raw < 4 then
        return nil
    end
    local raw_len = #raw
    local list_len = byte(raw, 1) * 256 + byte(raw, 2)
    local count = rshift(list_len, 1)
    local max_count = rshift(raw_len - 2, 1)
    if count > max_count then count = max_count end
    local algs = new_tab(count, 0)
    for i = 1, count do
        local offset = 2 + (i - 1) * 2
        if offset + 2 > raw_len then break end
        local hi = byte(raw, offset + 1)
        local lo = byte(raw, offset + 2)
        algs[i] = HEX4[hi * 256 + lo]
    end
    return algs
end

-- Section 8: HTTP parsing

function _M.parse_accept_language(lang)
    if not lang or lang == "" then
        return "0000"
    end
    local comma = str_find(lang, ",", 1, true)
    local first
    if comma then
        first = str_sub(lang, 1, comma - 1)
    else
        first = lang
    end
    local semi = str_find(first, ";", 1, true)
    if semi then
        first = str_sub(first, 1, semi - 1)
    end
    local b1, b2, b3, b4 = 0x30, 0x30, 0x30, 0x30
    local cn = 0
    for i = 1, #first do
        local b = byte(first, i)
        if b ~= 0x2D then
            if b >= 0x41 and b <= 0x5A then
                b = b + 32
            end
            cn = cn + 1
            if cn == 1 then b1 = b
            elseif cn == 2 then b2 = b
            elseif cn == 3 then b3 = b
            elseif cn == 4 then b4 = b; break
            end
        end
    end
    return char(b1, b2, b3, b4)
end

function _M.parse_cookies_into(cookie_str, names, pairs_list)
    if not cookie_str or cookie_str == "" then
        for i = 1, #names do names[i] = nil end
        for i = 1, #pairs_list do pairs_list[i] = nil end
        return 0
    end
    local n = 0
    local len = #cookie_str
    local pos = 1
    while pos <= len do
        while pos <= len and byte(cookie_str, pos) == 0x20 do
            pos = pos + 1
        end
        if pos > len then break end
        local semi = str_find(cookie_str, "; ", pos, true)
        local seg_end = semi and (semi - 1) or len
        while seg_end >= pos and byte(cookie_str, seg_end) == 0x20 do
            seg_end = seg_end - 1
        end
        if seg_end >= pos then
            local eq = str_find(cookie_str, "=", pos, true)
            if eq and eq <= seg_end then
                local name_end = eq - 1
                while name_end >= pos and byte(cookie_str, name_end) == 0x20 do
                    name_end = name_end - 1
                end
                if name_end >= pos then
                    n = n + 1
                    names[n] = str_sub(cookie_str, pos, name_end)
                    pairs_list[n] = str_sub(cookie_str, pos, seg_end)
                end
            end
        end
        pos = semi and (semi + 2) or (len + 1)
    end
    local old_len = #names
    for i = n + 1, old_len do names[i] = nil end
    old_len = #pairs_list
    for i = n + 1, old_len do pairs_list[i] = nil end
    return n
end

function _M.parse_raw_header_names(raw)
    if not raw or raw == "" then
        return EMPTY_TAB, 0
    end
    local names = new_tab(12, 0)
    local n = 0
    local pos = 1
    local len = #raw
    while pos <= len do
        local cr = str_find(raw, "\r\n", pos, true)
        if not cr or cr == pos then
            break
        end
        local colon = str_find(raw, ":", pos, true)
        if colon and colon < cr then
            local name_len = colon - pos
            local skip = false
            if name_len == 6 then
                local b = byte(raw, pos)
                if b == 0x43 or b == 0x63 then
                    skip = (str_lower(str_sub(raw, pos, colon - 1)) == "cookie")
                end
            elseif name_len == 7 then
                local b = byte(raw, pos)
                if b == 0x52 or b == 0x72 then
                    skip = (str_lower(str_sub(raw, pos, colon - 1)) == "referer")
                end
            end
            if not skip then
                n = n + 1
                names[n] = str_sub(raw, pos, colon - 1)
            end
        end
        pos = cr + 2
    end
    return names, n
end

return _M
