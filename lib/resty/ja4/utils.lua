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

-- Pre-computed uint16 → 4-char hex string lookup table.
-- Built once at module load (~256KB). Eliminates ffi_string allocations
-- from the hot path — every to_hex4() call becomes a single table index.
local HEX4 = {}
for i = 0, 65535 do
    HEX4[i] = string.format("%04x", i)
end

-- SHA256 via OpenSSL FFI
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

local hex_chars = ffi_new("const char[16]", "0123456789abcdef")
local hex_out = ffi_new("uint8_t[12]")

-- FFI buffer for building comma-separated hex values (ja4 hash inputs).
-- Max size: 99 ciphers × 5 bytes ("xxxx,") = 495 bytes. 512 with margin.
local csv_buf = ffi_new("uint8_t[512]")
_M.csv_buf = csv_buf

-- Little-endian assertion (required for hex_pair uint16 layout)
do
    local le_check = ffi_new("uint16_t[1]", 0x0001)
    assert(ffi.cast("uint8_t*", le_check)[0] == 1,
        "resty.ja4 requires little-endian architecture")
end

-- Byte → hex-pair lookup (uint16, LE).
-- hex_pair[byte_value] = uint16 that stores two ASCII hex chars
-- in memory as [hi_nibble_char, lo_nibble_char] on LE architectures.
-- Halves SHA256 hex conversion from 36 to 18 FFI operations.
local hex_ascii = "0123456789abcdef"
local hex_pair = ffi_new("uint16_t[256]")
for i = 0, 255 do
    local hi = rshift(i, 4) + 1
    local lo = band(i, 0x0f) + 1
    hex_pair[i] = byte(hex_ascii, hi) + byte(hex_ascii, lo) * 256
end
_M.hex_pair = hex_pair

-- Two-digit decimal lookup: NUM2[0]="00" .. NUM2[99]="99".
-- Replaces str_format("%02d", n) in section A construction.
local NUM2 = {}
for i = 0, 99 do
    NUM2[i] = string.format("%02d", i)
end
_M.NUM2 = NUM2

function _M.sha256_hex12(str)
    if not str or str == "" then
        evp_digest("", 0, md_buf, md_len, sha256_md, nil)
    else
        evp_digest(str, #str, md_buf, md_len, sha256_md, nil)
    end
    local b
    b = md_buf[0]; hex_out[0]  = hex_chars[rshift(b, 4)]; hex_out[1]  = hex_chars[band(b, 0x0f)]
    b = md_buf[1]; hex_out[2]  = hex_chars[rshift(b, 4)]; hex_out[3]  = hex_chars[band(b, 0x0f)]
    b = md_buf[2]; hex_out[4]  = hex_chars[rshift(b, 4)]; hex_out[5]  = hex_chars[band(b, 0x0f)]
    b = md_buf[3]; hex_out[6]  = hex_chars[rshift(b, 4)]; hex_out[7]  = hex_chars[band(b, 0x0f)]
    b = md_buf[4]; hex_out[8]  = hex_chars[rshift(b, 4)]; hex_out[9]  = hex_chars[band(b, 0x0f)]
    b = md_buf[5]; hex_out[10] = hex_chars[rshift(b, 4)]; hex_out[11] = hex_chars[band(b, 0x0f)]
    return ffi_string(hex_out, 12)
end

-- SHA256 of FFI buffer contents -> 12-char hex string.
-- Like sha256_hex12 but takes an FFI buffer + length, avoiding Lua string creation.
function _M.sha256_hex12_buf(buf, len)
    if len == 0 then
        evp_digest("", 0, md_buf, md_len, sha256_md, nil)
    else
        evp_digest(buf, len, md_buf, md_len, sha256_md, nil)
    end
    local b
    b = md_buf[0]; hex_out[0]  = hex_chars[rshift(b, 4)]; hex_out[1]  = hex_chars[band(b, 0x0f)]
    b = md_buf[1]; hex_out[2]  = hex_chars[rshift(b, 4)]; hex_out[3]  = hex_chars[band(b, 0x0f)]
    b = md_buf[2]; hex_out[4]  = hex_chars[rshift(b, 4)]; hex_out[5]  = hex_chars[band(b, 0x0f)]
    b = md_buf[3]; hex_out[6]  = hex_chars[rshift(b, 4)]; hex_out[7]  = hex_chars[band(b, 0x0f)]
    b = md_buf[4]; hex_out[8]  = hex_chars[rshift(b, 4)]; hex_out[9]  = hex_chars[band(b, 0x0f)]
    b = md_buf[5]; hex_out[10] = hex_chars[rshift(b, 4)]; hex_out[11] = hex_chars[band(b, 0x0f)]
    return ffi_string(hex_out, 12)
end

-- SHA256 of FFI buffer contents → 12 hex bytes written directly into target buffer.
-- Uses hex_pair uint16 lookup: 18 FFI ops vs 36 in sha256_hex12/sha256_hex12_buf.
-- No intermediate buffer, no ffi_string allocation.
-- Note: uint16 writes may be unaligned; OK on x86/x64 and aarch64 (LE asserted above).
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

-- Format uint16 as 4-char lowercase hex (zero-allocation table lookup)
local function to_hex4(val)
    return HEX4[val]
end
_M.to_hex4 = to_hex4

-- JIT-compilable insertion sort for small arrays.
-- O(n²) but fully JIT-compiled vs table_sort's O(n log n) in interpreter.
-- table_sort is NYI in LuaJIT, forcing JIT→interpreter transitions.
-- For n ≤ 40 (our max), insertion sort in machine code wins.
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

-- Write array of 4-char hex strings as comma-separated values into csv_buf.
-- Returns: byte count written. Caller reads csv_buf[0..len-1].
local function write_hex4_csv(hex_array, n)
    if n == 0 then return 0 end
    local pos = 0
    for i = 1, n do
        if i > 1 then
            csv_buf[pos] = 0x2C  -- ','
            pos = pos + 1
        end
        local s = hex_array[i]
        csv_buf[pos]     = byte(s, 1)
        csv_buf[pos + 1] = byte(s, 2)
        csv_buf[pos + 2] = byte(s, 3)
        csv_buf[pos + 3] = byte(s, 4)
        pos = pos + 4
    end
    return pos
end
_M.write_hex4_csv = write_hex4_csv

-- Append array of 4-char hex strings to csv_buf starting at offset.
-- Returns: new offset (byte count from start).
local function append_hex4_csv(hex_array, n, offset)
    if n == 0 then return offset end
    local pos = offset
    for i = 1, n do
        if pos > offset then
            csv_buf[pos] = 0x2C  -- ','
            pos = pos + 1
        end
        local s = hex_array[i]
        csv_buf[pos]     = byte(s, 1)
        csv_buf[pos + 1] = byte(s, 2)
        csv_buf[pos + 2] = byte(s, 3)
        csv_buf[pos + 3] = byte(s, 4)
        pos = pos + 4
    end
    return pos
end
_M.append_hex4_csv = append_hex4_csv

-- Write array of 4-char hex strings as CSV into arbitrary buffer at pos.
-- Returns: new pos after last byte written.
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
-- Returns: new pos after last byte written.
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

-- TLS version string to 2-char code
local TLS_VERSION_MAP = {
    ["TLSv1.3"] = "13",
    ["TLSv1.2"] = "12",
    ["TLSv1.1"] = "11",
    ["TLSv1"]   = "10",
    ["SSLv3"]   = "s3",
    ["SSLv2"]   = "s2",
}

function _M.tls_version_code(version_str)
    if not version_str then
        return "00"
    end
    return TLS_VERSION_MAP[version_str] or "00"
end

-- Check if byte is alphanumeric ASCII (0-9, A-Z, a-z)
local function is_alnum(b)
    return (b >= 0x30 and b <= 0x39)
        or (b >= 0x41 and b <= 0x5A)
        or (b >= 0x61 and b <= 0x7A)
end

-- Parse ALPN extension raw bytes.
-- Returns: 2-char string (first+last alphanumeric char of first protocol), "00" if absent.
function _M.parse_alpn(raw)
    if not raw or #raw < 4 then
        return "00"
    end
    -- [2B list_len] [1B proto_len] [NB proto_string] ...
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

-- Parse Signature Algorithms extension raw bytes.
-- Returns: array of 4-char hex strings in original order, or nil.
function _M.parse_sig_algs(raw)
    if not raw or #raw < 4 then
        return nil
    end
    local raw_len = #raw
    -- [2B list_len] [2B alg] [2B alg] ...
    local list_len = byte(raw, 1) * 256 + byte(raw, 2)
    local count = rshift(list_len, 1)
    -- Cap to actual available data
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

-- Parse Cookie header string into names and name=value pairs.
-- Returns: names_array, pairs_array  (or nil, nil if no cookies)
-- Names and pairs are NOT sorted (caller sorts as needed).
function _M.parse_cookies(cookie_str)
    if not cookie_str or cookie_str == "" then
        return nil, nil
    end

    local names = new_tab(8, 0)
    local pairs_list = new_tab(8, 0)
    local n = 0
    local len = #cookie_str
    local pos = 1

    while pos <= len do
        -- Skip leading spaces
        while pos <= len and byte(cookie_str, pos) == 0x20 do
            pos = pos + 1
        end
        if pos > len then break end

        -- Find end of this cookie pair ("; " delimiter or end of string)
        local semi = str_find(cookie_str, "; ", pos, true)
        local seg_end = semi and (semi - 1) or len

        -- Trim trailing spaces from segment
        while seg_end >= pos and byte(cookie_str, seg_end) == 0x20 do
            seg_end = seg_end - 1
        end

        if seg_end >= pos then
            -- Find '=' within the segment boundaries
            local eq = str_find(cookie_str, "=", pos, true)
            if eq and eq <= seg_end then
                -- Trim trailing spaces before '='
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

    if n == 0 then
        return nil, nil
    end

    return names, pairs_list
end

-- Parse raw header block, extract header names in order.
-- PRESERVES ORIGINAL CASE for hashing (JA4H spec requires original case).
-- Excludes Cookie and Referer (case-insensitive check).
-- Returns: names_array, count
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

        -- Find colon directly between pos and cr (skip full line extraction)
        local colon = str_find(raw, ":", pos, true)
        if colon and colon < cr then
            local name_len = colon - pos
            local skip = false
            -- Check "cookie" (6 chars) by length + first byte
            if name_len == 6 then
                local b = byte(raw, pos)
                if b == 0x43 or b == 0x63 then  -- 'C' or 'c'
                    skip = (str_lower(str_sub(raw, pos, colon - 1)) == "cookie")
                end
            -- Check "referer" (7 chars) by length + first byte
            elseif name_len == 7 then
                local b = byte(raw, pos)
                if b == 0x52 or b == 0x72 then  -- 'R' or 'r'
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

-- Parse Accept-Language header value.
-- Returns: 4-char lowercase code (e.g. "enus"), "0000" if absent.
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

    -- Remove hyphens, lowercase, collect up to 4 bytes
    local b1, b2, b3, b4 = 0x30, 0x30, 0x30, 0x30  -- "0"
    local cn = 0
    for i = 1, #first do
        local b = byte(first, i)
        if b ~= 0x2D then  -- not '-'
            if b >= 0x41 and b <= 0x5A then
                b = b + 32  -- lowercase
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

return _M
