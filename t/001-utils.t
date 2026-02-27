use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

repeat_each(1);
plan tests => repeat_each() * 2 * 37;

no_shuffle();

my $pwd = cwd();

add_block_preprocessor(sub {
    my $block = shift;
    if (!defined $block->config) {
        $block->set_value("config", "
            location /t {
                content_by_lua_block {
                    " . $block->lua_code . "
                }
            }
        ");
    }
    if (!defined $block->request) {
        $block->set_value("request", "GET /t");
    }
});

our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;$pwd/lib/?/init.lua;;";
};

no_long_string();
log_level('warn');
run_tests();

__DATA__

=== TEST 1: utils module loads
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
ngx.say(utils._VERSION)
--- response_body
0.1.0

=== TEST 2: sha256_hex12 with empty string
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
ngx.say(utils.sha256_hex12(""))
--- response_body
e3b0c44298fc

=== TEST 3: sha256_hex12 with JA4 cipher test vector
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
local input = "002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"
ngx.say(utils.sha256_hex12(input))
--- response_body
8daaf6152771

=== TEST 4: sha256_hex12 with extension+sigalg test vector
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
local input = "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601"
ngx.say(utils.sha256_hex12(input))
--- response_body
e5627efa2ab1

=== TEST 5: to_hex4 formats values
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
ngx.say(utils.to_hex4(0x002f))
ngx.say(utils.to_hex4(0x1301))
ngx.say(utils.to_hex4(0xc02b))
ngx.say(utils.to_hex4(0x0000))
ngx.say(utils.to_hex4(0xff01))
--- response_body
002f
1301
c02b
0000
ff01

=== TEST 6: tls_version_code maps versions
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
ngx.say(utils.tls_version_code("TLSv1.3"))
ngx.say(utils.tls_version_code("TLSv1.2"))
ngx.say(utils.tls_version_code("TLSv1.1"))
ngx.say(utils.tls_version_code("TLSv1"))
ngx.say(utils.tls_version_code("SSLv3"))
ngx.say(utils.tls_version_code(nil))
--- response_body
13
12
11
10
s3
00

=== TEST 7: parse_alpn extracts first+last char
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
local alpn_h2 = "\x00\x03\x02\x68\x32"
ngx.say(utils.parse_alpn(alpn_h2))
local alpn_h1 = "\x00\x09\x08\x68\x74\x74\x70\x2f\x31\x2e\x31"
ngx.say(utils.parse_alpn(alpn_h1))
ngx.say(utils.parse_alpn(nil))
--- response_body
h2
h1
00

=== TEST 8: parse_sig_algs extracts algorithms in order
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
local raw = "\x00\x10\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01"
local algs = utils.parse_sig_algs(raw)
ngx.say(table.concat(algs, ","))
--- response_body
0403,0804,0401,0503,0805,0501,0806,0601

=== TEST 9: parse_cookies with standard cookie header
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
local names, pairs_list = utils.parse_cookies("session=abc123; user=john; theme=dark")
table.sort(names)
table.sort(pairs_list)
ngx.say("names: ", table.concat(names, ","))
ngx.say("pairs: ", table.concat(pairs_list, ","))
--- response_body
names: session,theme,user
pairs: session=abc123,theme=dark,user=john

=== TEST 10: parse_cookies with nil
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
local names, pairs_list = utils.parse_cookies(nil)
ngx.say("names: ", names == nil and "nil" or "not nil")
names, pairs_list = utils.parse_cookies("")
ngx.say("names2: ", names == nil and "nil" or "not nil")
--- response_body
names: nil
names2: nil

=== TEST 11: parse_raw_header_names preserves ORIGINAL CASE
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
local raw = "Host: example.com\r\nConnection: keep-alive\r\nUser-Agent: Mozilla\r\nAccept-Encoding: gzip\r\nCookie: a=1\r\nReferer: http://x.com\r\nAccept-Language: en-US\r\n\r\n"
local names, count = utils.parse_raw_header_names(raw)
ngx.say("names: ", table.concat(names, ","))
ngx.say("count: ", count)
--- response_body
names: Host,Connection,User-Agent,Accept-Encoding,Accept-Language
count: 5

=== TEST 12: parse_accept_language
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
ngx.say(utils.parse_accept_language("en-US,en;q=0.9"))
ngx.say(utils.parse_accept_language("fr-FR"))
ngx.say(utils.parse_accept_language("zh"))
ngx.say(utils.parse_accept_language(nil))
--- response_body
enus
frfr
zh00
0000

=== TEST 13: isort sorts small arrays
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
-- Numeric sort
local nums = {5, 3, 1, 4, 2}
utils.isort(nums, 5)
ngx.say("nums: ", table.concat(nums, ","))
-- String sort
local strs = {"c02b", "002f", "1301", "0035", "cca9"}
utils.isort(strs, 5)
ngx.say("strs: ", table.concat(strs, ","))
-- Already sorted
local sorted = {"a", "b", "c"}
utils.isort(sorted, 3)
ngx.say("sorted: ", table.concat(sorted, ","))
-- Single element
local one = {"x"}
utils.isort(one, 1)
ngx.say("one: ", table.concat(one, ","))
-- Empty
local empty = {}
utils.isort(empty, 0)
ngx.say("empty: ok")
--- response_body
nums: 1,2,3,4,5
strs: 002f,0035,1301,c02b,cca9
sorted: a,b,c
one: x
empty: ok

=== TEST 14: write_hex4_csv builds comma-separated hex into buffer
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
local ffi = require "ffi"
-- Test with typical cipher list (sorted)
local hexes = {"002f", "0035", "009c", "1301", "1302"}
local len = utils.write_hex4_csv(hexes, 5)
local result = ffi.string(utils.csv_buf, len)
ngx.say(result)
-- Test with single element
local one = {"c02b"}
len = utils.write_hex4_csv(one, 1)
result = ffi.string(utils.csv_buf, len)
ngx.say(result)
-- Test with empty
len = utils.write_hex4_csv({}, 0)
ngx.say("empty_len: ", len)
--- response_body
002f,0035,009c,1301,1302
c02b
empty_len: 0

=== TEST 15: sha256_hex12_buf produces same hash as sha256_hex12
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
local ffi = require "ffi"
-- Compare: string path vs buffer path for cipher test vector
local input = "002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"
local str_hash = utils.sha256_hex12(input)
-- Build same content via write_hex4_csv
local hexes = {"002f","0035","009c","009d","1301","1302","1303","c013","c014","c02b","c02c","c02f","c030","cca8","cca9"}
local len = utils.write_hex4_csv(hexes, 15)
local buf_hash = utils.sha256_hex12_buf(utils.csv_buf, len)
ngx.say("str: ", str_hash)
ngx.say("buf: ", buf_hash)
ngx.say("match: ", str_hash == buf_hash)
-- Empty buffer
local empty_hash = utils.sha256_hex12_buf(utils.csv_buf, 0)
ngx.say("empty: ", empty_hash)
--- response_body
str: 8daaf6152771
buf: 8daaf6152771
match: true
empty: e3b0c44298fc

=== TEST 16: hex_pair produces correct hex byte-pairs
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
local ffi = require "ffi"
local hex_pair = utils.hex_pair
local buf = ffi.new("uint8_t[2]")
local p = ffi.cast("uint16_t*", buf)
-- 0x00 → "00"
p[0] = hex_pair[0x00]
ngx.say(ffi.string(buf, 2))
-- 0xAB → "ab"
p[0] = hex_pair[0xAB]
ngx.say(ffi.string(buf, 2))
-- 0xFF → "ff"
p[0] = hex_pair[0xFF]
ngx.say(ffi.string(buf, 2))
-- 0x1A → "1a"
p[0] = hex_pair[0x1A]
ngx.say(ffi.string(buf, 2))
--- response_body
00
ab
ff
1a

=== TEST 17: NUM2 produces zero-padded decimal strings
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
ngx.say(utils.NUM2[0])
ngx.say(utils.NUM2[1])
ngx.say(utils.NUM2[9])
ngx.say(utils.NUM2[10])
ngx.say(utils.NUM2[42])
ngx.say(utils.NUM2[99])
--- response_body
00
01
09
10
42
99

=== TEST 18: sha256_to_buf produces correct hash
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
local ffi = require "ffi"
-- Build cipher CSV via write_u16_hex_csv
local arr = ffi.new("uint16_t[15]", 0x002f,0x0035,0x009c,0x009d,0x1301,0x1302,0x1303,0xc013,0xc014,0xc02b,0xc02c,0xc02f,0xc030,0xcca8,0xcca9)
local buf = ffi.new("uint8_t[256]")
local len = utils.write_u16_hex_csv(arr, 15, buf, 0)
-- Hash via sha256_to_buf
local target = ffi.new("uint8_t[64]")
utils.sha256_to_buf(buf, len, target, 5)
local result = ffi.string(target + 5, 12)
ngx.say("result: ", result)
-- Known SHA256 first 12 hex chars
ngx.say("match: ", result == "8daaf6152771")
-- Empty input
utils.sha256_to_buf(buf, 0, target, 0)
local empty = ffi.string(target, 12)
ngx.say("empty: ", empty)
--- response_body
result: 8daaf6152771
match: true
empty: e3b0c44298fc

=== TEST 19: write_hex4_csv_at writes CSV into arbitrary buffer
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
local ffi = require "ffi"
local buf = ffi.new("uint8_t[256]")
-- Write at offset 10
local hexes = {"002f", "0035", "1301"}
local pos = utils.write_hex4_csv_at(hexes, 3, buf, 10)
ngx.say("result: ", ffi.string(buf + 10, pos - 10))
ngx.say("pos: ", pos)
-- Single element
pos = utils.write_hex4_csv_at({"cca9"}, 1, buf, 0)
ngx.say("single: ", ffi.string(buf, pos))
-- Empty
pos = utils.write_hex4_csv_at({}, 0, buf, 5)
ngx.say("empty_pos: ", pos)
--- response_body
result: 002f,0035,1301
pos: 24
single: cca9
empty_pos: 5

=== TEST 20: write_str_csv_at writes variable-length strings
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
local ffi = require "ffi"
local buf = ffi.new("uint8_t[256]")
-- Headers
local pos = utils.write_str_csv_at({"Host", "Accept", "Accept-Language"}, 3, buf, 0)
ngx.say("headers: ", ffi.string(buf, pos))
-- Single
pos = utils.write_str_csv_at({"X-Custom"}, 1, buf, 0)
ngx.say("single: ", ffi.string(buf, pos))
-- Empty
pos = utils.write_str_csv_at({}, 0, buf, 7)
ngx.say("empty_pos: ", pos)
--- response_body
headers: Host,Accept,Accept-Language
single: X-Custom
empty_pos: 7

=== TEST 21: parse_alpn with single-byte alphanumeric protocol
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
-- Single byte "h": [list_len=2][proto_len=1][proto='h']
local raw = "\x00\x02\x01\x68"
ngx.say(utils.parse_alpn(raw))
--- response_body
hh

=== TEST 22: parse_alpn with non-alphanumeric bytes (hex fallback)
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
-- Single non-alnum byte 0x01: [list_len=2][proto_len=1][0x01]
local raw1 = "\x00\x02\x01\x01"
ngx.say("single: ", utils.parse_alpn(raw1))
-- Two non-alnum bytes 0x01,0x02: [list_len=3][proto_len=2][0x01][0x02]
local raw2 = "\x00\x03\x02\x01\x02"
ngx.say("double: ", utils.parse_alpn(raw2))
-- Note: parse_alpn returns 4-char hex for non-alnum via HEX4 lookup.
-- build() only uses the first 2 chars for the ALPN field.
--- response_body
single: 0101
double: 0102

=== TEST 23: parse_alpn with empty/short input
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
-- Proto length 0: [list_len=2][proto_len=0][padding]
ngx.say("zero_len: ", utils.parse_alpn("\x00\x02\x00\x00"))
-- Too short (< 4 bytes)
ngx.say("short: ", utils.parse_alpn("\x00\x02"))
--- response_body
zero_len: 00
short: 00

=== TEST 24: parse_cookies with trailing semicolon
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
local names, pairs_list = utils.parse_cookies("a=1; b=2; ")
table.sort(names)
table.sort(pairs_list)
ngx.say("count: ", #names)
ngx.say("names: ", table.concat(names, ","))
ngx.say("pairs: ", table.concat(pairs_list, ","))
--- response_body
count: 2
names: a,b
pairs: a=1,b=2

=== TEST 25: parse_cookies with missing value
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
-- Cookie with empty value
local names, pairs_list = utils.parse_cookies("name=")
ngx.say("name: ", names[1])
ngx.say("pair: ", pairs_list[1])
-- Cookie without '=' sign should be skipped
local n2, p2 = utils.parse_cookies("invalid")
ngx.say("no_eq: ", n2 == nil and "nil" or "not nil")
--- response_body
name: name
pair: name=
no_eq: nil

=== TEST 26: parse_cookies with leading/trailing spaces
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
local names, pairs_list = utils.parse_cookies("  session=abc ; token=xyz  ")
table.sort(names)
table.sort(pairs_list)
ngx.say("names: ", table.concat(names, ","))
ngx.say("pairs: ", table.concat(pairs_list, ","))
--- response_body
names: session,token
pairs: session=abc,token=xyz

=== TEST 27: parse_cookies with single cookie
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
local names, pairs_list = utils.parse_cookies("session=abc123")
ngx.say("count: ", #names)
ngx.say("name: ", names[1])
ngx.say("pair: ", pairs_list[1])
--- response_body
count: 1
name: session
pair: session=abc123

=== TEST 28: parse_raw_header_names with header containing multiple colons
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
local raw = "X-Forwarded-For: host:8080\r\nAuthorization: Bearer:token\r\n\r\n"
local names, count = utils.parse_raw_header_names(raw)
ngx.say("count: ", count)
ngx.say("names: ", table.concat(names, ","))
--- response_body
count: 2
names: X-Forwarded-For,Authorization

=== TEST 29: parse_raw_header_names with only excluded headers
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
local raw = "Cookie: a=1\r\nReferer: http://x.com\r\n\r\n"
local names, count = utils.parse_raw_header_names(raw)
ngx.say("count: ", count)
ngx.say("empty: ", #names == 0 and "yes" or "no")
--- response_body
count: 0
empty: yes

=== TEST 30: parse_raw_header_names with nil and empty input
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
local names1, count1 = utils.parse_raw_header_names(nil)
ngx.say("nil_count: ", count1)
local names2, count2 = utils.parse_raw_header_names("")
ngx.say("empty_count: ", count2)
--- response_body
nil_count: 0
empty_count: 0

=== TEST 31: parse_accept_language with quality value on first tag
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
-- Quality value should be stripped before parsing
ngx.say(utils.parse_accept_language("de-DE;q=0.9"))
-- Multiple languages, quality on first
ngx.say(utils.parse_accept_language("fr;q=0.8,en-US"))
--- response_body
dede
fr00

=== TEST 32: parse_accept_language with single char
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
ngx.say(utils.parse_accept_language("x"))
--- response_body
x000

=== TEST 33: parse_accept_language with 3-char code (no hyphen)
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
ngx.say(utils.parse_accept_language("ast"))
--- response_body
ast0

=== TEST 34: isort_u16 sorts FFI uint16 array
--- http_config eval: $::HttpConfig
--- lua_code
local ffi = require "ffi"
local utils = require "resty.ja4.utils"
local fmt = string.format
-- Same values as TEST 13 string sort: c02b, 002f, 1301, 0035, cca9
local arr = ffi.new("uint16_t[5]", 0xc02b, 0x002f, 0x1301, 0x0035, 0xcca9)
utils.isort_u16(arr, 5)
local result = {}
for i = 0, 4 do result[i+1] = fmt("%04x", arr[i]) end
ngx.say("sorted: ", table.concat(result, ","))
-- Edge cases
local one = ffi.new("uint16_t[1]", 0x1301)
utils.isort_u16(one, 1)
ngx.say("one: ", fmt("%04x", one[0]))
utils.isort_u16(one, 0)
ngx.say("empty: ok")
-- Already sorted
local pre = ffi.new("uint16_t[3]", 0x0001, 0x0002, 0x0003)
utils.isort_u16(pre, 3)
ngx.say("pre: ", fmt("%04x", pre[0]), ",", fmt("%04x", pre[1]), ",", fmt("%04x", pre[2]))
--- response_body
sorted: 002f,0035,1301,c02b,cca9
one: 1301
empty: ok
pre: 0001,0002,0003

=== TEST 35: write_u16_hex_csv writes correct hex CSV
--- http_config eval: $::HttpConfig
--- lua_code
local ffi = require "ffi"
local utils = require "resty.ja4.utils"
local buf = ffi.new("uint8_t[256]")
-- 5 elements
local arr = ffi.new("uint16_t[5]", 0x002f, 0x0035, 0x009c, 0x1301, 0x1302)
local pos = utils.write_u16_hex_csv(arr, 5, buf, 0)
ngx.say("value: ", ffi.string(buf, pos))
-- Single element
pos = utils.write_u16_hex_csv(ffi.new("uint16_t[1]", 0xcca9), 1, buf, 0)
ngx.say("single: ", ffi.string(buf, pos))
-- Empty
pos = utils.write_u16_hex_csv(arr, 0, buf, 5)
ngx.say("empty_pos: ", pos)
-- At offset
pos = utils.write_u16_hex_csv(ffi.new("uint16_t[2]", 0x000a, 0x000d), 2, buf, 10)
ngx.say("offset: ", ffi.string(buf + 10, pos - 10))
--- response_body
value: 002f,0035,009c,1301,1302
single: cca9
empty_pos: 5
offset: 000a,000d

=== TEST 36: parse_cookies_into fills pre-allocated tables
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
-- Pre-allocate tables
local names = {}
local pairs_list = {}
-- First call
local n = utils.parse_cookies_into("session=abc123; user=john; theme=dark", names, pairs_list)
ngx.say("count: ", n)
table.sort(names)
table.sort(pairs_list)
ngx.say("names: ", table.concat(names, ","))
ngx.say("pairs: ", table.concat(pairs_list, ","))
-- Second call with fewer cookies (verifies stale entry cleanup)
n = utils.parse_cookies_into("a=1", names, pairs_list)
ngx.say("count2: ", n)
ngx.say("len: ", #names)
ngx.say("name2: ", names[1])
-- nil/empty input
n = utils.parse_cookies_into(nil, names, pairs_list)
ngx.say("nil: ", n)
n = utils.parse_cookies_into("", names, pairs_list)
ngx.say("empty: ", n)
--- response_body
count: 3
names: session,theme,user
pairs: session=abc123,theme=dark,user=john
count2: 1
len: 1
name2: a
nil: 0
empty: 0

=== TEST 37: parse_raw_header_names_into fills pre-allocated table
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
local names = {}
local raw = "Host: example.com\r\nCookie: a=1\r\nUser-Agent: Mozilla\r\nReferer: http://x.com\r\nAccept: */*\r\n\r\n"
local n = utils.parse_raw_header_names_into(raw, names)
ngx.say("count: ", n)
ngx.say("names: ", table.concat(names, ",", 1, n))
-- Second call with fewer headers (stale cleanup)
n = utils.parse_raw_header_names_into("Host: x\r\n\r\n", names)
ngx.say("count2: ", n)
ngx.say("len: ", #names)
-- nil/empty
n = utils.parse_raw_header_names_into(nil, names)
ngx.say("nil: ", n)
--- response_body
count: 3
names: Host,User-Agent,Accept
count2: 1
len: 1
nil: 0
