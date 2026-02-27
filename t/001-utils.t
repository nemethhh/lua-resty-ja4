use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

repeat_each(1);
plan tests => repeat_each() * 2 * 23;

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
ngx.say(utils.EMPTY_HASH)
--- response_body
000000000000

=== TEST 2: tls_version_code maps versions
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

=== TEST 3: parse_alpn extracts first+last char
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

=== TEST 4: parse_sig_algs extracts algorithms in order
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
local raw = "\x00\x10\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01"
local algs = utils.parse_sig_algs(raw)
ngx.say(table.concat(algs, ","))
--- response_body
0403,0804,0401,0503,0805,0501,0806,0601

=== TEST 5: parse_raw_header_names preserves ORIGINAL CASE
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

=== TEST 6: parse_accept_language
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

=== TEST 7: isort sorts small arrays
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

=== TEST 8: NUM2 produces zero-padded decimal strings
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

=== TEST 9: sha256_to_buf produces correct hash
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

=== TEST 10: write_hex4_csv_at writes CSV into arbitrary buffer
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

=== TEST 11: write_str_csv_at writes variable-length strings
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

=== TEST 12: parse_alpn with single-byte alphanumeric protocol
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
-- Single byte "h": [list_len=2][proto_len=1][proto='h']
local raw = "\x00\x02\x01\x68"
ngx.say(utils.parse_alpn(raw))
--- response_body
hh

=== TEST 13: parse_alpn with non-alphanumeric bytes (hex fallback)
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

=== TEST 14: parse_alpn with empty/short input
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

=== TEST 15: parse_raw_header_names with header containing multiple colons
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

=== TEST 16: parse_raw_header_names with only excluded headers
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

=== TEST 17: parse_raw_header_names with nil and empty input
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

=== TEST 18: parse_accept_language with quality value on first tag
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

=== TEST 19: parse_accept_language with single char
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
ngx.say(utils.parse_accept_language("x"))
--- response_body
x000

=== TEST 20: parse_accept_language with 3-char code (no hyphen)
--- http_config eval: $::HttpConfig
--- lua_code
local utils = require "resty.ja4.utils"
ngx.say(utils.parse_accept_language("ast"))
--- response_body
ast0

=== TEST 21: isort_u16 sorts FFI uint16 array
--- http_config eval: $::HttpConfig
--- lua_code
local ffi = require "ffi"
local utils = require "resty.ja4.utils"
local fmt = string.format
-- Same values as TEST 7 string sort: c02b, 002f, 1301, 0035, cca9
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

=== TEST 22: write_u16_hex_csv writes correct hex CSV
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

=== TEST 23: parse_cookies_into fills pre-allocated tables
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
