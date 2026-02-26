use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

repeat_each(1);
plan tests => repeat_each() * 2 * 8;

no_shuffle();

my $pwd = cwd();

our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;$pwd/lib/?/init.lua;;";
};

no_long_string();
log_level('warn');
run_tests();

__DATA__

=== TEST 1: FFI returns ordered header names (count > 0, contains Host)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            local names, count = ja4h._get_headers_ffi()
            ngx.say("count_gt_0: ", count > 0 and "yes" or "no")
            local has_host = false
            for i = 1, count do
                if names[i] == "Host" then has_host = true end
            end
            ngx.say("has_host: ", has_host and "yes" or "no")
        }
    }
--- request
GET /t
--- response_body
count_gt_0: yes
has_host: yes

=== TEST 2: FFI excludes cookie and referer, sets flags correctly
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            local names, count, has_cookie, has_referer = ja4h._get_headers_ffi()
            ngx.say("has_cookie: ", has_cookie and "yes" or "no")
            ngx.say("has_referer: ", has_referer and "yes" or "no")
            -- Verify Cookie and Referer are NOT in names list
            local found_cookie = false
            local found_referer = false
            for i = 1, count do
                local lower = names[i]:lower()
                if lower == "cookie" then found_cookie = true end
                if lower == "referer" then found_referer = true end
            end
            ngx.say("cookie_in_names: ", found_cookie and "yes" or "no")
            ngx.say("referer_in_names: ", found_referer and "yes" or "no")
        }
    }
--- request
GET /t
--- more_headers
Cookie: session=abc123
Referer: http://example.com
--- response_body
has_cookie: yes
has_referer: yes
cookie_in_names: no
referer_in_names: no

=== TEST 3: FFI collects cookie values into array
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            local names, count, has_cookie, has_referer, cookie_values = ja4h._get_headers_ffi()
            ngx.say("has_cookie: ", has_cookie and "yes" or "no")
            ngx.say("cookie_is_table: ", type(cookie_values) == "table" and "yes" or "no")
            ngx.say("cookie_count: ", cookie_values and #cookie_values or 0)
            if cookie_values and #cookie_values > 0 then
                ngx.say("cookie_1: ", cookie_values[1])
            end
        }
    }
--- request
GET /t
--- more_headers
Cookie: a=1; b=2
--- response_body
has_cookie: yes
cookie_is_table: yes
cookie_count: 1
cookie_1: a=1; b=2

=== TEST 4: FFI extracts accept-language value
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            local names, count, has_cookie, has_referer, cookie_values, accept_lang = ja4h._get_headers_ffi()
            ngx.say("accept_lang: ", accept_lang or "nil")
        }
    }
--- request
GET /t
--- more_headers
Accept-Language: fr-FR,en;q=0.5
--- response_body
accept_lang: fr-FR,en;q=0.5

=== TEST 5: FFI no cookie, no referer, no accept-language gives correct defaults
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            local names, count, has_cookie, has_referer, cookie_values, accept_lang = ja4h._get_headers_ffi()
            ngx.say("has_cookie: ", has_cookie and "yes" or "no")
            ngx.say("has_referer: ", has_referer and "yes" or "no")
            ngx.say("cookie_values: ", cookie_values == nil and "nil" or "not nil")
            ngx.say("accept_lang: ", accept_lang == nil and "nil" or "not nil")
        }
    }
--- request
GET /t
--- response_body
has_cookie: no
has_referer: no
cookie_values: nil
accept_lang: nil

=== TEST 6: FFI preserves header order (X-First, X-Second, X-Third)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            local names, count = ja4h._get_headers_ffi()
            -- Collect only X- headers to check order
            local x_headers = {}
            for i = 1, count do
                if names[i]:sub(1, 2) == "X-" then
                    x_headers[#x_headers + 1] = names[i]
                end
            end
            ngx.say("x_count: ", #x_headers)
            for i = 1, #x_headers do
                ngx.say("x_" .. i .. ": ", x_headers[i])
            end
        }
    }
--- request
GET /t
--- more_headers
X-First: 1
X-Second: 2
X-Third: 3
--- response_body
x_count: 3
x_1: X-First
x_2: X-Second
x_3: X-Third

=== TEST 7: FFI path header names match raw_header() path names
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            local utils = require "resty.ja4.utils"

            -- FFI path
            local ffi_names, ffi_count = ja4h._get_headers_ffi()

            -- raw_header() path
            local raw = ngx.req.raw_header(true)
            local raw_names, raw_count = utils.parse_raw_header_names(raw)

            ngx.say("count_match: ", ffi_count == raw_count and "yes" or "no")
            local all_match = true
            for i = 1, ffi_count do
                if ffi_names[i] ~= raw_names[i] then
                    all_match = false
                    ngx.say("mismatch at ", i, ": ffi=", ffi_names[i], " raw=", raw_names[i])
                end
            end
            ngx.say("names_match: ", all_match and "yes" or "no")
        }
    }
--- request
GET /t
--- more_headers
Accept: text/html
User-Agent: TestBot/1.0
Accept-Language: en-US
--- response_body
count_match: yes
names_match: yes

=== TEST 8: FFI handles many headers (10+)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            local names, count, has_cookie, has_referer, cookie_values, accept_lang = ja4h._get_headers_ffi()
            -- Host + Connection + 8 custom + Accept-Language = 11 (Cookie, Referer excluded)
            ngx.say("count: ", count)
            ngx.say("has_cookie: ", has_cookie and "yes" or "no")
            ngx.say("has_referer: ", has_referer and "yes" or "no")
            ngx.say("accept_lang: ", accept_lang or "nil")
        }
    }
--- request
GET /t
--- more_headers
X-Header-01: v1
X-Header-02: v2
X-Header-03: v3
X-Header-04: v4
X-Header-05: v5
X-Header-06: v6
X-Header-07: v7
X-Header-08: v8
Cookie: k=v
Referer: http://example.com
Accept-Language: de-DE
--- response_body
count: 11
has_cookie: yes
has_referer: yes
accept_lang: de-DE
