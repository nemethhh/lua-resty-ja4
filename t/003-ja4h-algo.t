use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

repeat_each(1);
plan tests => repeat_each() * 2 * 18;

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

=== TEST 1: JA4H build with test vector (HEAD request, no cookies)
--- http_config eval: $::HttpConfig
--- lua_code
local ja4h = require "resty.ja4h"
local result = ja4h.build({
    method          = "HEAD",
    version         = "11",
    has_cookie      = false,
    has_referer     = false,
    header_names    = {"Host", "Connection", "User-Agent", "Accept-Encoding", "Accept-Language"},
    accept_language = "en-US",
    cookie_str      = nil,
})
ngx.say("hash: ", result)
--- response_body
hash: he11nn05enus_6f8992deff94_000000000000_000000000000

=== TEST 2: JA4H build with cookies
--- http_config eval: $::HttpConfig
--- lua_code
local ja4h = require "resty.ja4h"
local result = ja4h.build({
    method          = "GET",
    version         = "20",
    has_cookie      = true,
    has_referer     = true,
    header_names    = {"Host", "User-Agent", "Accept"},
    accept_language = "fr-FR",
    cookie_str      = "b=2; a=1",
})
ngx.say("a: ", result:sub(1, 12))
--- response_body
a: ge20cr03frfr

=== TEST 3: JA4H build with no headers
--- http_config eval: $::HttpConfig
--- lua_code
local ja4h = require "resty.ja4h"
local result = ja4h.build({
    method          = "POST",
    version         = "11",
    has_cookie      = false,
    has_referer     = false,
    header_names    = {},
    accept_language = nil,
    cookie_str      = nil,
})
ngx.say("a: ", result:sub(1, 12))
--- response_body
a: po11nn000000

=== TEST 4: JA4H store and get round-trip
--- http_config eval: $::HttpConfig
--- lua_code
local ja4h = require "resty.ja4h"
ja4h.store("test_hash")
ngx.say("result: ", ja4h.get())
--- response_body
result: test_hash

=== TEST 5: JA4H format has 4 underscore-separated sections
--- http_config eval: $::HttpConfig
--- lua_code
local ja4h = require "resty.ja4h"
local result = ja4h.build({
    method          = "GET",
    version         = "11",
    has_cookie      = true,
    has_referer     = false,
    header_names    = {"Host", "Accept"},
    accept_language = "en-US",
    cookie_str      = "a=1; b=2",
})
local parts = {}
for part in result:gmatch("[^_]+") do
    parts[#parts + 1] = part
end
ngx.say("sections: ", #parts)
ngx.say("b_len: ", #parts[2])
ngx.say("c_len: ", #parts[3])
ngx.say("d_len: ", #parts[4])
--- response_body
sections: 4
b_len: 12
c_len: 12
d_len: 12

=== TEST 6: JA4H build hash=false produces raw output
--- http_config eval: $::HttpConfig
--- lua_code
local ja4h = require "resty.ja4h"
ja4h.configure({ hash = false })
local result = ja4h.build({
    method          = "HEAD",
    version         = "11",
    has_cookie      = false,
    has_referer     = false,
    header_names    = {"Host", "Connection", "User-Agent", "Accept-Encoding", "Accept-Language"},
    accept_language = "en-US",
    cookie_str      = nil,
})
ngx.say(result)
--- response_body
he11nn05enus_Host,Connection,User-Agent,Accept-Encoding,Accept-Language__

=== TEST 7: JA4H build() with nil data returns error
--- http_config eval: $::HttpConfig
--- lua_code
local ja4h = require "resty.ja4h"
local result, err = ja4h.build(nil)
ngx.say("result: ", result == nil and "nil" or "not nil")
ngx.say("err: ", err)
--- response_body
result: nil
err: no data

=== TEST 8: JA4H build with PUT method
--- http_config eval: $::HttpConfig
--- lua_code
local ja4h = require "resty.ja4h"
local result = ja4h.build({
    method = "PUT", version = "11",
    has_cookie = false, has_referer = false,
    header_names = {"Host"}, accept_language = nil, cookie_str = nil,
})
ngx.say("method: ", result:sub(1, 2))
--- response_body
method: pu

=== TEST 9: JA4H build with DELETE method
--- http_config eval: $::HttpConfig
--- lua_code
local ja4h = require "resty.ja4h"
local result = ja4h.build({
    method = "DELETE", version = "11",
    has_cookie = false, has_referer = false,
    header_names = {"Host"}, accept_language = nil, cookie_str = nil,
})
ngx.say("method: ", result:sub(1, 2))
--- response_body
method: de

=== TEST 10: JA4H build with PATCH method
--- http_config eval: $::HttpConfig
--- lua_code
local ja4h = require "resty.ja4h"
local result = ja4h.build({
    method = "PATCH", version = "11",
    has_cookie = false, has_referer = false,
    header_names = {"Host"}, accept_language = nil, cookie_str = nil,
})
ngx.say("method: ", result:sub(1, 2))
--- response_body
method: pa

=== TEST 11: JA4H build with OPTIONS method
--- http_config eval: $::HttpConfig
--- lua_code
local ja4h = require "resty.ja4h"
local result = ja4h.build({
    method = "OPTIONS", version = "11",
    has_cookie = false, has_referer = false,
    header_names = {"Host"}, accept_language = nil, cookie_str = nil,
})
ngx.say("method: ", result:sub(1, 2))
--- response_body
method: op

=== TEST 12: JA4H build with HTTP/1.0
--- http_config eval: $::HttpConfig
--- lua_code
local ja4h = require "resty.ja4h"
local result = ja4h.build({
    method = "GET", version = "10",
    has_cookie = false, has_referer = false,
    header_names = {"Host"}, accept_language = nil, cookie_str = nil,
})
ngx.say("version: ", result:sub(3, 4))
--- response_body
version: 10

=== TEST 13: JA4H build with HTTP/3.0
--- http_config eval: $::HttpConfig
--- lua_code
local ja4h = require "resty.ja4h"
local result = ja4h.build({
    method = "GET", version = "30",
    has_cookie = false, has_referer = false,
    header_names = {"Host"}, accept_language = nil, cookie_str = nil,
})
ngx.say("version: ", result:sub(3, 4))
--- response_body
version: 30

=== TEST 14: JA4H build with unknown version
--- http_config eval: $::HttpConfig
--- lua_code
local ja4h = require "resty.ja4h"
local result = ja4h.build({
    method = "GET", version = "00",
    has_cookie = false, has_referer = false,
    header_names = {"Host"}, accept_language = nil, cookie_str = nil,
})
ngx.say("version: ", result:sub(3, 4))
--- response_body
version: 00

=== TEST 15: JA4H header count capped at 99
--- http_config eval: $::HttpConfig
--- lua_code
local ja4h = require "resty.ja4h"
local headers = {}
for i = 1, 105 do headers[i] = "X-Header-" .. i end
local result = ja4h.build({
    method = "GET", version = "11",
    has_cookie = false, has_referer = false,
    header_names = headers, accept_language = nil, cookie_str = nil,
})
ngx.say("hc: ", result:sub(7, 8))
--- response_body
hc: 99

=== TEST 16: JA4H cookie names hash differs from cookie pairs hash
--- http_config eval: $::HttpConfig
--- lua_code
local ja4h = require "resty.ja4h"
local result = ja4h.build({
    method = "GET", version = "11",
    has_cookie = true, has_referer = false,
    header_names = {"Host"},
    accept_language = nil,
    cookie_str = "b=2; a=1",
})
local parts = {}
for part in result:gmatch("[^_]+") do parts[#parts + 1] = part end
ngx.say("sections: ", #parts)
ngx.say("c_ne_d: ", parts[3] ~= parts[4] and "yes" or "no")
ngx.say("c_len: ", #parts[3])
ngx.say("d_len: ", #parts[4])
--- response_body
sections: 4
c_ne_d: yes
c_len: 12
d_len: 12

=== TEST 17: JA4H build with cookies hash=false shows raw sections
--- http_config eval: $::HttpConfig
--- lua_code
local ja4h = require "resty.ja4h"
ja4h.configure({ hash = false })
local result = ja4h.build({
    method = "GET", version = "11",
    has_cookie = true, has_referer = false,
    header_names = {"Host"},
    accept_language = nil,
    cookie_str = "b=2; a=1",
})
ngx.say(result)
--- response_body
ge11cn010000_Host_a,b_a=1,b=2

=== TEST 18: JA4H configure toggle hash=false then back to hash=true
--- http_config eval: $::HttpConfig
--- lua_code
local ja4h = require "resty.ja4h"
local data = {
    method          = "HEAD",
    version         = "11",
    has_cookie      = false,
    has_referer     = false,
    header_names    = {"Host", "Connection", "User-Agent", "Accept-Encoding", "Accept-Language"},
    accept_language = "en-US",
    cookie_str      = nil,
}
ja4h.configure({ hash = false })
local raw = ja4h.build(data)
ja4h.configure({ hash = true })
local hashed = ja4h.build(data)
ngx.say("raw: ", raw)
ngx.say("hashed: ", hashed)
--- response_body
raw: he11nn05enus_Host,Connection,User-Agent,Accept-Encoding,Accept-Language__
hashed: he11nn05enus_6f8992deff94_000000000000_000000000000
