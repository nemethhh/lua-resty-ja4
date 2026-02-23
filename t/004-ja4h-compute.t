use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

repeat_each(1);
plan tests => repeat_each() * 2 * 10;

no_shuffle();

my $pwd = cwd();

our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;$pwd/lib/?/init.lua;;";
};

no_long_string();
log_level('warn');
run_tests();

__DATA__

=== TEST 1: ja4h.compute with simple GET request
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            local hash = ja4h.compute()
            if hash then
                local a_section = hash:match("^([^_]+)")
                ngx.say("a_starts_with: ", a_section:sub(1, 4))
                ngx.say("has_underscores: ", select(2, hash:gsub("_", "")) == 3 and "yes" or "no")
            else
                ngx.say("error")
            end
        }
    }
--- request
GET /t
--- more_headers
Accept-Language: en-US
--- response_body
a_starts_with: ge11
has_underscores: yes

=== TEST 2: ja4h.compute detects cookies and referer
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            local hash = ja4h.compute()
            local a_section = hash:match("^([^_]+)")
            ngx.say("cookie_flag: ", a_section:sub(5, 5))
            ngx.say("referer_flag: ", a_section:sub(6, 6))
        }
    }
--- request
GET /t
--- more_headers
Cookie: session=abc123; user=john
Referer: http://example.com
Accept-Language: en-US
--- response_body
cookie_flag: c
referer_flag: r

=== TEST 3: ja4h.compute store/get round-trip
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            local hash = ja4h.compute()
            ja4h.store(hash)
            ngx.say("match: ", ja4h.get() == hash and "yes" or "no")
        }
    }
--- request
GET /t
--- response_body
match: yes

=== TEST 4: ja4h.compute with POST request
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            local hash = ja4h.compute()
            ngx.say("method: ", hash:sub(1, 2))
        }
    }
--- request
POST /t
--- more_headers
Accept-Language: en-US
--- response_body
method: po

=== TEST 5: ja4h.compute with DELETE request
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            local hash = ja4h.compute()
            ngx.say("method: ", hash:sub(1, 2))
        }
    }
--- request
DELETE /t
--- more_headers
Accept-Language: en-US
--- response_body
method: de

=== TEST 6: ja4h.compute with cookies but no referer
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            local hash = ja4h.compute()
            ngx.say("cookie_flag: ", hash:sub(5, 5))
            ngx.say("referer_flag: ", hash:sub(6, 6))
        }
    }
--- request
GET /t
--- more_headers
Cookie: session=abc
Accept-Language: en-US
--- response_body
cookie_flag: c
referer_flag: n

=== TEST 7: ja4h.compute with referer but no cookies
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            local hash = ja4h.compute()
            ngx.say("cookie_flag: ", hash:sub(5, 5))
            ngx.say("referer_flag: ", hash:sub(6, 6))
        }
    }
--- request
GET /t
--- more_headers
Referer: http://example.com
Accept-Language: en-US
--- response_body
cookie_flag: n
referer_flag: r

=== TEST 8: ja4h.compute with no Accept-Language header
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            local hash = ja4h.compute()
            ngx.say("lang: ", hash:sub(9, 12))
        }
    }
--- request
GET /t
--- response_body
lang: 0000

=== TEST 9: ja4h.compute with multi-language Accept-Language
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            local hash = ja4h.compute()
            ngx.say("lang: ", hash:sub(9, 12))
        }
    }
--- request
GET /t
--- more_headers
Accept-Language: fr-FR,en;q=0.5
--- response_body
lang: frfr

=== TEST 10: ja4h.compute produces consistent hash for identical requests
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            local hash1 = ja4h.compute()
            local hash2 = ja4h.compute()
            ngx.say("match: ", hash1 == hash2 and "yes" or "no")
            ngx.say("len: ", #hash1)
        }
    }
--- request
GET /t
--- more_headers
Accept-Language: en-US
Cookie: a=1
Referer: http://test.com
--- response_body
match: yes
len: 51
