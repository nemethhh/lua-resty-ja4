use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

repeat_each(1);
plan tests => repeat_each() * 2 * 5;

no_shuffle();

my $pwd = cwd();

our $HttpConfig = qq{
    lua_package_path "$pwd/lib/?.lua;$pwd/lib/?/init.lua;;";
};

no_long_string();
log_level('warn');
run_tests();

__DATA__

=== TEST 1: FFI path matches raw_header path for simple GET (hash mode)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            ja4h.configure({ hash = true })

            -- compute() uses raw_header path for HTTP/1.1
            local raw_result = ja4h.compute()

            -- FFI path directly
            local ffi_result = ja4h._compute_ffi_path()

            ngx.say("raw: ", raw_result)
            ngx.say("ffi: ", ffi_result)
            ngx.say("match: ", raw_result == ffi_result and "yes" or "no")
        }
    }
--- request
GET /t
--- more_headers
Accept: text/html
User-Agent: TestBot/1.0
Accept-Language: en-US
--- response_body_like
raw: ge11nn\d+enus_[0-9a-f]{12}_000000000000_000000000000
ffi: ge11nn\d+enus_[0-9a-f]{12}_000000000000_000000000000
match: yes

=== TEST 2: FFI path with cookies produces correct fingerprint
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            ja4h.configure({ hash = true })

            local raw_result = ja4h.compute()
            local ffi_result = ja4h._compute_ffi_path()

            -- Extract sections for comparison
            local raw_parts = {}
            for part in raw_result:gmatch("[^_]+") do raw_parts[#raw_parts + 1] = part end
            local ffi_parts = {}
            for part in ffi_result:gmatch("[^_]+") do ffi_parts[#ffi_parts + 1] = part end

            ngx.say("sections_raw: ", #raw_parts)
            ngx.say("sections_ffi: ", #ffi_parts)
            ngx.say("a_match: ", raw_parts[1] == ffi_parts[1] and "yes" or "no")
            ngx.say("b_match: ", raw_parts[2] == ffi_parts[2] and "yes" or "no")
            ngx.say("c_match: ", raw_parts[3] == ffi_parts[3] and "yes" or "no")
            ngx.say("d_match: ", raw_parts[4] == ffi_parts[4] and "yes" or "no")
        }
    }
--- request
GET /t
--- more_headers
Accept: text/html
Cookie: b=2; a=1
Referer: http://example.com
Accept-Language: fr-FR,en;q=0.5
--- response_body
sections_raw: 4
sections_ffi: 4
a_match: yes
b_match: yes
c_match: yes
d_match: yes

=== TEST 3: FFI path raw mode matches raw_header path
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            ja4h.configure({ hash = false })

            local raw_result = ja4h.compute()
            local ffi_result = ja4h._compute_ffi_path()

            ngx.say("raw: ", raw_result)
            ngx.say("ffi: ", ffi_result)
            ngx.say("match: ", raw_result == ffi_result and "yes" or "no")

            -- Restore hash mode for subsequent tests
            ja4h.configure({ hash = true })
        }
    }
--- request
GET /t
--- more_headers
Accept: text/html
Cookie: z=3; m=1
Accept-Language: de-DE
--- response_body_like
raw: ge11cn\d+dede_.+_m,z_m=1,z=3
ffi: ge11cn\d+dede_.+_m,z_m=1,z=3
match: yes

=== TEST 4: FFI path with no cookies no referer has "nn" flags
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            ja4h.configure({ hash = true })

            local ffi_result = ja4h._compute_ffi_path()

            local flags = ffi_result:sub(5, 6)
            ngx.say("flags: ", flags)
            ngx.say("starts_with: ", ffi_result:sub(1, 4))
        }
    }
--- request
GET /t
--- response_body
flags: nn
starts_with: ge11

=== TEST 5: compute() stores result in ngx.ctx and produces 51-char hash
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua_block {
            local ja4h = require "resty.ja4h"
            ja4h.configure({ hash = true })

            local result = ja4h.compute()
            local stored = ja4h.get()

            ngx.say("stored_match: ", result == stored and "yes" or "no")
            ngx.say("len: ", #result)

            -- Also verify FFI path produces same length
            local ffi_result = ja4h._compute_ffi_path()
            ngx.say("ffi_len: ", #ffi_result)
            ngx.say("ffi_match: ", result == ffi_result and "yes" or "no")
        }
    }
--- request
GET /t
--- more_headers
Accept: text/html
Cookie: session=abc
Referer: http://test.com
Accept-Language: en-US
--- response_body
stored_match: yes
len: 51
ffi_len: 51
ffi_match: yes
