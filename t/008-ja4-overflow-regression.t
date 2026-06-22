use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

repeat_each(1);
plan tests => repeat_each() * 2 * 3;

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

=== TEST 1: JA4H with oversized Cookie (>16KB) must not overflow / crash
--- http_config eval: $::HttpConfig
--- lua_code
local ja4h = require "resty.ja4h"
-- ~300 cookies, total well over the 16KB hash buffer
local parts = {}
for i = 1, 300 do
    parts[i] = "ck" .. i .. "=" .. string.rep("v", 60)
end
local cookie_str = table.concat(parts, "; ")
local data = {
    method          = "GET",
    version         = "20",
    has_cookie      = true,
    has_referer     = false,
    header_names    = {"Host", "User-Agent", "Accept"},
    accept_language = "en-US",
    cookie_str      = cookie_str,
}
local r1 = ja4h.build(data)
local r2 = ja4h.build(data)
ngx.say("prefix=", r1:sub(1, 12), " len=", #r1, " det=", tostring(r1 == r2))
--- response_body
prefix=ge20cn03enus len=51 det=true

=== TEST 2: JA4H with many header names (>99) must not overflow / crash
--- http_config eval: $::HttpConfig
--- lua_code
local ja4h = require "resty.ja4h"
local names = {}
for i = 1, 200 do names[i] = "X-Custom-Header-" .. i end
local data = {
    method          = "GET",
    version         = "11",
    has_cookie      = false,
    has_referer     = false,
    header_names    = names,
    accept_language = nil,
    cookie_str      = nil,
}
local r1 = ja4h.build(data)
local r2 = ja4h.build(data)
ngx.say("prefix=", r1:sub(1, 12), " len=", #r1, " det=", tostring(r1 == r2))
--- response_body
prefix=ge11nn990000 len=51 det=true

=== TEST 3: JA4 with >256 ciphers and extensions must not overflow / crash
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
local ciphers, exts = {}, {}
for i = 1, 400 do ciphers[i] = 0x0100 + i end
for i = 1, 400 do exts[i] = 0x0100 + i end  -- none are SNI(0x0000)/ALPN(0x0010)
local data = {
    protocol   = "t",
    version    = "13",
    sni        = "d",
    ciphers    = ciphers,
    extensions = exts,
    alpn       = "h1",
    sig_algs   = nil,
}
local r1 = ja4.build(data)
local r2 = ja4.build(data)
ngx.say("prefix=", r1:sub(1, 10), " len=", #r1, " det=", tostring(r1 == r2))
--- response_body
prefix=t13d9999h1 len=36 det=true
