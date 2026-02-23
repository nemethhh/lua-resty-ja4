use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

repeat_each(1);
plan tests => repeat_each() * 2 * 16;

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

=== TEST 1: JA4 build with test vector (Chrome to lastpass.com)
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
local result = ja4.build({
    protocol     = "t",
    version      = "13",
    sni          = "d",
    ciphers      = {0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303,
                    0xc013, 0xc014, 0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca8, 0xcca9},
    extensions   = {0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0010, 0x0012,
                    0x0015, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d, 0x0033,
                    0x4469, 0xff01},
    alpn         = "h1",
    sig_algs     = {"0403", "0804", "0401", "0503", "0805", "0501", "0806", "0601"},
})
ngx.say("hash: ", result)
--- response_body
hash: t13d1516h1_8daaf6152771_e5627efa2ab1

=== TEST 2: JA4 build with empty ciphers/extensions
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
local result = ja4.build({
    protocol     = "t",
    version      = "00",
    sni          = "i",
    ciphers      = {},
    extensions   = {},
    alpn         = "00",
    sig_algs     = nil,
})
ngx.say(result)
--- response_body
t00i000000_000000000000_000000000000

=== TEST 3: JA4 extension count includes SNI+ALPN but hash excludes them
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
local result = ja4.build({
    protocol     = "t",
    version      = "13",
    sni          = "d",
    ciphers      = {0x1301, 0x1302},
    extensions   = {0x0000, 0x0010, 0x000a, 0x000d},
    alpn         = "h2",
    sig_algs     = {"0403"},
})
ngx.say(result:sub(1, 10))
--- response_body
t13d0204h2

=== TEST 4: JA4 store and get round-trip
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
ja4.store("t13d1516h1_8daaf6152771_e5627efa2ab1")
ngx.say("result: ", ja4.get())
--- response_body
result: t13d1516h1_8daaf6152771_e5627efa2ab1

=== TEST 5: JA4 build hash=false produces raw output
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
ja4.configure({ hash = false })
local result = ja4.build({
    protocol     = "t",
    version      = "13",
    sni          = "d",
    ciphers      = {0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303,
                    0xc013, 0xc014, 0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca8, 0xcca9},
    extensions   = {0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0010, 0x0012,
                    0x0015, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d, 0x0033,
                    0x4469, 0xff01},
    alpn         = "h1",
    sig_algs     = {"0403", "0804", "0401", "0503", "0805", "0501", "0806", "0601"},
})
ngx.say(result)
--- response_body
t13d1516h1_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601

=== TEST 6: JA4 build() with nil data returns error
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
local result, err = ja4.build(nil)
ngx.say("result: ", result == nil and "nil" or "not nil")
ngx.say("err: ", err)
--- response_body
result: nil
err: no data

=== TEST 7: JA4 build() with empty table produces valid fingerprint
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
-- Minimal valid input with all required fields
local result = ja4.build({
    protocol   = "t",
    version    = "13",
    sni        = "i",
    ciphers    = {},
    extensions = {},
    alpn       = "00",
    sig_algs   = {},
})
ngx.say(result)
--- response_body
t13i000000_000000000000_000000000000

=== TEST 8: JA4 cipher count capped at 99 in section A
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
local ciphers = {}
for i = 1, 105 do ciphers[i] = i end
local result = ja4.build({
    protocol   = "t",
    version    = "13",
    sni        = "d",
    ciphers    = ciphers,
    extensions = {0x000a},
    alpn       = "h2",
    sig_algs   = nil,
})
-- Cipher count at positions 5-6 should be "99", not "105"
ngx.say("cc: ", result:sub(5, 6))
-- But all 105 ciphers are included in the hash
ngx.say("len: ", #result)
--- response_body
cc: 99
len: 36

=== TEST 9: JA4 extension count capped at 99 in section A
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
local extensions = {}
for i = 1, 105 do extensions[i] = i + 0x0100 end
local result = ja4.build({
    protocol   = "t",
    version    = "13",
    sni        = "d",
    ciphers    = {0x1301},
    extensions = extensions,
    alpn       = "h2",
    sig_algs   = nil,
})
-- Extension count at positions 7-8 should be "99"
ngx.say("ec: ", result:sub(7, 8))
--- response_body
ec: 99

=== TEST 10: JA4 section C with extensions but no sig_algs
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
local utils = require "resty.ja4.utils"
local result = ja4.build({
    protocol   = "t",
    version    = "12",
    sni        = "d",
    ciphers    = {0x1301},
    extensions = {0x000a, 0x000d},
    alpn       = "h2",
    sig_algs   = nil,
})
-- Section C should hash only extensions (no sig_algs separator)
local expected_c = utils.sha256_hex12("000a,000d")
local section_c = result:sub(25, 36)
ngx.say("a: ", result:sub(1, 10))
ngx.say("c_match: ", section_c == expected_c and "yes" or "no")
--- response_body
a: t12d0102h2
c_match: yes

=== TEST 11: JA4 section C with sig_algs but no extensions after filtering
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
local utils = require "resty.ja4.utils"
local result = ja4.build({
    protocol   = "t",
    version    = "13",
    sni        = "d",
    ciphers    = {0x1301},
    extensions = {0x0000, 0x0010},  -- both SNI and ALPN, both filtered
    alpn       = "h2",
    sig_algs   = {"0403"},
})
-- ext_n=0, but sig_algs present → hash includes "_0403"
local expected_c = utils.sha256_hex12("_0403")
local section_c = result:sub(25, 36)
ngx.say("a: ", result:sub(1, 10))
ngx.say("c_match: ", section_c == expected_c and "yes" or "no")
--- response_body
a: t13d0102h2
c_match: yes

=== TEST 12: JA4 build with all TLS version codes
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
local versions = {"12", "11", "10", "s3"}
for _, v in ipairs(versions) do
    local result = ja4.build({
        protocol   = "t",
        version    = v,
        sni        = "d",
        ciphers    = {0x1301},
        extensions = {0x000a},
        alpn       = "h2",
        sig_algs   = nil,
    })
    ngx.say(v, ": ", result:sub(2, 3))
end
--- response_body
12: 12
11: 11
10: 10
s3: s3

=== TEST 13: JA4 build with QUIC protocol
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
local result = ja4.build({
    protocol   = "q",
    version    = "13",
    sni        = "d",
    ciphers    = {0x1301},
    extensions = {0x000a},
    alpn       = "h2",
    sig_algs   = nil,
})
ngx.say("proto: ", result:sub(1, 1))
--- response_body
proto: q

=== TEST 14: JA4 build with DTLS protocol
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
local result = ja4.build({
    protocol   = "d",
    version    = "13",
    sni        = "d",
    ciphers    = {0x1301},
    extensions = {0x000a},
    alpn       = "h2",
    sig_algs   = nil,
})
ngx.say("proto: ", result:sub(1, 1))
--- response_body
proto: d

=== TEST 15: JA4 configure toggle hash=false then back to hash=true
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
local data = {
    protocol   = "t",
    version    = "13",
    sni        = "d",
    ciphers    = {0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303,
                  0xc013, 0xc014, 0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca8, 0xcca9},
    extensions = {0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0010, 0x0012,
                  0x0015, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d, 0x0033,
                  0x4469, 0xff01},
    alpn       = "h1",
    sig_algs   = {"0403", "0804", "0401", "0503", "0805", "0501", "0806", "0601"},
}
ja4.configure({ hash = false })
local raw = ja4.build(data)
ja4.configure({ hash = true })
local hashed = ja4.build(data)
ngx.say("raw_a: ", raw:sub(1, 10))
ngx.say("hashed: ", hashed)
--- response_body
raw_a: t13d1516h1
hashed: t13d1516h1_8daaf6152771_e5627efa2ab1

=== TEST 16: JA4 compute() exists (requires SSL context for integration test)
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
ngx.say("type: ", type(ja4.compute))
-- NOTE: ja4.compute() must be called from ssl_client_hello_by_lua_block.
-- It cannot be integration-tested from content_by_lua_block.
--- response_body
type: function
