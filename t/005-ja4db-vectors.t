use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

repeat_each(1);
plan tests => repeat_each() * 2 * 19;

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

=== TEST 1: ja4db Chrome 94.0 — TLS 1.3, h2 (verified)
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
ja4.configure({ hash = true })
local result = ja4.build({
    protocol   = "t",
    version    = "13",
    sni        = "d",
    ciphers    = {0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303,
                  0xc013, 0xc014, 0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca8, 0xcca9},
    extensions = {0x0000, 0x0010, 0x0005, 0x000a, 0x000b, 0x000d, 0x0012,
                  0x0015, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d, 0x0033,
                  0x4469, 0xff01},
    alpn       = "h2",
    sig_algs   = {"0403", "0804", "0401", "0503", "0805", "0501", "0806", "0601"},
})
ngx.say(result)
--- response_body
t13d1516h2_8daaf6152771_e5627efa2ab1

=== TEST 2: ja4db Chrome 120.0 — TLS 1.3, h2, ECH extension fe0d (verified)
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
ja4.configure({ hash = true })
local result = ja4.build({
    protocol   = "t",
    version    = "13",
    sni        = "d",
    ciphers    = {0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303,
                  0xc013, 0xc014, 0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca8, 0xcca9},
    extensions = {0x0000, 0x0010, 0x0005, 0x000a, 0x000b, 0x000d, 0x0012,
                  0x0017, 0x001b, 0x0023, 0x002b, 0x002d, 0x0033, 0x4469,
                  0xfe0d, 0xff01},
    alpn       = "h2",
    sig_algs   = {"0403", "0804", "0401", "0503", "0805", "0501", "0806", "0601"},
})
ngx.say(result)
--- response_body
t13d1516h2_8daaf6152771_02713d6af862

=== TEST 3: ja4db Chrome 72.0 — TLS 1.3, h2, 9 sig_algs (verified)
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
ja4.configure({ hash = true })
local result = ja4.build({
    protocol   = "t",
    version    = "13",
    sni        = "d",
    ciphers    = {0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303,
                  0xc013, 0xc014, 0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca8, 0xcca9},
    extensions = {0x0000, 0x0010, 0x0005, 0x000a, 0x000b, 0x000d, 0x0012,
                  0x0015, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d, 0x0033,
                  0xff01},
    alpn       = "h2",
    sig_algs   = {"0403", "0804", "0401", "0503", "0805", "0501", "0806", "0601", "0201"},
})
ngx.say(result)
--- response_body
t13d1515h2_8daaf6152771_45f260be83e2

=== TEST 4: ja4db Chrome 62.0 — TLS 1.2, h2, channel_id 7550 (verified)
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
ja4.configure({ hash = true })
local result = ja4.build({
    protocol   = "t",
    version    = "12",
    sni        = "d",
    ciphers    = {0x002f, 0x0035, 0x009c, 0x009d, 0xc013, 0xc014, 0xc02b,
                  0xc02c, 0xc02f, 0xc030, 0xcca8, 0xcca9},
    extensions = {0x0000, 0x0010, 0x0005, 0x000a, 0x000b, 0x000d, 0x0012,
                  0x0017, 0x0023, 0x7550, 0xff01},
    alpn       = "h2",
    sig_algs   = {"0403", "0804", "0401", "0503", "0805", "0501", "0806", "0601", "0201"},
})
ngx.say(result)
--- response_body
t12d1211h2_d34a8e72043a_eb7c9aabf852

=== TEST 5: ja4db Chrome 31.0 — TLS 1.2, SPDY ALPN (verified)
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
ja4.configure({ hash = true })
local result = ja4.build({
    protocol   = "t",
    version    = "12",
    sni        = "d",
    ciphers    = {0x002f, 0x0032, 0x0033, 0x0035, 0x0039, 0x009c, 0x009e,
                  0xc009, 0xc00a, 0xc013, 0xc014, 0xc02b, 0xc02f},
    extensions = {0x0000, 0x0010, 0x0005, 0x000a, 0x000b, 0x000d, 0x0023,
                  0x3374, 0x754f, 0xff01},
    alpn       = "sp",
    sig_algs   = {"0401", "0501", "0201", "0403", "0503", "0203", "0402", "0202"},
})
ngx.say(result)
--- response_body
t12d1310sp_a571d07754c8_736b2a1ed4d3

=== TEST 6: ja4db Chrome 29.0 — TLS 1.2, no ALPN (verified)
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
ja4.configure({ hash = true })
local result = ja4.build({
    protocol   = "t",
    version    = "12",
    sni        = "d",
    ciphers    = {0x002f, 0x0032, 0x0033, 0x0035, 0x0039, 0x003c, 0x003d,
                  0x0067, 0x006b, 0xc009, 0xc00a, 0xc013, 0xc014, 0xc023, 0xc027},
    extensions = {0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0023,
                  0x3374, 0x754f, 0xff01},
    alpn       = "00",
    sig_algs   = {"0401", "0501", "0201", "0403", "0503", "0203", "0402", "0202"},
})
ngx.say(result)
--- response_body
t12d150900_49e15d6cf97a_736b2a1ed4d3

=== TEST 7: ja4db Firefox 68.0 — TLS 1.3, h2, 17 ciphers (verified)
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
ja4.configure({ hash = true })
local result = ja4.build({
    protocol   = "t",
    version    = "13",
    sni        = "d",
    ciphers    = {0x002f, 0x0033, 0x0035, 0x0039, 0x1301, 0x1302, 0x1303,
                  0xc009, 0xc00a, 0xc013, 0xc014, 0xc02b, 0xc02c, 0xc02f,
                  0xc030, 0xcca8, 0xcca9},
    extensions = {0x0000, 0x0010, 0x0005, 0x000a, 0x000b, 0x000d, 0x0015,
                  0x0017, 0x001c, 0x0023, 0x002b, 0x002d, 0x0033, 0xff01},
    alpn       = "h2",
    sig_algs   = {"0403", "0503", "0603", "0804", "0805", "0806", "0401", "0501", "0601", "0203", "0201"},
})
ngx.say(result)
--- response_body
t13d1714h2_95e1cefdbe28_d267a5f792d4

=== TEST 8: ja4db Firefox 120.0 — TLS 1.3, h2, ECH fe0d (verified)
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
ja4.configure({ hash = true })
local result = ja4.build({
    protocol   = "t",
    version    = "13",
    sni        = "d",
    ciphers    = {0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303,
                  0xc009, 0xc00a, 0xc013, 0xc014, 0xc02b, 0xc02c, 0xc02f,
                  0xc030, 0xcca8, 0xcca9},
    extensions = {0x0000, 0x0010, 0x0005, 0x000a, 0x000b, 0x000d, 0x0017,
                  0x001c, 0x0022, 0x0023, 0x002b, 0x002d, 0x0033, 0xfe0d,
                  0xff01},
    alpn       = "h2",
    sig_algs   = {"0403", "0503", "0603", "0804", "0805", "0806", "0401", "0501", "0601", "0203", "0201"},
})
ngx.say(result)
--- response_body
t13d1715h2_5b57614c22b0_5c2c66f702b0

=== TEST 9: ja4db Firefox 61.0 — TLS 1.2, h2, TLS 1.3 ciphers in 1.2 client (verified)
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
ja4.configure({ hash = true })
local result = ja4.build({
    protocol   = "t",
    version    = "12",
    sni        = "d",
    ciphers    = {0x002f, 0x0035, 0x1301, 0x1302, 0x1303, 0xc013, 0xc014,
                  0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca8, 0xcca9},
    extensions = {0x0000, 0x0010, 0x0005, 0x000a, 0x000b, 0x000d, 0x0015,
                  0x0017, 0x0023, 0x002b, 0x002d, 0x0033, 0xff01},
    alpn       = "h2",
    sig_algs   = {"0403", "0503", "0603", "0804", "0805", "0806", "0401", "0501", "0601", "0203", "0201"},
})
ngx.say(result)
--- response_body
t12d1313h2_07be0c029dc8_ad97e2351c08

=== TEST 10: ja4db Safari — TLS 1.3, h2, 23 ciphers, duplicate sig_alg 0805 (verified)
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
ja4.configure({ hash = true })
local result = ja4.build({
    protocol   = "t",
    version    = "13",
    sni        = "d",
    ciphers    = {0x002f, 0x0035, 0x003c, 0x003d, 0x009c, 0x009d, 0x1301,
                  0x1302, 0x1303, 0xc009, 0xc00a, 0xc013, 0xc014, 0xc023,
                  0xc024, 0xc027, 0xc028, 0xc02b, 0xc02c, 0xc02f, 0xc030,
                  0xcca8, 0xcca9},
    extensions = {0x0000, 0x0010, 0x0005, 0x000a, 0x000b, 0x000d, 0x0012,
                  0x0015, 0x0017, 0x002b, 0x002d, 0x0033, 0xff01},
    alpn       = "h2",
    sig_algs   = {"0403", "0804", "0401", "0503", "0203", "0805", "0805", "0501", "0806", "0601", "0201"},
})
ngx.say(result)
--- response_body
t13d2313h2_24fc43eb1c96_845d286b0d67

=== TEST 11: ja4db Safari 10.1 — TLS 1.2, h2, NPN 3374 (verified)
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
ja4.configure({ hash = true })
local result = ja4.build({
    protocol   = "t",
    version    = "12",
    sni        = "d",
    ciphers    = {0x002f, 0x0035, 0x003c, 0x003d, 0x009c, 0x009d, 0xc009,
                  0xc00a, 0xc013, 0xc014, 0xc023, 0xc024, 0xc027, 0xc028,
                  0xc02b, 0xc02c, 0xc02f, 0xc030},
    extensions = {0x0000, 0x0010, 0x0005, 0x000a, 0x000b, 0x000d, 0x0012,
                  0x0017, 0x3374},
    alpn       = "h2",
    sig_algs   = {"0401", "0201", "0501", "0601", "0403", "0203", "0503", "0603"},
})
ngx.say(result)
--- response_body
t12d1809h2_4b22cbed5bed_2cdefc264be7

=== TEST 12: ja4db Edge 17.0 — TLS 1.2, h2, 18 ciphers (verified)
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
ja4.configure({ hash = true })
local result = ja4.build({
    protocol   = "t",
    version    = "12",
    sni        = "d",
    ciphers    = {0x002f, 0x0035, 0x003c, 0x003d, 0x009c, 0x009d, 0xc009,
                  0xc00a, 0xc013, 0xc014, 0xc023, 0xc024, 0xc027, 0xc028,
                  0xc02b, 0xc02c, 0xc02f, 0xc030},
    extensions = {0x0000, 0x0010, 0x0005, 0x000a, 0x000b, 0x000d, 0x0017,
                  0x0018, 0x0023, 0xff01},
    alpn       = "h2",
    sig_algs   = {"0401", "0501", "0201", "0403", "0503", "0203", "0202", "0601", "0603"},
})
ngx.say(result)
--- response_body
t12d1810h2_4b22cbed5bed_27793441e138

=== TEST 13: ja4db Edge 111.0 — TLS 1.3, h2, duplicate cipher 1302 (verified)
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
ja4.configure({ hash = true })
local result = ja4.build({
    protocol   = "t",
    version    = "13",
    sni        = "d",
    ciphers    = {0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1302,
                  0x1303, 0xc013, 0xc014, 0xc02b, 0xc02c, 0xc02f, 0xc030,
                  0xcca8, 0xcca9},
    extensions = {0x0000, 0x0010, 0x0005, 0x000a, 0x000b, 0x000d, 0x0012,
                  0x0015, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d, 0x0033,
                  0x4469, 0xff01},
    alpn       = "h2",
    sig_algs   = {"0403", "0804", "0401", "0503", "0805", "0501", "0806", "0601"},
})
ngx.say(result)
--- response_body
t13d1616h2_e72c3b3287f1_e5627efa2ab1

=== TEST 14: ja4db Edge 84.0 — TLS 1.3, h2 (verified)
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
ja4.configure({ hash = true })
local result = ja4.build({
    protocol   = "t",
    version    = "13",
    sni        = "d",
    ciphers    = {0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303,
                  0xc013, 0xc014, 0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca8, 0xcca9},
    extensions = {0x0000, 0x0010, 0x0005, 0x000a, 0x000b, 0x000d, 0x0012,
                  0x0015, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d, 0x0033,
                  0xff01},
    alpn       = "h2",
    sig_algs   = {"0403", "0804", "0401", "0503", "0805", "0501", "0806", "0601"},
})
ngx.say(result)
--- response_body
t13d1515h2_8daaf6152771_de4a06bb82e3

=== TEST 15: ja4db Chrome 46.0 — TLS 1.2, ALPN ht (verified)
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
ja4.configure({ hash = true })
local result = ja4.build({
    protocol   = "t",
    version    = "12",
    sni        = "d",
    ciphers    = {0x002f, 0x0033, 0x0035, 0x0039, 0x009c, 0x009e, 0xc009,
                  0xc00a, 0xc013, 0xc014, 0xc02b, 0xc02f},
    extensions = {0x0000, 0x0010, 0x0005, 0x000a, 0x000b, 0x000d, 0x0012,
                  0x0017, 0x0023, 0x3374, 0x7550, 0xff01},
    alpn       = "ht",
    sig_algs   = {"0601", "0603", "0501", "0503", "0401", "0403", "0301", "0303", "0201", "0203"},
})
ngx.say(result)
--- response_body
t12d1212ht_39b11509324c_c9eaec7dbab4

=== TEST 16: huginn-net tls12.pcap — Firefox TLS 1.3, 17 ciphers, 15 extensions
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
ja4.configure({ hash = true })
local result = ja4.build({
    protocol   = "t",
    version    = "13",
    sni        = "d",
    ciphers    = {0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8,
                  0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c,
                  0x009d, 0x002f, 0x0035},
    extensions = {0x0000, 0x0010, 0x0005, 0x000a, 0x000b, 0x000d, 0x0015,
                  0x0017, 0x001c, 0x0022, 0x0023, 0x002b, 0x002d, 0x0033,
                  0xff01},
    alpn       = "h2",
    sig_algs   = {"0403", "0503", "0603", "0804", "0805", "0806", "0401", "0501", "0601", "0203", "0201"},
})
ngx.say(result)
--- response_body
t13d1715h2_5b57614c22b0_3d5424432f57

=== TEST 17: huginn-net tls-alpn-h2.pcap — TLS 1.2, 46 ciphers, 5 extensions, IPv6
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
ja4.configure({ hash = true })
local result = ja4.build({
    protocol   = "t",
    version    = "12",
    sni        = "d",
    ciphers    = {0xc030, 0xc02c, 0xc028, 0xc024, 0xc014, 0xc00a, 0x009f,
                  0x006b, 0x0039, 0xcca9, 0xcca8, 0xccaa, 0xff85, 0x00c4,
                  0x0088, 0x0081, 0x009d, 0x003d, 0x0035, 0x00c0, 0x0084,
                  0xc02f, 0xc02b, 0xc027, 0xc023, 0xc013, 0xc009, 0x009e,
                  0x0067, 0x0033, 0x00be, 0x0045, 0x009c, 0x003c, 0x002f,
                  0x00ba, 0x0041, 0xc011, 0xc007, 0x0005, 0x0004, 0xc012,
                  0xc008, 0x0016, 0x000a, 0x00ff},
    extensions = {0x0000, 0x000b, 0x000a, 0x000d, 0x0010},
    alpn       = "h2",
    sig_algs   = {"0601", "0603", "efef", "0501", "0503", "0401", "0403", "eeee", "eded", "0301", "0303", "0201", "0203"},
})
ngx.say(result)
--- response_body
t12d4605h2_85626a9a5f7f_aaf95bb78ec9

=== TEST 18: huginn-net known_ja4 — 16 extensions with 0018, sorted
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
ja4.configure({ hash = true })
local result = ja4.build({
    protocol   = "t",
    version    = "13",
    sni        = "d",
    ciphers    = {0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
                  0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035},
    extensions = {0x0000, 0x0017, 0x0018, 0xff01, 0x000a, 0x000b, 0x0023,
                  0x0010, 0x000d, 0x0012, 0x0033, 0x002b, 0x002d, 0x0015,
                  0x001b, 0x001c},
    alpn       = "h2",
    sig_algs   = {"0403", "0804", "0401", "0503", "0805", "0501", "0806", "0601"},
})
ngx.say(result)
--- response_body
t13d1516h2_8daaf6152771_64df15253037

=== TEST 19: huginn-net captured_traffic — extensions with 44cd and fe0d
--- http_config eval: $::HttpConfig
--- lua_code
local ja4 = require "resty.ja4"
ja4.configure({ hash = true })
local result = ja4.build({
    protocol   = "t",
    version    = "13",
    sni        = "d",
    ciphers    = {0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
                  0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035},
    extensions = {0x0012, 0x000d, 0x000b, 0xff01, 0x0000, 0x0023, 0x001b,
                  0x44cd, 0xfe0d, 0x0033, 0x0005, 0x0010, 0x000a, 0x002d,
                  0x0017, 0x002b},
    alpn       = "h2",
    sig_algs   = {"0403", "0804", "0401", "0503", "0805", "0501", "0806", "0601"},
})
ngx.say(result)
--- response_body
t13d1516h2_8daaf6152771_d8a2da3f94cd
