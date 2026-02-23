-- bench/testdata.lua
-- Synthetic test data for JIT performance analysis.
-- Three profiles: minimal, typical (Chrome-like), heavy.

local char = string.char
local floor = math.floor

local function u16(n)
    return char(floor(n / 256), n % 256)
end

local _M = {}

----------------------------------------------------------------
-- Minimal: bare-minimum TLS client, no cookies
----------------------------------------------------------------
_M.minimal = {
    ja4 = {
        protocol   = "t",
        version    = "13",
        sni        = "d",
        ciphers    = { 0x1301, 0x1302, 0x1303 },
        extensions = { 0x0000, 0x002b, 0x000d, 0x0033 },
        alpn       = "h2",
        sig_algs   = { "0403", "0804", "0401" },
    },
    ja4h = {
        method       = "GET",
        version      = "11",
        has_cookie   = false,
        has_referer  = false,
        header_names = { "Host", "User-Agent", "Accept" },
        accept_language = nil,
        cookie_str   = nil,
    },
    raw_alpn     = "\x00\x03\x02h2",
    raw_sig_algs = u16(6) .. u16(0x0403) .. u16(0x0804) .. u16(0x0401),
    cookie_str   = nil,
    raw_headers  = "Host: example.com\r\nUser-Agent: curl/7.0\r\nAccept: */*\r\n\r\n",
}

----------------------------------------------------------------
-- Typical: Chrome 120-like
----------------------------------------------------------------
_M.typical = {
    ja4 = {
        protocol   = "t",
        version    = "13",
        sni        = "d",
        ciphers    = {
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f,
            0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
            0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        },
        extensions = {
            0x0000, 0x0017, 0xff01, 0x000a, 0x000b,
            0x0023, 0x0010, 0x0005, 0x0012, 0x002b,
            0x000d, 0x001b, 0x0033, 0x002d,
        },
        alpn       = "h2",
        sig_algs   = {
            "0403", "0804", "0401", "0503", "0805", "0501",
            "0806", "0601", "0201", "0203", "0303", "0302",
        },
    },
    ja4h = {
        method       = "GET",
        version      = "20",
        has_cookie   = true,
        has_referer  = true,
        header_names = {
            "Host", "User-Agent", "Accept", "Accept-Encoding",
            "Accept-Language", "Connection", "Upgrade-Insecure-Requests",
            "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site",
        },
        accept_language = "en-US,en;q=0.9",
        cookie_str   = "session=abc123def456; theme=dark; _ga=GA1.2.123456789.1234567890",
    },
    raw_alpn     = "\x00\x03\x02h2",
    raw_sig_algs = u16(24)
        .. u16(0x0403) .. u16(0x0804) .. u16(0x0401) .. u16(0x0503)
        .. u16(0x0805) .. u16(0x0501) .. u16(0x0806) .. u16(0x0601)
        .. u16(0x0201) .. u16(0x0203) .. u16(0x0303) .. u16(0x0302),
    cookie_str   = "session=abc123def456; theme=dark; _ga=GA1.2.123456789.1234567890",
    raw_headers  = table.concat({
        "Host: www.example.com",
        "User-Agent: Mozilla/5.0 Chrome/120.0.0.0",
        "Accept: text/html,application/xhtml+xml",
        "Accept-Encoding: gzip, deflate, br",
        "Accept-Language: en-US,en;q=0.9",
        "Cookie: session=abc123def456; theme=dark",
        "Referer: https://www.google.com/",
        "Connection: keep-alive",
        "Upgrade-Insecure-Requests: 1",
        "Sec-Fetch-Dest: document",
        "Sec-Fetch-Mode: navigate",
        "Sec-Fetch-Site: cross-site",
    }, "\r\n") .. "\r\n\r\n",
}

----------------------------------------------------------------
-- Heavy: extension-heavy client, many cookies
----------------------------------------------------------------
_M.heavy = {
    ja4 = {
        protocol   = "t",
        version    = "13",
        sni        = "d",
        ciphers    = {
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
            0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f,
            0x0035, 0xc009, 0xc00a, 0xc023, 0xc024, 0xc027, 0xc028,
            0xc0a2, 0xc0a3, 0x009e, 0x009f, 0x006b, 0x0067, 0xccaa,
            0xc0ae, 0xc0af, 0x00a2, 0x00a3,
        },
        extensions = {
            0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010,
            0x0005, 0x0012, 0x002b, 0x000d, 0x001b, 0x0033, 0x002d,
            0x001c, 0x0015, 0x0011, 0x0016, 0xfe0d, 0x0029, 0x001a,
            0x0039, 0x003a, 0x003b, 0x0034,
        },
        alpn       = "h2",
        sig_algs   = {
            "0403", "0804", "0401", "0503", "0805", "0501",
            "0806", "0601", "0201", "0203", "0303", "0302",
            "0402", "0502", "0602", "0802", "0803", "0805",
            "0406", "0506",
        },
    },
    ja4h = {
        method       = "POST",
        version      = "20",
        has_cookie   = true,
        has_referer  = true,
        header_names = {
            "Host", "User-Agent", "Accept", "Accept-Encoding",
            "Accept-Language", "Content-Type", "Content-Length",
            "Connection", "Upgrade-Insecure-Requests",
            "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site",
            "Sec-Fetch-User", "Sec-CH-UA", "Sec-CH-UA-Mobile",
            "Sec-CH-UA-Platform",
        },
        accept_language = "en-US,en;q=0.9,fr;q=0.8,de;q=0.7",
        cookie_str   = "session=abc123def456; theme=dark; _ga=GA1.2.123456789.1234567890; "
                     .. "_gid=GA1.2.987654321; _fbp=fb.1.1234567890.123456789; "
                     .. "csrftoken=a1b2c3d4e5f6; lang=en-US; timezone=America/New_York; "
                     .. "prefs=compact; tracking_id=xyz789; ab_test=variant_b",
    },
    raw_alpn     = "\x00\x03\x02h2",
    raw_sig_algs = u16(40)
        .. u16(0x0403) .. u16(0x0804) .. u16(0x0401) .. u16(0x0503)
        .. u16(0x0805) .. u16(0x0501) .. u16(0x0806) .. u16(0x0601)
        .. u16(0x0201) .. u16(0x0203) .. u16(0x0303) .. u16(0x0302)
        .. u16(0x0402) .. u16(0x0502) .. u16(0x0602) .. u16(0x0802)
        .. u16(0x0803) .. u16(0x0805) .. u16(0x0406) .. u16(0x0506),
    cookie_str   = "session=abc123def456; theme=dark; _ga=GA1.2.123456789.1234567890; "
                .. "_gid=GA1.2.987654321; _fbp=fb.1.1234567890.123456789; "
                .. "csrftoken=a1b2c3d4e5f6; lang=en-US; timezone=America/New_York; "
                .. "prefs=compact; tracking_id=xyz789; ab_test=variant_b",
    raw_headers  = table.concat({
        "Host: api.example.com",
        "User-Agent: Mozilla/5.0 Chrome/120.0.0.0",
        "Accept: application/json",
        "Accept-Encoding: gzip, deflate, br, zstd",
        "Accept-Language: en-US,en;q=0.9,fr;q=0.8,de;q=0.7",
        "Content-Type: application/json",
        "Content-Length: 1234",
        "Cookie: session=abc123def456; theme=dark",
        "Referer: https://www.example.com/dashboard",
        "Connection: keep-alive",
        "Upgrade-Insecure-Requests: 1",
        "Sec-Fetch-Dest: empty",
        "Sec-Fetch-Mode: cors",
        "Sec-Fetch-Site: same-origin",
        "Sec-Fetch-User: ?1",
        "Sec-CH-UA: \"Chromium\";v=\"120\"",
        "Sec-CH-UA-Mobile: ?0",
        "Sec-CH-UA-Platform: \"Linux\"",
    }, "\r\n") .. "\r\n\r\n",
}

_M.profiles = { "minimal", "typical", "heavy" }

return _M
