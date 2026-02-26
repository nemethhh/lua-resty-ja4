"""E2E tests: send TLS ClientHellos with known browser parameters via scapy.

Each vector contains exact cipher suites, extensions, ALPN, and signature
algorithms from a real browser. Scapy constructs the ClientHello, completes
a TLS handshake with OpenResty, and verifies the X-JA4 response header.

Note: OpenSSL's SSL_client_hello_get1_extensions_present() only reports
extensions it has registered handlers for. Extensions like delegated_credentials
(0x0022), record_size_limit (0x001c), and application_settings (0x4469) are
silently omitted. Expected values for vectors containing these extensions
reflect what OpenSSL actually reports, not the full wire-level ClientHello.
Vectors without unrecognized extensions match ja4db.com reference values exactly.
"""
import os
import pytest
from scapy_tls_client import connect_and_get_ja4

NGINX_HOST = os.environ.get("NGINX_HOST", "nginx")
HASH_PORT = int(os.environ.get("NGINX_PORT", "443"))

VECTORS = [
    pytest.param(
        # Firefox 105, TLS 1.3, 17 ciphers, 15 extensions on wire
        # OpenSSL drops 0x0022 (delegated_credentials) and 0x001c (record_size_limit)
        # ja4db ref: t13d1715h2_5b57614c22b0_3d5424432f57
        [0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8,
         0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c,
         0x009d, 0x002f, 0x0035],
        [0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010,
         0x0005, 0x0022, 0x0033, 0x002b, 0x000d, 0x002d, 0x001c,
         0x0015],
        "h2",
        [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806,
         0x0401, 0x0501, 0x0601, 0x0203, 0x0201],
        "t13d1713h2_5b57614c22b0_ad97e2351c08",
        id="firefox-tls13",
    ),
    pytest.param(
        # GnuTLS, TLS 1.2, 46 ciphers, 5 extensions, GREASE sig_algs
        # All extensions recognized by OpenSSL — matches ja4db exactly
        [0xc030, 0xc02c, 0xc028, 0xc024, 0xc014, 0xc00a, 0x009f,
         0x006b, 0x0039, 0xcca9, 0xcca8, 0xccaa, 0xff85, 0x00c4,
         0x0088, 0x0081, 0x009d, 0x003d, 0x0035, 0x00c0, 0x0084,
         0xc02f, 0xc02b, 0xc027, 0xc023, 0xc013, 0xc009, 0x009e,
         0x0067, 0x0033, 0x00be, 0x0045, 0x009c, 0x003c, 0x002f,
         0x00ba, 0x0041, 0xc011, 0xc007, 0x0005, 0x0004, 0xc012,
         0xc008, 0x0016, 0x000a, 0x00ff],
        [0x0000, 0x000b, 0x000a, 0x000d, 0x0010],
        "h2",
        [0x0601, 0x0603, 0xefef, 0x0501, 0x0503, 0x0401, 0x0403,
         0xeeee, 0xeded, 0x0301, 0x0303, 0x0201, 0x0203],
        "t12d4605h2_85626a9a5f7f_aaf95bb78ec9",
        id="tls12-46cipher",
    ),
    pytest.param(
        # Chrome 94, TLS 1.3, GREASE ciphers + extensions
        # OpenSSL drops 0x4469 (application_settings/ALPS)
        # ja4db ref: t13d1516h2_8daaf6152771_e5627efa2ab1
        [0xaaaa, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c,
         0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d,
         0x002f, 0x0035],
        [0x6a6a, 0x000d, 0x0000, 0x000a, 0x0005, 0x000b, 0x002b,
         0x001b, 0xff01, 0x0033, 0x4469, 0x002d, 0x0023, 0x0017,
         0x0012, 0x0010, 0x0a0a, 0x0015],
        "h2",
        [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806,
         0x0601],
        "t13d1515h2_8daaf6152771_de4a06bb82e3",
        id="chrome-tls13",
    ),
    pytest.param(
        # Chrome 72, TLS 1.3, GREASE, 17 ciphers incl 0x000a
        # All extensions recognized by OpenSSL — matches ja4db exactly
        [0xaaaa, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c,
         0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d,
         0x002f, 0x0035, 0x000a],
        [0x4a4a, 0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023,
         0x0010, 0x0005, 0x000d, 0x0012, 0x0033, 0x002d, 0x002b,
         0x001b, 0x7a7a, 0x0015],
        "h2",
        [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806,
         0x0601, 0x0201],
        "t13d1615h2_46e7e9700bed_45f260be83e2",
        id="chrome-tls13-v2",
    ),
    pytest.param(
        # WinHTTP, TLS 1.2, 19 ciphers, no ALPN
        # All extensions recognized by OpenSSL — matches ja4db exactly
        [0xc02c, 0xc02b, 0xc030, 0xc02f, 0xc024, 0xc023, 0xc028,
         0xc027, 0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c,
         0x003d, 0x003c, 0x0035, 0x002f, 0x000a],
        [0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0023, 0x0017,
         0xff01],
        None,
        [0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0201, 0x0403,
         0x0503, 0x0203, 0x0202, 0x0601, 0x0603],
        "t12d190800_d83cc789557e_7af1ed941c26",
        id="tls12-no-alpn",
    ),
]


@pytest.mark.parametrize("ciphers,ext_types,alpn,sig_algs,expected_ja4", VECTORS)
def test_ja4_scapy_vectors(ciphers, ext_types, alpn, sig_algs, expected_ja4):
    """Send ClientHello with known browser params, verify JA4 fingerprint."""
    ja4 = connect_and_get_ja4(NGINX_HOST, HASH_PORT, ciphers, ext_types, alpn, sig_algs)
    assert ja4 == expected_ja4
