import re


# JA4 hash format: t<ver>d<cc><ec><alpn>_<12hex>_<12hex>
# Section A is 10 chars: 1 protocol + 2 version + 1 sni + 2 cipher_count + 2 ext_count + 2 alpn
JA4_HASH_RE = re.compile(
    r"^t(?:13|12|11|10|s3|s2|00)[di]\d{2}\d{2}[a-z0-9]{2}_[a-f0-9]{12}_[a-f0-9]{12}$"
)

# JA4 raw format: section_a_csv_ciphers_csv_extensions (possibly with trailing _sig_algs)
JA4_RAW_RE = re.compile(
    r"^t(?:13|12|11|10|s3|s2|00)[di]\d{2}\d{2}[a-z0-9]{2}_[a-f0-9,]*_[a-f0-9,_]*$"
)


class TestJA4Hash:
    """JA4 TLS fingerprinting — hash mode (port 443)."""

    def test_ja4_header_present(self, hash_request, ssl_ctx_default):
        headers, _ = hash_request(ctx=ssl_ctx_default)
        assert "x-ja4" in headers, f"X-JA4 header missing. Headers: {headers}"

    def test_ja4_hash_format_tls13(self, hash_request, ssl_ctx_tls13):
        headers, _ = hash_request(ctx=ssl_ctx_tls13)
        ja4 = headers["x-ja4"]
        assert JA4_HASH_RE.match(ja4), f"JA4 '{ja4}' doesn't match hash format"
        assert ja4[1:3] == "13", f"Expected TLS 1.3 version '13', got '{ja4[1:3]}'"

    def test_ja4_hash_format_tls12(self, hash_request, ssl_ctx_tls12):
        headers, _ = hash_request(ctx=ssl_ctx_tls12)
        ja4 = headers["x-ja4"]
        assert JA4_HASH_RE.match(ja4), f"JA4 '{ja4}' doesn't match hash format"
        # Pure TLS 1.2 clients don't send supported_versions extension,
        # so ja4.lua reports "00" (no fallback to legacy version field yet)
        assert ja4[1:3] == "00", f"Expected TLS 1.2 version '00', got '{ja4[1:3]}'"

    def test_ja4_deterministic(self, hash_request, ssl_ctx_tls13):
        h1, _ = hash_request(ctx=ssl_ctx_tls13)
        h2, _ = hash_request(ctx=ssl_ctx_tls13)
        assert h1["x-ja4"] == h2["x-ja4"], "JA4 should be deterministic for same TLS context"

    def test_ja4_sni_flag_is_domain(self, hash_request, ssl_ctx_default):
        headers, _ = hash_request(ctx=ssl_ctx_default)
        ja4 = headers["x-ja4"]
        # Python's http.client sends SNI (the hostname), so flag should be 'd'
        assert ja4[3] == "d", f"Expected SNI flag 'd', got '{ja4[3]}'"

    def test_ja4_different_tls_versions_differ(self, hash_request, ssl_ctx_tls13, ssl_ctx_tls12):
        h13, _ = hash_request(ctx=ssl_ctx_tls13)
        h12, _ = hash_request(ctx=ssl_ctx_tls12)
        # At minimum the version portion differs
        assert h13["x-ja4"][:3] != h12["x-ja4"][:3], \
            "TLS 1.3 and 1.2 should produce different version sections"


class TestJA4Raw:
    """JA4 TLS fingerprinting — raw mode (port 8443)."""

    def test_ja4_raw_header_present(self, raw_request, ssl_ctx_default):
        headers, _ = raw_request(ctx=ssl_ctx_default)
        assert "x-ja4" in headers, f"X-JA4 header missing. Headers: {headers}"

    def test_ja4_raw_format(self, raw_request, ssl_ctx_tls13):
        headers, _ = raw_request(ctx=ssl_ctx_tls13)
        ja4 = headers["x-ja4"]
        # Raw mode: section_a has same 10-char prefix, but sections B/C are CSV hex
        assert JA4_RAW_RE.match(ja4), f"JA4 raw '{ja4}' doesn't match raw format"

    def test_ja4_raw_contains_commas(self, raw_request, ssl_ctx_default):
        headers, _ = raw_request(ctx=ssl_ctx_default)
        ja4 = headers["x-ja4"]
        # Raw mode sections B and C should have comma-separated hex values
        parts = ja4.split("_", 1)
        assert len(parts) >= 2, "Raw JA4 should have underscore separators"
        rest = parts[1]
        assert "," in rest, f"Raw mode should contain commas in cipher/ext sections: '{rest}'"

    def test_ja4_raw_longer_than_hash(self, raw_request, ssl_ctx_default):
        headers, _ = raw_request(ctx=ssl_ctx_default)
        ja4 = headers["x-ja4"]
        # Hash mode is always 36 chars; raw mode is typically much longer
        assert len(ja4) > 36, f"Raw JA4 should be longer than 36 chars, got {len(ja4)}"
