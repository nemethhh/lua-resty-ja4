import re


# JA4H hash: 12-char section_a + 3x _<12hex> = 51 chars
JA4H_HASH_RE = re.compile(
    r"^[a-z]{2}(?:11|10|20|30|00)[cnr]{2}\d{2}[a-z0-9]{4}"
    r"_[a-f0-9]{12}_[a-f0-9]{12}_[a-f0-9]{12}$"
)


class TestJA4HHttp2Hash:
    """JA4H HTTP/2 fingerprinting — hash mode."""

    def test_h2_ja4h_header_present(self, h2_hash_request):
        headers, _ = h2_hash_request()
        assert "x-ja4h" in headers, f"X-JA4H header missing. Headers: {dict(headers)}"

    def test_h2_ja4h_hash_format(self, h2_hash_request):
        headers, _ = h2_hash_request()
        ja4h = headers["x-ja4h"]
        assert JA4H_HASH_RE.match(ja4h), f"JA4H '{ja4h}' doesn't match hash format"

    def test_h2_version_is_20(self, h2_hash_request):
        headers, _ = h2_hash_request()
        ja4h = headers["x-ja4h"]
        version = ja4h[2:4]
        assert version == "20", f"Expected HTTP/2 version '20', got '{version}'"

    def test_h2_get_method(self, h2_hash_request):
        headers, _ = h2_hash_request(method="GET")
        ja4h = headers["x-ja4h"]
        assert ja4h[:2] == "ge", f"Expected method 'ge', got '{ja4h[:2]}'"

    def test_h2_head_method(self, h2_hash_request):
        headers, _ = h2_hash_request(method="HEAD")
        ja4h = headers["x-ja4h"]
        assert ja4h[:2] == "he", f"Expected method 'he', got '{ja4h[:2]}'"

    def test_h2_cookie_flag_absent(self, h2_hash_request):
        headers, _ = h2_hash_request()
        ja4h = headers["x-ja4h"]
        assert ja4h[4] == "n", f"Expected cookie flag 'n', got '{ja4h[4]}'"

    def test_h2_cookie_flag_present(self, h2_hash_request):
        headers, _ = h2_hash_request(headers={"Cookie": "session=abc123"})
        ja4h = headers["x-ja4h"]
        assert ja4h[4] == "c", f"Expected cookie flag 'c', got '{ja4h[4]}'"

    def test_h2_referer_flag_absent(self, h2_hash_request):
        headers, _ = h2_hash_request()
        ja4h = headers["x-ja4h"]
        assert ja4h[5] == "n", f"Expected referer flag 'n', got '{ja4h[5]}'"

    def test_h2_referer_flag_present(self, h2_hash_request):
        headers, _ = h2_hash_request(headers={"Referer": "https://example.com"})
        ja4h = headers["x-ja4h"]
        assert ja4h[5] == "r", f"Expected referer flag 'r', got '{ja4h[5]}'"

    def test_h2_accept_language(self, h2_hash_request):
        headers, _ = h2_hash_request(headers={"Accept-Language": "en-US,en;q=0.9"})
        ja4h = headers["x-ja4h"]
        lang = ja4h[8:12]
        assert lang == "enus", f"Expected language 'enus', got '{lang}'"

    def test_h2_no_language_defaults(self, h2_hash_request):
        headers, _ = h2_hash_request()
        ja4h = headers["x-ja4h"]
        lang = ja4h[8:12]
        assert lang == "0000", f"Expected default language '0000', got '{lang}'"

    def test_h2_deterministic(self, h2_hash_request):
        h1, _ = h2_hash_request(headers={"Accept-Language": "fr-FR"})
        h2, _ = h2_hash_request(headers={"Accept-Language": "fr-FR"})
        assert h1["x-ja4h"] == h2["x-ja4h"], "JA4H should be deterministic"

    def test_h2_fingerprint_length(self, h2_hash_request):
        headers, _ = h2_hash_request()
        ja4h = headers["x-ja4h"]
        assert len(ja4h) == 51, f"Hash JA4H should be 51 chars, got {len(ja4h)}"


class TestJA4HHttp2Raw:
    """JA4H HTTP/2 fingerprinting — raw mode."""

    def test_h2_raw_header_present(self, h2_raw_request):
        headers, _ = h2_raw_request()
        assert "x-ja4h" in headers, f"X-JA4H header missing. Headers: {dict(headers)}"

    def test_h2_raw_version_is_20(self, h2_raw_request):
        headers, _ = h2_raw_request()
        ja4h = headers["x-ja4h"]
        version = ja4h[2:4]
        assert version == "20", f"Expected HTTP/2 version '20', got '{version}'"

    def test_h2_raw_contains_header_names(self, h2_raw_request):
        headers, _ = h2_raw_request(headers={"Accept-Language": "en-US"})
        ja4h = headers["x-ja4h"]
        parts = ja4h.split("_")
        assert len(parts) >= 2, f"Raw JA4H should have underscore separators: '{ja4h}'"
        section_b = parts[1]
        # HTTP/2 headers are lowercase; should contain accept-language
        assert "accept-language" in section_b.lower(), \
            f"Raw section B should contain header names: '{section_b}'"

    def test_h2_raw_cookie_names_sorted(self, h2_raw_request):
        headers, _ = h2_raw_request(headers={"Cookie": "zebra=3; alpha=1; mango=2"})
        ja4h = headers["x-ja4h"]
        parts = ja4h.split("_")
        assert len(parts) >= 3, f"Expected at least 3 sections: '{ja4h}'"
        section_c = parts[2]
        assert "alpha" in section_c and "mango" in section_c and "zebra" in section_c, \
            f"Raw section C should contain sorted cookie names: '{section_c}'"
        # Verify alphabetical order
        names = section_c.split(",")
        assert names == sorted(names), f"Cookie names should be sorted: {names}"
