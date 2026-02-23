import re


# JA4H hash: 12-char section_a + 3x _<12hex> = 12 + 3*(1+12) = 51 chars
JA4H_HASH_RE = re.compile(
    r"^[a-z]{2}(?:11|10|20|30|00)[cnr]{2}\d{2}[a-z0-9]{4}"
    r"_[a-f0-9]{12}_[a-f0-9]{12}_[a-f0-9]{12}$"
)


class TestJA4HHash:
    """JA4H HTTP fingerprinting — hash mode (port 443)."""

    def test_ja4h_header_present(self, hash_request):
        headers, _ = hash_request()
        assert "x-ja4h" in headers, f"X-JA4H header missing. Headers: {headers}"

    def test_ja4h_hash_format(self, hash_request):
        headers, _ = hash_request()
        ja4h = headers["x-ja4h"]
        assert JA4H_HASH_RE.match(ja4h), f"JA4H '{ja4h}' doesn't match hash format"

    def test_ja4h_get_method(self, hash_request):
        headers, _ = hash_request(method="GET")
        ja4h = headers["x-ja4h"]
        assert ja4h[:2] == "ge", f"Expected method code 'ge', got '{ja4h[:2]}'"

    def test_ja4h_head_method(self, hash_request):
        headers, _ = hash_request(method="HEAD")
        ja4h = headers["x-ja4h"]
        assert ja4h[:2] == "he", f"Expected method code 'he', got '{ja4h[:2]}'"

    def test_ja4h_cookie_flag_absent(self, hash_request):
        headers, _ = hash_request()
        ja4h = headers["x-ja4h"]
        assert ja4h[4] == "n", f"Expected cookie flag 'n' (no cookie), got '{ja4h[4]}'"

    def test_ja4h_cookie_flag_present(self, hash_request):
        headers, _ = hash_request(headers={"Cookie": "session=abc123"})
        ja4h = headers["x-ja4h"]
        assert ja4h[4] == "c", f"Expected cookie flag 'c', got '{ja4h[4]}'"

    def test_ja4h_referer_flag_absent(self, hash_request):
        headers, _ = hash_request()
        ja4h = headers["x-ja4h"]
        assert ja4h[5] == "n", f"Expected referer flag 'n', got '{ja4h[5]}'"

    def test_ja4h_referer_flag_present(self, hash_request):
        headers, _ = hash_request(headers={"Referer": "https://example.com"})
        ja4h = headers["x-ja4h"]
        assert ja4h[5] == "r", f"Expected referer flag 'r', got '{ja4h[5]}'"

    def test_ja4h_accept_language(self, hash_request):
        headers, _ = hash_request(headers={"Accept-Language": "en-US,en;q=0.9"})
        ja4h = headers["x-ja4h"]
        lang = ja4h[8:12]
        assert lang == "enus", f"Expected language 'enus', got '{lang}'"

    def test_ja4h_no_language_defaults(self, hash_request):
        headers, _ = hash_request()
        ja4h = headers["x-ja4h"]
        lang = ja4h[8:12]
        assert lang == "0000", f"Expected default language '0000', got '{lang}'"

    def test_ja4h_deterministic(self, hash_request):
        h1, _ = hash_request(headers={"Accept-Language": "fr-FR"})
        h2, _ = hash_request(headers={"Accept-Language": "fr-FR"})
        assert h1["x-ja4h"] == h2["x-ja4h"], "JA4H should be deterministic"


class TestJA4HRaw:
    """JA4H HTTP fingerprinting — raw mode (port 8443)."""

    def test_ja4h_raw_header_present(self, raw_request):
        headers, _ = raw_request()
        assert "x-ja4h" in headers, f"X-JA4H header missing. Headers: {headers}"

    def test_ja4h_raw_contains_header_names(self, raw_request):
        headers, _ = raw_request(headers={"Accept-Language": "en-US"})
        ja4h = headers["x-ja4h"]
        # In raw mode, section B contains actual header names (comma-separated)
        parts = ja4h.split("_")
        assert len(parts) >= 2, f"Raw JA4H should have underscore separators: '{ja4h}'"
        section_b = parts[1]
        # http.client sends Host header; Accept-Language was added by us
        assert "Host" in section_b or "host" in section_b or "Accept-Language" in section_b, \
            f"Raw section B should contain header names: '{section_b}'"

    def test_ja4h_raw_cookie_names_visible(self, raw_request):
        headers, _ = raw_request(headers={"Cookie": "alpha=1; beta=2"})
        ja4h = headers["x-ja4h"]
        parts = ja4h.split("_")
        # Section C should contain sorted cookie names
        assert len(parts) >= 3, f"Expected at least 3 sections: '{ja4h}'"
        section_c = parts[2]
        assert "alpha" in section_c and "beta" in section_c, \
            f"Raw section C should contain cookie names: '{section_c}'"

    def test_ja4h_raw_longer_than_hash(self, raw_request):
        headers, _ = raw_request(headers={
            "Accept-Language": "en-US",
            "Cookie": "session=abc123",
        })
        ja4h = headers["x-ja4h"]
        # Hash mode is always 51 chars; raw mode is typically longer
        assert len(ja4h) > 51, f"Raw JA4H should be longer than 51 chars, got {len(ja4h)}"
