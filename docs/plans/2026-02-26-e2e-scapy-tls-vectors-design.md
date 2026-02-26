# E2E Scapy TLS Vector Tests — Design

## Goal

Send TLS ClientHellos with known browser parameters to OpenResty via scapy and
verify that `ja4.compute()` (the full OpenSSL FFI pipeline) produces correct JA4
fingerprints. This tests the complete path: raw ClientHello bytes → OpenSSL FFI
parsing → cipher/extension extraction → GREASE filtering → sorting → SHA256
hashing → HTTP response header.

## Approach

**Scapy-based TLS connections with hardcoded browser vectors.** Each test vector
contains the exact cipher suites, extension type IDs, ALPN, signature algorithms,
and TLS version from a real browser ClientHello. Scapy constructs a
TLSClientHello with those parameters (fresh cryptographic material), completes a
real TLS handshake with OpenResty, and asserts the `X-JA4` response header
matches the expected fingerprint.

JA4 fingerprints depend only on protocol-level IDs (cipher suite numbers,
extension type numbers, ALPN string, sig_alg codes, TLS version) — not on actual
key bytes or random values. So constructing a new connection with identical ID
lists produces the same fingerprint as the original browser.

## Test Vectors

6 vectors, 6 unique fingerprints, covering TLS 1.2 and 1.3:

| ID | Browser | Expected JA4 | Notes |
|----|---------|-------------|-------|
| firefox-tls13 | Firefox 105 | `t13d1715h2_5b57614c22b0_3d5424432f57` | TLS 1.3, 17 ciphers, 15 extensions |
| tls12-46cipher | GnuTLS | `t12d4605h2_85626a9a5f7f_aaf95bb78ec9` | TLS 1.2, 46 ciphers, GREASE sig_algs |
| chrome-tls13 | Chrome 94 | `t13d1516h2_8daaf6152771_e5627efa2ab1` | TLS 1.3, GREASE ciphers+extensions |
| chrome-tls13-v2 | Chrome 72 | `t13d1615h2_46e7e9700bed_45f260be83e2` | TLS 1.3, 16 ciphers incl 0x000a |
| tls12-no-alpn | WinHTTP | `t12d190800_d83cc789557e_7af1ed941c26` | TLS 1.2, 19 ciphers, no ALPN |
| chrome-tls13-slack | Chrome 94 | `t13d1516h2_8daaf6152771_9b887d9acb53` | TLS 1.3, ext 0x0029 (pre_shared_key) |

Expected values cross-validated against `docs/ja4/python/test/testdata/*.json`
and unit tests in `t/005-ja4db-vectors.t`.

## File Layout

```
e2e/
├── scapy_tls_client.py          # scapy TLS client helper (connect_and_get_ja4)
├── test_ja4_scapy.py            # pytest parametrized test cases
├── Dockerfile.tests             # add scapy + cryptography deps
├── conftest.py                  # existing (unchanged)
└── ...                          # existing files unchanged
```

## Test Architecture

### scapy_tls_client.py

Single function: **`connect_and_get_ja4(host, port, ciphers, ext_types, alpn, sig_algs)`**

Maps extension type IDs to scapy extension objects, constructs a TLSClientHello,
uses `TLSClientAutomaton` to complete the handshake, sends HTTP GET, parses the
response, and returns the `X-JA4` header value.

### test_ja4_scapy.py

Parametrized pytest test with 6 vectors. Each vector is a tuple of
`(ciphers, ext_types, alpn, sig_algs, expected_ja4)`.

### Dockerfile.tests changes

Add `scapy` and `cryptography` to pip install. No other infrastructure changes.

### nginx.conf / docker-compose changes

None. Existing hash-mode server on port 443 already returns `X-JA4` in response
headers.

## Risks and Mitigations

**Risk:** Scapy `TLSClientAutomaton` may not accept a fully custom ClientHello.
**Mitigation:** Fall back to manual socket-level TLS using scapy's record/handshake
layer classes. More code but full control over every byte sent.

**Risk:** Some vectors have exotic cipher suites that OpenResty doesn't support,
causing handshake failure.
**Mitigation:** JA4 is computed from what the client offers, not what's negotiated.
As long as at least one offered cipher suite is supported by OpenResty (all vectors
include standard suites like AES-GCM, ChaCha20), the handshake will complete.

## Test Counts

6 parametrized cases x 2 OpenResty versions (1.27 + 1.29) = 12 test runs.
Added to existing 24 e2e tests = 36 total (72 across both versions).
