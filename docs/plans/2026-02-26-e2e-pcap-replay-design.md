# E2E PCAP Replay Tests — Design

## Goal

Replay real TLS ClientHello packets from PCAP files against OpenResty and verify
that `ja4.compute()` (the full OpenSSL FFI pipeline) produces correct JA4
fingerprints. This tests the complete path: raw ClientHello bytes → OpenSSL FFI
parsing → cipher/extension extraction → GREASE filtering → sorting → SHA256
hashing → HTTP response header.

## Approach

**Scapy-based ClientHello reconstruction.** Parse PCAPs offline, extract
ClientHello parameters (cipher suite IDs, extension type IDs, ALPN, signature
algorithms, TLS version), reconstruct a new ClientHello with the same "shape"
but fresh cryptographic material, complete a real TLS handshake with OpenResty,
and assert the `X-JA4` response header matches the expected fingerprint.

JA4 fingerprints depend only on protocol-level IDs (cipher suite numbers,
extension type numbers, ALPN string, sig_alg codes, TLS version) — not on
actual key bytes or random values. So reconstructing with fresh crypto but
identical ID lists produces the same fingerprint.

## PCAP Selection

5 files, 6 unique fingerprints, covering TLS 1.2 and 1.3:

| PCAP | Stream | Expected JA4 | Notes |
|------|--------|-------------|-------|
| `tls12.pcap` | 0 | `t13d1715h2_5b57614c22b0_3d5424432f57` | Firefox TLS 1.3, 17 ciphers |
| `tls-alpn-h2.pcap` | 0 | `t12d4605h2_85626a9a5f7f_aaf95bb78ec9` | TLS 1.2, 46 ciphers, NULL datalink |
| `browsers-x509.pcapng` | 0 | `t13d1516h2_8daaf6152771_e5627efa2ab1` | Chrome TLS 1.3 |
| `badcurveball.pcap` | 0 | `t13d1615h2_46e7e9700bed_45f260be83e2` | TLS 1.3 edge case |
| `latest.pcapng` | tcp3 | `t12d190800_d83cc789557e_7af1ed941c26` | TLS 1.2, no ALPN |
| `latest.pcapng` | tcp5 | `t13d1516h2_8daaf6152771_9b887d9acb53` | TLS 1.3 variant sig_algs |

Source: `docs/ja4/python/test/testdata/*.json` (JA4 reference implementation
expected values). Cross-validated against unit tests in `t/005-ja4db-vectors.t`
(tests 16-17 match tls12.pcap and tls-alpn-h2.pcap exactly).

## File Layout

```
e2e/
├── pcap/                        # copied from docs/ja4/pcap/
│   ├── tls12.pcap
│   ├── tls-alpn-h2.pcap
│   ├── browsers-x509.pcapng
│   ├── badcurveball.pcap
│   └── latest.pcapng
├── pcap_helper.py               # scapy PCAP parsing + ClientHello replay
├── test_ja4_pcap.py             # pytest parametrized test cases
├── Dockerfile.tests             # add scapy + cryptography deps
├── conftest.py                  # existing (may add pcap fixtures)
└── ...                          # existing files unchanged
```

## Test Architecture

### pcap_helper.py

Two responsibilities:

1. **`extract_client_hellos(pcap_path)`** — Parse PCAP with `rdpcap()`, filter
   packets with `TLSClientHello` layer, return list of
   `(tcp_stream_key, client_hello_layer)` tuples. TCP stream key is
   `(src_ip, dst_ip, src_port, dst_port)` for matching against expected values.

2. **`replay_client_hello(host, port, client_hello)`** — Reconstruct a
   `TLSClientHello` with the same cipher suites, extension types, ALPN,
   signature algorithms, and TLS version. Use scapy's `TLSClientAutomaton` (or
   manual socket-level TLS if the automaton doesn't support custom ClientHello
   injection) to complete a handshake with OpenResty. Send
   `GET / HTTP/1.1\r\nHost: localhost\r\n\r\n`, parse the response, return the
   `X-JA4` header value.

### test_ja4_pcap.py

```python
PCAP_VECTORS = [
    ("pcap/tls12.pcap", 0, "t13d1715h2_5b57614c22b0_3d5424432f57"),
    ("pcap/tls-alpn-h2.pcap", 0, "t12d4605h2_85626a9a5f7f_aaf95bb78ec9"),
    ("pcap/browsers-x509.pcapng", 0, "t13d1516h2_8daaf6152771_e5627efa2ab1"),
    ("pcap/badcurveball.pcap", 0, "t13d1615h2_46e7e9700bed_45f260be83e2"),
    ("pcap/latest.pcapng", "tcp3", "t12d190800_d83cc789557e_7af1ed941c26"),
    ("pcap/latest.pcapng", "tcp5", "t13d1516h2_8daaf6152771_9b887d9acb53"),
]

@pytest.mark.parametrize("pcap_file,stream_id,expected_ja4", PCAP_VECTORS)
def test_ja4_pcap_replay(pcap_file, stream_id, expected_ja4):
    ...
```

### Dockerfile.tests changes

```dockerfile
FROM python:3.12-slim
RUN pip install pytest scapy cryptography
COPY . /tests
WORKDIR /tests
CMD ["pytest", "-v"]
```

### nginx.conf / docker-compose changes

None. Existing hash-mode server on port 443 already returns `X-JA4` in response
headers.

## Risks and Mitigations

**Risk:** Scapy `TLSClientAutomaton` may not accept a fully custom ClientHello.
**Mitigation:** Fall back to manual socket-level TLS using scapy's record/handshake
layer classes. More code but full control over every byte sent.

**Risk:** Some PCAPs have exotic cipher suites that OpenResty doesn't support,
causing handshake failure.
**Mitigation:** JA4 is computed from what the client offers, not what's negotiated.
As long as at least one offered cipher suite is supported by OpenResty (all PCAPs
include standard suites like AES-GCM, ChaCha20), the handshake will complete.

**Risk:** `latest.pcapng` TCP stream identification — sequential ClientHello index
may not match TCP stream number.
**Mitigation:** Match by TCP flow tuple `(src_ip, dst_ip, src_port, dst_port)` or
enumerate all ClientHellos and verify against expected fingerprint during
implementation.

## Test Counts

6 parametrized cases x 2 OpenResty versions (1.27 + 1.29) = 12 test runs.
Added to existing 24 e2e tests = 36 total (72 across both versions).
