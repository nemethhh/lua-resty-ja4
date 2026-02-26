# E2E PCAP Replay Tests — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Use scapy to send TLS ClientHellos with exact PCAP-derived parameters to OpenResty, verifying the full `ja4.compute()` FFI pipeline produces correct fingerprints.

**Architecture:** Parameters extracted once from 5 PCAPs (tls12.pcap, tls-alpn-h2.pcap, browsers-x509.pcapng, badcurveball.pcap, latest.pcapng) are hardcoded as test vectors. At test time, scapy constructs a TLSClientHello with those exact cipher suites, extension types, ALPN, and signature algorithms, completes a real TLS handshake with OpenResty, sends HTTP, and asserts the `X-JA4` response header. No PCAP files at runtime.

**Tech Stack:** Python 3.12, pytest, scapy 2.7+, cryptography (scapy TLS dependency)

**Design doc:** `docs/plans/2026-02-26-e2e-pcap-replay-design.md`

---

### Task 1: Update Dockerfile.tests

**Files:**
- Modify: `e2e/Dockerfile.tests`

**Step 1: Add scapy and cryptography to pip install**

```dockerfile
FROM python:3.12-slim

RUN pip install --no-cache-dir pytest scapy cryptography

WORKDIR /app
COPY e2e/conftest.py e2e/test_ja4.py e2e/test_ja4h.py /app/

CMD ["pytest", "-v", "--tb=short"]
```

Change the `RUN pip install` line from `pytest` to `pytest scapy cryptography`.

**Step 2: Verify Dockerfile builds**

Run: `docker build -f e2e/Dockerfile.tests -t ja4-test-deps-check ..`
Expected: builds successfully with scapy installed

**Step 3: Commit**

```bash
git add e2e/Dockerfile.tests
git commit -m "build(e2e): add scapy + cryptography to test container"
```

---

### Task 2: Spike — verify scapy TLS handshake with custom ClientHello

This is a critical spike. We need to confirm scapy can:
1. Construct a TLSClientHello with arbitrary cipher suites and extensions
2. Complete a real TLS handshake with OpenResty
3. Send an HTTP request and receive the response with X-JA4 header

**Files:**
- Create: `e2e/spike_scapy_tls.py` (temporary, deleted after spike)

**Step 1: Write a minimal spike script**

```python
"""Spike: can scapy complete a TLS handshake with custom ClientHello?"""
import os
import sys

# Suppress scapy warnings
import logging
logging.getLogger("scapy").setLevel(logging.ERROR)

from scapy.all import load_layer, conf
conf.logLevel = 40
load_layer("tls")

from scapy.layers.tls.automaton import TLSClientAutomaton
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.extensions import (
    TLS_Ext_ServerName, ServerName,
    TLS_Ext_SupportedGroups,
    TLS_Ext_SupportedVersions, TLS_Ext_SupportedVersion_CH,
    TLS_Ext_SignatureAlgorithms,
    TLS_Ext_ALPN, ProtocolName,
    TLS_Ext_KeyShareClient, KeyShareEntry,
    TLS_Ext_PSKKeyExchangeModes,
    TLS_Ext_RenegotiationInfo,
    TLS_Ext_SessionTicket,
    TLS_Ext_ExtendedMasterSecret,
    TLS_Ext_EncryptThenMAC,
    TLS_Ext_ECPointsFormat,
)

HOST = os.environ.get("NGINX_HOST", "localhost")
PORT = int(os.environ.get("NGINX_PORT", "443"))

# Simple TLS 1.3 ClientHello (Firefox-like from tls12.pcap)
ch = TLSClientHello(
    ciphers=[
        0x1301, 0x1303, 0x1302,
        0xc02b, 0xc02f, 0xcca9, 0xcca8,
        0xc02c, 0xc030, 0xc00a, 0xc009,
        0xc013, 0xc014, 0x009c, 0x009d,
        0x002f, 0x0035,
    ],
    ext=[
        TLS_Ext_ServerName(servernames=[ServerName(servername=HOST.encode())]),
        TLS_Ext_SupportedGroups(groups=[0x001d, 0x0017, 0x0018, 0x0019]),
        TLS_Ext_ECPointsFormat(ecpl=[0]),
        TLS_Ext_SessionTicket(),
        TLS_Ext_ALPN(protocols=[ProtocolName(protocol=b"h2")]),
        TLS_Ext_EncryptThenMAC(),
        TLS_Ext_ExtendedMasterSecret(),
        TLS_Ext_SignatureAlgorithms(sig_algs=[
            0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806,
            0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
        ]),
        TLS_Ext_SupportedVersion_CH(versions=[0x0304, 0x0303]),
        TLS_Ext_PSKKeyExchangeModes(kxmodes=[1]),
        TLS_Ext_RenegotiationInfo(),
    ],
)

print(f"Connecting to {HOST}:{PORT} ...")

try:
    # TLSClientAutomaton approach
    t = TLSClientAutomaton(
        server=HOST,
        dport=PORT,
        client_hello=ch,
    )
    # The automaton's run() should complete the handshake
    # After that we need to send HTTP and read response
    result = t.run()
    print(f"Handshake result: {result}")
    print("SUCCESS: TLSClientAutomaton works")
except Exception as e:
    print(f"TLSClientAutomaton failed: {e}")
    print("Trying manual socket approach...")

    # Fallback: manual socket + scapy TLS record layer
    import socket
    from scapy.layers.tls.record import TLS
    from scapy.layers.tls.handshake import TLSClientHello

    s = socket.socket()
    s.settimeout(5)
    s.connect((HOST, PORT))

    # Build TLS record containing our ClientHello
    record = TLS(msg=[ch])
    s.send(bytes(record))

    # Read server response
    data = s.recv(8192)
    print(f"Received {len(data)} bytes from server")
    s.close()

    if len(data) > 0:
        print("SUCCESS: Server responded to custom ClientHello")
    else:
        print("FAIL: No response")
```

**Step 2: Run the spike inside the e2e Docker environment**

Temporarily add the spike script to Dockerfile.tests COPY line, then:
```bash
docker compose -f e2e/docker-compose.e2e.yml run --rm tests-1.27 python spike_scapy_tls.py
```

Expected outcomes (one of):
- TLSClientAutomaton completes handshake → use that approach
- Automaton fails, manual socket gets server response → use manual approach
- Both fail → investigate scapy API, try alternative extensions

**Step 3: Based on spike results, decide approach**

- If automaton works: use `TLSClientAutomaton` for the helper
- If manual socket works: use raw socket + scapy TLS records
- If neither: investigate scapy `tlsSession` / `SSLStreamSocket` APIs

**Step 4: Delete spike file**

```bash
rm e2e/spike_scapy_tls.py
```

---

### Task 3: Write scapy_tls_client.py helper

**Files:**
- Create: `e2e/scapy_tls_client.py`

This module contains one function: `connect_and_get_ja4()`. The exact implementation depends on Task 2 spike results. Below is the TLSClientAutomaton version (adapt if spike shows manual approach is needed).

**Step 1: Write the helper module**

```python
"""Scapy-based TLS client for JA4 e2e tests.

Constructs a TLSClientHello with exact cipher/extension parameters,
completes a TLS handshake with OpenResty, sends HTTP GET, and returns
the X-JA4 response header value.
"""
import logging
logging.getLogger("scapy").setLevel(logging.ERROR)

from scapy.all import load_layer, conf
conf.logLevel = 40
load_layer("tls")

from scapy.layers.tls.automaton import TLSClientAutomaton
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.extensions import (
    TLS_Ext_ServerName, ServerName,
    TLS_Ext_SupportedGroups,
    TLS_Ext_SupportedVersions, TLS_Ext_SupportedVersion_CH,
    TLS_Ext_SignatureAlgorithms,
    TLS_Ext_ALPN, ProtocolName,
    TLS_Ext_PSKKeyExchangeModes,
    TLS_Ext_RenegotiationInfo,
    TLS_Ext_SessionTicket,
    TLS_Ext_ExtendedMasterSecret,
    TLS_Ext_EncryptThenMAC,
    TLS_Ext_ECPointsFormat,
    TLS_Ext_EarlyDataIndication,
    TLS_Ext_PreSharedKey,
)


# Map extension type IDs to scapy extension constructors.
# Extensions that carry data need specific constructors.
# Unknown/simple extensions use a generic TLS_Ext with just the type ID.
def _build_extensions(ext_types, host, alpn, sig_algs, tls13):
    """Build scapy extension objects from a list of extension type IDs.

    Args:
        ext_types: list of int extension type IDs (from PCAP extraction)
        host: str server hostname for SNI
        alpn: str ALPN protocol (e.g. "h2") or None
        sig_algs: list of int signature algorithm codes
        tls13: bool whether to include TLS 1.3 extensions (key_share, etc.)
    """
    exts = []
    for etype in ext_types:
        # GREASE values (0x?a?a pattern) — include as raw extension
        if (etype & 0x0f0f) == 0x0a0a:
            from scapy.layers.tls.extensions import TLS_Ext_Unknown
            exts.append(TLS_Ext_Unknown(type=etype, data=b"\x00"))
            continue

        if etype == 0x0000:  # SNI
            exts.append(TLS_Ext_ServerName(
                servernames=[ServerName(servername=host.encode())]
            ))
        elif etype == 0x0005:  # status_request
            from scapy.layers.tls.extensions import TLS_Ext_CSR
            exts.append(TLS_Ext_CSR(stype=1, req=b"\x00\x00\x00\x00\x00"))
        elif etype == 0x000a:  # supported_groups
            groups = [0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]
            exts.append(TLS_Ext_SupportedGroups(groups=groups))
        elif etype == 0x000b:  # ec_point_formats
            exts.append(TLS_Ext_ECPointsFormat(ecpl=[0]))
        elif etype == 0x000d:  # signature_algorithms
            exts.append(TLS_Ext_SignatureAlgorithms(sig_algs=sig_algs))
        elif etype == 0x0010:  # ALPN
            if alpn:
                exts.append(TLS_Ext_ALPN(
                    protocols=[ProtocolName(protocol=alpn.encode())]
                ))
        elif etype == 0x0012:  # signed_certificate_timestamp
            from scapy.layers.tls.extensions import TLS_Ext_Unknown
            exts.append(TLS_Ext_Unknown(type=0x0012, data=b""))
        elif etype == 0x0015:  # padding
            from scapy.layers.tls.extensions import TLS_Ext_Padding
            exts.append(TLS_Ext_Padding(padding=b"\x00" * 10))
        elif etype == 0x0017:  # extended_master_secret
            exts.append(TLS_Ext_ExtendedMasterSecret())
        elif etype == 0x0023:  # session_ticket
            exts.append(TLS_Ext_SessionTicket())
        elif etype == 0x002b:  # supported_versions
            if tls13:
                exts.append(TLS_Ext_SupportedVersion_CH(
                    versions=[0x0304, 0x0303]
                ))
            else:
                exts.append(TLS_Ext_SupportedVersion_CH(
                    versions=[0x0303, 0x0302]
                ))
        elif etype == 0x002d:  # psk_key_exchange_modes
            exts.append(TLS_Ext_PSKKeyExchangeModes(kxmodes=[1]))
        elif etype == 0x0033:  # key_share
            from scapy.layers.tls.extensions import TLS_Ext_KeyShareClient
            exts.append(TLS_Ext_KeyShareClient())
        elif etype == 0xff01:  # renegotiation_info
            exts.append(TLS_Ext_RenegotiationInfo())
        else:
            # Generic/unknown extension — send as raw with type ID
            from scapy.layers.tls.extensions import TLS_Ext_Unknown
            exts.append(TLS_Ext_Unknown(type=etype, data=b""))
    return exts


def connect_and_get_ja4(host, port, ciphers, ext_types, alpn, sig_algs):
    """Connect to host:port with exact ClientHello params, return X-JA4 header.

    Args:
        host: str server hostname
        port: int server port
        ciphers: list of int cipher suite IDs (in original PCAP order)
        ext_types: list of int extension type IDs (in original PCAP order)
        alpn: str ALPN protocol (e.g. "h2") or None
        sig_algs: list of int signature algorithm codes
    Returns:
        str: X-JA4 header value from HTTP response
    Raises:
        RuntimeError: if handshake fails or X-JA4 header is missing
    """
    # Determine if TLS 1.3 (has TLS 1.3 ciphers or supported_versions ext)
    tls13_ciphers = {0x1301, 0x1302, 0x1303, 0x1304, 0x1305}
    tls13 = bool(set(ciphers) & tls13_ciphers) or 0x002b in ext_types

    extensions = _build_extensions(ext_types, host, alpn, sig_algs, tls13)

    ch = TLSClientHello(
        ciphers=ciphers,
        ext=extensions,
    )

    # --- Approach: TLSClientAutomaton ---
    # (Replace with manual socket approach if spike shows this doesn't work)
    t = TLSClientAutomaton(
        server=host,
        dport=port,
        client_hello=ch,
    )
    sock = t.run()

    # Send HTTP/1.1 request
    http_req = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"
    sock.send(http_req.encode())

    # Read response
    data = sock.recv(8192)
    sock.close()

    # Parse HTTP response headers
    response_text = data.decode("utf-8", errors="replace")
    ja4 = None
    for line in response_text.split("\r\n"):
        if line.lower().startswith("x-ja4:"):
            ja4 = line.split(":", 1)[1].strip()
            break

    if ja4 is None:
        raise RuntimeError(
            f"X-JA4 header not found in response:\n{response_text[:500]}"
        )
    return ja4
```

**NOTE:** The `_build_extensions` function maps extension type IDs to scapy
extension objects. This is the most likely place to need adjustment after the
spike. Some extension classes may have different names or require different
constructor args in scapy 2.7.

**Step 2: Verify import works**

Run: `docker compose -f e2e/docker-compose.e2e.yml run --rm tests-1.27 python -c "from scapy_tls_client import connect_and_get_ja4; print('OK')"`
Expected: `OK`

---

### Task 4: Write test_ja4_pcap.py with hardcoded vectors

**Files:**
- Create: `e2e/test_ja4_pcap.py`

**Step 1: Write the test file**

All 6 vectors with parameters extracted from PCAPs (via one-time scapy extraction)
and expected JA4 values from `docs/ja4/python/test/testdata/*.json`.

```python
"""E2E tests: replay PCAP-derived ClientHello parameters via scapy.

Each vector contains the exact cipher suites, extensions, ALPN, and
signature algorithms from a real PCAP capture. Scapy reconstructs
the ClientHello, completes a TLS handshake with OpenResty, and
verifies the X-JA4 response header matches the expected fingerprint.

Sources:
  - tls12.pcap: Firefox TLS 1.3 (docs/ja4/pcap/)
  - tls-alpn-h2.pcap: TLS 1.2 46-cipher IPv6 (docs/ja4/pcap/)
  - browsers-x509.pcapng: Chrome TLS 1.3 (docs/ja4/pcap/)
  - badcurveball.pcap: Chrome TLS 1.3 variant (docs/ja4/pcap/)
  - latest.pcapng: mixed TLS 1.2/1.3 (docs/ja4/pcap/)
"""
import os
import pytest

from scapy_tls_client import connect_and_get_ja4

NGINX_HOST = os.environ.get("NGINX_HOST", "nginx")
HASH_PORT = int(os.environ.get("NGINX_PORT", "443"))


# --- Test vectors (extracted from PCAPs, expected from ja4 reference testdata) ---

PCAP_VECTORS = [
    pytest.param(
        # tls12.pcap stream 0 — Firefox TLS 1.3, 17 ciphers, 15 extensions
        [0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8,
         0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c,
         0x009d, 0x002f, 0x0035],
        [0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010,
         0x0005, 0x0022, 0x0033, 0x002b, 0x000d, 0x002d, 0x001c,
         0x0015],
        "h2",
        [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806,
         0x0401, 0x0501, 0x0601, 0x0203, 0x0201],
        "t13d1715h2_5b57614c22b0_3d5424432f57",
        id="tls12.pcap-firefox-tls13",
    ),
    pytest.param(
        # tls-alpn-h2.pcap stream 0 — TLS 1.2, 46 ciphers, 5 extensions, IPv6
        # (from unit test 17, NULL datalink PCAP not parseable by scapy)
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
        id="tls-alpn-h2.pcap-tls12-46cipher",
    ),
    pytest.param(
        # browsers-x509.pcapng stream 0 — Chrome TLS 1.3 with GREASE
        [0xaaaa, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c,
         0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d,
         0x002f, 0x0035],
        [0x6a6a, 0x000d, 0x0000, 0x000a, 0x0005, 0x000b, 0x002b,
         0x001b, 0xff01, 0x0033, 0x4469, 0x002d, 0x0023, 0x0017,
         0x0012, 0x0010, 0x0a0a, 0x0015],
        "h2",
        [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806,
         0x0601],
        "t13d1516h2_8daaf6152771_e5627efa2ab1",
        id="browsers-x509.pcapng-chrome-tls13",
    ),
    pytest.param(
        # badcurveball.pcap stream 0 — Chrome TLS 1.3 variant with GREASE
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
        id="badcurveball.pcap-chrome-tls13-variant",
    ),
    pytest.param(
        # latest.pcapng stream tcp3 — TLS 1.2, 19 ciphers, no ALPN
        [0xc02c, 0xc02b, 0xc030, 0xc02f, 0xc024, 0xc023, 0xc028,
         0xc027, 0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c,
         0x003d, 0x003c, 0x0035, 0x002f, 0x000a],
        [0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0023, 0x0017,
         0xff01],
        None,
        [0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0201, 0x0403,
         0x0503, 0x0203, 0x0202, 0x0601, 0x0603],
        "t12d190800_d83cc789557e_7af1ed941c26",
        id="latest.pcapng-tcp3-tls12-no-alpn",
    ),
    pytest.param(
        # latest.pcapng stream tcp5 — Chrome TLS 1.3 with GREASE + ext 0x0029
        [0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c,
         0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d,
         0x002f, 0x0035],
        [0x5a5a, 0x000d, 0x0010, 0x0000, 0x000b, 0x0023, 0x4469,
         0xff01, 0x0033, 0x000a, 0x002d, 0x002b, 0x0005, 0x0017,
         0x0012, 0x001b, 0x6a6a, 0x0029],
        "h2",
        [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806,
         0x0601],
        "t13d1516h2_8daaf6152771_9b887d9acb53",
        id="latest.pcapng-tcp5-chrome-tls13-slack",
    ),
]


@pytest.mark.parametrize("ciphers,ext_types,alpn,sig_algs,expected_ja4", PCAP_VECTORS)
def test_ja4_pcap_replay(ciphers, ext_types, alpn, sig_algs, expected_ja4):
    """Replay PCAP-derived ClientHello params and verify JA4 fingerprint."""
    ja4 = connect_and_get_ja4(NGINX_HOST, HASH_PORT, ciphers, ext_types, alpn, sig_algs)
    assert ja4 == expected_ja4
```

**Step 2: Add new files to Dockerfile.tests COPY**

Update the COPY line in `e2e/Dockerfile.tests`:
```dockerfile
COPY e2e/conftest.py e2e/test_ja4.py e2e/test_ja4h.py e2e/scapy_tls_client.py e2e/test_ja4_pcap.py /app/
```

---

### Task 5: Run e2e tests and iterate

**Step 1: Run the full e2e suite**

```bash
make e2e
```

Expected: All existing tests pass + 6 new PCAP vector tests pass on both OpenResty 1.27 and 1.29.

**Step 2: Debug failures**

Common issues to check:
- Scapy extension construction errors → fix `_build_extensions()` mappings
- TLS handshake failures → check cipher suite compatibility, try fewer extensions
- Missing X-JA4 header → check nginx error log for Lua errors
- Wrong JA4 value → compare raw mode output to expected, check which field differs

**Step 3: If TLSClientAutomaton doesn't work**

Switch `scapy_tls_client.py` to manual socket approach:
```python
import socket
from scapy.layers.tls.record import TLS

s = socket.socket()
s.connect((host, port))
record = TLS(msg=[ch])
s.send(bytes(record))
# ... manual handshake handling ...
```

---

### Task 6: Commit

**Step 1: Verify all tests pass**

```bash
make e2e
```

Expected: All tests green on both OpenResty 1.27 and 1.29.

**Step 2: Commit**

```bash
git add e2e/Dockerfile.tests e2e/scapy_tls_client.py e2e/test_ja4_pcap.py
git commit -m "test(e2e): add PCAP-derived JA4 vector tests via scapy TLS

Replay real browser ClientHello parameters (extracted from tls12.pcap,
tls-alpn-h2.pcap, browsers-x509.pcapng, badcurveball.pcap, latest.pcapng)
against OpenResty using scapy's TLS stack. 6 vectors covering TLS 1.2/1.3,
GREASE filtering, Chrome/Firefox, and no-ALPN edge case."
```

---

## Extracted PCAP Parameters Reference

Used for hardcoding test vectors. Source: one-time scapy extraction from PCAPs.

### tls12.pcap #0 (Firefox TLS 1.3)
- **src_port:** 36372
- **ciphers (17):** 1301,1303,1302,c02b,c02f,cca9,cca8,c02c,c030,c00a,c009,c013,c014,009c,009d,002f,0035
- **extensions (15):** 0000,0017,ff01,000a,000b,0023,0010,0005,0022,0033,002b,000d,002d,001c,0015
- **alpn:** h2
- **sig_algs (11):** 0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201
- **expected:** `t13d1715h2_5b57614c22b0_3d5424432f57`

### tls-alpn-h2.pcap #0 (TLS 1.2, 46 ciphers, IPv6 NULL datalink)
- **Source:** unit test 17 in `t/005-ja4db-vectors.t` (PCAP not parseable by scapy)
- **ciphers (46):** c030,c02c,c028,c024,c014,c00a,009f,006b,0039,cca9,cca8,ccaa,ff85,00c4,0088,0081,009d,003d,0035,00c0,0084,c02f,c02b,c027,c023,c013,c009,009e,0067,0033,00be,0045,009c,003c,002f,00ba,0041,c011,c007,0005,0004,c012,c008,0016,000a,00ff
- **extensions (5):** 0000,000b,000a,000d,0010
- **alpn:** h2
- **sig_algs (13):** 0601,0603,efef,0501,0503,0401,0403,eeee,eded,0301,0303,0201,0203
- **expected:** `t12d4605h2_85626a9a5f7f_aaf95bb78ec9`

### browsers-x509.pcapng #0 (Chrome TLS 1.3 + GREASE)
- **src_port:** 54524
- **ciphers (16):** aaaa,1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035
- **extensions (18):** 6a6a,000d,0000,000a,0005,000b,002b,001b,ff01,0033,4469,002d,0023,0017,0012,0010,0a0a,0015
- **alpn:** h2
- **sig_algs (8):** 0403,0804,0401,0503,0805,0501,0806,0601
- **expected:** `t13d1516h2_8daaf6152771_e5627efa2ab1`

### badcurveball.pcap #0 (Chrome TLS 1.3 variant + GREASE)
- **src_port:** 55318
- **ciphers (17):** aaaa,1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035,000a
- **extensions (17):** 4a4a,0000,0017,ff01,000a,000b,0023,0010,0005,000d,0012,0033,002d,002b,001b,7a7a,0015
- **alpn:** h2
- **sig_algs (9):** 0403,0804,0401,0503,0805,0501,0806,0601,0201
- **expected:** `t13d1615h2_46e7e9700bed_45f260be83e2`

### latest.pcapng #1 (TLS 1.2, port 52937 = tcp stream 3)
- **src_port:** 52937
- **ciphers (19):** c02c,c02b,c030,c02f,c024,c023,c028,c027,c00a,c009,c014,c013,009d,009c,003d,003c,0035,002f,000a
- **extensions (8):** 0000,0005,000a,000b,000d,0023,0017,ff01
- **alpn:** None
- **sig_algs (12):** 0804,0805,0806,0401,0501,0201,0403,0503,0203,0202,0601,0603
- **expected:** `t12d190800_d83cc789557e_7af1ed941c26`

### latest.pcapng #2 (Chrome TLS 1.3, port 52938 = tcp stream 5)
- **src_port:** 52938
- **ciphers (16):** 0a0a,1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035
- **extensions (18):** 5a5a,000d,0010,0000,000b,0023,4469,ff01,0033,000a,002d,002b,0005,0017,0012,001b,6a6a,0029
- **alpn:** h2
- **sig_algs (8):** 0403,0804,0401,0503,0805,0501,0806,0601
- **expected:** `t13d1516h2_8daaf6152771_9b887d9acb53`
