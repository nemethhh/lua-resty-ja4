# E2E Scapy TLS Vector Tests — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Use scapy to send TLS ClientHellos with known browser parameters to OpenResty, verifying the full `ja4.compute()` FFI pipeline produces correct fingerprints.

**Architecture:** 6 test vectors with hardcoded cipher suites, extensions, ALPN, and signature algorithms from real browser captures. Scapy constructs TLS connections with those exact parameters, completes handshakes with OpenResty, and asserts the `X-JA4` response header.

**Tech Stack:** Python 3.12, pytest, scapy 2.7+, cryptography (scapy TLS dependency)

**Design doc:** `docs/plans/2026-02-26-e2e-scapy-tls-vectors-design.md`

---

## Extracted Browser ClientHello Parameters

Parameters extracted once from real captures via scapy. These are hardcoded in
test vectors — no capture files needed at runtime.

### Vector 1: firefox-tls13 (Firefox 105, TLS 1.3)
- **ciphers (17):** `0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035`
- **extensions (15):** `0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x0022, 0x0033, 0x002b, 0x000d, 0x002d, 0x001c, 0x0015`
- **alpn:** `h2`
- **sig_algs (11):** `0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201`
- **expected:** `t13d1715h2_5b57614c22b0_3d5424432f57`

### Vector 2: tls12-46cipher (GnuTLS, TLS 1.2, 46 ciphers)
- **ciphers (46):** `0xc030, 0xc02c, 0xc028, 0xc024, 0xc014, 0xc00a, 0x009f, 0x006b, 0x0039, 0xcca9, 0xcca8, 0xccaa, 0xff85, 0x00c4, 0x0088, 0x0081, 0x009d, 0x003d, 0x0035, 0x00c0, 0x0084, 0xc02f, 0xc02b, 0xc027, 0xc023, 0xc013, 0xc009, 0x009e, 0x0067, 0x0033, 0x00be, 0x0045, 0x009c, 0x003c, 0x002f, 0x00ba, 0x0041, 0xc011, 0xc007, 0x0005, 0x0004, 0xc012, 0xc008, 0x0016, 0x000a, 0x00ff`
- **extensions (5):** `0x0000, 0x000b, 0x000a, 0x000d, 0x0010`
- **alpn:** `h2`
- **sig_algs (13):** `0x0601, 0x0603, 0xefef, 0x0501, 0x0503, 0x0401, 0x0403, 0xeeee, 0xeded, 0x0301, 0x0303, 0x0201, 0x0203`
- **expected:** `t12d4605h2_85626a9a5f7f_aaf95bb78ec9`

### Vector 3: chrome-tls13 (Chrome 94, TLS 1.3, GREASE)
- **ciphers (16):** `0xaaaa, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035`
- **extensions (18):** `0x6a6a, 0x000d, 0x0000, 0x000a, 0x0005, 0x000b, 0x002b, 0x001b, 0xff01, 0x0033, 0x4469, 0x002d, 0x0023, 0x0017, 0x0012, 0x0010, 0x0a0a, 0x0015`
- **alpn:** `h2`
- **sig_algs (8):** `0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601`
- **expected:** `t13d1516h2_8daaf6152771_e5627efa2ab1`

### Vector 4: chrome-tls13-v2 (Chrome 72, TLS 1.3, GREASE)
- **ciphers (17):** `0xaaaa, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035, 0x000a`
- **extensions (17):** `0x4a4a, 0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d, 0x0012, 0x0033, 0x002d, 0x002b, 0x001b, 0x7a7a, 0x0015`
- **alpn:** `h2`
- **sig_algs (9):** `0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201`
- **expected:** `t13d1615h2_46e7e9700bed_45f260be83e2`

### Vector 5: tls12-no-alpn (WinHTTP, TLS 1.2, no ALPN)
- **ciphers (19):** `0xc02c, 0xc02b, 0xc030, 0xc02f, 0xc024, 0xc023, 0xc028, 0xc027, 0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0x000a`
- **extensions (8):** `0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0023, 0x0017, 0xff01`
- **alpn:** `None`
- **sig_algs (12):** `0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203, 0x0202, 0x0601, 0x0603`
- **expected:** `t12d190800_d83cc789557e_7af1ed941c26`

### Vector 6: chrome-tls13-slack (Chrome 94, TLS 1.3, ext 0x0029)
- **ciphers (16):** `0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035`
- **extensions (18):** `0x5a5a, 0x000d, 0x0010, 0x0000, 0x000b, 0x0023, 0x4469, 0xff01, 0x0033, 0x000a, 0x002d, 0x002b, 0x0005, 0x0017, 0x0012, 0x001b, 0x6a6a, 0x0029`
- **alpn:** `h2`
- **sig_algs (8):** `0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601`
- **expected:** `t13d1516h2_8daaf6152771_9b887d9acb53`

---

### Task 1: Update Dockerfile.tests

**Files:**
- Modify: `e2e/Dockerfile.tests`

**Step 1: Add scapy and cryptography to pip install**

Change the `RUN pip install` line from `pytest` to `pytest scapy cryptography`:

```dockerfile
RUN pip install --no-cache-dir pytest scapy cryptography
```

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

Critical spike. Confirm scapy can:
1. Construct a TLSClientHello with arbitrary cipher suites and extensions
2. Complete a real TLS handshake with OpenResty
3. Send an HTTP request and receive the response with X-JA4 header

**Files:**
- Create: `e2e/spike_scapy_tls.py` (temporary, deleted after spike)

**Step 1: Write a minimal spike script**

Use Vector 1 (firefox-tls13) parameters — simplest vector, no GREASE:

```python
"""Spike: can scapy complete a TLS handshake with custom ClientHello?"""
import os
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
    TLS_Ext_SupportedVersion_CH,
    TLS_Ext_SignatureAlgorithms,
    TLS_Ext_ALPN, ProtocolName,
    TLS_Ext_PSKKeyExchangeModes,
    TLS_Ext_RenegotiationInfo,
    TLS_Ext_SessionTicket,
    TLS_Ext_ExtendedMasterSecret,
    TLS_Ext_ECPointsFormat,
)

HOST = os.environ.get("NGINX_HOST", "localhost")
PORT = int(os.environ.get("NGINX_PORT", "443"))

ch = TLSClientHello(
    ciphers=[
        0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8,
        0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c,
        0x009d, 0x002f, 0x0035,
    ],
    ext=[
        TLS_Ext_ServerName(servernames=[ServerName(servername=HOST.encode())]),
        TLS_Ext_ExtendedMasterSecret(),
        TLS_Ext_RenegotiationInfo(),
        TLS_Ext_SupportedGroups(groups=[0x001d, 0x0017, 0x0018, 0x0019]),
        TLS_Ext_ECPointsFormat(ecpl=[0]),
        TLS_Ext_SessionTicket(),
        TLS_Ext_ALPN(protocols=[ProtocolName(protocol=b"h2")]),
        TLS_Ext_SignatureAlgorithms(sig_algs=[
            0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806,
            0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
        ]),
        TLS_Ext_SupportedVersion_CH(versions=[0x0304, 0x0303]),
        TLS_Ext_PSKKeyExchangeModes(kxmodes=[1]),
    ],
)

print(f"Connecting to {HOST}:{PORT} ...")
try:
    t = TLSClientAutomaton(server=HOST, dport=PORT, client_hello=ch)
    result = t.run()
    print(f"Handshake result: {result}")
    print("SUCCESS: TLSClientAutomaton works")
except Exception as e:
    print(f"TLSClientAutomaton failed: {e}")
    print("Trying manual socket approach...")
    import socket
    from scapy.layers.tls.record import TLS
    s = socket.socket()
    s.settimeout(5)
    s.connect((HOST, PORT))
    record = TLS(msg=[ch])
    s.send(bytes(record))
    data = s.recv(8192)
    print(f"Received {len(data)} bytes from server")
    s.close()
    if len(data) > 0:
        print("SUCCESS: Server responded to custom ClientHello")
    else:
        print("FAIL: No response")
```

**Step 2: Run spike inside e2e Docker environment**

Temporarily add spike script to Dockerfile.tests COPY line, then:
```bash
docker compose -f e2e/docker-compose.e2e.yml run --rm tests-1.27 python spike_scapy_tls.py
```

Expected outcomes (one of):
- TLSClientAutomaton completes handshake → use that approach
- Automaton fails, manual socket gets server response → use manual approach
- Both fail → investigate scapy `tlsSession` / `SSLStreamSocket` APIs

**Step 3: Delete spike file after confirming approach**

```bash
rm e2e/spike_scapy_tls.py
```

---

### Task 3: Write scapy_tls_client.py helper

**Files:**
- Create: `e2e/scapy_tls_client.py`

Single function `connect_and_get_ja4()`. Exact implementation depends on Task 2
spike results. Below is the TLSClientAutomaton version.

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
    TLS_Ext_SupportedVersion_CH,
    TLS_Ext_SignatureAlgorithms,
    TLS_Ext_ALPN, ProtocolName,
    TLS_Ext_PSKKeyExchangeModes,
    TLS_Ext_RenegotiationInfo,
    TLS_Ext_SessionTicket,
    TLS_Ext_ExtendedMasterSecret,
    TLS_Ext_EncryptThenMAC,
    TLS_Ext_ECPointsFormat,
)


def _build_extensions(ext_types, host, alpn, sig_algs, tls13):
    """Build scapy extension objects from extension type ID list."""
    from scapy.layers.tls.extensions import TLS_Ext_Unknown

    exts = []
    for etype in ext_types:
        # GREASE values (0x?a?a pattern)
        if (etype & 0x0f0f) == 0x0a0a:
            exts.append(TLS_Ext_Unknown(type=etype, data=b"\x00"))
            continue

        if etype == 0x0000:    # server_name
            exts.append(TLS_Ext_ServerName(
                servernames=[ServerName(servername=host.encode())]))
        elif etype == 0x0005:  # status_request
            from scapy.layers.tls.extensions import TLS_Ext_CSR
            exts.append(TLS_Ext_CSR(stype=1, req=b"\x00\x00\x00\x00\x00"))
        elif etype == 0x000a:  # supported_groups
            exts.append(TLS_Ext_SupportedGroups(
                groups=[0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]))
        elif etype == 0x000b:  # ec_point_formats
            exts.append(TLS_Ext_ECPointsFormat(ecpl=[0]))
        elif etype == 0x000d:  # signature_algorithms
            exts.append(TLS_Ext_SignatureAlgorithms(sig_algs=sig_algs))
        elif etype == 0x0010:  # application_layer_protocol_negotiation
            if alpn:
                exts.append(TLS_Ext_ALPN(
                    protocols=[ProtocolName(protocol=alpn.encode())]))
        elif etype == 0x0017:  # extended_master_secret
            exts.append(TLS_Ext_ExtendedMasterSecret())
        elif etype == 0x0023:  # session_ticket
            exts.append(TLS_Ext_SessionTicket())
        elif etype == 0x002b:  # supported_versions
            if tls13:
                exts.append(TLS_Ext_SupportedVersion_CH(versions=[0x0304, 0x0303]))
            else:
                exts.append(TLS_Ext_SupportedVersion_CH(versions=[0x0303, 0x0302]))
        elif etype == 0x002d:  # psk_key_exchange_modes
            exts.append(TLS_Ext_PSKKeyExchangeModes(kxmodes=[1]))
        elif etype == 0x0033:  # key_share
            from scapy.layers.tls.extensions import TLS_Ext_KeyShareClient
            exts.append(TLS_Ext_KeyShareClient())
        elif etype == 0xff01:  # renegotiation_info
            exts.append(TLS_Ext_RenegotiationInfo())
        else:
            # Unknown/simple extension — send type ID with empty data
            exts.append(TLS_Ext_Unknown(type=etype, data=b""))
    return exts


def connect_and_get_ja4(host, port, ciphers, ext_types, alpn, sig_algs):
    """Connect with exact ClientHello params, return X-JA4 header value."""
    tls13_ciphers = {0x1301, 0x1302, 0x1303, 0x1304, 0x1305}
    tls13 = bool(set(ciphers) & tls13_ciphers) or 0x002b in ext_types
    extensions = _build_extensions(ext_types, host, alpn, sig_algs, tls13)

    ch = TLSClientHello(ciphers=ciphers, ext=extensions)

    t = TLSClientAutomaton(server=host, dport=port, client_hello=ch)
    sock = t.run()

    http_req = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"
    sock.send(http_req.encode())
    data = sock.recv(8192)
    sock.close()

    response_text = data.decode("utf-8", errors="replace")
    for line in response_text.split("\r\n"):
        if line.lower().startswith("x-ja4:"):
            return line.split(":", 1)[1].strip()

    raise RuntimeError(
        f"X-JA4 header not found in response:\n{response_text[:500]}")
```

**Step 2: Verify import works**

```bash
docker compose -f e2e/docker-compose.e2e.yml run --rm tests-1.27 \
  python -c "from scapy_tls_client import connect_and_get_ja4; print('OK')"
```
Expected: `OK`

---

### Task 4: Write test_ja4_scapy.py with hardcoded vectors

**Files:**
- Create: `e2e/test_ja4_scapy.py`

**Step 1: Write the test file**

```python
"""E2E tests: send TLS ClientHellos with known browser parameters via scapy.

Each vector contains exact cipher suites, extensions, ALPN, and signature
algorithms from a real browser. Scapy constructs the ClientHello, completes
a TLS handshake with OpenResty, and verifies the X-JA4 response header.
"""
import os
import pytest
from scapy_tls_client import connect_and_get_ja4

NGINX_HOST = os.environ.get("NGINX_HOST", "nginx")
HASH_PORT = int(os.environ.get("NGINX_PORT", "443"))

VECTORS = [
    pytest.param(
        # Firefox 105, TLS 1.3, 17 ciphers, 15 extensions
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
        id="firefox-tls13",
    ),
    pytest.param(
        # GnuTLS, TLS 1.2, 46 ciphers, 5 extensions, GREASE sig_algs
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
        id="chrome-tls13",
    ),
    pytest.param(
        # Chrome 72, TLS 1.3, GREASE, 17 ciphers incl 0x000a
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
    pytest.param(
        # Chrome 94, TLS 1.3, GREASE, ext 0x0029 (pre_shared_key)
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
        id="chrome-tls13-slack",
    ),
]


@pytest.mark.parametrize("ciphers,ext_types,alpn,sig_algs,expected_ja4", VECTORS)
def test_ja4_scapy_vectors(ciphers, ext_types, alpn, sig_algs, expected_ja4):
    """Send ClientHello with known browser params, verify JA4 fingerprint."""
    ja4 = connect_and_get_ja4(NGINX_HOST, HASH_PORT, ciphers, ext_types, alpn, sig_algs)
    assert ja4 == expected_ja4
```

**Step 2: Add new files to Dockerfile.tests COPY**

```dockerfile
COPY e2e/conftest.py e2e/test_ja4.py e2e/test_ja4h.py e2e/scapy_tls_client.py e2e/test_ja4_scapy.py /app/
```

---

### Task 5: Run e2e tests and iterate

**Step 1: Run the full e2e suite**

```bash
make e2e
```

Expected: all existing tests pass + 6 new scapy vector tests pass on both
OpenResty 1.27 and 1.29.

**Step 2: Debug failures**

Common issues:
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

**Step 2: Commit**

```bash
git add e2e/Dockerfile.tests e2e/scapy_tls_client.py e2e/test_ja4_scapy.py
git commit -m "test(e2e): add scapy TLS vector tests for JA4 fingerprinting

6 vectors with real browser ClientHello parameters (Firefox, Chrome,
GnuTLS, WinHTTP) tested via scapy TLS stack against OpenResty.
Covers TLS 1.2/1.3, GREASE filtering, and no-ALPN edge case."
```
