# E2E Scapy TLS Vector Tests — Implementation Plan (v2)

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Use scapy to send TLS ClientHellos with known browser parameters to OpenResty, verifying the full `ja4.compute()` FFI pipeline produces correct fingerprints.

**Architecture:** 6 test vectors with hardcoded cipher suites, extensions, ALPN, and signature algorithms from real browser captures. Scapy constructs TLS connections with those exact parameters, completes handshakes with OpenResty, and asserts the `X-JA4` response header.

**Tech Stack:** Python 3.12, pytest, scapy 2.7+, cryptography (scapy TLS dependency)

**Design doc:** `docs/plans/2026-02-26-e2e-scapy-tls-vectors-design.md`

**Worktree:** `.worktrees/e2e-scapy-tls-vectors` (branch `e2e-scapy-tls-vectors`)

---

## Spike Findings (completed)

The previous session performed extensive spike testing. These findings are **non-negotiable constraints** — do not re-spike.

### Scapy 2.7 API

- Import is `from scapy.layers.tls.automaton_cli import TLSClientAutomaton` (NOT `automaton`)
- EC point formats class is `TLS_Ext_SupportedPointFormat` (NOT `ECPointsFormat`)
- `TLS_Ext_Unknown` field is `val=` (NOT `data=`)
- Use `TLSClientAutomaton.tlslink(Raw, server=host, dport=port, ...)` for send/recv
- After `tlslink`, call `sock.send(Raw(payload))` and `resp = sock.recv()` — returns `Raw` packet

### TLS 1.3 Extension Problem

The automaton's `tls13_should_add_ClientHello()` **always replaces** `p.ext` with its own list (supported_versions, supported_groups, key_share, sig_algs). Our custom extensions are lost. **Fix:** Subclass `TLSClientAutomaton`, override `tls13_should_add_ClientHello()` to append our extra extensions after the automaton builds its required ones. Extra extensions use `TLS_Ext_Unknown(type=N, val=bytes)` which bypasses tls_session filtering.

### TLS 1.2 Key Exchange

The automaton preserves custom `client_hello.ext` for TLS 1.2 (no extension replacement). **But** scapy can only complete TLS 1.2 handshakes with RSA key exchange — ECDHE fails ("stuck in RECEIVED_SERVERFLIGHT2"). **Fix:** `ssl_prefer_server_ciphers on;` with RSA ciphers first in nginx.

### ALPN Handling

Without `http2 on;` in nginx: sending ALPN `["h2"]` → server rejects (`no_application_protocol`). Sending `["h2", "http/1.1"]` → server negotiates `http/1.1`. **JA4 only uses the FIRST ALPN value** (line 273-274 of `ja4.lua`), and **ALPN extension type 0x0010 is excluded from section C** (line 75 of `ja4.lua`). So adding `http/1.1` alongside `h2` produces **identical JA4 fingerprints** while allowing the server to negotiate HTTP/1.1.

### HTTP/2 and JA4H

`ngx.req.raw_header()` throws `"http2 requests not supported yet"` for HTTP/2 requests. JA4H HTTP/2 support (version code `20`, ordered header extraction via nginx FFI) is a **separate feature** — tracked separately, not part of this plan. **For this plan:** do NOT enable `http2 on;` in nginx. Use ALPN `["h2", "http/1.1"]` workaround.

### Verified Working Pattern

```python
# TLS 1.2 — default automaton, HTTP/1.1 response, X-JA4 extracted
sock = TLSClientAutomaton.tlslink(Raw, server=host, dport=port, data=[http_req])
# → t12i130100_12ca15e9fa31_9ffaceab5a69

# TLS 1.3 — default automaton, HTTP/1.1 response, X-JA4 extracted
sock = TLSClientAutomaton.tlslink(Raw, server=host, dport=port, version="tls13")
sock.send(Raw(http_req.encode()))
resp = sock.recv()  # → Raw packet with HTTP/1.1 response including X-JA4

# TLS 1.3 custom ciphers — section B hash matches expected
sock = TLSClientAutomaton.tlslink(Raw, server=host, dport=port,
    client_hello=TLSClientHello(ciphers=[...]), version="tls13")
# → Cipher hash 5b57614c22b0 matches Vector 1 expected
```

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

### Task 1: Reset worktree to clean state

The previous session left partial work in `.worktrees/e2e-scapy-tls-vectors`. Some of it is usable, some needs rework (nginx.conf has `http2 on;` which must be reverted).

**Files:**
- Revert: `e2e/nginx.conf` (remove `http2 on;` and `ssl_prefer_server_ciphers`/`ssl_ciphers`)
- Keep modified: `e2e/Dockerfile.tests` (pip install line is correct)
- Delete: `e2e/scapy_tls_client.py` (will be rewritten)
- Delete: `e2e/test_ja4_scapy.py` (will be rewritten)

**Step 1: Navigate to worktree**

```bash
cd /home/am/Fun/lua-resty-ja4/.worktrees/e2e-scapy-tls-vectors
```

**Step 2: Revert nginx.conf to original, then apply only ssl_prefer_server_ciphers**

```bash
git checkout e2e/nginx.conf
```

Then add **only** `ssl_prefer_server_ciphers` + RSA-first cipher list to BOTH server blocks (needed for TLS 1.2 scapy key exchange). Do NOT add `http2 on;`.

In `e2e/nginx.conf`, after each `ssl_protocols TLSv1.2 TLSv1.3;` line, add:

```nginx
        ssl_prefer_server_ciphers on;
        ssl_ciphers AES128-GCM-SHA256:AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:HIGH:!aNULL:!MD5;
```

**Step 3: Fix Dockerfile.tests — remove h2, keep scapy + cryptography**

Change pip install line to:
```dockerfile
RUN pip install --no-cache-dir pytest scapy cryptography
```

(No `h2` — we use HTTP/1.1 via the ALPN workaround)

**Step 4: Update Dockerfile.tests COPY line for final files**

```dockerfile
COPY e2e/conftest.py e2e/test_ja4.py e2e/test_ja4h.py e2e/scapy_tls_client.py e2e/test_ja4_scapy.py /app/
```

**Step 5: Delete stale files**

```bash
rm -f e2e/scapy_tls_client.py e2e/test_ja4_scapy.py e2e/spike_scapy_tls.py
```

**Step 6: Verify existing tests still pass**

```bash
make e2e
```

Expected: 25 passed on both OpenResty 1.27 and 1.29.

**Step 7: Commit**

```bash
git add e2e/Dockerfile.tests e2e/nginx.conf
git commit -m "build(e2e): add scapy deps + RSA cipher preference for TLS 1.2"
```

---

### Task 2: Write scapy_tls_client.py helper

**Files:**
- Create: `e2e/scapy_tls_client.py`

Single function `connect_and_get_ja4()`. Architecture:
- TLS 1.3: Subclassed automaton (`_JA4TLSClientAutomaton`) merges extra extensions
- TLS 1.2: Custom `client_hello.ext` preserved directly
- ALPN: Always adds `http/1.1` alongside test ALPN — server negotiates HTTP/1.1
- Extensions: `TLS_Ext_Unknown(type=N, val=bytes)` bypasses session filtering
- HTTP: Always HTTP/1.1 (`Connection: close`), parse response for `X-JA4` header

**Step 1: Write the helper module**

```python
"""Scapy-based TLS client for JA4 e2e tests.

Constructs a TLSClientHello with exact cipher/extension parameters,
completes a TLS handshake with OpenResty, sends HTTP GET, and returns
the X-JA4 response header value.

Key design decisions (from spike):
- TLS 1.3: Subclass TLSClientAutomaton to merge extra extensions.
  The automaton's tls13_should_add_ClientHello() always replaces p.ext.
- TLS 1.2: Custom client_hello.ext preserved by the automaton.
  Nginx ssl_prefer_server_ciphers picks RSA ciphers scapy can handle.
- ALPN: Send ["h2", "http/1.1"] so JA4 sees "h2" but server negotiates
  http/1.1. ALPN type 0x0010 is excluded from JA4 section C hashing.
- Extensions that scapy strips during tls_session serialization use
  TLS_Ext_Unknown(type=N, val=data) to bypass filtering.
"""
import re
import struct
import logging

logging.getLogger("scapy").setLevel(logging.ERROR)

from scapy.all import load_layer, conf, Raw
conf.logLevel = 40
load_layer("tls")

from scapy.layers.tls.automaton_cli import TLSClientAutomaton
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.extensions import (
    TLS_Ext_SupportedGroups,
    TLS_Ext_SupportedVersion_CH,
    TLS_Ext_SignatureAlgorithms,
    TLS_Ext_Unknown,
)

# Extension types the TLS 1.3 automaton always builds itself.
# We skip these in _build_extensions — the automaton handles them.
_TLS13_AUTOMATON_EXTS = {0x002b, 0x000a, 0x0033, 0x000d}

# Scapy sig_alg string names for the automaton's supported_signature_algorithms
_SA_MAP = {
    0x0401: "sha256+rsa", 0x0501: "sha384+rsa", 0x0601: "sha512+rsa",
    0x0403: "sha256+ecdsa", 0x0503: "sha384+ecdsa", 0x0603: "sha512+ecdsa",
    0x0804: "sha256+rsaepss", 0x0805: "sha384+rsaepss", 0x0806: "sha512+rsaepss",
    0x0201: "sha1+rsa", 0x0203: "sha1+ecdsa", 0x0202: "sha1+dsa",
}


def _build_ext_bytes(ext_type):
    """Build raw extension data bytes for common extension types."""
    if ext_type == 0x0017:  # extended_master_secret
        return b""
    if ext_type == 0xff01:  # renegotiation_info
        return b"\x00"
    if ext_type == 0x000b:  # ec_point_formats (uncompressed)
        return struct.pack("!BB", 1, 0)
    if ext_type == 0x0023:  # session_ticket
        return b""
    if ext_type == 0x002d:  # psk_key_exchange_modes (psk_dhe_ke)
        return struct.pack("!BB", 1, 1)
    if ext_type == 0x0005:  # status_request (OCSP)
        return b"\x01\x00\x00\x00\x00"
    if ext_type == 0x001b:  # compress_certificate
        return b"\x02\x00\x02"
    if ext_type == 0x0012:  # signed_certificate_timestamp
        return b""
    if ext_type == 0x0015:  # padding
        return b""
    if ext_type == 0x001c:  # record_size_limit
        return struct.pack("!H", 16385)
    if ext_type == 0x0029:  # pre_shared_key (type presence only)
        return b""
    if ext_type == 0x0022:  # delegated_credentials
        return b""
    return b""


def _build_sni_bytes(hostname):
    """Build SNI extension data bytes."""
    name = hostname.encode() if isinstance(hostname, str) else hostname
    entry = struct.pack("!BH", 0, len(name)) + name
    return struct.pack("!H", len(entry)) + entry


def _build_alpn_bytes(protocols):
    """Build ALPN extension data bytes."""
    entries = b""
    for proto in protocols:
        p = proto.encode() if isinstance(proto, str) else proto
        entries += struct.pack("!B", len(p)) + p
    return struct.pack("!H", len(entries)) + entries


def _build_extensions(ext_types, host, alpn, sig_algs, tls13):
    """Build extension objects for ClientHello.

    TLS 1.3: Skip automaton-managed types (0x002b, 0x000a, 0x0033, 0x000d).
    TLS 1.2: Include all extensions.
    All non-automaton extensions use TLS_Ext_Unknown to bypass session filtering.
    """
    exts = []
    for etype in ext_types:
        # GREASE values (0x?a?a pattern)
        if (etype & 0x0f0f) == 0x0a0a:
            exts.append(TLS_Ext_Unknown(type=etype, val=b"\x00"))
            continue

        if tls13 and etype in _TLS13_AUTOMATON_EXTS:
            continue

        if etype == 0x0000:  # SNI
            exts.append(TLS_Ext_Unknown(type=0x0000, val=_build_sni_bytes(host)))
            continue

        if etype == 0x0010:  # ALPN
            if alpn:
                exts.append(TLS_Ext_Unknown(
                    type=0x0010,
                    val=_build_alpn_bytes([alpn, "http/1.1"]),
                ))
            continue

        # Sig algs for TLS 1.2 (TLS 1.3 handled by automaton)
        if etype == 0x000d and not tls13:
            sa_data = struct.pack("!H", len(sig_algs) * 2)
            for sa in sig_algs:
                sa_data += struct.pack("!H", sa)
            exts.append(TLS_Ext_Unknown(type=0x000d, val=sa_data))
            continue

        # Supported groups for TLS 1.2
        if etype == 0x000a and not tls13:
            groups = [0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]
            g_data = struct.pack("!H", len(groups) * 2)
            for g in groups:
                g_data += struct.pack("!H", g)
            exts.append(TLS_Ext_Unknown(type=0x000a, val=g_data))
            continue

        # Supported versions for TLS 1.2
        if etype == 0x002b and not tls13:
            exts.append(TLS_Ext_Unknown(
                type=0x002b, val=struct.pack("!BHH", 4, 0x0303, 0x0302),
            ))
            continue

        exts.append(TLS_Ext_Unknown(type=etype, val=_build_ext_bytes(etype)))

    return exts


class _JA4TLSClientAutomaton(TLSClientAutomaton):
    """Subclass that merges extra extensions into TLS 1.3 ClientHello.

    Parent's tls13_should_add_ClientHello() replaces all extensions.
    This subclass appends our TLS_Ext_Unknown extras after the parent
    builds its required ones (supported_versions, supported_groups,
    key_share, sig_algs).
    """

    def parse_args(self, extra_ext=None, **kargs):
        super().parse_args(**kargs)
        self._extra_ext = extra_ext or []

    def tls13_should_add_ClientHello(self):
        from scapy.layers.tls.automaton_cli import (
            TLS_Ext_SupportedVersion_CH,
            TLS_Ext_SupportedGroups,
            TLS_Ext_SignatureAlgorithms,
            TLS_Ext_KeyShare_CH,
            KeyShareEntry,
        )

        self.add_record(is_tls13=False)
        if self.client_hello:
            p = self.client_hello
        else:
            if self.ciphersuite is None:
                c = 0x1301
            else:
                c = self.ciphersuite
            from scapy.layers.tls.handshake import TLS13ClientHello
            p = TLS13ClientHello(ciphers=c)

        ext = []
        ext += TLS_Ext_SupportedVersion_CH(versions=[self.advertised_tls_version])
        ext += TLS_Ext_SupportedGroups(groups=self.supported_groups)
        ext += TLS_Ext_KeyShare_CH(
            client_shares=[KeyShareEntry(group=self.curve)]
        )
        ext += TLS_Ext_SignatureAlgorithms(
            sig_algs=self.supported_signature_algorithms,
        )
        ext.extend(self._extra_ext)

        p.ext = ext
        self.add_msg(p)
        raise self.TLS13_ADDED_CLIENTHELLO()


def connect_and_get_ja4(host, port, ciphers, ext_types, alpn, sig_algs):
    """Connect with exact ClientHello params, return X-JA4 header value."""
    tls13_ciphers = {0x1301, 0x1302, 0x1303, 0x1304, 0x1305}
    tls13 = bool(set(ciphers) & tls13_ciphers) or 0x002b in ext_types

    extra_extensions = _build_extensions(ext_types, host, alpn, sig_algs, tls13)
    ch = TLSClientHello(ciphers=ciphers)

    http_req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"

    if tls13:
        sa_names = [_SA_MAP[sa] for sa in sig_algs if sa in _SA_MAP]
        if not sa_names:
            sa_names = ["sha256+rsaepss", "sha256+rsa"]

        sock = _JA4TLSClientAutomaton.tlslink(
            Raw, server=host, dport=port,
            client_hello=ch, version="tls13",
            extra_ext=extra_extensions,
            supported_signature_algorithms=sa_names,
            verbose=False,
        )
    else:
        ch.ext = extra_extensions
        sock = TLSClientAutomaton.tlslink(
            Raw, server=host, dport=port,
            client_hello=ch, verbose=False,
        )

    try:
        sock.send(Raw(http_req.encode()))
        resp = sock.recv()
        if not resp:
            raise RuntimeError("No response received")
        payload = bytes(resp)
        m = re.search(rb"X-JA4:\s*(\S+)", payload)
        if m:
            return m.group(1).decode("ascii")
        raise RuntimeError(
            f"X-JA4 header not found in response:\n"
            f"{payload[:500].decode('utf-8', errors='replace')}"
        )
    finally:
        try:
            sock.close()
        except Exception:
            pass
```

**Step 2: Verify import works**

```bash
docker compose -f e2e/docker-compose.e2e.yml build tests-1.27 && \
docker compose -f e2e/docker-compose.e2e.yml run --rm tests-1.27 \
  python -c "from scapy_tls_client import connect_and_get_ja4; print('OK')"
```

Expected: `OK`

---

### Task 3: Write test_ja4_scapy.py with hardcoded vectors

**Files:**
- Create: `e2e/test_ja4_scapy.py`

**Step 1: Write the test file**

Use exact same vector data from the "Extracted Browser ClientHello Parameters" section above. Same test structure as old plan — parametrized pytest with 6 vectors.

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

---

### Task 4: Run e2e tests and iterate

**Step 1: Run the full e2e suite**

```bash
make e2e
```

Expected: all existing 25 tests pass + 6 new scapy vector tests pass on both
OpenResty 1.27 and 1.29.

**Step 2: Debug failures**

Common issues and fixes:
- **`TLS_Ext_Unknown` still stripped by automaton** → check that `_extra_ext` is being passed through `tlslink` → `parse_args` → `_extra_ext`
- **`no_application_protocol` for ALPN vectors** → verify `_build_alpn_bytes(["h2", "http/1.1"])` produces correct wire format: `\x00\x0c\x02h2\x08http/1.1`
- **TLS 1.2 "stuck in RECEIVED_SERVERFLIGHT2"** → verify `ssl_prefer_server_ciphers on;` is in nginx.conf, check which cipher server selects (should be RSA-only like AES128-GCM-SHA256)
- **Wrong JA4 section A (e.g. `i` instead of `d`)** → SNI extension not reaching server. Check `_build_sni_bytes()` produces valid SNI data. Try raw mode port 8443 to inspect the actual extension list.
- **Wrong JA4 section B** → cipher list issue. Run against raw port to see exact cipher CSV.
- **Wrong JA4 section C** → extension list issue. Run against raw port. If the automaton's 4 managed extensions replace ours, the count will be wrong. Check that `TLS_Ext_Unknown` instances survive in the final `p.ext`.
- **Timeout / hang** → add `signal.alarm(30)` in test to prevent hangs. Check `Connection: close` is in HTTP request.

**Step 3: If TLS 1.2 ECDHE still fails despite RSA preference**

The server might not have the RSA ciphers available. Check:
```bash
docker compose -f e2e/docker-compose.e2e.yml exec nginx-1.27 \
  openssl ciphers -v 'AES128-GCM-SHA256'
```

If empty, broaden the cipher string in nginx.conf.

---

### Task 5: Commit

**Step 1: Verify all tests pass**

```bash
make e2e
```

**Step 2: Commit**

```bash
git add e2e/Dockerfile.tests e2e/nginx.conf e2e/scapy_tls_client.py e2e/test_ja4_scapy.py
git commit -m "test(e2e): add scapy TLS vector tests for JA4 fingerprinting

6 vectors with real browser ClientHello parameters (Firefox, Chrome,
GnuTLS, WinHTTP) tested via scapy TLS stack against OpenResty.
Covers TLS 1.2/1.3, GREASE filtering, and no-ALPN edge case."
```
