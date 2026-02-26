"""Scapy-based TLS client for JA4 e2e tests.

Constructs a TLSClientHello with exact cipher/extension parameters,
completes a TLS handshake with OpenResty, sends HTTP GET, and returns
the X-JA4 response header value.

Key design decisions:
- Both TLS 1.2 and 1.3 use the same approach: let the automaton build
  its own ClientHello (proper session state), then hook add_msg() to
  replace cipher list and append extra extensions before serialization.
  Passing client_hello= breaks session state for both TLS versions.
- Cannot override tls13_should_add_ClientHello() because scapy's ATMT
  state machine decorator registration breaks on subclass overrides.
- ALPN: When the vector specifies "h2", we send "h2" in ClientHello
  and use the h2 library for HTTP/2 framing (nginx has http2 on).
- Nginx must have ssl_session_tickets off — scapy's automaton hangs
  on NewSessionTicket messages it doesn't expect.
- Extensions use TLS_Ext_Unknown(type=N, val=data) to bypass scapy's
  session filtering that strips unrecognized extensions.
"""
import re
import struct
import time
import logging

logging.getLogger("scapy").setLevel(logging.ERROR)

from scapy.all import load_layer, conf, Raw
conf.logLevel = 40
load_layer("tls")

from scapy.layers.tls.automaton_cli import TLSClientAutomaton
from scapy.layers.tls.handshake import TLSClientHello, TLS13ClientHello
from scapy.layers.tls.extensions import TLS_Ext_Unknown

# For TLS 1.3: keep only key_share (0x0033) from the automaton's extensions.
# key_share contains the ECDH private key needed for key exchange. All other
# extensions (including supported_versions, supported_groups, sig_algs) are
# replaced by our TLS_Ext_Unknown versions so they appear in raw bytes exactly
# as we specify — scapy's session layer strips some TLS_Ext_Unknown types when
# they coexist with native extension classes.
_TLS13_KEEP_FROM_AUTOMATON = {0x0033}

# For TLS 1.2: no automaton extensions need to be kept.

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
    """Build ALL extension objects for ClientHello as TLS_Ext_Unknown.

    For TLS 1.3: skip only key_share (0x0033) — the automaton's key_share
    contains the ECDH private key needed for the handshake.
    Everything else is built as TLS_Ext_Unknown so it bypasses scapy's
    session-layer filtering and appears verbatim in raw bytes.

    For TLS 1.2: build all extensions (no skipping).
    """
    skip = _TLS13_KEEP_FROM_AUTOMATON if tls13 else set()
    exts = []
    for etype in ext_types:
        # GREASE values (0x?a?a pattern)
        if (etype & 0x0f0f) == 0x0a0a:
            exts.append(TLS_Ext_Unknown(type=etype, val=b"\x00"))
            continue

        if etype in skip:
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

        # Signature algorithms — build raw bytes for all TLS versions
        if etype == 0x000d:
            sa_data = struct.pack("!H", len(sig_algs) * 2)
            for sa in sig_algs:
                sa_data += struct.pack("!H", sa)
            exts.append(TLS_Ext_Unknown(type=0x000d, val=sa_data))
            continue

        # Supported groups — build raw bytes for all TLS versions
        if etype == 0x000a:
            groups = [0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]
            g_data = struct.pack("!H", len(groups) * 2)
            for g in groups:
                g_data += struct.pack("!H", g)
            exts.append(TLS_Ext_Unknown(type=0x000a, val=g_data))
            continue

        # Supported versions
        if etype == 0x002b:
            if tls13:
                exts.append(TLS_Ext_Unknown(
                    type=0x002b, val=struct.pack("!BHH", 4, 0x0304, 0x0303),
                ))
            else:
                exts.append(TLS_Ext_Unknown(
                    type=0x002b, val=struct.pack("!BHH", 4, 0x0303, 0x0302),
                ))
            continue

        exts.append(TLS_Ext_Unknown(type=etype, val=_build_ext_bytes(etype)))

    return exts


class _JA4TLSClientAutomaton(TLSClientAutomaton):
    """Replaces cipher list and appends extra extensions via add_msg hook.

    The automaton builds its own ClientHello with proper session state
    (key exchange material, signature algorithms, etc). We hook add_msg
    to replace the cipher list and append our extra TLS_Ext_Unknown
    extensions just before the ClientHello is serialized and sent.

    This avoids two pitfalls:
    1. client_hello= param bypasses automaton session state setup (hangs)
    2. Overriding ATMT-decorated methods breaks state machine (hangs)
    """

    def parse_args(self, custom_ciphers=None, extra_ext=None, **kargs):
        super().parse_args(**kargs)
        self._custom_ciphers = custom_ciphers
        self._extra_ext = extra_ext or []
        self._ch_patched = False

    def add_msg(self, pkt):
        if (not self._ch_patched
                and isinstance(pkt, (TLSClientHello, TLS13ClientHello))):
            if self._custom_ciphers:
                pkt.ciphers = self._custom_ciphers
            if self._extra_ext:
                if isinstance(pkt, TLS13ClientHello):
                    # Keep only key_share from automaton (has ECDH private key)
                    kept = [e for e in (pkt.ext or [])
                            if getattr(e, 'type', None) in _TLS13_KEEP_FROM_AUTOMATON]
                    pkt.ext = kept + list(self._extra_ext)
                else:
                    # TLS 1.2: replace all automaton extensions with ours
                    pkt.ext = list(self._extra_ext)
            self._ch_patched = True
        super().add_msg(pkt)


def _extract_ja4(response_bytes):
    """Extract X-JA4 header value from HTTP response bytes."""
    m = re.search(rb"X-JA4:\s*(\S+)", response_bytes)
    if m:
        return m.group(1).decode("ascii")
    raise RuntimeError(
        f"X-JA4 header not found in response:\n"
        f"{response_bytes[:500].decode('utf-8', errors='replace')}"
    )


def _send_h2_request(sock, host):
    """Send HTTP/2 request over TLS socket, return response headers+body."""
    import h2.connection
    import h2.config
    import h2.events

    config = h2.config.H2Configuration(
        client_side=True,
        header_encoding="utf-8",
    )
    conn = h2.connection.H2Connection(config=config)
    conn.initiate_connection()
    sock.send(Raw(conn.data_to_send()))

    headers = [
        (":method", "GET"),
        (":path", "/"),
        (":authority", host),
        (":scheme", "https"),
    ]
    conn.send_headers(1, headers, end_stream=True)
    sock.send(Raw(conn.data_to_send()))

    response_headers = {}
    body = b""

    # Poll recv with short sleeps — scapy supersockets don't support select()
    deadline = time.monotonic() + 10
    for _ in range(100):
        if time.monotonic() > deadline:
            break
        try:
            data = sock.recv()
        except Exception:
            break
        if not data:
            time.sleep(0.05)
            continue
        raw = bytes(data)
        events = conn.receive_data(raw)
        for event in events:
            if isinstance(event, h2.events.ResponseReceived):
                for k, v in event.headers:
                    response_headers[k.decode() if isinstance(k, bytes) else k] = (
                        v.decode() if isinstance(v, bytes) else v
                    )
            elif isinstance(event, h2.events.DataReceived):
                body += event.data
                conn.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id
                )
            elif isinstance(event, h2.events.StreamEnded):
                out = conn.data_to_send()
                if out:
                    sock.send(Raw(out))
                return response_headers, body
            elif isinstance(event, h2.events.WindowUpdated):
                pass
        out = conn.data_to_send()
        if out:
            sock.send(Raw(out))
        time.sleep(0.05)

    return response_headers, body


def connect_and_get_ja4(host, port, ciphers, ext_types, alpn, sig_algs):
    """Connect with exact ClientHello params, return X-JA4 header value."""
    tls13_ciphers = {0x1301, 0x1302, 0x1303, 0x1304, 0x1305}
    tls13 = bool(set(ciphers) & tls13_ciphers) or 0x002b in ext_types

    extra_extensions = _build_extensions(ext_types, host, alpn, sig_algs, tls13)

    kw = dict(
        server=host, dport=port,
        custom_ciphers=ciphers,
        extra_ext=extra_extensions,
        verbose=False,
    )

    if tls13:
        sa_names = [_SA_MAP[sa] for sa in sig_algs if sa in _SA_MAP]
        if not sa_names:
            sa_names = ["sha256+rsaepss", "sha256+rsa"]
        kw["version"] = "tls13"
        kw["supported_signature_algorithms"] = sa_names

    sock = _JA4TLSClientAutomaton.tlslink(Raw, **kw)

    try:
        if alpn == "h2":
            headers, _ = _send_h2_request(sock, host)
            ja4 = headers.get("x-ja4")
            if not ja4:
                raise RuntimeError(
                    f"X-JA4 header not found in h2 response headers: {headers}"
                )
            return ja4
        else:
            http_req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            sock.send(Raw(http_req.encode()))
            resp = sock.recv()
            if resp:
                return _extract_ja4(bytes(resp))
            raise RuntimeError("No response received")
    finally:
        try:
            sock.close()
        except Exception:
            pass
