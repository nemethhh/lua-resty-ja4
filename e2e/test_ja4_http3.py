"""E2E: JA4 over a real HTTP/3 (QUIC) connection must use the "q" protocol marker."""
import asyncio
import os
import re
import ssl

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration

NGINX_HOST = os.environ.get("NGINX_HOST", "nginx")
HASH_PORT = int(os.environ.get("NGINX_PORT", "443"))

JA4_QUIC_HASH_RE = re.compile(
    r"^q(?:13|12|11|10|s3|s2|00)[di]\d{2}\d{2}[a-z0-9]{2}_[a-f0-9]{12}_[a-f0-9]{12}$"
)


class _H3Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self._headers = {}
        self._waiters = {}

    def quic_event_received(self, event):
        for ev in self._http.handle_event(event):
            if isinstance(ev, HeadersReceived):
                self._headers.setdefault(ev.stream_id, []).extend(ev.headers)
            if isinstance(ev, (HeadersReceived, DataReceived)) and ev.stream_ended:
                waiter = self._waiters.pop(ev.stream_id, None)
                if waiter and not waiter.done():
                    waiter.set_result(self._headers.pop(ev.stream_id, []))

    async def get(self, authority, path="/"):
        stream_id = self._quic.get_next_available_stream_id()
        self._http.send_headers(stream_id, [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", authority.encode()),
            (b":path", path.encode()),
        ], end_stream=True)
        waiter = asyncio.get_running_loop().create_future()
        self._waiters[stream_id] = waiter
        self.transmit()
        raw = await asyncio.wait_for(waiter, timeout=5)
        return {k.decode().lower(): v.decode() for k, v in raw}


async def _h3_get(host, port, path="/"):
    config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN,
                               verify_mode=ssl.CERT_NONE, server_name=host)
    async with connect(host, port, configuration=config,
                       create_protocol=_H3Client) as client:
        return await client.get(f"{host}:{port}", path)


class TestJA4HTTP3:
    """JA4 over HTTP/3 — hash mode (port 443/udp). Issue #4."""

    def test_ja4_quic_marker(self):
        headers = asyncio.run(_h3_get(NGINX_HOST, HASH_PORT))
        assert headers.get(":status") == "200", f"Unexpected response: {headers}"
        ja4 = headers.get("x-ja4")
        assert ja4, f"X-JA4 header missing. Headers: {headers}"
        assert JA4_QUIC_HASH_RE.match(ja4), f"JA4 '{ja4}' doesn't match QUIC hash format"
        assert ja4[8:10] == "h3", f"Expected ALPN 'h3', got '{ja4[8:10]}'"
