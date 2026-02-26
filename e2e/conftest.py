import os
import ssl
import http.client

import httpx
import pytest


NGINX_HOST = os.environ.get("NGINX_HOST", "nginx")
HASH_PORT = int(os.environ.get("NGINX_PORT", "443"))
RAW_PORT = int(os.environ.get("NGINX_RAW_PORT", "8443"))


def _make_ssl_context(max_version=None, min_version=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if max_version:
        ctx.maximum_version = max_version
    if min_version:
        ctx.minimum_version = min_version
    return ctx


@pytest.fixture
def ssl_ctx_tls13():
    return _make_ssl_context(
        min_version=ssl.TLSVersion.TLSv1_3,
        max_version=ssl.TLSVersion.TLSv1_3,
    )


@pytest.fixture
def ssl_ctx_tls12():
    return _make_ssl_context(
        min_version=ssl.TLSVersion.TLSv1_2,
        max_version=ssl.TLSVersion.TLSv1_2,
    )


@pytest.fixture
def ssl_ctx_default():
    return _make_ssl_context()


def make_request(port, path="/", method="GET", headers=None, ctx=None):
    """Make an HTTPS request and return (response_headers_dict, body_bytes)."""
    if ctx is None:
        ctx = _make_ssl_context()
    conn = http.client.HTTPSConnection(NGINX_HOST, port, context=ctx)
    conn.request(method, path, headers=headers or {})
    resp = conn.getresponse()
    resp_headers = {k.lower(): v for k, v in resp.getheaders()}
    body = resp.read()
    conn.close()
    return resp_headers, body


@pytest.fixture
def hash_request():
    """Make a request to the hash-mode server (port 443)."""
    def _request(path="/", method="GET", headers=None, ctx=None):
        return make_request(HASH_PORT, path, method, headers, ctx)
    return _request


@pytest.fixture
def raw_request():
    """Make a request to the raw-mode server (port 8443)."""
    def _request(path="/", method="GET", headers=None, ctx=None):
        return make_request(RAW_PORT, path, method, headers, ctx)
    return _request


H2_HASH_PORT = HASH_PORT
H2_RAW_PORT = RAW_PORT


def make_h2_request(port, path="/", method="GET", headers=None):
    """Make an HTTP/2 request and return (response_headers_dict, body_bytes)."""
    url = f"https://{NGINX_HOST}:{port}{path}"
    with httpx.Client(http2=True, verify=False) as client:
        resp = client.request(method, url, headers=headers or {})
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        return resp_headers, resp.content


@pytest.fixture
def h2_hash_request():
    """Make an HTTP/2 request to the hash-mode server (port 443)."""
    def _request(path="/", method="GET", headers=None):
        return make_h2_request(H2_HASH_PORT, path, method, headers)
    return _request


@pytest.fixture
def h2_raw_request():
    """Make an HTTP/2 request to the raw-mode server (port 8443)."""
    def _request(path="/", method="GET", headers=None):
        return make_h2_request(H2_RAW_PORT, path, method, headers)
    return _request
