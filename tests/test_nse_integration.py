"""Integration tests for custom NSE scripts.

Each test:
1. Starts a plain-TCP stub server that mimics the target protocol response
2. Runs nmap with the custom NSE against 127.0.0.1 on the real port
3. Asserts the script output (positive) or absence of output (negative)

Requires nmap to be installed and tests to run as root (for nmap raw socket access).
Skip the module if nmap is not found or if the required port is already in use.

Run exclusively:
    uv run pytest tests/test_nse_integration.py -v
"""

import os
import shutil
import socket
import socketserver
import subprocess
import threading
import time

import pytest

# ── helpers ───────────────────────────────────────────────────────────────────

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_NSE_DIR = os.path.join(_ROOT, 'nse')

pytestmark = pytest.mark.skipif(
    shutil.which('nmap') is None,
    reason='nmap not installed',
)


def _port_is_free(port: int) -> bool:
    """Return True if nobody is listening on 127.0.0.1:port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(('127.0.0.1', port))
            return True
        except OSError:
            return False


class _ReuseAddrServer(socketserver.TCPServer):
    allow_reuse_address = True


class _StubServer:
    """Context manager: plain-TCP server that sends a fixed response to any connection.

    The server runs in a daemon thread so it does not block the test.  It
    handles connections sequentially, which is sufficient because nmap makes
    at most two connections per script invocation (SSL attempt + TCP fallback).
    """

    def __init__(self, port: int, response: bytes):
        self._port = port
        self._response = response
        self._server: _ReuseAddrServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> '_StubServer':
        response = self._response

        class _Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    self.request.recv(4096)       # drain probe (may be TLS or HTTP)
                    self.request.sendall(response)
                except Exception:
                    pass

        self._server = _ReuseAddrServer(('127.0.0.1', self._port), _Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._thread.start()
        time.sleep(0.05)  # give the server a moment to bind
        return self

    def __exit__(self, *_):
        if self._server:
            self._server.shutdown()
            self._server.server_close()


def _run_nmap(port: int, script_path: str) -> str:
    """Run nmap with a single NSE script against 127.0.0.1; return combined output."""
    cmd = [
        'nmap', '-sT', '-p', str(port),
        '--script', script_path,
        '--script-timeout', '10s',
        '-T4',
        '127.0.0.1',
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return result.stdout + result.stderr


# ── nodejs-inspector ──────────────────────────────────────────────────────────

_NODEJS_PORT   = 9229
_NODEJS_SCRIPT = os.path.join(_NSE_DIR, 'nodejs-inspector.nse')

_NODEJS_VALID = (
    b'HTTP/1.0 200 OK\r\n'
    b'Content-Type: application/json\r\n\r\n'
    b'{"Browser": "node.js/v18.17.0", "V8-Version": "10.7.193.23"}'
)
_NODEJS_INVALID = (
    b'HTTP/1.0 200 OK\r\n'
    b'Content-Type: text/html\r\n\r\n'
    b'<html>Not a Node.js service</html>'
)


@pytest.mark.skipif(not _port_is_free(_NODEJS_PORT),
                    reason=f'port {_NODEJS_PORT} already in use')
class TestNodejsInspectorNse:

    def test_detects_nodejs_inspector(self):
        """Stub returns valid /json/version → script reports version string."""
        with _StubServer(_NODEJS_PORT, _NODEJS_VALID):
            output = _run_nmap(_NODEJS_PORT, _NODEJS_SCRIPT)
        assert 'nodejs-inspector' in output
        assert 'Node.js Inspector accessible' in output
        assert 'node.js/v18.17.0' in output

    def test_no_output_for_non_nodejs_service(self):
        """Stub returns HTML → script produces no output (fingerprint mismatch)."""
        with _StubServer(_NODEJS_PORT, _NODEJS_INVALID):
            output = _run_nmap(_NODEJS_PORT, _NODEJS_SCRIPT)
        assert 'Node.js Inspector accessible' not in output


# ── delve-debugger ────────────────────────────────────────────────────────────

_DELVE_PORT   = 2345
_DELVE_SCRIPT = os.path.join(_NSE_DIR, 'delve-debugger.nse')

_DELVE_VALID = (
    b'{"seq":1,"type":"response","command":"initialize",'
    b'"success":true,"body":{"supportsConfigurationDoneRequest":true}}\n'
)
_DELVE_INVALID = b'HELLO stranger\n'


@pytest.mark.skipif(not _port_is_free(_DELVE_PORT),
                    reason=f'port {_DELVE_PORT} already in use')
class TestDelveDebuggerNse:

    def test_detects_delve_debugger(self):
        """Stub returns DAP response → script reports Delve responding."""
        with _StubServer(_DELVE_PORT, _DELVE_VALID):
            output = _run_nmap(_DELVE_PORT, _DELVE_SCRIPT)
        assert 'delve-debugger' in output
        assert 'Delve debugger responding' in output

    def test_no_output_for_non_delve_service(self):
        """Stub returns non-DAP data → script produces no output."""
        with _StubServer(_DELVE_PORT, _DELVE_INVALID):
            output = _run_nmap(_DELVE_PORT, _DELVE_SCRIPT)
        assert 'Delve debugger responding' not in output


# ── kubelet-anon-check ────────────────────────────────────────────────────────

_KUBELET_PORT   = 10250
_KUBELET_SCRIPT = os.path.join(_NSE_DIR, 'kubelet-anon-check.nse')

_KUBELET_VALID = (
    b'HTTP/1.0 200 OK\r\n'
    b'Content-Type: application/json\r\n\r\n'
    b'{"items":[]}'
)
_KUBELET_UNAUTH = (
    b'HTTP/1.0 401 Unauthorized\r\n'
    b'Content-Type: application/json\r\n\r\n'
    b'{"message":"Unauthorized"}'
)


@pytest.mark.skipif(not _port_is_free(_KUBELET_PORT),
                    reason=f'port {_KUBELET_PORT} already in use')
class TestKubeletAnonCheckNse:

    def test_detects_anonymous_access(self):
        """Stub returns HTTP 200 → script reports anonymous access enabled.

        The script tries TLS first; the stub is plain TCP so TLS handshake
        fails, the script creates a new socket and falls back to plain TCP,
        which succeeds.  The stub handles both connections sequentially.
        """
        with _StubServer(_KUBELET_PORT, _KUBELET_VALID):
            output = _run_nmap(_KUBELET_PORT, _KUBELET_SCRIPT)
        assert 'kubelet-anon-check' in output
        assert 'Anonymous access enabled' in output

    def test_no_output_when_auth_required(self):
        """Stub returns HTTP 401 → script produces no output."""
        with _StubServer(_KUBELET_PORT, _KUBELET_UNAUTH):
            output = _run_nmap(_KUBELET_PORT, _KUBELET_SCRIPT)
        assert 'Anonymous access enabled' not in output
