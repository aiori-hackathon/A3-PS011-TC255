"""
Unit tests for Threat Lens AssetDiscovery Engine.
AIORI Hackathon 3 | Problem Statement PS-011 | Team: A3-PS011-TC255
"""

import http.server
import os
import socketserver
import tempfile
import threading
import pytest
from asset_discovery import AssetDiscovery, extract_title, probe_http_service
from scope_manager import ScopeViolationError, InvalidTargetError
import database


@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    database.init_db(path)
    yield path
    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass


class CustomTestHandler(http.server.BaseHTTPRequestHandler):
    server_version = ""
    sys_version = ""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "ThreatLens-MockTestServer/1.0")
        self.send_header("X-Test-Header", "Active")
        self.end_headers()
        html = "<html><head><title>ThreatLens Local Test Page</title></head><body><h1>OK</h1></body></html>"
        self.wfile.write(html.encode("utf-8"))

    def log_message(self, format, *args):
        # Suppress stdout logging during test run
        pass


@pytest.fixture(scope="module")
def mock_http_server():
    """Spin up a mock HTTP server on 127.0.0.1 on an available port."""
    server = socketserver.TCPServer(("127.0.0.1", 0), CustomTestHandler)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield host, port
    server.shutdown()
    server.server_close()


def test_scope_enforcement_blocks_external(temp_db):
    """Verify that an external target is rejected by AssetDiscovery with zero network requests."""
    discovery = AssetDiscovery(db_path=temp_db)
    disallowed_targets = ["google.com", "192.168.1.100", "8.8.8.8"]

    for target in disallowed_targets:
        with pytest.raises(ScopeViolationError):
            discovery.scan(target)

    # Check audit log to ensure rejection was recorded
    logs = database.get_audit_logs(db_path=temp_db)
    rejections = [l for l in logs if l["status"] == "REJECTED"]
    assert len(rejections) >= len(disallowed_targets)


def test_extract_title():
    """Verify safe HTML title parsing."""
    html = "<html><head><title>My Test Dashboard</title></head><body>Hello</body></html>"
    assert extract_title(html) == "My Test Dashboard"
    assert extract_title("<html><body>No Title</body></html>") == ""
    assert extract_title("") == ""
    assert extract_title(None) == ""  # type: ignore


def test_discovery_on_mock_service(mock_http_server, temp_db):
    """Verify safe probe on our running local test service."""
    host, port = mock_http_server
    discovery = AssetDiscovery(db_path=temp_db)

    observations, duration = discovery.scan(host, ports=[port])
    assert len(observations) == 1
    obs = observations[0]

    assert obs["host"] == host
    assert obs["port"] == port
    assert obs["status_code"] == 200
    assert "ThreatLens-MockTestServer" in obs["server_header"]
    assert obs["title"] == "ThreatLens Local Test Page"
    assert obs["headers"].get("X-Test-Header") == "Active"
    assert duration >= 0.0


def test_graceful_handling_of_closed_ports(temp_db):
    """Verify closed ports are handled gracefully without exceptions or crashes."""
    discovery = AssetDiscovery(db_path=temp_db)
    # Port 49999 is typically closed locally
    observations, duration = discovery.scan("127.0.0.1", ports=[49999], timeout=0.2)
    assert isinstance(observations, list)
    # Closed port should either be omitted or empty
    assert len(observations) == 0
    assert duration >= 0.0


class RawEchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.recv(512)
        except Exception:
            pass


@pytest.fixture(scope="module")
def mock_raw_tcp_server():
    """Spin up a raw TCP server on 127.0.0.1 that does not speak HTTP."""
    server = socketserver.TCPServer(("127.0.0.1", 0), RawEchoHandler)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield host, port
    server.shutdown()
    server.server_close()


def test_discovery_on_non_http_tcp_service(mock_raw_tcp_server, temp_db):
    """
    Verify that an open TCP port which does not speak HTTP is inventoried
    as an active observation with service='tcp-open', protocol='tcp', and status_code=None.
    """
    host, port = mock_raw_tcp_server
    discovery = AssetDiscovery(db_path=temp_db)

    observations, duration = discovery.scan(host, ports=[port])
    assert len(observations) == 1
    obs = observations[0]

    assert obs["host"] == host
    assert obs["port"] == port
    assert obs["protocol"] == "tcp"
    assert obs["service"] == "tcp-open"
    assert obs["status_code"] is None
    assert obs["state"] == "open"
    assert obs["headers"] == {}
    assert duration >= 0.0
