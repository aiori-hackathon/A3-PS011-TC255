"""
Unit and Security Regression Tests for RFC 9116 security.txt Engine
AIORI Hackathon 3 | Problem Statement PS-011 | Team: A3-PS011-TC255
"""

from datetime import datetime, timezone, timedelta
import http.server
import json
import socketserver
import threading
from unittest import mock
import pytest
import requests

from scope_manager import ScopeManager, ScopeViolationError
from security_txt import SecurityTxtParser, probe_security_txt, parse_rfc3339_datetime
from asset_discovery import AssetDiscovery, probe_http_service
from change_engine import ChangeEngine
import database


# ==============================================================================
# RFC 9116 PARSER TESTS
# ==============================================================================

def test_parse_valid_security_txt():
    future_date = (datetime.now(timezone.utc) + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw = f"""# Vulnerability Disclosure Policy
Contact: mailto:security@example.com
Contact: https://example.com/reporting
Expires: {future_date}
Encryption: https://example.com/pgp-key.txt
Preferred-Languages: en, es, de
Policy: https://example.com/disclosure-policy
Acknowledgments: https://example.com/hall-of-fame
Hiring: https://example.com/careers
Canonical: https://example.com/.well-known/security.txt
"""
    res = SecurityTxtParser.parse(raw)
    assert res["is_valid_format"] is True
    assert res["status"] == "valid"
    assert res["is_expired"] is False
    assert res["expires_at"] is not None
    assert "mailto:security@example.com" in res["contact"]
    assert "https://example.com/reporting" in res["contact"]
    assert "https://example.com/pgp-key.txt" in res["encryption"]
    assert res["preferred_languages"] == ["en", "es", "de"]
    assert "https://example.com/disclosure-policy" in res["policy"]
    assert "https://example.com/hall-of-fame" in res["acknowledgments"]
    assert "https://example.com/careers" in res["hiring"]
    assert "https://example.com/.well-known/security.txt" in res["canonical"]


def test_parse_expired_security_txt():
    past_date = "2020-01-01T00:00:00Z"
    raw = f"""Contact: mailto:security@example.com
Expires: {past_date}
"""
    res = SecurityTxtParser.parse(raw)
    assert res["is_valid_format"] is True
    assert res["status"] == "expired"
    assert res["is_expired"] is True
    assert any("expired" in n.lower() for n in res["notes"])


def test_parse_malformed_missing_contact():
    future_date = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw = f"""# Missing Contact
Expires: {future_date}
Policy: https://example.com/policy
"""
    res = SecurityTxtParser.parse(raw)
    assert res["is_valid_format"] is False
    assert res["status"] == "malformed"
    assert any("contact" in n.lower() for n in res["notes"])


def test_parse_malformed_missing_expires():
    raw = """Contact: mailto:security@example.com
Policy: https://example.com/policy
"""
    res = SecurityTxtParser.parse(raw)
    assert res["is_valid_format"] is False
    assert res["status"] == "malformed"
    assert any("expires" in n.lower() for n in res["notes"])


def test_parse_malformed_duplicate_expires():
    """Verify RFC 9116 Section 2.5.5: Exactly one Expires field must be present."""
    raw = """Contact: mailto:security@example.com
Expires: 2028-01-01T00:00:00Z
Expires: 2029-01-01T00:00:00Z
"""
    res = SecurityTxtParser.parse(raw)
    assert res["is_valid_format"] is False
    assert res["status"] == "malformed"
    assert any("multiple 'expires'" in n.lower() for n in res["notes"])


def test_parse_malformed_date_without_time():
    """Verify RFC 3339 date-time requirement: date without time component is invalid."""
    raw = """Contact: mailto:security@example.com
Expires: 2028-12-31
"""
    res = SecurityTxtParser.parse(raw)
    assert res["is_valid_format"] is False
    assert res["status"] == "malformed"


def test_parse_malformed_invalid_date_format():
    raw = """Contact: mailto:security@example.com
Expires: not-a-valid-date-timestamp
"""
    res = SecurityTxtParser.parse(raw)
    assert res["is_valid_format"] is False
    assert res["status"] == "malformed"
    assert any("not valid rfc 3339" in n.lower() for n in res["notes"])


def test_parse_empty_content_graceful():
    res1 = SecurityTxtParser.parse("")
    assert res1["status"] == "malformed"
    assert res1["is_valid_format"] is False

    res2 = SecurityTxtParser.parse(None)  # type: ignore
    assert res2["status"] == "malformed"


def test_parse_rfc3339_timestamps():
    # Valid UTC Z
    dt1 = parse_rfc3339_datetime("2028-12-31T23:59:59Z")
    assert dt1 is not None and dt1.year == 2028

    # Valid with numeric offset
    dt2 = parse_rfc3339_datetime("2028-12-31T18:59:59-05:00")
    assert dt2 is not None and dt2.year == 2028

    # Invalid: no time
    assert parse_rfc3339_datetime("2028-12-31") is None
    # Invalid: empty
    assert parse_rfc3339_datetime("") is None


# ==============================================================================
# NETWORK PROBING & MOCK SERVER TESTS
# ==============================================================================

class MockSecurityTxtHandler(http.server.BaseHTTPRequestHandler):
    well_known_body = None
    well_known_status = 404
    well_known_content_type = "text/plain; charset=utf-8"

    root_body = None
    root_status = 404
    root_content_type = "text/plain; charset=utf-8"

    redirect_target = None
    step2_redirect_target = None

    def do_GET(self):
        if self.path == "/.well-known/security.txt":
            if MockSecurityTxtHandler.redirect_target:
                self.send_response(302)
                self.send_header("Location", MockSecurityTxtHandler.redirect_target)
                self.end_headers()
                return

            self.send_response(MockSecurityTxtHandler.well_known_status)
            self.send_header("Content-Type", MockSecurityTxtHandler.well_known_content_type)
            self.end_headers()
            if MockSecurityTxtHandler.well_known_body:
                self.wfile.write(MockSecurityTxtHandler.well_known_body.encode("utf-8"))

        elif self.path == "/security.txt":
            if MockSecurityTxtHandler.step2_redirect_target:
                self.send_response(302)
                self.send_header("Location", MockSecurityTxtHandler.step2_redirect_target)
                self.end_headers()
                return

            self.send_response(MockSecurityTxtHandler.root_status)
            self.send_header("Content-Type", MockSecurityTxtHandler.root_content_type)
            self.end_headers()
            if MockSecurityTxtHandler.root_body:
                self.wfile.write(MockSecurityTxtHandler.root_body.encode("utf-8"))

        elif self.path == "/target_security.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            future_date = (datetime.now(timezone.utc) + timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
            self.wfile.write(f"Contact: mailto:target@test.local\nExpires: {future_date}\n".encode("utf-8"))

        elif self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><head><title>App</title></head><body>OK</body></html>")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


@pytest.fixture
def mock_sec_server():
    server = socketserver.TCPServer(("127.0.0.1", 0), MockSecurityTxtHandler)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    # Reset state
    MockSecurityTxtHandler.well_known_body = None
    MockSecurityTxtHandler.well_known_status = 404
    MockSecurityTxtHandler.well_known_content_type = "text/plain; charset=utf-8"
    MockSecurityTxtHandler.root_body = None
    MockSecurityTxtHandler.root_status = 404
    MockSecurityTxtHandler.root_content_type = "text/plain; charset=utf-8"
    MockSecurityTxtHandler.redirect_target = None
    MockSecurityTxtHandler.step2_redirect_target = None

    yield host, port

    server.shutdown()
    server.server_close()


def test_probe_primary_location_found(mock_sec_server):
    host, port = mock_sec_server
    future_date = (datetime.now(timezone.utc) + timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
    MockSecurityTxtHandler.well_known_status = 200
    MockSecurityTxtHandler.well_known_body = f"Contact: mailto:sec@test.local\nExpires: {future_date}\n"

    res = probe_security_txt(host, port)
    assert res["status"] == "valid"
    assert res["found"] is True
    assert res["path"] == "/.well-known/security.txt"
    assert "mailto:sec@test.local" in res["contact"]
    assert res["is_expired"] is False


def test_probe_fallback_location_found(mock_sec_server):
    host, port = mock_sec_server
    future_date = (datetime.now(timezone.utc) + timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
    # Primary returns 404, fallback at /security.txt returns 200
    MockSecurityTxtHandler.well_known_status = 404
    MockSecurityTxtHandler.root_status = 200
    MockSecurityTxtHandler.root_body = f"Contact: mailto:fallback@test.local\nExpires: {future_date}\n"

    res = probe_security_txt(host, port)
    assert res["status"] == "valid"
    assert res["found"] is True
    assert res["path"] == "/security.txt"
    assert "mailto:fallback@test.local" in res["contact"]


def test_probe_both_missing_returns_missing(mock_sec_server):
    host, port = mock_sec_server
    MockSecurityTxtHandler.well_known_status = 404
    MockSecurityTxtHandler.root_status = 404

    res = probe_security_txt(host, port)
    assert res["status"] == "missing"
    assert res["found"] is False


def test_probe_unreachable_endpoint_not_reported_as_missing():
    """Verify probe failure: unreachable/closed port returns 'unreachable', NOT 'missing'."""
    # Port 59999 is closed locally
    res = probe_security_txt("127.0.0.1", 59999, timeout=0.2)
    assert res["status"] == "unreachable"
    assert res["found"] is False
    assert any("probe failed" in n.lower() for n in res["notes"])


def test_probe_server_error_not_reported_as_missing(mock_sec_server):
    """Verify probe failure: HTTP 500 returns 'server_error', NOT 'missing'."""
    host, port = mock_sec_server
    MockSecurityTxtHandler.well_known_status = 500
    MockSecurityTxtHandler.root_status = 500

    res = probe_security_txt(host, port)
    assert res["status"] == "server_error"
    assert res["found"] is False


def test_probe_tls_error_not_reported_as_missing():
    """Verify probe failure: TLS certificate verification failure returns 'tls_error', NOT 'missing'."""
    with mock.patch("requests.get", side_effect=requests.exceptions.SSLError("certificate verify failed")):
        res = probe_security_txt("127.0.0.1", 443, protocol="https", verify_tls=True)
        assert res["status"] == "tls_error"
        assert res["found"] is False
        assert any("tls verification failed" in n.lower() for n in res["notes"])


def test_probe_html_soft_404_rejected(mock_sec_server):
    host, port = mock_sec_server
    # Server returns 200 with HTML (e.g. single page app catchall)
    MockSecurityTxtHandler.well_known_status = 200
    MockSecurityTxtHandler.well_known_content_type = "text/html"
    MockSecurityTxtHandler.well_known_body = "<html><body>404 Not Found</body></html>"
    MockSecurityTxtHandler.root_status = 404

    res = probe_security_txt(host, port)
    assert res["found"] is False
    assert res["status"] == "missing"


# ==============================================================================
# SCOPE & REDIRECT REGRESSION TESTS
# ==============================================================================

def test_probe_blocks_external_targets():
    with pytest.raises(ScopeViolationError):
        probe_security_txt("google.com", 80)

    with pytest.raises(ScopeViolationError):
        probe_security_txt("192.168.1.1", 8080)

    with pytest.raises(ScopeViolationError):
        probe_security_txt("8.8.8.8", 443)


def test_probe_blocks_redirect_to_external_target(mock_sec_server):
    host, port = mock_sec_server
    MockSecurityTxtHandler.redirect_target = "https://external-evil.com/security.txt"

    res = probe_security_txt(host, port)
    assert res["status"] == "redirect_blocked"
    assert res["found"] is False
    assert any("blocked" in n.lower() for n in res["notes"])


def test_probe_blocks_redirect_to_cloud_metadata(mock_sec_server):
    host, port = mock_sec_server
    MockSecurityTxtHandler.redirect_target = "http://169.254.169.254/latest/meta-data/"

    res = probe_security_txt(host, port)
    assert res["status"] == "redirect_blocked"
    assert res["found"] is False


def test_probe_allows_multi_hop_safe_local_redirect(mock_sec_server):
    host, port = mock_sec_server
    # Hop 1 (.well-known) redirects to Hop 2 (/security.txt), which redirects to /target_security.txt
    MockSecurityTxtHandler.redirect_target = f"http://{host}:{port}/security.txt"
    MockSecurityTxtHandler.step2_redirect_target = f"http://{host}:{port}/target_security.txt"

    res = probe_security_txt(host, port)
    assert res["status"] == "valid"
    assert res["found"] is True
    assert "mailto:target@test.local" in res["contact"]


# ==============================================================================
# DATABASE AND CHANGE ENGINE INTEGRATION TESTS
# ==============================================================================

def test_database_persists_and_retrieves_security_txt():
    import tempfile
    fd, path = tempfile.mkstemp(suffix=".db")
    import os
    os.close(fd)

    try:
        database.init_db(path)
        obs = [
            {
                "host": "127.0.0.1",
                "port": 8080,
                "protocol": "http",
                "service": "http-web",
                "status_code": 200,
                "server_header": "nginx/1.24",
                "content_type": "text/html",
                "title": "Test Portal",
                "response_time_ms": 10.0,
                "headers": {"server": "nginx"},
                "security_txt": {
                    "status": "valid",
                    "found": True,
                    "path": "/.well-known/security.txt",
                    "contact": ["mailto:admin@test.local"],
                    "expires_at": "2030-01-01T00:00:00+00:00",
                },
            }
        ]

        snap_id = database.save_snapshot("127.0.0.1", obs, scan_duration_sec=0.1, db_path=path)
        retrieved_obs = database.get_observations_for_snapshot(snap_id, db_path=path)
        assert len(retrieved_obs) == 1

        sec = retrieved_obs[0].get("security_txt")
        assert sec is not None
        assert sec["status"] == "valid"
        assert sec["path"] == "/.well-known/security.txt"
        assert "mailto:admin@test.local" in sec["contact"]

    finally:
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass


def test_change_engine_detects_security_txt_drift():
    baseline = [
        {
            "host": "127.0.0.1",
            "port": 8080,
            "protocol": "http",
            "service": "http-web",
            "status_code": 200,
            "server_header": "nginx/1.24",
            "title": "Portal",
            "headers": {},
            "security_txt": {
                "status": "valid",
                "path": "/.well-known/security.txt",
                "contact": ["mailto:admin@test.local"],
            },
        }
    ]

    current = [
        {
            "host": "127.0.0.1",
            "port": 8080,
            "protocol": "http",
            "service": "http-web",
            "status_code": 200,
            "server_header": "nginx/1.24",
            "title": "Portal",
            "headers": {},
            "security_txt": {
                "status": "missing",
                "path": None,
                "contact": [],
            },
        }
    ]

    diff = ChangeEngine.compare_observations(baseline, current, current_tested_ports=[8080])
    assert diff["summary"]["has_changes"] is True
    assert diff["summary"]["modified_count"] == 1

    mod_changes = diff["modified"][0]["changes"]
    sec_change = next((c for c in mod_changes if c["field"] == "security_txt_status"), None)
    assert sec_change is not None
    assert sec_change["old_value"] == "Valid"
    assert sec_change["new_value"] == "Missing"

    # Verify Markdown report includes RFC 9116 change
    report = ChangeEngine.generate_change_report(diff)
    assert "RFC 9116 security.txt" in report
