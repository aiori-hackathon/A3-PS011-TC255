"""
Threat Lens - Security & Reliability Regression Test Suite
AIORI Hackathon 3 | Problem Statement PS-011 | Team: A3-PS011-TC255

Tests all 7 critical regression requirements:
1. Local redirects to external, private LAN, and link-local addresses are never followed.
2. Direct calls to low-level helpers reject unauthorized targets before network activity.
3. Disjoint port ranges do not produce false removals (marked UNTESTED).
4. Timeouts and connection errors produce inconclusive outcomes (marked INCONCLUSIVE).
5. Sensitive headers are redacted before SQLite persistence and dashboard display.
6. Failed scans and blocked UI scope checks are accurately audited.
7. Existing valid localhost scanning and change detection continue to function cleanly.
"""

import http.server
import json
import os
import socketserver
import tempfile
import threading
import pytest

from scope_manager import ScopeManager, ScopeViolationError, InvalidTargetError
from asset_discovery import (
    AssetDiscovery,
    check_tcp_port,
    check_tcp_port_outcome,
    probe_http_service,
    sanitize_headers,
)
from change_engine import ChangeEngine
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


# -----------------------------------------------------------------------------
# 1. REDIRECT HANDLING REGRESSION TESTS
# -----------------------------------------------------------------------------
class RedirectTestHandler(http.server.BaseHTTPRequestHandler):
    target_location = "https://external-domain.com/"

    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", RedirectTestHandler.target_location)
        self.end_headers()

    def log_message(self, format, *args):
        pass


@pytest.fixture(scope="module")
def redirect_server():
    server = socketserver.TCPServer(("127.0.0.1", 0), RedirectTestHandler)
    host, port = server.server_address
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield host, port
    server.shutdown()
    server.server_close()


def test_redirects_to_external_and_metadata_never_followed(redirect_server):
    """
    Priority 1 & 5.1:
    Verify that automatic HTTP redirects are disabled by default and
    redirects pointing to external hosts, LAN IPs, or link-local cloud metadata (169.254.169.254)
    are strictly prevented from dispatching outbound network requests.
    """
    host, port = redirect_server

    dangerous_locations = [
        "https://external-attacker.com/evil",
        "http://192.168.1.1/admin",
        "http://10.0.0.1/sensitive",
        "http://169.254.169.254/latest/meta-data/",
        "http://0.0.0.0:8000/",
    ]

    for loc in dangerous_locations:
        RedirectTestHandler.target_location = loc

        # Probe with default settings (allow_redirects=False)
        obs = probe_http_service(host, port, timeout=1.0)
        assert obs is not None
        assert obs["status_code"] == 302
        # Redirect was detected but not followed
        assert obs["redirect_info"]["in_scope"] is False
        assert "blocked_reason" in obs["redirect_info"]

        # Even if allow_redirects=True is explicitly passed, it must refuse to follow out-of-scope target
        obs_attempt = probe_http_service(host, port, timeout=1.0, allow_redirects=True, max_redirects=2)
        assert obs_attempt is not None
        assert obs_attempt["status_code"] == 302
        assert obs_attempt["redirect_info"]["in_scope"] is False


def test_safe_local_redirect_allowed():
    """Verify that an in-scope local redirect (e.g. /login on loopback) is validated safely."""
    current_url = "http://127.0.0.1:8080/"
    safe_rel = "/login"
    safe_abs = "http://127.0.0.1:8080/dashboard"

    resolved_rel = ScopeManager.validate_redirect(current_url, safe_rel)
    assert resolved_rel == "http://127.0.0.1:8080/login"

    resolved_abs = ScopeManager.validate_redirect(current_url, safe_abs)
    assert resolved_abs == "http://127.0.0.1:8080/dashboard"


# -----------------------------------------------------------------------------
# 2. LOW-LEVEL HELPER SCOPE ENFORCEMENT
# -----------------------------------------------------------------------------
def test_low_level_helpers_reject_unauthorized():
    """
    Priority 1 & 5.2:
    Direct calls to check_tcp_port() and probe_http_service() must reject
    out-of-scope targets before attempting any network socket or request.
    """
    unauthorized_targets = [
        "google.com",
        "8.8.8.8",
        "192.168.1.1",
        "169.254.169.254",
        "0.0.0.0",
    ]

    for target in unauthorized_targets:
        with pytest.raises(ScopeViolationError):
            check_tcp_port(target, 80)

        with pytest.raises(ScopeViolationError):
            check_tcp_port_outcome(target, 80)

        with pytest.raises(ScopeViolationError):
            probe_http_service(target, 80)


# -----------------------------------------------------------------------------
# 3. DISJOINT PORT RANGES DO NOT PRODUCE FALSE REMOVALS
# -----------------------------------------------------------------------------
def test_disjoint_ports_classified_as_untested_not_removed():
    """
    Priority 3 & 5.3:
    When Snapshot 1 tested ports [80, 8080], but Snapshot 2 only tested port [5000],
    ports 80 and 8080 must be classified as UNTESTED, NEVER as REMOVED.
    """
    baseline_obs = [
        {"host": "127.0.0.1", "port": 80, "status_code": 200, "service": "http"},
        {"host": "127.0.0.1", "port": 8080, "status_code": 200, "service": "http"},
    ]
    # Snapshot 2 only scanned port 5000
    current_obs = [
        {"host": "127.0.0.1", "port": 5000, "status_code": 200, "service": "http"}
    ]
    current_tested_ports = [5000]

    diff = ChangeEngine.compare_observations(
        baseline_obs=baseline_obs,
        current_obs=current_obs,
        current_tested_ports=current_tested_ports,
    )

    summary = diff["summary"]
    # Ports 80 and 8080 were NOT in current_tested_ports
    assert summary["removed_count"] == 0, "Untested ports must NOT be marked as removed!"
    assert summary["untested_count"] == 2
    assert summary["added_count"] == 1  # Port 5000 was added

    untested_ports = [u["observation"]["port"] for u in diff["untested"]]
    assert 80 in untested_ports
    assert 8080 in untested_ports


# -----------------------------------------------------------------------------
# 4. TIMEOUTS AND CONNECTION ERRORS PRODUCE INCONCLUSIVE OUTCOMES
# -----------------------------------------------------------------------------
def test_timeouts_and_errors_classified_as_inconclusive():
    """
    Priority 3 & 5.4:
    A baseline active service that times out during a subsequent scan must be
    classified as INCONCLUSIVE / UNREACHABLE, NOT as REMOVED.
    """
    baseline_obs = [
        {"host": "127.0.0.1", "port": 8080, "status_code": 200}
    ]
    current_obs = []  # No response received

    # Port 8080 was tested, but socket timed out
    diff = ChangeEngine.compare_observations(
        baseline_obs=baseline_obs,
        current_obs=current_obs,
        current_tested_ports=[8080],
        current_port_outcomes={8080: "timeout"},
    )

    summary = diff["summary"]
    assert summary["removed_count"] == 0, "Timed-out port must NOT be declared removed!"
    assert summary["inconclusive_count"] == 1
    assert diff["inconclusive"][0]["endpoint"] == "127.0.0.1:8080"


def test_unknown_historical_coverage_is_inconclusive():
    """
    Priority 3:
    When comparing legacy snapshots where tested_ports metadata is unknown,
    missing endpoints must be classified as INCONCLUSIVE rather than falsely REMOVED.
    """
    baseline_obs = [{"host": "127.0.0.1", "port": 8080, "status_code": 200}]
    current_obs = []

    # tested_ports is None (unknown historical coverage)
    diff = ChangeEngine.compare_observations(
        baseline_obs=baseline_obs,
        current_obs=current_obs,
        current_tested_ports=None,
    )
    assert diff["summary"]["removed_count"] == 0
    assert diff["summary"]["inconclusive_count"] == 1


# -----------------------------------------------------------------------------
# 5. SENSITIVE HEADERS ARE REDACTED BEFORE PERSISTENCE AND DISPLAY
# -----------------------------------------------------------------------------
class SensitiveHeaderHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Server", "ThreatLens-AuthMock/1.0")
        self.send_header("Set-Cookie", "session_id=super_secret_jwt_token_12345; Secure; HttpOnly")
        self.send_header("Authorization", "Bearer sensitive_api_bearer_token")
        self.send_header("X-Api-Key", "sk-live-9876543210abcdef")
        self.send_header("X-Public-Metadata", "safe_public_info")
        self.end_headers()
        self.wfile.write(b"Authenticated OK")

    def log_message(self, format, *args):
        pass


@pytest.fixture(scope="module")
def sensitive_server():
    server = socketserver.TCPServer(("127.0.0.1", 0), SensitiveHeaderHandler)
    host, port = server.server_address
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield host, port
    server.shutdown()
    server.server_close()


def test_sensitive_headers_redacted_before_db_storage(sensitive_server, temp_db):
    """
    Priority 2 & 5.5:
    Sensitive headers (Set-Cookie, Authorization, X-Api-Key) must be redacted
    with '[REDACTED]' before SQLite storage and observation display.
    """
    host, port = sensitive_server
    discovery = AssetDiscovery(db_path=temp_db)

    observations, _ = discovery.scan(host, ports=[port])
    assert len(observations) == 1
    obs = observations[0]

    # Verify discovery observation has redacted values
    headers = obs["headers"]
    assert headers.get("Set-Cookie") == "[REDACTED]"
    assert headers.get("Authorization") == "[REDACTED]"
    assert headers.get("X-Api-Key") == "[REDACTED]"
    assert headers.get("X-Public-Metadata") == "safe_public_info"

    # Save to SQLite database
    snap_id = database.save_snapshot(host, observations, tested_ports=[port], db_path=temp_db)

    # Inspect raw SQLite database row directly to confirm no raw secrets leaked
    with database.db_session(temp_db) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT headers_json FROM observations WHERE snapshot_id = ?", (snap_id,))
        raw_json = cursor.fetchone()[0]
        assert "super_secret_jwt_token_12345" not in raw_json
        assert "sensitive_api_bearer_token" not in raw_json
        assert "sk-live-9876543210abcdef" not in raw_json
        assert "[REDACTED]" in raw_json

    # Retrieve through database API
    stored_obs = database.get_observations_for_snapshot(snap_id, db_path=temp_db)
    stored_headers = stored_obs[0]["headers"]
    assert stored_headers.get("Set-Cookie") == "[REDACTED]"
    assert stored_headers.get("Authorization") == "[REDACTED]"


# -----------------------------------------------------------------------------
# 6. FAILED SCANS AND BLOCKED UI CHECKS ARE AUDITED
# -----------------------------------------------------------------------------
def test_failed_scan_and_blocked_checks_audited(temp_db):
    """
    Priority 4 & 5.6:
    Failed scans and blocked pre-flight scope checks must be recorded accurately
    in the audit trail without leaking sensitive details.
    """
    discovery = AssetDiscovery(db_path=temp_db)

    # 1. Blocked attempt
    with pytest.raises(ScopeViolationError):
        discovery.scan("attacker.com")

    # 2. UI Pre-Flight check simulation
    try:
        ScopeManager.validate_target("192.168.1.1")
    except ScopeViolationError as exc:
        database.log_audit_event(
            action="UI_SCOPE_CHECK",
            target="192.168.1.1",
            status="REJECTED",
            details=str(exc)[:150],
            db_path=temp_db,
        )

    # Retrieve audit logs
    logs = database.get_audit_logs(limit=10, db_path=temp_db)
    actions = [l["action"] for l in logs]
    statuses = [l["status"] for l in logs]

    assert "SCOPE_VALIDATION" in actions
    assert "REJECTED" in statuses
    assert "UI_SCOPE_CHECK" in actions


# -----------------------------------------------------------------------------
# 7. EXISTING VALID LOCALHOST SCANNING AND CHANGE DETECTION STILL WORK
# -----------------------------------------------------------------------------
def test_existing_valid_localhost_scanning_and_diff(sensitive_server, temp_db):
    """
    Priority 5.7:
    Verify normal authorized localhost scanning, snapshot persistence,
    and change detection remain 100% functional.
    """
    host, port = sensitive_server
    discovery = AssetDiscovery(db_path=temp_db)

    # Scan 1: Baseline
    obs_1, dur_1 = discovery.scan(host, ports=[port])
    snap_1_id = database.save_snapshot(host, obs_1, tested_ports=[port], db_path=temp_db)
    assert snap_1_id > 0

    # Scan 2: Empty scan (confirmed closed)
    snap_2_id = database.save_snapshot(host, [], tested_ports=[port], db_path=temp_db)

    # Compare snapshots
    diff = ChangeEngine.compare_snapshots(snap_1_id, snap_2_id, db_path=temp_db)
    summary = diff["summary"]

    assert summary["has_changes"] is True
    assert summary["removed_count"] == 1
    assert diff["removed"][0]["port"] == port
