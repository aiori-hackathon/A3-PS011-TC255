"""
End-to-End integration tests for Threat Lens MVP.
AIORI Hackathon 3 | Problem Statement PS-011 | Team: A3-PS011-TC255

Verifies the entire workflow:
1. Pre-flight Scope check
2. Safe discovery on local services
3. Snapshot storage in SQLite
4. State change (Added / Removed / Modified)
5. Differential change analysis
"""

import http.server
import os
import socketserver
import tempfile
import threading
import pytest

from scope_manager import ScopeManager, ScopeViolationError
from asset_discovery import AssetDiscovery
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


class DynamicTestHandler(http.server.BaseHTTPRequestHandler):
    # Suppress default server strings
    server_version = ""
    sys_version = ""

    # Class-level state to simulate service updates
    status_to_return = 200
    server_to_return = "ThreatLens-V1/1.0"
    title_to_return = "ThreatLens Portal V1"

    def do_GET(self):
        self.send_response(DynamicTestHandler.status_to_return)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", DynamicTestHandler.server_to_return)
        self.end_headers()
        html = f"<html><head><title>{DynamicTestHandler.title_to_return}</title></head><body>V1</body></html>"
        self.wfile.write(html.encode("utf-8"))

    def log_message(self, format, *args):
        pass


@pytest.fixture
def dynamic_server():
    server = socketserver.TCPServer(("127.0.0.1", 0), DynamicTestHandler)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield host, port
    server.shutdown()
    server.server_close()


def test_end_to_end_workflow(dynamic_server, temp_db):
    """
    Test full lifecycle:
    Scan baseline -> Modify service & add new service -> Scan current -> Verify diff.
    """
    host, port1 = dynamic_server
    discovery = AssetDiscovery(db_path=temp_db)

    # 1. Pre-flight check works as expected
    assert ScopeManager.is_in_scope(host) is True
    with pytest.raises(ScopeViolationError):
        discovery.scan("unauthorized-external-site.com")

    # 2. Baseline scan: Service 1 is running V1
    DynamicTestHandler.status_to_return = 200
    DynamicTestHandler.server_to_return = "ThreatLens-V1/1.0"
    DynamicTestHandler.title_to_return = "ThreatLens Portal V1"

    obs_snap1, dur1 = discovery.scan(host, ports=[port1])
    assert len(obs_snap1) == 1
    assert obs_snap1[0]["status_code"] == 200
    assert "ThreatLens-V1/1.0" in obs_snap1[0]["server_header"]

    snap1_id = database.save_snapshot(
        target_host=host,
        observations=obs_snap1,
        scan_duration_sec=dur1,
        notes="Snapshot 1 - Baseline",
        db_path=temp_db,
    )

    # 3. Simulate service modification on port1
    DynamicTestHandler.status_to_return = 503
    DynamicTestHandler.server_to_return = "ThreatLens-V2/2.0-Upgraded"
    DynamicTestHandler.title_to_return = "Service Unavailable"

    # Also start a temporary secondary service on port2 to test "added"
    class SecondaryHandler(http.server.BaseHTTPRequestHandler):
        server_version = ""
        sys_version = ""
        def do_GET(self):
            self.send_response(200)
            self.send_header("Server", "Secondary-Microservice/1.0")
            self.end_headers()
            self.wfile.write(b"OK")
        def log_message(self, format, *args):
            pass

    server2 = socketserver.TCPServer(("127.0.0.1", 0), SecondaryHandler)
    _, port2 = server2.server_address
    t2 = threading.Thread(target=server2.serve_forever, daemon=True)
    t2.start()

    try:
        # Scan snapshot 2 with both ports
        obs_snap2, dur2 = discovery.scan(host, ports=[port1, port2])
        assert len(obs_snap2) == 2

        snap2_id = database.save_snapshot(
            target_host=host,
            observations=obs_snap2,
            scan_duration_sec=dur2,
            notes="Snapshot 2 - Post-deployment upgrade",
            db_path=temp_db,
        )

        # 4. Run Change Engine
        diff = ChangeEngine.compare_snapshots(snap1_id, snap2_id, db_path=temp_db)

        # 5. Assert differential results
        summary = diff["summary"]
        assert summary["has_changes"] is True
        assert summary["added_count"] == 1
        assert summary["modified_count"] == 1
        assert summary["removed_count"] == 0

        # Assert Added
        added_port = diff["added"][0]["port"]
        assert added_port == port2

        # Assert Modified
        modified_port = diff["modified"][0]["port"]
        assert modified_port == port1
        field_changes = {ch["field"]: (ch["old_value"], ch["new_value"]) for ch in diff["modified"][0]["changes"]}
        assert "status_code" in field_changes
        assert field_changes["status_code"] == (200, 503)
        assert "server_header" in field_changes

        # Verify audit log recorded everything
        logs = database.get_audit_logs(db_path=temp_db)
        actions = [l["action"] for l in logs]
        assert "CHANGE_ANALYSIS" in actions
        assert "SNAPSHOT_SAVED" in actions

    finally:
        server2.shutdown()
        server2.server_close()
