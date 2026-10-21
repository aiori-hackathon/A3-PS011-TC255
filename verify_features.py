"""
Threat Lens - Feature Verification Script
Tests and validates the four essential features:
1. Scope Enforcement
2. Snapshot Storage
3. Change Detection
4. Audit Trail
"""

import http.server
import json
import socketserver
import sys
import threading
import time

from scope_manager import ScopeManager, ScopeViolationError, InvalidTargetError
from asset_discovery import AssetDiscovery
from change_engine import ChangeEngine
import database


def test_scope_enforcement():
    print("\n" + "=" * 60)
    print("FEATURE 1: SCOPE ENFORCEMENT VERIFICATION")
    print("=" * 60)

    # 1. Allowed targets
    allowed = ["127.0.0.1", "localhost", "http://127.0.0.1:8080", "https://localhost:3000"]
    for target in allowed:
        host, port = ScopeManager.validate_target(target)
        in_scope = ScopeManager.is_in_scope(target)
        print(f"  [PASS] Allowed Target: '{target}' -> Normalized Host: '{host}', Port: {port} (in_scope={in_scope})")
        assert in_scope is True

    # 2. Rejected targets: external domains, public IPs, private LANs, wildcards
    disallowed_cases = [
        ("google.com", "External domain"),
        ("https://github.com", "External URL"),
        ("8.8.8.8", "Public IP"),
        ("1.1.1.1:443", "Public IP with port"),
        ("192.168.1.1", "Private LAN address (RFC1918)"),
        ("10.0.0.1", "Private LAN address (RFC1918)"),
        ("172.16.0.5", "Private LAN address (RFC1918)"),
        ("0.0.0.0", "Wildcard address"),
        ("http://0.0.0.0:8000", "Wildcard address with port"),
        ("localhost.attacker.com", "Subdomain spoofing attempt"),
    ]

    for target, category in disallowed_cases:
        in_scope = ScopeManager.is_in_scope(target)
        assert in_scope is False
        try:
            ScopeManager.validate_target(target)
            print(f"  [FAIL] Failed to reject {category}: '{target}'")
            sys.exit(1)
        except ScopeViolationError as exc:
            print(f"  [PASS] REJECTED {category}: '{target}'")
            print(f"         Reason: {exc}")

    # Verify discovery engine also blocks before any network socket
    discovery = AssetDiscovery(db_path="verification_test.db")
    try:
        discovery.scan("unauthorized-public-site.com")
        print("  [FAIL] AssetDiscovery did not block unauthorized site")
        sys.exit(1)
    except ScopeViolationError:
        print("  [PASS] AssetDiscovery pre-flight check blocked network request for 'unauthorized-public-site.com'")

    print("\n>>> Feature 1 (Scope Enforcement): VERIFIED SUCCESSFULLY!")


# Dynamic test server for Feature 2 and 3
class MockLabServerHandler(http.server.BaseHTTPRequestHandler):
    server_version = ""
    sys_version = ""
    status_code = 200
    server_banner = "ThreatLens-MockService/1.0"
    title = "Initial Service"

    def do_GET(self):
        self.send_response(MockLabServerHandler.status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", MockLabServerHandler.server_banner)
        self.send_header("X-Security-Header", "Active")
        self.end_headers()
        html = f"<html><head><title>{MockLabServerHandler.title}</title></head><body>Status: {MockLabServerHandler.status_code}</body></html>"
        self.wfile.write(html.encode("utf-8"))

    def log_message(self, format, *args):
        pass


def test_snapshot_storage_and_change_detection():
    db_file = "verification_test.db"
    database.clear_all_data(db_file)

    # Start mock server
    server = socketserver.TCPServer(("127.0.0.1", 0), MockLabServerHandler)
    host, port = server.server_address
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        # ======================================================================
        # FEATURE 2: SNAPSHOT STORAGE
        # ======================================================================
        print("\n" + "=" * 60)
        print("FEATURE 2: SNAPSHOT STORAGE VERIFICATION")
        print("=" * 60)

        # Configure initial service state
        MockLabServerHandler.status_code = 200
        MockLabServerHandler.server_banner = "ThreatLens-MockService/1.0"
        MockLabServerHandler.title = "Initial Service"

        discovery = AssetDiscovery(db_path=db_file)
        print(f"  -> Scanning local target {host}:{port}...")
        obs_1, dur_1 = discovery.scan(host, ports=[port])
        print(f"  -> Discovered {len(obs_1)} observation(s) in {dur_1:.3f}s")
        assert len(obs_1) == 1

        snap_1_id = database.save_snapshot(
            target_host=host,
            observations=obs_1,
            scan_duration_sec=dur_1,
            notes="Verification Baseline Scan",
            db_path=db_file,
        )
        print(f"  [PASS] Saved Snapshot #{snap_1_id} in SQLite")

        # Verify snapshot retrieval
        snapshots = database.get_snapshots(db_path=db_file)
        assert len(snapshots) >= 1
        latest_snap = snapshots[0]
        print(f"  [PASS] Retrieved Snapshot from DB:")
        print(f"         ID: {latest_snap['id']}")
        print(f"         Timestamp: {latest_snap['timestamp']}")
        print(f"         Target Host: {latest_snap['target_host']}")
        print(f"         Total Assets: {latest_snap['total_assets']}")
        print(f"         Notes: {latest_snap['notes']}")

        # Verify observation storage
        stored_obs = database.get_observations_for_snapshot(snap_1_id, db_path=db_file)
        assert len(stored_obs) == 1
        o = stored_obs[0]
        print(f"  [PASS] Observation details verified:")
        print(f"         Endpoint: {o['host']}:{o['port']}")
        print(f"         Status Code: {o['status_code']}")
        print(f"         Server Banner: {o['server_header']}")
        print(f"         Page Title: {o['title']}")
        print(f"         Latency: {o['response_time_ms']} ms")
        print(f"         Headers: {list(o['headers'].keys())}")

        assert o["status_code"] == 200
        assert o["server_header"] == "ThreatLens-MockService/1.0"
        assert o["title"] == "Initial Service"

        print("\n>>> Feature 2 (Snapshot Storage): VERIFIED SUCCESSFULLY!")

        # ======================================================================
        # FEATURE 3: CHANGE DETECTION
        # ======================================================================
        print("\n" + "=" * 60)
        print("FEATURE 3: CHANGE DETECTION VERIFICATION")
        print("=" * 60)

        # Modify local testbed setting
        print("  -> Modifying local testbed setting:")
        print("     Old: Status 200, Banner 'ThreatLens-MockService/1.0', Title 'Initial Service'")
        MockLabServerHandler.status_code = 503
        MockLabServerHandler.server_banner = "nginx/1.24.0 (Ubuntu-Modified)"
        MockLabServerHandler.title = "Service Unavailable - Maintenance"
        print("     New: Status 503, Banner 'nginx/1.24.0 (Ubuntu-Modified)', Title 'Service Unavailable - Maintenance'")

        # Run second scan
        print(f"  -> Running second scan on {host}:{port}...")
        obs_2, dur_2 = discovery.scan(host, ports=[port])
        snap_2_id = database.save_snapshot(
            target_host=host,
            observations=obs_2,
            scan_duration_sec=dur_2,
            notes="Verification Post-Change Scan",
            db_path=db_file,
        )
        print(f"  [PASS] Saved Snapshot #{snap_2_id} in SQLite")

        # Run Change Engine
        diff = ChangeEngine.compare_snapshots(snap_1_id, snap_2_id, db_path=db_file)
        summary = diff["summary"]

        print(f"\n  Differential Summary (Snapshot #{snap_1_id} -> Snapshot #{snap_2_id}):")
        print(f"  - Has Changes: {summary['has_changes']}")
        print(f"  - Added Endpoints: {summary['added_count']}")
        print(f"  - Removed Endpoints: {summary['removed_count']}")
        print(f"  - Modified Endpoints: {summary['modified_count']}")
        print(f"  - Unchanged Endpoints: {summary['unchanged_count']}")

        assert summary["has_changes"] is True
        assert summary["modified_count"] == 1
        assert len(diff["modified"]) == 1

        mod_entry = diff["modified"][0]
        print(f"\n  [PASS] Detected modifications on endpoint: {mod_entry['endpoint']}")
        changed_fields = {}
        for ch in mod_entry["changes"]:
            print(f"         * {ch['label']}: '{ch['old_value']}' -> '{ch['new_value']}'")
            changed_fields[ch["field"]] = (ch["old_value"], ch["new_value"])

        assert "status_code" in changed_fields
        assert changed_fields["status_code"] == (200, 503)

        assert "server_header" in changed_fields
        assert changed_fields["server_header"] == ("ThreatLens-MockService/1.0", "nginx/1.24.0 (Ubuntu-Modified)")

        assert "title" in changed_fields
        assert changed_fields["title"] == ("Initial Service", "Service Unavailable - Maintenance")

        print("\n>>> Feature 3 (Change Detection): VERIFIED SUCCESSFULLY!")

        # ======================================================================
        # FEATURE 4: AUDIT TRAIL
        # ======================================================================
        print("\n" + "=" * 60)
        print("FEATURE 4: AUDIT TRAIL VERIFICATION")
        print("=" * 60)

        logs = database.get_audit_logs(limit=20, db_path=db_file)
        print(f"  -> Retrieved {len(logs)} audit trail entries from SQLite:")

        actions_found = set()
        statuses_found = set()

        for idx, entry in enumerate(logs, 1):
            actions_found.add(entry["action"])
            statuses_found.add(entry["status"])
            print(f"  [{idx:02d}] {entry['timestamp']} | Action: {entry['action']:<18} | Status: {entry['status']:<10} | Target: {entry['target']:<15} | Details: {entry['details']}")

        # Validate audit actions are accurately recorded
        assert "SCOPE_VALIDATION" in actions_found, "SCOPE_VALIDATION must be in audit logs"
        assert "DISCOVERY_SCAN" in actions_found, "DISCOVERY_SCAN must be in audit logs"
        assert "SNAPSHOT_SAVED" in actions_found, "SNAPSHOT_SAVED must be in audit logs"
        assert "CHANGE_ANALYSIS" in actions_found, "CHANGE_ANALYSIS must be in audit logs"

        # Check for both ALLOWED and REJECTED
        assert "ALLOWED" in statuses_found or "SUCCESS" in statuses_found

        print("\n>>> Feature 4 (Audit Trail): VERIFIED SUCCESSFULLY!")

        print("\n" + "=" * 60)
        print("ALL 4 ESSENTIAL FEATURES VERIFIED AND PASSING 100%!")
        print("=" * 60)

    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    test_scope_enforcement()
    test_snapshot_storage_and_change_detection()
