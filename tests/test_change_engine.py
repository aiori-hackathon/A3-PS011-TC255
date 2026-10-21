"""
Unit tests for Threat Lens ChangeEngine (Differential Analysis).
AIORI Hackathon 3 | Problem Statement PS-011 | Team: A3-PS011-TC255
"""

import os
import tempfile
import pytest
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


def test_no_changes():
    """Verify comparing identical snapshots reports no changes."""
    baseline = [
        {"host": "127.0.0.1", "port": 8080, "status_code": 200, "server_header": "uvicorn", "title": "API"}
    ]
    current = [
        {"host": "127.0.0.1", "port": 8080, "status_code": 200, "server_header": "uvicorn", "title": "API"}
    ]
    diff = ChangeEngine.compare_observations(baseline, current)
    assert diff["summary"]["has_changes"] is False
    assert diff["summary"]["added_count"] == 0
    assert diff["summary"]["removed_count"] == 0
    assert diff["summary"]["modified_count"] == 0
    assert diff["summary"]["unchanged_count"] == 1


def test_added_endpoint():
    """Verify new endpoint detection."""
    baseline = [
        {"host": "127.0.0.1", "port": 8080, "status_code": 200, "server_header": "uvicorn"}
    ]
    current = [
        {"host": "127.0.0.1", "port": 8080, "status_code": 200, "server_header": "uvicorn"},
        {"host": "127.0.0.1", "port": 5000, "status_code": 200, "server_header": "Flask"},
    ]
    diff = ChangeEngine.compare_observations(baseline, current)
    assert diff["summary"]["has_changes"] is True
    assert diff["summary"]["added_count"] == 1
    assert diff["summary"]["removed_count"] == 0
    assert diff["summary"]["modified_count"] == 0
    assert diff["added"][0]["port"] == 5000


def test_removed_endpoint():
    """Verify shut down or removed endpoint detection when port was tested and confirmed closed."""
    baseline = [
        {"host": "127.0.0.1", "port": 8080, "status_code": 200},
        {"host": "127.0.0.1", "port": 3000, "status_code": 200},
    ]
    current = [
        {"host": "127.0.0.1", "port": 8080, "status_code": 200}
    ]
    diff = ChangeEngine.compare_observations(
        baseline,
        current,
        current_tested_ports=[8080, 3000],
        current_port_outcomes={8080: "open", 3000: "closed"},
    )
    assert diff["summary"]["has_changes"] is True
    assert diff["summary"]["added_count"] == 0
    assert diff["summary"]["removed_count"] == 1
    assert diff["removed"][0]["port"] == 3000


def test_modified_status_code_and_server():
    """Verify attribute changes (status code, server banner) are flagged as modified."""
    baseline = [
        {
            "host": "127.0.0.1",
            "port": 8080,
            "status_code": 200,
            "server_header": "nginx/1.24",
            "title": "Welcome",
        }
    ]
    current = [
        {
            "host": "127.0.0.1",
            "port": 8080,
            "status_code": 500,
            "server_header": "nginx/1.26",
            "title": "Internal Server Error",
        }
    ]
    diff = ChangeEngine.compare_observations(baseline, current)
    assert diff["summary"]["has_changes"] is True
    assert diff["summary"]["modified_count"] == 1
    mod = diff["modified"][0]
    assert mod["endpoint"] == "127.0.0.1:8080"
    changed_fields = {ch["field"]: (ch["old_value"], ch["new_value"]) for ch in mod["changes"]}
    assert "status_code" in changed_fields
    assert changed_fields["status_code"] == (200, 500)
    assert "server_header" in changed_fields
    assert changed_fields["server_header"] == ("nginx/1.24", "nginx/1.26")
    assert "title" in changed_fields
    assert changed_fields["title"] == ("Welcome", "Internal Server Error")


def test_modified_security_headers():
    """Verify changes in security headers are detected."""
    baseline = [
        {
            "host": "127.0.0.1",
            "port": 8080,
            "status_code": 200,
            "headers": {"content-security-policy": "default-src 'self'"},
        }
    ]
    current = [
        {
            "host": "127.0.0.1",
            "port": 8080,
            "status_code": 200,
            "headers": {},  # CSP header was removed!
        }
    ]
    diff = ChangeEngine.compare_observations(baseline, current)
    assert diff["summary"]["has_changes"] is True
    assert diff["summary"]["modified_count"] == 1
    mod = diff["modified"][0]
    header_change = next(ch for ch in mod["changes"] if "content-security-policy" in ch["field"])
    assert header_change["old_value"] == "default-src 'self'"
    assert header_change["new_value"] == "[MISSING]"


def test_compare_snapshots_from_db(temp_db):
    """Verify comparing snapshots saved in database."""
    snap1_id = database.save_snapshot(
        "127.0.0.1",
        [{"host": "127.0.0.1", "port": 80, "status_code": 200}],
        db_path=temp_db,
    )
    snap2_id = database.save_snapshot(
        "127.0.0.1",
        [
            {"host": "127.0.0.1", "port": 80, "status_code": 200},
            {"host": "127.0.0.1", "port": 8080, "status_code": 200},
        ],
        db_path=temp_db,
    )

    diff = ChangeEngine.compare_snapshots(snap1_id, snap2_id, db_path=temp_db)
    assert diff["summary"]["added_count"] == 1
    assert diff["summary"]["removed_count"] == 0
    assert diff["added"][0]["port"] == 8080

    report = ChangeEngine.generate_change_report(diff)
    assert "Added Endpoints" in report
    assert "127.0.0.1:8080" in report
