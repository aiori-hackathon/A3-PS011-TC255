"""
Unit tests for Threat Lens SQLite Database Persistence.
AIORI Hackathon 3 | Problem Statement PS-011 | Team: A3-PS011-TC255
"""

import os
import tempfile
import pytest
import database


@pytest.fixture
def temp_db():
    """Create a temporary database file for isolation."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    database.init_db(path)
    yield path
    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass


def test_init_db(temp_db):
    """Verify database tables are created."""
    with database.db_session(temp_db) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {row[0] for row in cursor.fetchall()}
        assert "snapshots" in tables
        assert "observations" in tables
        assert "audit_logs" in tables


def test_save_and_retrieve_snapshot(temp_db):
    """Verify saving a snapshot and its observations."""
    sample_observations = [
        {
            "host": "127.0.0.1",
            "port": 8080,
            "protocol": "http",
            "service": "http-web",
            "status_code": 200,
            "server_header": "Werkzeug/3.0.0",
            "content_type": "text/html",
            "title": "Local API Portal",
            "response_time_ms": 12.5,
            "headers": {"Server": "Werkzeug/3.0.0", "X-Custom": "TestVal"},
            "state": "open",
        },
        {
            "host": "127.0.0.1",
            "port": 3000,
            "protocol": "http",
            "service": "http-web",
            "status_code": 404,
            "server_header": "NodeJS",
            "content_type": "application/json",
            "title": "",
            "response_time_ms": 8.1,
            "headers": {"Server": "NodeJS"},
            "state": "open",
        },
    ]

    snap_id = database.save_snapshot(
        target_host="127.0.0.1",
        observations=sample_observations,
        scan_duration_sec=0.45,
        notes="Baseline scan",
        db_path=temp_db,
    )
    assert snap_id > 0

    # Retrieve snapshot record
    snap = database.get_snapshot_by_id(snap_id, temp_db)
    assert snap is not None
    assert snap["target_host"] == "127.0.0.1"
    assert snap["total_assets"] == 2
    assert snap["scan_duration_sec"] == 0.45
    assert snap["notes"] == "Baseline scan"

    # Retrieve observations
    obs_list = database.get_observations_for_snapshot(snap_id, temp_db)
    assert len(obs_list) == 2
    ports = [o["port"] for o in obs_list]
    assert 3000 in ports
    assert 8080 in ports

    obs_8080 = next(o for o in obs_list if o["port"] == 8080)
    assert obs_8080["status_code"] == 200
    assert obs_8080["server_header"] == "Werkzeug/3.0.0"
    assert obs_8080["title"] == "Local API Portal"
    assert obs_8080["headers"]["X-Custom"] == "TestVal"


def test_get_latest_snapshot(temp_db):
    """Verify fetching the most recent snapshot."""
    database.save_snapshot("127.0.0.1", [], notes="First", db_path=temp_db)
    snap2_id = database.save_snapshot("127.0.0.1", [], notes="Second", db_path=temp_db)

    latest = database.get_latest_snapshot("127.0.0.1", temp_db)
    assert latest is not None
    assert latest["id"] == snap2_id
    assert latest["notes"] == "Second"


def test_audit_logging(temp_db):
    """Verify audit log records actions and compliance."""
    database.log_audit_event(
        action="SCOPE_VALIDATION",
        target="127.0.0.1",
        status="ALLOWED",
        details="Authorized target",
        db_path=temp_db,
    )
    database.log_audit_event(
        action="SCOPE_VALIDATION",
        target="google.com",
        status="REJECTED",
        details="Disallowed external domain",
        db_path=temp_db,
    )

    logs = database.get_audit_logs(limit=10, db_path=temp_db)
    assert len(logs) >= 2
    actions = [l["action"] for l in logs]
    statuses = [l["status"] for l in logs]
    assert "SCOPE_VALIDATION" in actions
    assert "ALLOWED" in statuses
    assert "REJECTED" in statuses


def test_cascade_delete_snapshot(temp_db):
    """Verify deleting a snapshot removes its associated observations."""
    snap_id = database.save_snapshot(
        "127.0.0.1",
        [{"host": "127.0.0.1", "port": 80, "protocol": "http"}],
        db_path=temp_db,
    )
    obs_before = database.get_observations_for_snapshot(snap_id, temp_db)
    assert len(obs_before) == 1

    deleted = database.delete_snapshot(snap_id, temp_db)
    assert deleted is True

    snap_after = database.get_snapshot_by_id(snap_id, temp_db)
    assert snap_after is None

    obs_after = database.get_observations_for_snapshot(snap_id, temp_db)
    assert len(obs_after) == 0
