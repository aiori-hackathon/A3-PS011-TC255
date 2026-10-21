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


def test_save_snapshot_with_tested_ports(temp_db):
    """
    Verify snapshot persistence with tested_ports metadata,
    supporting keyword arguments, positional arguments, and kwargs.
    """
    obs = [{"host": "127.0.0.1", "port": 8080, "protocol": "http"}]

    # 1. Keyword argument call
    snap_id = database.save_snapshot(
        target_host="127.0.0.1",
        observations=obs,
        scan_duration_sec=0.12,
        notes="Coverage test",
        tested_ports=[80, 443, 8080, 3000],
        db_path=temp_db,
    )
    snap = database.get_snapshot_by_id(snap_id, temp_db)
    assert snap is not None
    assert snap["tested_ports"] == [80, 443, 3000, 8080]

    # 2. Backward-compatible positional call (5th argument is db_path string)
    snap_id_pos = database.save_snapshot(
        "127.0.0.1",
        obs,
        0.05,
        "Positional test",
        temp_db,
    )
    snap_pos = database.get_snapshot_by_id(snap_id_pos, temp_db)
    assert snap_pos is not None
    assert snap_pos["tested_ports"] == [8080]

    # 3. Call using supported alias 'ports'
    snap_id_alias_ports = database.save_snapshot(
        target_host="127.0.0.1",
        observations=obs,
        ports=[80, 8080],
        db_path=temp_db,
    )
    snap_ports = database.get_snapshot_by_id(snap_id_alias_ports, temp_db)
    assert snap_ports is not None
    assert snap_ports["tested_ports"] == [80, 8080]

    # 4. Call via asset_discovery.save_snapshot alias
    import asset_discovery
    snap_id_alias = asset_discovery.save_snapshot(
        target_host="127.0.0.1",
        observations=obs,
        tested_ports=[8080, 5000],
        db_path=temp_db,
    )
    snap_alias = database.get_snapshot_by_id(snap_id_alias, temp_db)
    assert snap_alias is not None
    assert snap_alias["tested_ports"] == [5000, 8080]


def test_save_snapshot_rejects_unsupported_kwargs(temp_db):
    """
    Verify save_snapshot raises a clear TypeError when unknown or misspelled
    keyword arguments are passed instead of silently ignoring them.
    """
    obs = [{"host": "127.0.0.1", "port": 8080, "protocol": "http"}]

    # 1. Misspelled singular 'tested_port'
    with pytest.raises(TypeError) as exc_info:
        database.save_snapshot(
            target_host="127.0.0.1",
            observations=obs,
            tested_port=[8080],
            db_path=temp_db,
        )
    assert "unexpected keyword argument" in str(exc_info.value)
    assert "tested_port" in str(exc_info.value)
    assert "Supported arguments" in str(exc_info.value)

    # 2. Arbitrary unsupported argument
    with pytest.raises(TypeError) as exc_info2:
        database.save_snapshot(
            target_host="127.0.0.1",
            observations=obs,
            invalid_arg="unsupported",
            db_path=temp_db,
        )
    assert "unexpected keyword argument" in str(exc_info2.value)
    assert "invalid_arg" in str(exc_info2.value)
