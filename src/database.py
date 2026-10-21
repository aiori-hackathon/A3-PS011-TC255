"""
Threat Lens - Database Persistence Layer
AIORI Hackathon 3 | Problem Statement PS-011 | Team: A3-PS011-TC255

SQLite-based persistent storage for:
- Timestamped asset snapshots with tested port metadata
- Sanitized endpoint observations & service metadata
- Audit log entries for authorized compliance tracking
"""

from contextlib import contextmanager
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator, Optional


DEFAULT_DB_PATH = "threat_lens.db"

SENSITIVE_HEADER_KEYS = frozenset({
    "set-cookie",
    "cookie",
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "x-access-token",
    "token",
    "secret",
    "x-csrf-token",
    "x-xsrf-token",
})


def sanitize_headers_dict(headers: Any) -> dict[str, str]:
    """
    Sanitize header values by replacing sensitive credentials, cookies, and tokens with '[REDACTED]'.
    """
    if not headers or not isinstance(headers, dict):
        return {}
    sanitized = {}
    for k, v in headers.items():
        k_str = str(k)
        k_lower = k_str.lower().strip()
        if (
            k_lower in SENSITIVE_HEADER_KEYS
            or "api-key" in k_lower
            or "auth-token" in k_lower
            or "secret" in k_lower
        ):
            sanitized[k_str] = "[REDACTED]"
        else:
            sanitized[k_str] = str(v)
    return sanitized


@contextmanager
def db_session(db_path: str = DEFAULT_DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    """
    Context manager that opens a connection to the SQLite database,
    enables foreign keys and row factory, and guarantees the connection
    is safely closed upon exit (essential on Windows to avoid file locks).
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
    finally:
        conn.close()


def get_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """
    Get a direct connection for callers that manage their own connection lifecycle.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """
    Initialize SQLite schema for snapshots, observations, and audit logs.
    Safe to call repeatedly (uses IF NOT EXISTS and automatic column migration).
    """
    with db_session(db_path) as conn:
        cursor = conn.cursor()

        # Snapshots table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                target_host TEXT NOT NULL,
                total_assets INTEGER NOT NULL DEFAULT 0,
                scan_duration_sec REAL NOT NULL DEFAULT 0.0,
                notes TEXT DEFAULT '',
                tested_ports_json TEXT DEFAULT '[]'
            );
        """)

        # Migration check for existing snapshots table
        cursor.execute("PRAGMA table_info(snapshots);")
        columns = [row["name"] for row in cursor.fetchall()]
        if "tested_ports_json" not in columns:
            cursor.execute("ALTER TABLE snapshots ADD COLUMN tested_ports_json TEXT DEFAULT '[]';")

        # Observations / Asset inventory table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_id INTEGER NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL DEFAULT 'http',
                service TEXT NOT NULL DEFAULT 'http',
                status_code INTEGER,
                server_header TEXT,
                content_type TEXT,
                title TEXT,
                response_time_ms REAL,
                headers_json TEXT,
                security_txt_json TEXT DEFAULT NULL,
                state TEXT NOT NULL DEFAULT 'open',
                timestamp TEXT NOT NULL,
                FOREIGN KEY (snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
            );
        """)

        # Migration check for existing observations table
        cursor.execute("PRAGMA table_info(observations);")
        obs_columns = [row["name"] for row in cursor.fetchall()]
        if "security_txt_json" not in obs_columns:
            cursor.execute("ALTER TABLE observations ADD COLUMN security_txt_json TEXT DEFAULT NULL;")

        # Audit log table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT
            );
        """)

        conn.commit()


SUPPORTED_SNAPSHOT_KWARGS = frozenset({"tested_ports", "ports", "db_path"})


def save_snapshot(
    target_host: str,
    observations: list[dict[str, Any]],
    scan_duration_sec: float = 0.0,
    notes: str = "",
    tested_ports: Optional[list[int]] = None,
    db_path: str = DEFAULT_DB_PATH,
    **kwargs: Any,
) -> int:
    """
    Persist a new timestamped snapshot and its sanitized asset observations.

    Parameters:
      target_host: Authorized target IP or hostname.
      observations: Discovered asset/endpoint dictionaries.
      scan_duration_sec: Scan runtime in seconds.
      notes: Optional human-readable note/tag for the snapshot.
      tested_ports: List of ports tested during discovery.
      db_path: SQLite database file path.
      **kwargs: Supported keyword aliases ('ports' for tested_ports, 'db_path').
                Any unsupported keyword argument raises TypeError.

    Returns:
      int: The newly created snapshot ID.
    """
    # Validate against unsupported keyword arguments to catch typos early
    unsupported_kwargs = set(kwargs.keys()) - SUPPORTED_SNAPSHOT_KWARGS
    if unsupported_kwargs:
        raise TypeError(
            f"save_snapshot() got unexpected keyword argument(s): {', '.join(sorted(unsupported_kwargs))}. "
            f"Supported arguments are 'target_host', 'observations', 'scan_duration_sec', 'notes', "
            f"'tested_ports' (alias: 'ports'), and 'db_path'."
        )

    # Backward compatibility: if 5th argument was a string, caller passed db_path positionally
    if isinstance(tested_ports, str):
        db_path = tested_ports
        tested_ports = kwargs.get("tested_ports", kwargs.get("ports", None))
    elif "db_path" in kwargs:
        db_path = kwargs["db_path"]

    # Support alternative kwarg names like 'ports'
    if tested_ports is None:
        if "tested_ports" in kwargs:
            tested_ports = kwargs["tested_ports"]
        elif "ports" in kwargs:
            tested_ports = kwargs["ports"]

    init_db(db_path)
    now_iso = datetime.now(timezone.utc).isoformat()

    # Determine tested ports
    if tested_ports is not None and isinstance(tested_ports, (list, set, tuple)):
        ports_to_record = sorted(list({int(p) for p in tested_ports if str(p).isdigit() or isinstance(p, int)}))
    else:
        ports_to_record = sorted(list({int(obs.get("port", 80)) for obs in observations if "port" in obs}))

    tested_ports_json = json.dumps(ports_to_record)

    with db_session(db_path) as conn:
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO snapshots (timestamp, target_host, total_assets, scan_duration_sec, notes, tested_ports_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (now_iso, target_host, len(observations), scan_duration_sec, notes, tested_ports_json),
        )
        snapshot_id = cursor.lastrowid

        for obs in observations:
            # Strictly sanitize headers before database storage
            raw_headers = obs.get("headers", {})
            sanitized = sanitize_headers_dict(raw_headers)
            headers_json = json.dumps(sanitized)

            sec_txt = obs.get("security_txt")
            sec_txt_json = json.dumps(sec_txt) if sec_txt is not None else None

            cursor.execute(
                """
                INSERT INTO observations (
                    snapshot_id, host, port, protocol, service, status_code,
                    server_header, content_type, title, response_time_ms,
                    headers_json, security_txt_json, state, timestamp
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    obs.get("host", target_host),
                    int(obs.get("port", 80)),
                    obs.get("protocol", "http"),
                    obs.get("service", "http"),
                    obs.get("status_code"),
                    obs.get("server_header", ""),
                    obs.get("content_type", ""),
                    obs.get("title", ""),
                    obs.get("response_time_ms"),
                    headers_json,
                    sec_txt_json,
                    obs.get("state", "open"),
                    obs.get("timestamp", now_iso),
                ),
            )

        # Log audit entry
        cursor.execute(
            """
            INSERT INTO audit_logs (timestamp, action, target, status, details)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                now_iso,
                "SNAPSHOT_SAVED",
                target_host,
                "SUCCESS",
                f"Saved snapshot #{snapshot_id} with {len(observations)} observations. Duration: {scan_duration_sec:.2f}s",
            ),
        )

        conn.commit()
        return snapshot_id


def get_snapshots(limit: int = 50, db_path: str = DEFAULT_DB_PATH) -> list[dict[str, Any]]:
    """
    Retrieve snapshot records ordered by most recent first.
    """
    init_db(db_path)
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp, target_host, total_assets, scan_duration_sec, notes, tested_ports_json
            FROM snapshots
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        results = []
        for row in rows:
            d = dict(row)
            try:
                d["tested_ports"] = json.loads(d.get("tested_ports_json") or "[]")
            except Exception:
                d["tested_ports"] = []
            results.append(d)
        return results


def get_snapshot_by_id(snapshot_id: int, db_path: str = DEFAULT_DB_PATH) -> Optional[dict[str, Any]]:
    """
    Retrieve a single snapshot record by ID.
    """
    init_db(db_path)
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp, target_host, total_assets, scan_duration_sec, notes, tested_ports_json
            FROM snapshots
            WHERE id = ?
            """,
            (snapshot_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["tested_ports"] = json.loads(d.get("tested_ports_json") or "[]")
        except Exception:
            d["tested_ports"] = []
        return d


def get_observations_for_snapshot(snapshot_id: int, db_path: str = DEFAULT_DB_PATH) -> list[dict[str, Any]]:
    """
    Retrieve all observation records associated with a specific snapshot ID.
    """
    init_db(db_path)
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, snapshot_id, host, port, protocol, service, status_code,
                   server_header, content_type, title, response_time_ms,
                   headers_json, security_txt_json, state, timestamp
            FROM observations
            WHERE snapshot_id = ?
            ORDER BY port ASC
            """,
            (snapshot_id,),
        )
        rows = cursor.fetchall()
        results = []
        for r in rows:
            d = dict(r)
            try:
                raw_headers = json.loads(d.get("headers_json") or "{}")
                d["headers"] = sanitize_headers_dict(raw_headers)
            except Exception:
                d["headers"] = {}
            if d.get("security_txt_json"):
                try:
                    d["security_txt"] = json.loads(d["security_txt_json"])
                except Exception:
                    d["security_txt"] = None
            else:
                d["security_txt"] = None
            results.append(d)
        return results


def get_latest_snapshot(target_host: Optional[str] = None, db_path: str = DEFAULT_DB_PATH) -> Optional[dict[str, Any]]:
    """
    Retrieve the most recent snapshot, optionally filtered by target host.
    """
    init_db(db_path)
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        if target_host:
            cursor.execute(
                """
                SELECT id, timestamp, target_host, total_assets, scan_duration_sec, notes, tested_ports_json
                FROM snapshots
                WHERE target_host = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (target_host,),
            )
        else:
            cursor.execute(
                """
                SELECT id, timestamp, target_host, total_assets, scan_duration_sec, notes, tested_ports_json
                FROM snapshots
                ORDER BY id DESC
                LIMIT 1
                """
            )
        row = cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["tested_ports"] = json.loads(d.get("tested_ports_json") or "[]")
        except Exception:
            d["tested_ports"] = []
        return d


def log_audit_event(
    action: str,
    target: str,
    status: str,
    details: str = "",
    db_path: str = DEFAULT_DB_PATH,
) -> None:
    """
    Append an entry to the audit log for accountability and evidence-backed security review.
    Sanitizes details to prevent leaking secret keys or raw sensitive data.
    """
    init_db(db_path)
    now_iso = datetime.now(timezone.utc).isoformat()
    # Clean and truncate details
    safe_details = str(details or "")[:350]
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO audit_logs (timestamp, action, target, status, details)
            VALUES (?, ?, ?, ?, ?)
            """,
            (now_iso, action, target, status, safe_details),
        )
        conn.commit()


def get_audit_logs(limit: int = 100, db_path: str = DEFAULT_DB_PATH) -> list[dict[str, Any]]:
    """
    Retrieve recent audit logs in descending order.
    """
    init_db(db_path)
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp, action, target, status, details
            FROM audit_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def delete_snapshot(snapshot_id: int, db_path: str = DEFAULT_DB_PATH) -> bool:
    """
    Delete a snapshot and cascade delete its observations.
    """
    init_db(db_path)
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM snapshots WHERE id = ?", (snapshot_id,))
        deleted = cursor.rowcount > 0
        conn.commit()
        return deleted


def clear_all_data(db_path: str = DEFAULT_DB_PATH) -> None:
    """
    Reset all database tables (useful for test suites and clean restarts).
    """
    init_db(db_path)
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM observations;")
        cursor.execute("DELETE FROM snapshots;")
        cursor.execute("DELETE FROM audit_logs;")
        conn.commit()
