"""
Threat Lens Core Source Package
AIORI Hackathon 3 | Problem Statement PS-011 | Team: A3-PS011-TC255
"""

from .scope_manager import ScopeManager, ScopeViolationError, InvalidTargetError
from .database import (
    init_db,
    save_snapshot,
    get_snapshots,
    get_snapshot_by_id,
    get_observations_for_snapshot,
    get_latest_snapshot,
    log_audit_event,
    get_audit_logs,
)
from .asset_discovery import AssetDiscovery, DEFAULT_LOCAL_PORTS
from .change_engine import ChangeEngine
from .risk_engine import RiskEngine

__all__ = [
    "ScopeManager",
    "ScopeViolationError",
    "InvalidTargetError",
    "init_db",
    "save_snapshot",
    "get_snapshots",
    "get_snapshot_by_id",
    "get_observations_for_snapshot",
    "get_latest_snapshot",
    "log_audit_event",
    "get_audit_logs",
    "AssetDiscovery",
    "DEFAULT_LOCAL_PORTS",
    "ChangeEngine",
    "RiskEngine",
]
