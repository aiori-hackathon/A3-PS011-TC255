"""
Threat Lens - Change Detection & Differential Analysis Engine
AIORI Hackathon 3 | Problem Statement PS-011 | Team: A3-PS011-TC255

Compares successive asset snapshots to identify:
- Added observations: New endpoints, exposed ports, or freshly responsive services
- Removed observations: Confirmed closed/decommissioned endpoints that were actively tested
- Modified observations: Attribute drifts (status code changes, server banners, title updates, headers)
- Untested observations: Baseline endpoints not scanned in the current scan (never falsely marked as removed)
- Inconclusive observations: Endpoints that timed out, encountered socket errors, or have unknown historical coverage
- Unchanged observations: Verified stable assets
"""

from typing import Any, Optional
import database
from risk_engine import RiskEngine


MONITORED_FIELDS = [
    ("status_code", "Status Code"),
    ("server_header", "Server Banner"),
    ("title", "Page Title"),
    ("content_type", "Content-Type"),
    ("protocol", "Protocol"),
    ("service", "Service Type"),
]

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
]


class ChangeEngine:
    """
    Computes differentials between attack surface snapshots with high accuracy:
    Distinguishes confirmed REMOVED from UNTESTED, UNREACHABLE, and INCONCLUSIVE.
    """

    @staticmethod
    def _endpoint_key(obs: dict[str, Any]) -> str:
        """Generate a unique endpoint key: host:port"""
        host = str(obs.get("host", "127.0.0.1")).lower().strip()
        port = int(obs.get("port", 80))
        return f"{host}:{port}"

    @classmethod
    def compare_observations(
        cls,
        baseline_obs: list[dict[str, Any]],
        current_obs: list[dict[str, Any]],
        current_tested_ports: Optional[list[int]] = None,
        current_port_outcomes: Optional[dict[int, str]] = None,
    ) -> dict[str, Any]:
        """
        Compare two lists of observations (baseline vs current).

        Parameters:
          baseline_obs: List of active observations from the baseline snapshot.
          current_obs: List of active observations from the current snapshot.
          current_tested_ports: Ports that were tested in the current scan.
          current_port_outcomes: Optional map of port -> outcome ('closed', 'timeout', 'unreachable').

        Returns:
          dict containing:
            - summary: {added_count, removed_count, modified_count, unchanged_count, untested_count, inconclusive_count, has_changes}
            - added: list of new observations
            - removed: list of confirmed decommissioned/closed observations
            - modified: list of dicts detailing field-by-field changes
            - unchanged: list of static observations
            - untested: list of baseline observations not scanned in current run
            - inconclusive: list of baseline observations with timeouts or unknown coverage
        """
        baseline_map = {cls._endpoint_key(obs): obs for obs in baseline_obs}
        current_map = {cls._endpoint_key(obs): obs for obs in current_obs}

        baseline_keys = set(baseline_map.keys())
        current_keys = set(current_map.keys())

        added_keys = current_keys - baseline_keys
        missing_keys = baseline_keys - current_keys
        common_keys = baseline_keys & current_keys

        added = []
        for k in sorted(added_keys):
            item = dict(current_map[k])
            item["risk"] = RiskEngine.evaluate_change_risk("added", item)
            added.append(item)

        removed = []
        untested = []
        inconclusive = []
        modified = []
        unchanged = []

        def _with_removed_risk(raw_obs: dict[str, Any]) -> dict[str, Any]:
            item = dict(raw_obs)
            item["risk"] = RiskEngine.evaluate_change_risk("removed", item)
            return item

        # Process baseline endpoints absent from current active observations
        for k in sorted(missing_keys):
            b_item = baseline_map[k]
            port = int(b_item.get("port", 80))

            if current_tested_ports is not None and len(current_tested_ports) > 0:
                if port not in current_tested_ports:
                    # Priority 3: Disjoint port ranges must not produce false removals
                    untested.append({
                        "endpoint": k,
                        "observation": b_item,
                        "reason": f"Port {port} was not included in the current scan's port list.",
                    })
                else:
                    # Port was tested in current scan
                    if current_port_outcomes:
                        outcome = current_port_outcomes.get(port, "closed")
                        if outcome == "closed":
                            removed.append(_with_removed_risk(b_item))
                        elif outcome in ("timeout", "unreachable"):
                            inconclusive.append({
                                "endpoint": k,
                                "observation": b_item,
                                "reason": f"Port {port} probe timed out or was unreachable; status inconclusive.",
                            })
                        else:
                            removed.append(_with_removed_risk(b_item))
                    else:
                        # Port was in tested ports list and did not respond (connection closed)
                        removed.append(_with_removed_risk(b_item))
            else:
                # Priority 3: Never infer removal solely because an endpoint is absent;
                # mark unknown historical coverage as inconclusive.
                inconclusive.append({
                    "endpoint": k,
                    "observation": b_item,
                    "reason": "Historical scan coverage unknown; removal cannot be confirmed.",
                })

        # Process common endpoints for attribute drift
        for k in sorted(common_keys):
            b_item = baseline_map[k]
            c_item = current_map[k]

            field_changes = []

            for field, label in MONITORED_FIELDS:
                b_val = b_item.get(field)
                c_val = c_item.get(field)
                if isinstance(b_val, str):
                    b_val = b_val.strip()
                if isinstance(c_val, str):
                    c_val = c_val.strip()

                if b_val != c_val:
                    field_changes.append({
                        "field": field,
                        "label": label,
                        "old_value": b_val,
                        "new_value": c_val,
                        "category": "attribute_drift",
                    })

            # Compare security headers
            b_headers = {str(hk).lower(): str(hv) for hk, hv in (b_item.get("headers") or {}).items()}
            c_headers = {str(hk).lower(): str(hv) for hk, hv in (c_item.get("headers") or {}).items()}

            for sec_header in SECURITY_HEADERS:
                b_has = sec_header in b_headers
                c_has = sec_header in c_headers
                if b_has != c_has:
                    field_changes.append({
                        "field": f"header:{sec_header}",
                        "label": f"Security Header ({sec_header})",
                        "old_value": b_headers.get(sec_header, "[MISSING]"),
                        "new_value": c_headers.get(sec_header, "[MISSING]"),
                        "category": "security_posture",
                    })

            if field_changes:
                mod_entry = {
                    "endpoint": k,
                    "host": c_item.get("host"),
                    "port": c_item.get("port"),
                    "changes": field_changes,
                    "before": b_item,
                    "after": c_item,
                }
                mod_entry["risk"] = RiskEngine.evaluate_change_risk("modified", mod_entry)
                modified.append(mod_entry)
            else:
                unchanged_entry = dict(c_item)
                unchanged_entry["risk"] = RiskEngine.evaluate_change_risk("unchanged", unchanged_entry)
                unchanged.append(unchanged_entry)

        has_changes = bool(added or removed or modified)
        all_changes = added + modified + removed
        critical_count = sum(1 for item in all_changes if item.get("risk", {}).get("level") == "CRITICAL")
        high_count = sum(1 for item in all_changes if item.get("risk", {}).get("level") == "HIGH")
        medium_count = sum(1 for item in all_changes if item.get("risk", {}).get("level") == "MEDIUM")
        low_count = sum(1 for item in all_changes if item.get("risk", {}).get("level") == "LOW")

        return {
            "summary": {
                "total_baseline": len(baseline_obs),
                "total_current": len(current_obs),
                "added_count": len(added),
                "removed_count": len(removed),
                "modified_count": len(modified),
                "unchanged_count": len(unchanged),
                "untested_count": len(untested),
                "inconclusive_count": len(inconclusive),
                "has_changes": has_changes,
                "critical_count": critical_count,
                "high_count": high_count,
                "medium_count": medium_count,
                "low_count": low_count,
            },
            "added": added,
            "removed": removed,
            "modified": modified,
            "unchanged": unchanged,
            "untested": untested,
            "inconclusive": inconclusive,
        }

    @classmethod
    def compare_snapshots(
        cls,
        baseline_snapshot_id: int,
        current_snapshot_id: int,
        db_path: str = database.DEFAULT_DB_PATH,
    ) -> dict[str, Any]:
        """
        Retrieve observations and tested port metadata for two snapshots from the database and perform diff.
        """
        baseline_snap = database.get_snapshot_by_id(baseline_snapshot_id, db_path)
        current_snap = database.get_snapshot_by_id(current_snapshot_id, db_path)

        if not baseline_snap or not current_snap:
            raise ValueError(f"Snapshot ID {baseline_snapshot_id} or {current_snapshot_id} not found.")

        b_obs = database.get_observations_for_snapshot(baseline_snapshot_id, db_path)
        c_obs = database.get_observations_for_snapshot(current_snapshot_id, db_path)

        # Retrieve tested ports for accurate removal detection
        current_tested_ports = current_snap.get("tested_ports", [])

        diff = cls.compare_observations(
            baseline_obs=b_obs,
            current_obs=c_obs,
            current_tested_ports=current_tested_ports,
        )
        diff["baseline_snapshot"] = baseline_snap
        diff["current_snapshot"] = current_snap

        # Log audit event
        database.log_audit_event(
            action="CHANGE_ANALYSIS",
            target=f"Snap #{baseline_snapshot_id} -> Snap #{current_snapshot_id}",
            status="SUCCESS",
            details=(
                f"Diff complete. Added: {diff['summary']['added_count']}, "
                f"Removed: {diff['summary']['removed_count']}, "
                f"Modified: {diff['summary']['modified_count']}, "
                f"Untested: {diff['summary']['untested_count']}, "
                f"Inconclusive: {diff['summary']['inconclusive_count']}"
            ),
            db_path=db_path,
        )

        return diff

    @classmethod
    def compare_latest_two(
        cls,
        target_host: Optional[str] = None,
        db_path: str = database.DEFAULT_DB_PATH,
    ) -> Optional[dict[str, Any]]:
        """
        Compare the two most recent snapshots in the database.
        Returns None if fewer than 2 snapshots exist.
        """
        snapshots = database.get_snapshots(limit=10, db_path=db_path)
        if target_host:
            snapshots = [s for s in snapshots if s.get("target_host") == target_host]

        if len(snapshots) < 2:
            return None

        current_snap = snapshots[0]
        baseline_snap = snapshots[1]

        return cls.compare_snapshots(
            baseline_snapshot_id=baseline_snap["id"],
            current_snapshot_id=current_snap["id"],
            db_path=db_path,
        )

    @classmethod
    def generate_change_report(cls, diff: dict[str, Any]) -> str:
        """
        Generate a human-readable markdown summary report of the differential analysis.
        """
        summary = diff.get("summary", {})
        lines = [
            "# Threat Lens Differential Change Report",
            f"- **Status**: {'Changes Detected' if summary.get('has_changes') else 'Stable / No Changes'}",
            f"- **Risk Posture**: Critical: {summary.get('critical_count', 0)} | High: {summary.get('high_count', 0)} | Medium: {summary.get('medium_count', 0)} | Low: {summary.get('low_count', 0)}",
            f"- **Baseline Assets**: {summary.get('total_baseline', 0)}",
            f"- **Current Assets**: {summary.get('total_current', 0)}",
            f"- **Added Assets**: {summary.get('added_count', 0)}",
            f"- **Confirmed Removed Assets**: {summary.get('removed_count', 0)}",
            f"- **Modified Assets**: {summary.get('modified_count', 0)}",
            f"- **Unchanged Assets**: {summary.get('unchanged_count', 0)}",
            f"- **Untested Baseline Assets**: {summary.get('untested_count', 0)}",
            f"- **Inconclusive Observations**: {summary.get('inconclusive_count', 0)}",
            "",
        ]

        if diff.get("added"):
            lines.append("## [+] Added Endpoints (Attack Surface Expansion)")
            for item in diff["added"]:
                r = item.get("risk", {})
                r_label = f"[{r.get('level', 'INFO')}]"
                reasons_str = "; ".join(r.get("reasons", []))
                lines.append(
                    f"- `{item['host']}:{item['port']}` | Risk: **{r_label}** | Service: {item.get('service')} | Status: {item.get('status_code')} | Banner: {item.get('server_header') or 'N/A'}"
                )
                if reasons_str:
                    lines.append(f"  * Evidence: {reasons_str}")
            lines.append("")

        if diff.get("removed"):
            lines.append("## [-] Confirmed Removed Endpoints (Decommissioned)")
            for item in diff["removed"]:
                r = item.get("risk", {})
                r_label = f"[{r.get('level', 'INFO')}]"
                lines.append(
                    f"- `{item['host']}:{item['port']}` | Risk: **{r_label}** | Previous Service: {item.get('service')} | Previous Status: {item.get('status_code')}"
                )
            lines.append("")

        if diff.get("modified"):
            lines.append("## [~] Modified Endpoints (Attribute Drift)")
            for mod in diff["modified"]:
                r = mod.get("risk", {})
                r_label = f"[{r.get('level', 'INFO')}]"
                reasons_str = "; ".join(r.get("reasons", []))
                lines.append(f"### Endpoint `{mod['endpoint']}` | Risk: **{r_label}**")
                if reasons_str:
                    lines.append(f"  * Evidence: {reasons_str}")
                for ch in mod["changes"]:
                    lines.append(
                        f"  - **{ch['label']}**: `{ch['old_value']}` -> `{ch['new_value']}` ({ch['category']})"
                    )
            lines.append("")

        if diff.get("untested"):
            lines.append("## [?] Untested Baseline Endpoints (Not in Current Scan Scope)")
            for u in diff["untested"]:
                lines.append(f"- `{u['endpoint']}`: {u.get('reason')}")
            lines.append("")

        if diff.get("inconclusive"):
            lines.append("## [!] Inconclusive Observations (Timeout or Unknown Coverage)")
            for inc in diff["inconclusive"]:
                lines.append(f"- `{inc['endpoint']}`: {inc.get('reason')}")
            lines.append("")

        if not summary.get("has_changes") and not diff.get("untested") and not diff.get("inconclusive"):
            lines.append("No changes detected between the evaluated snapshots. The attack surface remains stable.")

        return "\n".join(lines)
