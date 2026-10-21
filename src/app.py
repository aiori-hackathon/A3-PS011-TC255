"""
Threat Lens - Web Dashboard
AIORI Hackathon 3 | Problem Statement PS-011 | Team: A3-PS011-TC255
Authorised Attack-Surface Inventory and Continuous Change-Monitoring Platform

Discover responsibly. Track changes. Keep evidence.
"""

import http.server
import json
import socketserver
import threading
import time
from typing import Optional

import pandas as pd
import streamlit as st

from scope_manager import ScopeManager, ScopeViolationError, InvalidTargetError
from asset_discovery import AssetDiscovery, DEFAULT_LOCAL_PORTS
from change_engine import ChangeEngine
from risk_engine import RiskEngine
import database


# Page setup
st.set_page_config(
    page_title="Threat Lens - Attack Surface & Change Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling
st.markdown("""
<style>
    .threat-header {
        background: linear-gradient(135deg, #0d1b2a 0%, #1b263b 50%, #415a77 100%);
        padding: 24px 28px;
        border-radius: 12px;
        color: #ffffff;
        margin-bottom: 24px;
        border: 1px solid #778da9;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    }
    .threat-header h1 {
        margin: 0;
        font-size: 2.2rem;
        font-weight: 700;
        color: #e0e1dd;
    }
    .threat-header p {
        margin: 6px 0 0 0;
        color: #a9bcd0;
        font-size: 1.05rem;
    }
    .badge-scope {
        display: inline-block;
        background-color: #198754;
        color: white;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.85rem;
        font-weight: 600;
        margin-top: 10px;
    }
    .badge-aiori {
        display: inline-block;
        background-color: #0d6efd;
        color: white;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.85rem;
        font-weight: 600;
        margin-left: 8px;
    }
    .metric-card {
        background-color: var(--secondary-background-color, #f8f9fa);
        border: 1px solid rgba(128, 128, 128, 0.25);
        border-radius: 10px;
        padding: 16px;
        text-align: center;
        box-shadow: 0 2px 4px rgba(0,0,0,0.04);
        color: var(--text-color, #212529);
    }
    .metric-value {
        font-size: 1.8rem;
        font-weight: 700;
        margin: 4px 0;
        color: var(--text-color, #212529);
    }
    .metric-label {
        font-size: 0.85rem;
        text-transform: uppercase;
        color: var(--text-color, #6c757d);
        opacity: 0.85;
        font-weight: 600;
    }
    .diff-added {
        color: #198754;
        font-weight: bold;
    }
    .diff-removed {
        color: #dc3545;
        font-weight: bold;
    }
    .diff-modified {
        color: #fd7e14;
        font-weight: bold;
    }
    .diff-unchanged {
        color: var(--text-color, #6c757d);
        opacity: 0.75;
    }
    .risk-badge-critical {
        display: inline-block;
        background-color: #dc3545;
        color: white;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.8rem;
    }
    .risk-badge-high {
        display: inline-block;
        background-color: #fd7e14;
        color: white;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.8rem;
    }
    .risk-badge-medium {
        display: inline-block;
        background-color: #ffc107;
        color: #212529;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.8rem;
    }
    .risk-badge-low {
        display: inline-block;
        background-color: #0dcaf0;
        color: #212529;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.8rem;
    }
</style>
""", unsafe_allow_html=True)


# Initialize Database
database.init_db()


# Session State Management for Mock Lab Server
if "lab_server_running" not in st.session_state:
    st.session_state.lab_server_running = False
    st.session_state.lab_server_port = 5555
    st.session_state.lab_status_code = 200
    st.session_state.lab_server_banner = "ThreatLens-MockService/1.0"
    st.session_state.lab_server_title = "Threat Lens Test Environment"
    st.session_state.lab_server_obj = None


class LabHTTPHandler(http.server.BaseHTTPRequestHandler):
    server_version = ""
    sys_version = ""

    def do_GET(self):
        code = getattr(st.session_state, "lab_status_code", 200)
        banner = getattr(st.session_state, "lab_server_banner", "ThreatLens-Lab/1.0")
        title = getattr(st.session_state, "lab_server_title", "Lab Endpoint")

        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", banner)
        self.send_header("X-ThreatLens-Lab", "Active")
        self.end_headers()
        html = f"<html><head><title>{title}</title></head><body><h1>Lab Active - Status {code}</h1></body></html>"
        self.wfile.write(html.encode("utf-8"))

    def log_message(self, format, *args):
        pass


def toggle_lab_server():
    if not st.session_state.lab_server_running:
        try:
            port = int(st.session_state.lab_server_port)
            server = socketserver.TCPServer(("127.0.0.1", port), LabHTTPHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            st.session_state.lab_server_obj = server
            st.session_state.lab_server_running = True
            st.success(f"Lab mock service started on 127.0.0.1:{port}")
        except Exception as e:
            st.error(f"Failed to start lab server on port {st.session_state.lab_server_port}: {e}")
    else:
        if st.session_state.lab_server_obj:
            try:
                st.session_state.lab_server_obj.shutdown()
                st.session_state.lab_server_obj.server_close()
            except Exception:
                pass
        st.session_state.lab_server_running = False
        st.session_state.lab_server_obj = None
        st.info("Lab mock service stopped.")


# Header Banner
st.markdown("""
<div class="threat-header">
    <h1>🛡️ Threat Lens</h1>
    <p>Authorised Attack-Surface Inventory & Continuous Change Monitoring</p>
    <div>
        <span class="badge-scope">🔒 Strict Scope: 127.0.0.1 & localhost</span>
        <span class="badge-aiori">AIORI Hackathon 3 | PS-011 | Team: A3-PS011-TC255</span>
    </div>
</div>
""", unsafe_allow_html=True)


# Sidebar Configuration
st.sidebar.header("🎯 Discovery Target Configuration")
target_input = st.sidebar.text_input(
    "Target Host / URL",
    value="127.0.0.1",
    help="Strict Scope MVP: Only '127.0.0.1' and 'localhost' are authorized.",
)

# Scope quick validation in sidebar
is_target_valid = ScopeManager.is_in_scope(target_input)
if is_target_valid:
    st.sidebar.success(f"Target '{target_input}' is AUTHORIZED.")
else:
    st.sidebar.error(f"Target '{target_input}' is OUT OF SCOPE. Network requests are prohibited.")

port_selection_mode = st.sidebar.radio(
    "Port Selection",
    ["Standard Web Ports", "Custom Port List"],
    index=0,
)

if port_selection_mode == "Standard Web Ports":
    selected_ports = DEFAULT_LOCAL_PORTS
    st.sidebar.caption(f"Scanning {len(selected_ports)} default local ports: `{','.join(map(str, selected_ports))}`")
else:
    custom_ports_str = st.sidebar.text_input("Comma-separated ports", "80, 3000, 5000, 5555, 8000, 8080, 8501")
    try:
        selected_ports = [int(p.strip()) for p in custom_ports_str.split(",") if p.strip().isdigit()]
    except Exception:
        selected_ports = DEFAULT_LOCAL_PORTS
    st.sidebar.caption(f"Selected ports: {selected_ports}")

scan_notes = st.sidebar.text_input("Snapshot Note / Tag", value="Scheduled Surface Check")

run_scan_btn = st.sidebar.button("🚀 Run Authorised Scan", type="primary", use_container_width=True)

st.sidebar.markdown("---")
st.sidebar.caption("**Team Name:** Threat Lens  \n**Team Code:** A3-PS011-TC255  \n**Philosophy:** *Discover responsibly. Track changes. Keep evidence.*")


# Primary Tabs
tab_scanner, tab_diff, tab_history, tab_scope, tab_lab = st.tabs([
    "🔎 Active Surface Scanner",
    "🔄 Change Detection & Diff",
    "📜 Snapshot History",
    "🛡️ Scope Guardian & Audit Log",
    "🧪 Local Testbed Lab",
])


# ==============================================================================
# TAB 1: ACTIVE SURFACE SCANNER
# ==============================================================================
with tab_scanner:
    st.subheader("Asset Discovery & Local Inventory")
    st.write(
        "Safely probe authorized local endpoints to discover active HTTP services, "
        "response status codes, banners, and security metadata without exploitation."
    )

    if run_scan_btn:
        discovery = AssetDiscovery()
        try:
            with st.spinner(f"Validating scope and safely scanning {target_input}..."):
                observations, duration = discovery.scan(
                    target=target_input,
                    ports=selected_ports,
                    timeout=1.0,
                )

                # Persist snapshot with tested ports metadata
                snapshot_id = database.save_snapshot(
                    target_host=target_input,
                    observations=observations,
                    scan_duration_sec=duration,
                    notes=scan_notes,
                    tested_ports=selected_ports,
                )

            st.success(f"Scan complete in {duration:.2f} seconds! Snapshot #{snapshot_id} saved successfully.")

            # Metrics row
            m1, m2, m3 = st.columns(3)
            with m1:
                st.metric(label="Target Scanned", value=target_input, border=True)
            with m2:
                st.metric(label="Active Services Discovered", value=len(observations), border=True)
            with m3:
                st.metric(label="Scan Duration", value=f"{duration:.2f}s", border=True)

            st.markdown("<br>", unsafe_allow_html=True)

            if observations:
                st.markdown("### Discovered Endpoints")
                df_data = []
                for obs in observations:
                    risk_info = RiskEngine.evaluate_asset_risk(obs)
                    df_data.append({
                        "Endpoint": f"{obs['host']}:{obs['port']}",
                        "Port": obs["port"],
                        "Risk Rating": risk_info["level"],
                        "Risk Evidence": "; ".join(risk_info["reasons"]),
                        "Protocol": obs.get("protocol", "http").upper(),
                        "Service": obs.get("service", "http"),
                        "Status Code": obs.get("status_code"),
                        "Server Header": obs.get("server_header") or "None specified",
                        "Title": obs.get("title") or "None",
                        "Response Time (ms)": obs.get("response_time_ms", 0.0),
                    })
                df = pd.DataFrame(df_data)
                st.dataframe(df, use_container_width=True)

                # Detailed Inspection
                with st.expander("🔍 Deep Endpoint Observation & Response Headers"):
                    for obs in observations:
                        st.markdown(f"#### Endpoint: `{obs['host']}:{obs['port']}`")
                        risk_info = RiskEngine.evaluate_asset_risk(obs)
                        col_a, col_b = st.columns(2)
                        with col_a:
                            st.write(f"**Risk Rating:** `{risk_info['level']}`")
                            st.write(f"**Risk Evidence:** {'; '.join(risk_info['reasons'])}")
                            st.write(f"**Status Code:** `{obs.get('status_code')}`")
                            st.write(f"**Server Banner:** `{obs.get('server_header') or 'N/A'}`")
                            st.write(f"**Content-Type:** `{obs.get('content_type') or 'N/A'}`")
                            st.write(f"**Page Title:** `{obs.get('title') or 'N/A'}`")
                        with col_b:
                            st.write(f"**Observed Timestamp:** `{obs.get('timestamp')}`")
                            st.write(f"**Latency:** `{obs.get('response_time_ms')} ms`")
                            st.write("**Collected Headers:**")
                            st.json(obs.get("headers", {}))
                        st.markdown("---")
            else:
                st.info(f"No active HTTP services responded on the {len(selected_ports)} scanned ports.")

        except ScopeViolationError as exc:
            st.error(f"⛔ Scope Violation: {exc}")
        except InvalidTargetError as exc:
            st.error(f"⚠️ Invalid Target: {exc}")
        except Exception as exc:
            st.error(f"An unexpected scan error occurred: {exc}")

    else:
        # Display latest snapshot if available
        latest_snap = database.get_latest_snapshot()
        if latest_snap:
            st.info(
                f"Showing previous Snapshot #{latest_snap['id']} taken at {latest_snap['timestamp']} "
                f"({latest_snap['total_assets']} active assets). Click 'Run Authorised Scan' in sidebar to take a new snapshot."
            )
            latest_obs = database.get_observations_for_snapshot(latest_snap["id"])
            if latest_obs:
                df_data = []
                for obs in latest_obs:
                    risk_info = RiskEngine.evaluate_asset_risk(obs)
                    df_data.append({
                        "Endpoint": f"{obs['host']}:{obs['port']}",
                        "Port": obs["port"],
                        "Risk Rating": risk_info["level"],
                        "Risk Evidence": "; ".join(risk_info["reasons"]),
                        "Protocol": obs.get("protocol", "http").upper(),
                        "Service": obs.get("service", "http"),
                        "Status Code": obs.get("status_code"),
                        "Server Header": obs.get("server_header") or "None specified",
                        "Title": obs.get("title") or "None",
                        "Response Time (ms)": obs.get("response_time_ms", 0.0),
                    })
                st.dataframe(pd.DataFrame(df_data), use_container_width=True)
        else:
            st.info("No snapshots recorded yet. Configure your target on the sidebar and click 'Run Authorised Scan' to create your first baseline snapshot.")


# ==============================================================================
# TAB 2: CHANGE DETECTION & DIFFERENTIAL ANALYSIS
# ==============================================================================
with tab_diff:
    st.subheader("Continuous Change Monitoring Engine")
    st.write(
        "Compare successive attack-surface snapshots to identify newly added services, "
        "decommissioned endpoints, and attribute drift (e.g. status code changes, server updates)."
    )

    all_snapshots = database.get_snapshots(limit=50)

    if len(all_snapshots) < 2:
        st.warning(
            f"Differential analysis requires at least 2 snapshots. Currently {len(all_snapshots)} snapshot(s) exist. "
            "Run another scan from Tab 1 or start a simulated service in the 'Local Testbed Lab' tab to record successive snapshots."
        )
    else:
        snapshot_options = {
            f"Snapshot #{s['id']} | {s['timestamp'][:19]} | Target: {s['target_host']} | Assets: {s['total_assets']}": s["id"]
            for s in all_snapshots
        }

        col1, col2 = st.columns(2)
        with col1:
            baseline_label = st.selectbox(
                "Baseline Snapshot (Older / Reference)",
                options=list(snapshot_options.keys()),
                index=min(1, len(snapshot_options) - 1),
            )
            baseline_id = snapshot_options[baseline_label]

        with col2:
            compare_label = st.selectbox(
                "Compare Snapshot (Newer / Current)",
                options=list(snapshot_options.keys()),
                index=0,
            )
            compare_id = snapshot_options[compare_label]

        if baseline_id == compare_id:
            st.info("You have selected the same snapshot for baseline and comparison. Differentials will show zero changes.")

        try:
            diff_result = ChangeEngine.compare_snapshots(baseline_id, compare_id)
            summary = diff_result["summary"]

            # Differential Metric Cards
            c1, c2, c3, c4, c5, c6 = st.columns(6)
            with c1:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-label">Added</div>
                    <div class="metric-value diff-added">+{summary['added_count']}</div>
                </div>
                """, unsafe_allow_html=True)
            with c2:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-label">Confirmed Removed</div>
                    <div class="metric-value diff-removed">-{summary['removed_count']}</div>
                </div>
                """, unsafe_allow_html=True)
            with c3:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-label">Modified</div>
                    <div class="metric-value diff-modified">~{summary['modified_count']}</div>
                </div>
                """, unsafe_allow_html=True)
            with c4:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-label">Unchanged</div>
                    <div class="metric-value diff-unchanged">{summary['unchanged_count']}</div>
                </div>
                """, unsafe_allow_html=True)
            with c5:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-label">Untested Scope</div>
                    <div class="metric-value" style="color: #6f42c1;">{summary.get('untested_count', 0)}</div>
                </div>
                """, unsafe_allow_html=True)
            with c6:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-label">Inconclusive</div>
                    <div class="metric-value" style="color: #d63384;">{summary.get('inconclusive_count', 0)}</div>
                </div>
                """, unsafe_allow_html=True)

            # Risk Drift Metrics
            st.markdown("<br>", unsafe_allow_html=True)
            rc1, rc2, rc3, rc4 = st.columns(4)
            with rc1:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-label">Critical Risk Drift</div>
                    <div class="metric-value" style="color: #dc3545;">{summary.get('critical_count', 0)}</div>
                </div>
                """, unsafe_allow_html=True)
            with rc2:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-label">High Risk Drift</div>
                    <div class="metric-value" style="color: #fd7e14;">{summary.get('high_count', 0)}</div>
                </div>
                """, unsafe_allow_html=True)
            with rc3:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-label">Medium Risk Drift</div>
                    <div class="metric-value" style="color: #ffc107;">{summary.get('medium_count', 0)}</div>
                </div>
                """, unsafe_allow_html=True)
            with rc4:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="metric-label">Low Risk Drift</div>
                    <div class="metric-value" style="color: #0dcaf0;">{summary.get('low_count', 0)}</div>
                </div>
                """, unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)

            if not summary["has_changes"]:
                st.success("✅ **Attack Surface is Stable**: No additions, removals, or attribute changes were detected between these snapshots.")
            else:
                if summary.get("critical_count", 0) > 0:
                    st.error(f"🚨 **CRITICAL RISK DRIFT**: {summary['critical_count']} critical drift event(s) identified. Immediate inspection required.")
                elif summary.get("high_count", 0) > 0:
                    st.warning(f"⚠️ **HIGH RISK DRIFT**: {summary['high_count']} high-risk drift event(s) identified.")
                elif summary.get("medium_count", 0) > 0:
                    st.info(f"ℹ️ **MEDIUM RISK DRIFT**: {summary['medium_count']} medium-risk drift event(s) identified.")

                # 1. Added
                if diff_result["added"]:
                    st.markdown("#### 🟢 [+] Newly Added Endpoints (Attack Surface Expansion)")
                    added_df = pd.DataFrame([{
                        "Endpoint": f"{a['host']}:{a['port']}",
                        "Port": a["port"],
                        "Risk Rating": a.get("risk", {}).get("level", "LOW"),
                        "Risk Evidence": "; ".join(a.get("risk", {}).get("reasons", [])),
                        "Service": a.get("service"),
                        "Status Code": a.get("status_code"),
                        "Server": a.get("server_header") or "N/A",
                        "Title": a.get("title") or "N/A",
                    } for a in diff_result["added"]])
                    st.dataframe(added_df, use_container_width=True)

                # 2. Removed
                if diff_result["removed"]:
                    st.markdown("#### 🔴 [-] Removed Endpoints (Decommissioned or Inaccessible)")
                    removed_df = pd.DataFrame([{
                        "Endpoint": f"{r['host']}:{r['port']}",
                        "Port": r["port"],
                        "Risk Rating": r.get("risk", {}).get("level", "LOW"),
                        "Risk Evidence": "; ".join(r.get("risk", {}).get("reasons", [])),
                        "Previous Service": r.get("service"),
                        "Previous Status": r.get("status_code"),
                        "Previous Server": r.get("server_header") or "N/A",
                    } for r in diff_result["removed"]])
                    st.dataframe(removed_df, use_container_width=True)

                # 3. Modified
                if diff_result["modified"]:
                    st.markdown("#### 🟡 [~] Modified Endpoints (Configuration & Attribute Drift)")
                    for mod in diff_result["modified"]:
                        r_level = mod.get("risk", {}).get("level", "LOW")
                        r_reasons = mod.get("risk", {}).get("reasons", [])
                        st.markdown(f"**Endpoint:** `{mod['endpoint']}` — **Risk:** `{r_level}`")
                        if r_reasons:
                            st.caption(f"**Evidence:** {'; '.join(r_reasons)}")
                        changes_rows = []
                        for ch in mod["changes"]:
                            changes_rows.append({
                                "Field Changed": ch["label"],
                                "Old Value (Baseline)": str(ch["old_value"]),
                                "New Value (Current)": str(ch["new_value"]),
                                "Category": ch["category"].replace("_", " ").title(),
                            })
                        st.table(pd.DataFrame(changes_rows))

            # Markdown report export
            report_text = ChangeEngine.generate_change_report(diff_result)
            with st.expander("📋 View & Export Full Markdown Audit Report"):
                st.code(report_text, language="markdown")
                st.download_button(
                    "📥 Download Markdown Report",
                    data=report_text,
                    file_name=f"threat_lens_diff_{baseline_id}_vs_{compare_id}.md",
                    mime="text/markdown",
                )

        except Exception as exc:
            st.error(f"Error computing diff: {exc}")


# ==============================================================================
# TAB 3: SNAPSHOT HISTORY
# ==============================================================================
with tab_history:
    st.subheader("Snapshot Repository")
    st.write("All historical scans are permanently timestamped and stored in SQLite for evidence-backed audits.")

    snapshots = database.get_snapshots(limit=100)
    if snapshots:
        snap_df = pd.DataFrame(snapshots)
        snap_df.rename(columns={
            "id": "Snapshot ID",
            "timestamp": "Timestamp (UTC)",
            "target_host": "Target Host",
            "total_assets": "Assets Found",
            "scan_duration_sec": "Duration (s)",
            "notes": "Notes / Tag",
        }, inplace=True)
        st.dataframe(snap_df, use_container_width=True)

        st.markdown("### Snapshot Inspector")
        selected_snap_id = st.selectbox(
            "Select Snapshot to Inspect",
            options=[s["id"] for s in snapshots],
            format_func=lambda sid: f"Snapshot #{sid} ({next(s['timestamp'] for s in snapshots if s['id'] == sid)})",
        )

        if selected_snap_id:
            obs = database.get_observations_for_snapshot(selected_snap_id)
            if obs:
                st.write(f"**Observations for Snapshot #{selected_snap_id}:**")
                obs_df = pd.DataFrame([{
                    "Host": o["host"],
                    "Port": o["port"],
                    "Risk Rating": RiskEngine.evaluate_asset_risk(o)["level"],
                    "Risk Evidence": "; ".join(RiskEngine.evaluate_asset_risk(o)["reasons"]),
                    "Protocol": o["protocol"],
                    "Service": o["service"],
                    "Status": o["status_code"],
                    "Server": o["server_header"],
                    "Title": o["title"],
                    "Latency (ms)": o["response_time_ms"],
                } for o in obs])
                st.dataframe(obs_df, use_container_width=True)
            else:
                st.info("No active endpoints were recorded in this snapshot.")

            # Management action
            if st.button("🗑️ Delete Selected Snapshot", type="secondary"):
                database.delete_snapshot(selected_snap_id)
                st.success(f"Snapshot #{selected_snap_id} deleted.")
                st.rerun()

    else:
        st.info("No snapshots recorded yet.")


# ==============================================================================
# TAB 4: SCOPE GUARDIAN & AUDIT LOG
# ==============================================================================
with tab_scope:
    st.subheader("Scope Policy Enforcement & Audit Trail")
    st.write(
        "Ethical discovery requires strict authorization boundaries. Threat Lens enforces "
        "pre-flight validation before any network socket is opened."
    )

    # Scope Policy Overview
    scope_meta = ScopeManager.describe_scope_rules()
    col_p1, col_p2 = st.columns(2)
    with col_p1:
        st.markdown(f"""
        **Policy Name:** `{scope_meta['policy_name']}`
        **Enforcement Level:** `{scope_meta['enforcement_level']}`
        **Permitted Targets:** `{', '.join(scope_meta['allowed_hosts'])}`
        **External Targets Allowed:** `{"Yes" if scope_meta['allow_public_targets'] else "NO (REJECTED)"}`
        """)
    with col_p2:
        st.info(scope_meta["description"])

    st.markdown("---")
    st.markdown("### Interactive Pre-Flight Scope Tester")
    st.write("Test whether a given host, domain, or URL is accepted by the Scope Guardian.")

    test_input = st.text_input("Enter test target", value="google.com", placeholder="e.g. google.com, 192.168.1.1, localhost:8000")
    if st.button("Verify Target Scope"):
        try:
            host, port = ScopeManager.validate_target(test_input)
            database.log_audit_event(
                action="UI_SCOPE_CHECK",
                target=test_input,
                status="ALLOWED",
                details=f"Interactive pre-flight check allowed host '{host}' (port: {port})",
            )
            st.success(f"✅ **AUTHORIZED**: Host `{host}` (port: `{port}`) is within the authorized scope. Network requests are permitted.")
        except ScopeViolationError as exc:
            database.log_audit_event(
                action="UI_SCOPE_CHECK",
                target=test_input,
                status="REJECTED",
                details=f"Interactive pre-flight check rejected: {str(exc)[:150]}",
            )
            st.error(f"⛔ **REJECTED**: {exc}")
        except InvalidTargetError as exc:
            database.log_audit_event(
                action="UI_SCOPE_CHECK",
                target=test_input,
                status="INVALID",
                details=f"Interactive pre-flight check invalid target: {str(exc)[:150]}",
            )
            st.warning(f"⚠️ **INVALID TARGET**: {exc}")

    st.markdown("---")
    st.markdown("### Compliance Audit Trail")
    st.write("Every authorization check, scan execution, and change diff is recorded for evidence.")

    audit_logs = database.get_audit_logs(limit=50)
    if audit_logs:
        audit_df = pd.DataFrame(audit_logs)
        audit_df.rename(columns={
            "id": "Log ID",
            "timestamp": "Timestamp",
            "action": "Action",
            "target": "Target",
            "status": "Verdict / Status",
            "details": "Details",
        }, inplace=True)
        st.dataframe(audit_df, use_container_width=True)
    else:
        st.info("No audit logs recorded yet.")


# ==============================================================================
# TAB 5: LOCAL TESTBED LAB (INTERACTIVE DEMO)
# ==============================================================================
with tab_lab:
    st.subheader("Interactive Local Testbed & Change Simulator")
    st.write(
        "Demonstrate Threat Lens live! Start a mock local HTTP service on port `5555`, take Snapshot 1, "
        "modify its configuration or status code, take Snapshot 2, and watch Threat Lens detect the change instantly."
    )

    col_l1, col_l2 = st.columns([1, 1])

    with col_l1:
        st.markdown("#### Mock Service Controls")
        st.number_input(
            "Lab Port",
            min_value=1024,
            max_value=65535,
            value=st.session_state.lab_server_port,
            key="lab_port_input",
            on_change=lambda: setattr(st.session_state, "lab_server_port", st.session_state.lab_port_input),
        )

        status_label = "🟢 RUNNING" if st.session_state.lab_server_running else "⚪ STOPPED"
        st.write(f"**Current Status:** {status_label}")

        btn_label = "Stop Mock Service" if st.session_state.lab_server_running else "Start Mock Service"
        btn_type = "secondary" if st.session_state.lab_server_running else "primary"
        if st.button(btn_label, type=btn_type):
            toggle_lab_server()
            st.rerun()

    with col_l2:
        st.markdown("#### Live Service Configuration")
        new_status = st.selectbox(
            "HTTP Response Status",
            [200, 403, 404, 500, 503],
            index=[200, 403, 404, 500, 503].index(st.session_state.lab_status_code),
            key="status_select",
        )
        new_banner = st.selectbox(
            "Server Banner",
            [
                "ThreatLens-MockService/1.0",
                "Apache/2.4.52 (Ubuntu)",
                "nginx/1.24.0",
                "uvicorn/0.30.0",
                "Python-BaseHTTP/3.14",
            ],
            index=0 if st.session_state.lab_server_banner not in [
                "ThreatLens-MockService/1.0",
                "Apache/2.4.52 (Ubuntu)",
                "nginx/1.24.0",
                "uvicorn/0.30.0",
                "Python-BaseHTTP/3.14",
            ] else [
                "ThreatLens-MockService/1.0",
                "Apache/2.4.52 (Ubuntu)",
                "nginx/1.24.0",
                "uvicorn/0.30.0",
                "Python-BaseHTTP/3.14",
            ].index(st.session_state.lab_server_banner),
            key="banner_select",
        )
        new_title = st.text_input("Page Title", value=st.session_state.lab_server_title, key="title_input")

        if st.button("Apply Service Updates"):
            st.session_state.lab_status_code = new_status
            st.session_state.lab_server_banner = new_banner
            st.session_state.lab_server_title = new_title
            st.success("Service parameters updated! Future scans will observe these new attributes.")

    st.markdown("---")
    st.markdown("""
    #### 💡 Hackathon Evaluation Walkthrough:
    1. **Step 1 (Baseline)**: Click **Start Mock Service** above on port `5555`. Go to the sidebar, set port to `Custom: 5555` (or add 5555), and click **Run Authorised Scan**.
    2. **Step 2 (Simulate Change)**: Change the **HTTP Response Status** to `503` or **Server Banner** to `nginx/1.24.0`, click **Apply Service Updates**, and click **Run Authorised Scan** again.
    3. **Step 3 (Observe Diff)**: Go to **Change Detection & Diff** tab to see Threat Lens immediately detect and highlight the modified attribute drift!
    4. **Step 4 (Test Removal)**: Click **Stop Mock Service**, scan again, and see Threat Lens detect the endpoint as **Removed**.
    """)
