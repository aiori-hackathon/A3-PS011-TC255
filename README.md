# AIORI-3-HACKATHON-PROJECTS
This repository will contain the code and resources for the AIORI-3 hackathon that will be developed during the AIORI-3

## Team Introduction Video

Watch our team introduction for AIORI Hackathon 3, Problem Statement PS-011.

**Team Name:** Threat Lens  
**Team Code:** A3-PS011-TC255

**Team Members:**
- Sabari Moulish S
- Sunil Ram T

**Video Link:** [Watch on YouTube](https://youtu.be/b5v_1W8kQO8)

Our proposed solution focuses on authorised attack-surface inventory, continuous change monitoring, and evidence-backed security reviews.

*Discover responsibly. Track changes. Keep evidence.*

---

# Threat Lens - MVP Implementation (PS-011)

**Threat Lens** is an authorized attack-surface inventory and change-monitoring platform built for **AIORI Hackathon 3 (Problem Statement PS-011)**.

It provides defensive and authorized security engineers with real-time visibility into active services, tracks state drift across successive scans, and maintains an unalterable, evidence-backed audit trail in SQLite.

---

## 🎯 Key Capabilities & Architecture

| Component | File | Purpose |
| :--- | :--- | :--- |
| **Scope Guardian** | `scope_manager.py` | Strict pre-flight boundary. Strictly allows **only `127.0.0.1` and `localhost`**. Unconditionally rejects external targets before any network socket is opened. |
| **Safe Discovery Engine** | `asset_discovery.py` | Performs non-destructive, non-intrusive observation of local HTTP services. Collects status codes, response headers, titles, and latency. Handles connection errors and closed ports gracefully. |
| **Persistence Layer** | `database.py` | Stores timestamped snapshots, endpoint observations, and compliance audit logs in SQLite (`threat_lens.db`). |
| **Differential Engine** | `change_engine.py` | Compares successive snapshots to classify changes into **Added (+)**, **Removed (-)**, **Modified (~)**, and **Unchanged (=)** assets. |
| **Web Dashboard** | `app.py` | Intuitive Streamlit GUI featuring live scanner controls, visual diff cards, audit trail viewer, and an interactive local testbed lab. |
| **Automated Tests** | `tests/` | 23 comprehensive unit and integration tests covering scope enforcement, persistence, differential logic, safe probing, and end-to-end workflows. |

---

## 🛡️ Ethical Boundaries & Security Rules

1. **Pre-Flight Scope Enforcement**: No network packets or HTTP connections are sent to any host outside `127.0.0.1` and `localhost`. External domains (e.g., `google.com`), LAN IPs (e.g., `192.168.1.1`), and wildcard IPs (e.g., `0.0.0.0`) are blocked immediately.
2. **Zero Exploitation**: Threat Lens performs strictly passive and observational HTTP requests (`GET`/`HEAD`) to discover active services and headers. No credentials, payloads, fuzzing, or destructive actions are used.
3. **Audit Trail**: Every scope check, scan invocation, and snapshot comparison is recorded with timestamps for evidence-backed audits.

---

## 🚀 Quickstart & Setup Instructions

### Prerequisites
- Python 3.10+ (tested on Python 3.14 on Windows)
- Git

### 1. Clone & Navigate to Repository
```bash
git clone https://github.com/sabari-moulish/A3-PS011-TC255.git
cd A3-PS011-TC255
```

### 2. Install Dependencies
Install all required packages from `requirements.txt`:
```bash
pip install -r requirements.txt
```

*(Key libraries: `streamlit`, `requests`, `pandas`, `pytest`)*

---

## 🖥️ Running the Streamlit Dashboard

Launch the web interface from the project root:
```bash
python -m streamlit run app.py
```

Once started, open your web browser at:
```
http://localhost:8501
```

### Dashboard Features:
1. **Active Surface Scanner**: Configure target (`127.0.0.1` or `localhost`), select ports (defaults to `80, 3000, 5000, 8000, 8080, 8501, 8888, 9000`), run scans, and view discovered services and response headers.
2. **Change Detection & Diff**: Select any two historical snapshots to visualize added endpoints (green), decommissioned endpoints (red), and attribute drifts like status code changes or server updates (yellow).
3. **Snapshot History**: Review all timestamped scans stored in SQLite.
4. **Scope Guardian & Audit Log**: Test any host with the interactive Pre-Flight Scope Tester and view audit trail logs.
5. **Local Testbed Lab**: Spin up a mock local HTTP service on port `5555`, toggle status codes and server banners in real-time, and observe Threat Lens detect changes live!

---

## 🧪 Running Automated Tests

Run the full automated pytest suite:
```bash
python -m pytest -v
```

All 32 tests cover:
- **`test_scope_manager.py`**: Validates loopback allowance, external target rejection, LAN rejection, subdomain spoofing attempts, and URL parsing.
- **`test_database.py`**: Verifies SQLite schema creation, snapshot persistence, observation serialization, audit logging, and cascade deletes.
- **`test_change_engine.py`**: Verifies accurate detection of added endpoints, removed endpoints, modified status codes/banners, security header drifts, and markdown report generation.
- **`test_asset_discovery.py`**: Verifies pre-flight scope blocking before network activity, safe HTTP title and header parsing, and graceful handling of closed ports.
- **`test_end_to_end.py`**: Verifies full multi-step lifecycle: Baseline scan -> Service update -> Secondary scan -> Differential change detection.
- **`test_regression.py`**: Security & reliability regressions: out-of-scope redirect prevention, low-level helper enforcement, disjoint port untested classification, timeout inconclusive handling, sensitive header redaction, and audit logging for failed scans/UI checks.

---

## 🔬 Demonstration Guide (Simulating Changes Locally)

You can demonstrate Threat Lens's change-monitoring capability directly using the built-in **Local Testbed Lab** (Tab 5 in the dashboard):

1. **Step 1 - Create Baseline**:
   - Go to **Local Testbed Lab** tab and click **Start Mock Service** on port `5555`.
   - Go to sidebar, select **Custom Port List**, and ensure `5555` is included.
   - Click **🚀 Run Authorised Scan**. Threat Lens saves **Snapshot 1** with port `5555` running at status `200` with banner `ThreatLens-MockService/1.0`.
2. **Step 2 - Simulate Attribute Drift (Modified Asset)**:
   - In the **Local Testbed Lab**, change **HTTP Response Status** to `503` and **Server Banner** to `nginx/1.24.0`.
   - Click **Apply Service Updates**, then click **🚀 Run Authorised Scan**. Threat Lens saves **Snapshot 2**.
3. **Step 3 - View Differential**:
   - Switch to the **Change Detection & Diff** tab.
   - Select Snapshot 1 as Baseline and Snapshot 2 as Compare.
   - Threat Lens flags endpoint `127.0.0.1:5555` under **🟡 Modified Endpoints**, highlighting the status code shift (`200` -> `503`) and banner shift (`ThreatLens-MockService/1.0` -> `nginx/1.24.0`).
4. **Step 4 - Simulate Service Decommission (Removed Asset)**:
   - In the **Local Testbed Lab**, click **Stop Mock Service**.
   - Click **🚀 Run Authorised Scan** to take **Snapshot 3**.
   - Compare Snapshot 2 and Snapshot 3 in the diff tab to see endpoint `127.0.0.1:5555` clearly marked as **🔴 Removed**.

---

## 📂 Project Structure

```
A3-PS011-TC255/
├── app.py                                  # Streamlit web application
├── scope_manager.py                        # Strict scope authorization manager
├── asset_discovery.py                      # Safe HTTP discovery engine
├── change_engine.py                        # Differential snapshot comparison engine
├── database.py                             # SQLite persistence layer
├── requirements.txt                        # Project dependencies
├── Threat_Lens_AIORI3_PS011_Presentation.pdf # Hackathon presentation (Preserved)
├── Proposed-structure-hackathon.pdf        # Structure guidelines (Preserved)
├── README.md                               # Project documentation & team info
├── src/                                    # Modular source package
│   ├── __init__.py
│   ├── app.py
│   ├── asset_discovery.py
│   ├── change_engine.py
│   ├── database.py
│   ├── scope_manager.py
│   └── README.md
└── tests/                                  # Pytest test suite
    ├── __init__.py
    ├── test_scope_manager.py
    ├── test_database.py
    ├── test_change_engine.py
    ├── test_asset_discovery.py
    ├── test_end_to_end.py
    └── test_regression.py
```
