"""
Tests for Threat Lens Deterministic Rule-Based Risk Engine
AIORI Hackathon 3 | Problem Statement PS-011 | Team: A3-PS011-TC255
"""

import pytest
from risk_engine import RiskEngine
from change_engine import ChangeEngine


# ==============================================================================
# STATIC ASSET RISK EVALUATION TESTS
# ==============================================================================

def test_critical_asset_risk_ports():
    critical_ports = [23, 445, 3389, 5900, 5901, 6379, 9200, 11211, 27017]
    for port in critical_ports:
        obs = {
            "host": "127.0.0.1",
            "port": port,
            "protocol": "tcp",
            "service": "tcp-open",
            "status_code": None,
        }
        res = RiskEngine.evaluate_asset_risk(obs)
        assert res["level"] == "CRITICAL", f"Port {port} should be CRITICAL"
        assert res["score"] == 4
        assert any(str(port) in r for r in res["reasons"])


def test_critical_asset_risk_directory_listing():
    obs = {
        "host": "127.0.0.1",
        "port": 80,
        "protocol": "http",
        "service": "http-web",
        "status_code": 200,
        "title": "Index of /backup",
    }
    res = RiskEngine.evaluate_asset_risk(obs)
    assert res["level"] == "CRITICAL"
    assert res["score"] == 4
    assert any("directory index" in r.lower() for r in res["reasons"])


def test_high_asset_risk_management_ports():
    high_ports = [21, 22, 1433, 1521, 3306, 5432]
    for port in high_ports:
        obs = {
            "host": "127.0.0.1",
            "port": port,
            "protocol": "tcp",
            "service": "tcp-open",
            "status_code": None,
        }
        res = RiskEngine.evaluate_asset_risk(obs)
        assert res["level"] == "HIGH", f"Port {port} should be HIGH"
        assert res["score"] == 3
        assert any(str(port) in r for r in res["reasons"])


def test_port_8080_not_falsely_marked_high():
    """Verify FP prevention: Port 8080 with standard homepage is not blindly marked HIGH."""
    obs = {
        "host": "127.0.0.1",
        "port": 8080,
        "protocol": "http",
        "service": "http-web",
        "status_code": 200,
        "title": "Welcome to Acme Corp",
        "headers": {"content-security-policy": "default-src 'self'"},
    }
    res = RiskEngine.evaluate_asset_risk(obs)
    assert res["level"] != "HIGH", "Standard web server on port 8080 must not be flagged HIGH"


def test_high_asset_risk_sensitive_titles():
    keywords = ["phpMyAdmin", "Admin Console", "Swagger UI", "Kibana", "Grafana", "Spring Boot Actuator"]
    for kw in keywords:
        obs = {
            "host": "127.0.0.1",
            "port": 80,
            "protocol": "http",
            "service": "http-web",
            "status_code": 200,
            "title": f"Welcome to {kw}",
        }
        res = RiskEngine.evaluate_asset_risk(obs)
        assert res["level"] == "HIGH", f"Title with '{kw}' should be HIGH"
        assert res["score"] == 3
        assert any("sensitive administration keyword" in r.lower() for r in res["reasons"])


def test_medium_asset_risk_http_500():
    """Verify HTTP 500 is assigned MEDIUM operational risk, not inflated to HIGH."""
    obs = {
        "host": "127.0.0.1",
        "port": 80,
        "protocol": "http",
        "service": "http-web",
        "status_code": 500,
        "server_header": "nginx/1.24",
    }
    res = RiskEngine.evaluate_asset_risk(obs)
    assert res["level"] == "MEDIUM"
    assert res["score"] == 2
    assert any("500" in r for r in res["reasons"])


def test_medium_asset_risk_debug_banner():
    debug_banners = [
        "Werkzeug/2.2.2 Python/3.10.12",
        "BaseHTTP/0.6 Python/3.11.0",
        "TornadoServer/6.3.2",
        "Waitress/2.1.2",
    ]
    for banner in debug_banners:
        obs = {
            "host": "127.0.0.1",
            "port": 80,
            "protocol": "http",
            "service": "http-web",
            "status_code": 200,
            "server_header": banner,
            "headers": {"content-security-policy": "default-src 'self'"},
        }
        res = RiskEngine.evaluate_asset_risk(obs)
        assert res["level"] == "MEDIUM", f"Banner '{banner}' should be MEDIUM"
        assert res["score"] == 2
        assert any("development/debug server banner" in r.lower() for r in res["reasons"])


def test_auth_restricted_not_falsely_marked_medium():
    """Verify FP prevention: HTTP 401/403 is recognized as enforced access control (LOW)."""
    for code in (401, 403):
        obs = {
            "host": "127.0.0.1",
            "port": 80,
            "protocol": "http",
            "service": "http-web",
            "status_code": code,
            "server_header": "nginx/1.24",
        }
        res = RiskEngine.evaluate_asset_risk(obs)
        assert res["level"] == "LOW", f"HTTP {code} enforcing access control must not be marked risk"
        assert res["score"] == 1
        assert any("access control enforced" in r.lower() for r in res["reasons"])


def test_missing_headers_fp_prevention_on_cleartext_http():
    """Verify FP prevention: RFC 6797 prohibits HSTS over cleartext HTTP; do not flag plain HTTP for missing HSTS."""
    obs = {
        "host": "127.0.0.1",
        "port": 80,
        "protocol": "http",
        "service": "http-web",
        "status_code": 200,
        "server_header": "nginx/1.24",
        "headers": {"content-security-policy": "default-src 'self'"},
    }
    res = RiskEngine.evaluate_asset_risk(obs)
    assert not any("hsts" in r.lower() for r in res["reasons"]), "Cleartext HTTP must not be flagged for missing HSTS"


def test_missing_headers_on_https():
    """Verify HTTPS web service missing HSTS is appropriately flagged."""
    obs = {
        "host": "127.0.0.1",
        "port": 443,
        "protocol": "https",
        "service": "http-web",
        "status_code": 200,
        "server_header": "nginx/1.24",
        "headers": {"content-security-policy": "default-src 'self'"},
    }
    res = RiskEngine.evaluate_asset_risk(obs)
    assert res["level"] == "MEDIUM"
    assert any("hsts" in r.lower() for r in res["reasons"])


def test_missing_csp_on_web_service():
    obs = {
        "host": "127.0.0.1",
        "port": 80,
        "protocol": "http",
        "service": "http-web",
        "status_code": 200,
        "server_header": "nginx/1.24",
        "headers": {"content-type": "text/html"},
    }
    res = RiskEngine.evaluate_asset_risk(obs)
    assert res["level"] == "MEDIUM"
    assert any("content-security-policy" in r.lower() for r in res["reasons"])


def test_low_asset_risk_standard_service():
    obs = {
        "host": "127.0.0.1",
        "port": 443,
        "protocol": "https",
        "service": "http-web",
        "status_code": 200,
        "server_header": "nginx/1.24",
        "headers": {
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000",
        },
    }
    res = RiskEngine.evaluate_asset_risk(obs)
    assert res["level"] == "LOW"
    assert res["score"] == 1
    assert any("baseline exposure parameters" in r.lower() for r in res["reasons"])


# ==============================================================================
# ATTACK SURFACE DRIFT RISK EVALUATION TESTS
# ==============================================================================

def test_change_risk_added_critical():
    item = {"host": "127.0.0.1", "port": 6379, "service": "tcp-open"}
    res = RiskEngine.evaluate_change_risk("added", item)
    assert res["level"] == "CRITICAL"
    assert res["score"] == 4
    assert any("critical port 6379" in r.lower() for r in res["reasons"])


def test_change_risk_added_high():
    item = {"host": "127.0.0.1", "port": 3306, "service": "tcp-open"}
    res = RiskEngine.evaluate_change_risk("added", item)
    assert res["level"] == "HIGH"
    assert res["score"] == 3


def test_change_risk_added_web_endpoint():
    item = {"host": "127.0.0.1", "port": 80, "service": "http-web", "status_code": 200}
    res = RiskEngine.evaluate_change_risk("added", item)
    assert res["level"] == "HIGH"
    assert res["score"] == 3


def test_change_risk_added_raw_tcp():
    item = {"host": "127.0.0.1", "port": 9999, "service": "tcp-open"}
    res = RiskEngine.evaluate_change_risk("added", item)
    assert res["level"] == "MEDIUM"
    assert res["score"] == 2


def test_change_risk_modified_auth_drop():
    """Verify authentication drop (401/403 -> 200) is CRITICAL with before/after evidence."""
    for old_code in (401, 403):
        item = {
            "endpoint": "127.0.0.1:8080",
            "port": 8080,
            "changes": [
                {"field": "status_code", "label": "Status Code", "old_value": old_code, "new_value": 200, "category": "state"},
            ],
        }
        res = RiskEngine.evaluate_change_risk("modified", item)
        assert res["level"] == "CRITICAL", f"Auth drop from {old_code} to 200 must be CRITICAL"
        assert res["score"] == 4
        assert any(f"http {old_code}" in r.lower() and "http 200" in r.lower() for r in res["reasons"])


def test_change_risk_modified_access_restricted_hardening():
    """Verify access restriction (200 -> 401/403) is recognized as hardening / reduced exposure (LOW)."""
    for new_code in (401, 403):
        item = {
            "endpoint": "127.0.0.1:8080",
            "port": 8080,
            "changes": [
                {"field": "status_code", "label": "Status Code", "old_value": 200, "new_value": new_code, "category": "state"},
            ],
        }
        res = RiskEngine.evaluate_change_risk("modified", item)
        assert res["level"] == "LOW", "Applying authentication must be classified as LOW risk drift"
        assert res["score"] == 1
        assert any("access restriction applied" in r.lower() for r in res["reasons"])


def test_change_risk_modified_hsts_removed():
    item = {
        "endpoint": "127.0.0.1:443",
        "port": 443,
        "changes": [
            {"field": "header:strict-transport-security", "label": "Strict-Transport-Security", "old_value": "max-age=31536000", "new_value": "[MISSING]", "category": "security_headers"},
        ],
    }
    res = RiskEngine.evaluate_change_risk("modified", item)
    assert res["level"] == "HIGH"
    assert res["score"] == 3
    assert any("strict-transport-security" in r.lower() and "baseline:" in r.lower() for r in res["reasons"])


def test_change_risk_modified_csp_removed():
    item = {
        "endpoint": "127.0.0.1:80",
        "port": 80,
        "changes": [
            {"field": "header:content-security-policy", "label": "Content-Security-Policy", "old_value": "default-src 'self'", "new_value": "[MISSING]", "category": "security_headers"},
        ],
    }
    res = RiskEngine.evaluate_change_risk("modified", item)
    assert res["level"] == "HIGH"
    assert res["score"] == 3
    assert any("content-security-policy" in r.lower() and "baseline:" in r.lower() for r in res["reasons"])


def test_change_risk_modified_header_added_hardening():
    """Verify adding defensive headers is recognized as hardening / reduced exposure (LOW)."""
    item = {
        "endpoint": "127.0.0.1:80",
        "port": 80,
        "changes": [
            {"field": "header:content-security-policy", "label": "Content-Security-Policy", "old_value": "[MISSING]", "new_value": "default-src 'self'", "category": "security_headers"},
        ],
    }
    res = RiskEngine.evaluate_change_risk("modified", item)
    assert res["level"] == "LOW"
    assert res["score"] == 1
    assert any("hardened" in r.lower() and "content-security-policy" in r.lower() for r in res["reasons"])


def test_change_risk_modified_server_error_500():
    item = {
        "endpoint": "127.0.0.1:80",
        "port": 80,
        "changes": [
            {"field": "status_code", "label": "Status Code", "old_value": 200, "new_value": 500, "category": "state"},
        ],
    }
    res = RiskEngine.evaluate_change_risk("modified", item)
    assert res["level"] == "MEDIUM"
    assert res["score"] == 2
    assert any("500" in r for r in res["reasons"])


def test_change_risk_modified_frame_options_removed():
    item = {
        "endpoint": "127.0.0.1:80",
        "port": 80,
        "changes": [
            {"field": "header:x-frame-options", "label": "X-Frame-Options", "old_value": "DENY", "new_value": "[MISSING]", "category": "security_headers"},
        ],
    }
    res = RiskEngine.evaluate_change_risk("modified", item)
    assert res["level"] == "MEDIUM"
    assert res["score"] == 2
    assert any("baseline:" in r.lower() for r in res["reasons"])


def test_change_risk_modified_banner_to_debug():
    item = {
        "endpoint": "127.0.0.1:5000",
        "port": 5000,
        "changes": [
            {"field": "server_header", "label": "Server Banner", "old_value": "nginx/1.24", "new_value": "Werkzeug/2.2.2 Python/3.10", "category": "banner"},
        ],
    }
    res = RiskEngine.evaluate_change_risk("modified", item)
    assert res["level"] == "MEDIUM"
    assert res["score"] == 2
    assert any("werkzeug" in r.lower() and "baseline:" in r.lower() for r in res["reasons"])


def test_change_risk_modified_title_admin_disclosure():
    item = {
        "endpoint": "127.0.0.1:80",
        "port": 80,
        "changes": [
            {"field": "title", "label": "Page Title", "old_value": "Welcome", "new_value": "phpMyAdmin Database Portal", "category": "content"},
        ],
    }
    res = RiskEngine.evaluate_change_risk("modified", item)
    assert res["level"] == "HIGH"
    assert res["score"] == 3
    assert any("sensitive administrative keyword" in r.lower() and "baseline:" in r.lower() for r in res["reasons"])


def test_change_risk_modified_title_directory_listing():
    item = {
        "endpoint": "127.0.0.1:80",
        "port": 80,
        "changes": [
            {"field": "title", "label": "Page Title", "old_value": "Welcome", "new_value": "Index of /secret", "category": "content"},
        ],
    }
    res = RiskEngine.evaluate_change_risk("modified", item)
    assert res["level"] == "CRITICAL"
    assert res["score"] == 4
    assert any("directory listing" in r.lower() and "baseline:" in r.lower() for r in res["reasons"])


def test_change_risk_modified_title_only():
    item = {
        "endpoint": "127.0.0.1:80",
        "port": 80,
        "changes": [
            {"field": "title", "label": "Page Title", "old_value": "My App v1", "new_value": "My App v2", "category": "content"},
        ],
    }
    res = RiskEngine.evaluate_change_risk("modified", item)
    assert res["level"] == "LOW"
    assert res["score"] == 1


def test_change_risk_removed_reduces_exposure_hardening():
    """Verify FP prevention: Closing a critical or high-risk port is attack surface reduction (hardening, LOW drift)."""
    item_crit = {"host": "127.0.0.1", "port": 3389, "service": "tcp-open"}
    res_crit = RiskEngine.evaluate_change_risk("removed", item_crit)
    assert res_crit["level"] == "LOW", "Closing RDP must be classified as LOW drift (hardening)"
    assert res_crit["score"] == 1
    assert any("hardening" in r.lower() and "reduced" in r.lower() for r in res_crit["reasons"])

    item_std = {"host": "127.0.0.1", "port": 80, "service": "http-web"}
    res_std = RiskEngine.evaluate_change_risk("removed", item_std)
    assert res_std["level"] == "LOW"
    assert res_std["score"] == 1


def test_change_risk_unchanged():
    item_unchanged = {"host": "127.0.0.1", "port": 80, "service": "http-web"}
    res_unchanged = RiskEngine.evaluate_change_risk("unchanged", item_unchanged)
    assert res_unchanged["level"] == "LOW"
    assert res_unchanged["score"] == 1


# ==============================================================================
# EDGE CASES AND ROBUSTNESS TESTS
# ==============================================================================

def test_edge_cases_empty_and_none_fields():
    # Empty observation
    res1 = RiskEngine.evaluate_asset_risk({})
    assert res1["level"] == "LOW"
    assert res1["score"] == 1

    # Observation with None values
    obs_none = {
        "host": None,
        "port": None,
        "protocol": None,
        "service": None,
        "status_code": None,
        "server_header": None,
        "title": None,
        "headers": None,
    }
    res2 = RiskEngine.evaluate_asset_risk(obs_none)
    assert res2["level"] == "LOW"
    assert res2["score"] == 1

    # String port
    obs_str_port = {"port": "6379"}
    res3 = RiskEngine.evaluate_asset_risk(obs_str_port)
    assert res3["level"] == "CRITICAL"

    # Unknown high ephemeral port
    obs_unknown = {"port": 54321, "protocol": "tcp", "service": "tcp-open"}
    res4 = RiskEngine.evaluate_asset_risk(obs_unknown)
    assert res4["level"] == "LOW"


# ==============================================================================
# CHANGE ENGINE INTEGRATION TESTS
# ==============================================================================

def test_change_engine_diff_includes_risk_metadata():
    baseline = [
        {
            "host": "127.0.0.1",
            "port": 8080,
            "protocol": "http",
            "service": "http-web",
            "status_code": 401,
            "server_header": "nginx/1.24",
            "title": "Auth Required",
            "headers": {"content-type": "text/html"},
        },
        {
            "host": "127.0.0.1",
            "port": 3389,
            "protocol": "tcp",
            "service": "tcp-open",
            "status_code": None,
            "server_header": None,
            "title": None,
            "headers": {},
        },
    ]

    current = [
        # 8080 modified: 401 -> 200 (CRITICAL auth drop)
        {
            "host": "127.0.0.1",
            "port": 8080,
            "protocol": "http",
            "service": "http-web",
            "status_code": 200,
            "server_header": "nginx/1.24",
            "title": "Auth Required",
            "headers": {"content-type": "text/html"},
        },
        # 3389 removed (closed -> LOW hardening)
        # 22 added: SSH (HIGH management port)
        {
            "host": "127.0.0.1",
            "port": 22,
            "protocol": "tcp",
            "service": "tcp-open",
            "status_code": None,
            "server_header": "OpenSSH_9.0",
            "title": None,
            "headers": {},
        },
    ]

    diff = ChangeEngine.compare_observations(baseline, current, current_tested_ports=[8080, 3389, 22])
    summary = diff["summary"]

    assert summary["has_changes"] is True
    assert summary["added_count"] == 1
    assert summary["removed_count"] == 1
    assert summary["modified_count"] == 1

    # Verify risk counts:
    # 8080 modified (auth drop) = CRITICAL (1)
    # 22 added (SSH) = HIGH (1)
    # 3389 removed (closed) = LOW hardening (1)
    assert "critical_count" in summary
    assert "high_count" in summary
    assert "medium_count" in summary
    assert "low_count" in summary

    assert summary["critical_count"] == 1
    assert summary["high_count"] == 1
    assert summary["medium_count"] == 0
    assert summary["low_count"] == 1

    # Verify individual item risk metadata
    assert diff["added"][0]["risk"]["level"] == "HIGH"
    assert diff["removed"][0]["risk"]["level"] == "LOW"
    assert diff["modified"][0]["risk"]["level"] == "CRITICAL"

    # Verify Markdown report formatting
    report = ChangeEngine.generate_change_report(diff)
    assert "- **Risk Posture**: Critical: 1 | High: 1 | Medium: 0 | Low: 1" in report
    assert "[CRITICAL]" in report
    assert "[HIGH]" in report
    assert "[LOW]" in report
    assert "Evidence:" in report
