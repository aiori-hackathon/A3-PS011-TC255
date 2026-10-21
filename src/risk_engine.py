"""
Threat Lens - Deterministic Rule-Based Risk Engine
AIORI Hackathon 3 | Problem Statement PS-011 | Team: A3-PS011-TC255

Provides deterministic, evidence-grounded risk labeling (Critical, High, Medium, Low)
for asset exposure and attack surface change drift.

Core Principles:
1. Grounded in Evidence: Every risk rating is tied to verifiable network facts
   (observed open ports, status codes, defensive headers, banner leakage).
2. Zero Speculation: Avoids claiming specific unverified CVEs or exploits.
3. Deterministic & Transparent: Evaluates explicit rules and provides human-readable reasons.
4. Distinguish Exposure Direction: Correctly separates increased attack surface (risk)
   from reduced attack surface / hardening (positive security actions).
"""

from typing import Any, Optional


# Critical administrative, remote control, and unauthenticated datastore ports
CRITICAL_PORTS: dict[int, str] = {
    23: "Telnet (Unencrypted remote terminal)",
    445: "SMB (Direct network file sharing)",
    3389: "RDP (Microsoft Remote Desktop)",
    5900: "VNC (Remote Framebuffer Display 0)",
    5901: "VNC (Remote Framebuffer Display 1)",
    6379: "Redis (In-memory datastore, default unauthenticated)",
    9200: "Elasticsearch (HTTP cluster search API)",
    11211: "Memcached (Memory caching daemon)",
    27017: "MongoDB (NoSQL database listener)",
}

# High-exposure database and remote management services
HIGH_PORTS: dict[int, str] = {
    21: "FTP (File Transfer Protocol - cleartext credentials)",
    22: "SSH (Secure Shell remote management)",
    1433: "MSSQL (Microsoft SQL Server)",
    1521: "Oracle Database listener",
    3306: "MySQL / MariaDB database",
    5432: "PostgreSQL database",
}

# Server banner tokens indicating development, debug, or internal runtime servers
DEBUG_SERVER_TOKENS: list[str] = [
    "werkzeug",
    "basehttp",
    "development",
    "wsgiref",
    "webrick",
    "thin",
    "kestrel",
    "tornado",
    "waitress",
    "simplehttp",
]

# Sensitive page title keywords indicating administrative or debug interfaces
SENSITIVE_TITLE_KEYWORDS: list[str] = [
    "index of /",
    "directory listing",
    "phpmyadmin",
    "admin console",
    "dashboard",
    "swagger",
    "kibana",
    "grafana",
    "actuator",
]

# Monitored defensive security headers
SECURITY_HEADERS: list[str] = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
]

# Risk Severity Definitions
RISK_LEVEL_CRITICAL = "CRITICAL"
RISK_LEVEL_HIGH = "HIGH"
RISK_LEVEL_MEDIUM = "MEDIUM"
RISK_LEVEL_LOW = "LOW"

_SEVERITY_SCORES = {
    RISK_LEVEL_CRITICAL: 4,
    RISK_LEVEL_HIGH: 3,
    RISK_LEVEL_MEDIUM: 2,
    RISK_LEVEL_LOW: 1,
}

_SCORE_TO_LEVEL = {
    4: RISK_LEVEL_CRITICAL,
    3: RISK_LEVEL_HIGH,
    2: RISK_LEVEL_MEDIUM,
    1: RISK_LEVEL_LOW,
}


def _safe_int_port(val: Any) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return 0


class RiskEngine:
    """
    Evaluates observed asset state and change drift to assign transparent risk labels.
    """

    @classmethod
    def evaluate_asset_risk(cls, obs: dict[str, Any]) -> dict[str, Any]:
        """
        Evaluate the static exposure risk of an individual asset observation.

        Returns:
            dict containing:
              - 'level': 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
              - 'score': int (1-4)
              - 'reasons': list[str] detailing the evidence for the rating
        """
        port = _safe_int_port(obs.get("port"))
        status_code = obs.get("status_code")
        server_header = str(obs.get("server_header") or "").lower()
        title = str(obs.get("title") or "").lower()
        headers = {str(k).lower(): str(v) for k, v in (obs.get("headers") or {}).items()}
        protocol = str(obs.get("protocol") or "http").lower()
        service = str(obs.get("service") or "").lower()

        reasons: list[str] = []
        max_score = 1

        # 1. Critical Port Exposure
        if port in CRITICAL_PORTS:
            reasons.append(f"Exposed critical service on port {port}: {CRITICAL_PORTS[port]}")
            max_score = max(max_score, 4)

        # 2. Sensitive Page Title / Directory Listing
        for kw in SENSITIVE_TITLE_KEYWORDS:
            if kw in title:
                if kw in ("index of /", "directory listing"):
                    reasons.append(f"Exposed directory index in page title: '{obs.get('title')}'")
                    max_score = max(max_score, 4)
                else:
                    reasons.append(f"Sensitive administration keyword in page title: '{obs.get('title')}'")
                    max_score = max(max_score, 3)
                break

        # 3. High-Exposure Database / Administrative Port
        if port in HIGH_PORTS:
            reasons.append(f"Exposed management/database port {port}: {HIGH_PORTS[port]}")
            max_score = max(max_score, 3)

        # 4. HTTP 500 Internal Server Error (Application exception / stack trace leak risk)
        if status_code == 500:
            reasons.append("HTTP 500 Internal Server Error observed (potential application exception or error leakage)")
            max_score = max(max_score, 2)

        # 5. Development / Debug Server Banner
        for token in DEBUG_SERVER_TOKENS:
            if token in server_header:
                reasons.append(f"Development/debug server banner disclosed: '{obs.get('server_header')}'")
                max_score = max(max_score, 2)
                break

        # 6. Access-Restricted Endpoints (HTTP 401 / 403)
        # Note: 401/403 represents active access control, not elevated risk.
        if status_code in (401, 403):
            reasons.append(f"Access control enforced (HTTP {status_code}: authentication/authorization required)")

        # 7. Missing Transport Encryption on Non-Standard Web Port
        if protocol == "http" and port not in (80, 8080) and service == "http-web":
            reasons.append(f"Cleartext HTTP service running on non-standard port {port}")
            max_score = max(max_score, 2)

        # 8. Defensive Security Headers (Web services only)
        # Note: HSTS is only applicable over HTTPS (RFC 6797 prohibits HSTS over cleartext HTTP).
        if service == "http-web" and status_code is not None and status_code < 400:
            if (protocol == "https" or port == 443) and "strict-transport-security" not in headers:
                reasons.append("HTTPS service missing Strict-Transport-Security (HSTS) header")
                max_score = max(max_score, 2)
            if "content-security-policy" not in headers:
                reasons.append("Web service missing Content-Security-Policy (CSP) header")
                max_score = max(max_score, 2)

        if not reasons:
            reasons.append("Standard service operating within baseline exposure parameters")

        level = _SCORE_TO_LEVEL[max_score]
        return {
            "level": level,
            "score": max_score,
            "reasons": reasons,
        }

    @classmethod
    def evaluate_change_risk(cls, change_type: str, item: dict[str, Any]) -> dict[str, Any]:
        """
        Evaluate the risk of a detected attack surface drift using before/after evidence.

        Parameters:
            change_type: 'added' | 'modified' | 'removed' | 'unchanged'
            item: The diff item dict containing observation or change details.

        Returns:
            dict containing:
              - 'level': 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
              - 'score': int (1-4)
              - 'reasons': list[str] detailing the evidence for the rating
        """
        reasons: list[str] = []
        max_score = 1

        if change_type == "added":
            port = _safe_int_port(item.get("port"))
            service = str(item.get("service") or "").lower()
            status_code = item.get("status_code")
            title = str(item.get("title") or "").lower()

            # Newly added critical port
            if port in CRITICAL_PORTS:
                reasons.append(f"Attack surface expanded (CRITICAL exposure): Newly opened critical port {port} ({CRITICAL_PORTS[port]})")
                max_score = max(max_score, 4)
            # Newly added database/management port
            elif port in HIGH_PORTS:
                reasons.append(f"Attack surface expanded (HIGH exposure): Newly opened database/management port {port} ({HIGH_PORTS[port]})")
                max_score = max(max_score, 3)
            # Newly responsive web endpoint
            elif service == "http-web" and status_code == 200:
                if "index of /" in title or "directory listing" in title:
                    reasons.append(f"Attack surface expanded (CRITICAL): Newly exposed directory listing on port {port}")
                    max_score = max(max_score, 4)
                elif any(kw in title for kw in SENSITIVE_TITLE_KEYWORDS):
                    reasons.append(f"Attack surface expanded (HIGH): Newly exposed administrative interface on port {port}")
                    max_score = max(max_score, 3)
                else:
                    reasons.append(f"Attack surface expanded: Newly responsive HTTP web endpoint on port {port}")
                    max_score = max(max_score, 3)
            # Newly opened raw TCP port
            elif service == "tcp-open":
                reasons.append(f"Attack surface expanded: Newly opened non-HTTP TCP port {port}")
                max_score = max(max_score, 2)
            else:
                reasons.append(f"Attack surface expanded: Newly active endpoint on port {port}")
                max_score = max(max_score, 2)

        elif change_type == "modified":
            changes = item.get("changes", [])
            endpoint = item.get("endpoint", "")

            for ch in changes:
                field = ch.get("field", "")
                old_val = ch.get("old_value")
                new_val = ch.get("new_value")

                # 1. Access Control Changes (Status Code)
                if field == "status_code":
                    # Critical: Authentication Drop (401/403 -> 200)
                    if old_val in (401, 403) and new_val == 200:
                        reasons.append(
                            f"Authentication drop on {endpoint}: Previously restricted endpoint (HTTP {old_val}) became publicly accessible (HTTP 200)"
                        )
                        max_score = max(max_score, 4)
                    # Hardening: Access Restriction Applied (200 -> 401/403)
                    elif old_val == 200 and new_val in (401, 403):
                        reasons.append(
                            f"Access restriction applied on {endpoint}: Status changed from HTTP {old_val} to HTTP {new_val} (authentication/authorization now enforced)"
                        )
                    # Service fault: Internal Server Error (200 -> 500)
                    elif new_val == 500:
                        reasons.append(
                            f"Service fault drift on {endpoint}: Status changed from HTTP {old_val} to HTTP 500 Internal Server Error (potential crash/leak state)"
                        )
                        max_score = max(max_score, 2)
                    # Service outage / error: 200 -> 404 / 503
                    elif old_val == 200 and new_val in (404, 503):
                        reasons.append(f"Service availability drift on {endpoint}: Status changed from HTTP {old_val} to HTTP {new_val}")
                        max_score = max(max_score, 2)
                    else:
                        reasons.append(f"HTTP status code updated on {endpoint}: HTTP {old_val} -> HTTP {new_val}")

                # 2. Defensive Security Headers
                elif field.startswith("header:"):
                    header_name = field.split(":", 1)[1]
                    # Security Downgrade: Header Removed
                    if new_val == "[MISSING]":
                        if header_name in ("strict-transport-security", "content-security-policy"):
                            reasons.append(
                                f"Security posture downgrade: Defensive header '{header_name}' removed on {endpoint} (baseline: '{old_val}')"
                            )
                            max_score = max(max_score, 3)
                        else:
                            reasons.append(
                                f"Defensive header removed on {endpoint}: '{header_name}' (baseline: '{old_val}')"
                            )
                            max_score = max(max_score, 2)
                    # Security Hardening: Header Added
                    elif old_val == "[MISSING]" and new_val != "[MISSING]":
                        reasons.append(
                            f"Security posture hardened: Added defensive header '{header_name}' on {endpoint} (new value: '{new_val}')"
                        )
                    else:
                        reasons.append(f"Header '{header_name}' modified on {endpoint}: '{old_val}' -> '{new_val}'")

                # 3. Server Banner Drift
                elif field == "server_header":
                    old_str = str(old_val or "").lower()
                    new_str = str(new_val or "").lower()
                    new_is_debug = any(token in new_str for token in DEBUG_SERVER_TOKENS)
                    old_is_debug = any(token in old_str for token in DEBUG_SERVER_TOKENS)
                    if new_is_debug and not old_is_debug:
                        reasons.append(
                            f"Server banner drift on {endpoint}: Development/debug server '{new_val}' disclosed (baseline: '{old_val}')"
                        )
                        max_score = max(max_score, 2)
                    else:
                        reasons.append(f"Server banner modified on {endpoint}: '{old_val}' -> '{new_val}'")

                # 4. Page Title Drift
                elif field == "title":
                    old_title = str(old_val or "").lower()
                    new_title = str(new_val or "").lower()
                    if ("index of /" in new_title or "directory listing" in new_title) and not ("index of /" in old_title or "directory listing" in old_title):
                        reasons.append(
                            f"Sensitive directory listing exposed in page title on {endpoint}: '{new_val}' (baseline: '{old_val}')"
                        )
                        max_score = max(max_score, 4)
                    elif any(kw in new_title for kw in SENSITIVE_TITLE_KEYWORDS) and not any(kw in old_title for kw in SENSITIVE_TITLE_KEYWORDS):
                        reasons.append(
                            f"Sensitive administrative keyword disclosed in page title on {endpoint}: '{new_val}' (baseline: '{old_val}')"
                        )
                        max_score = max(max_score, 3)
                    else:
                        reasons.append(f"Page title updated on {endpoint}: '{old_val}' -> '{new_val}'")

                # 5. Service & Protocol Profile Drift
                elif field in ("service", "protocol"):
                    if str(old_val).lower() == "tcp-open" and str(new_val).lower() == "http-web":
                        reasons.append(
                            f"Service profile expanded on {endpoint}: Changed from unprobed raw TCP to active HTTP web service"
                        )
                        max_score = max(max_score, 2)
                    else:
                        reasons.append(f"Service profile drift on {endpoint}: {field} changed from '{old_val}' to '{new_val}'")

            if not reasons:
                reasons.append(f"Attribute modifications observed on endpoint {endpoint}")

        elif change_type == "removed":
            # Note: Removal of an endpoint represents attack surface reduction / hardening.
            # It is classified as LOW risk drift to avoid false-positive alarms on service decommissioning.
            port = _safe_int_port(item.get("port"))
            if port in CRITICAL_PORTS:
                reasons.append(f"Attack surface reduced (hardening): Critical port {port} ({CRITICAL_PORTS[port]}) confirmed closed/decommissioned")
            elif port in HIGH_PORTS:
                reasons.append(f"Attack surface reduced (hardening): High-exposure port {port} ({HIGH_PORTS[port]}) confirmed closed/decommissioned")
            else:
                reasons.append(f"Attack surface reduced: Port {port} confirmed closed/decommissioned")
            max_score = 1

        elif change_type == "unchanged":
            reasons.append("Asset state confirmed stable across successive scans")
            max_score = 1

        else:
            reasons.append(f"Observation processed under change category '{change_type}'")
            max_score = 1

        level = _SCORE_TO_LEVEL[max_score]
        return {
            "level": level,
            "score": max_score,
            "reasons": reasons,
        }
