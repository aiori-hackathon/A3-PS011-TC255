"""
Threat Lens - Safe Local Asset Discovery Engine
AIORI Hackathon 3 | Problem Statement PS-011 | Team: A3-PS011-TC255

Implements safe, non-destructive discovery for the local test environment.
Enforces pre-flight scope validation on all entry points (scan, probe, check_tcp).
Disables automatic HTTP redirects by default and strictly validates any redirect destination.
Sanitizes sensitive headers (cookies, auth tokens, API keys) prior to storage or display.
"""

import concurrent.futures
from datetime import datetime, timezone
import re
import socket
import time
from typing import Any, Optional
import requests

from scope_manager import ScopeManager, ScopeViolationError, InvalidTargetError
from security_txt import probe_security_txt, SecurityTxtParser
import database


# Standard local test ports frequently used in web and API development
DEFAULT_LOCAL_PORTS = [80, 3000, 5000, 8000, 8080, 8501, 8888, 9000]

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


def sanitize_headers(headers: Optional[dict[str, Any]]) -> dict[str, str]:
    """
    Redact sensitive credentials, cookies, and API keys from HTTP headers.
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


def extract_title(html_content: str) -> str:
    """
    Safely extract the <title> tag text from HTML content without executing scripts.
    Returns empty string if no title is present.
    """
    if not html_content or not isinstance(html_content, str):
        return ""
    match = re.search(r"<title[^>]*>(.*?)</title>", html_content, re.IGNORECASE | re.DOTALL)
    if match:
        raw_title = match.group(1).strip()
        cleaned = re.sub(r"\s+", " ", raw_title)
        return cleaned[:120]
    return ""


def check_tcp_port_outcome(host: str, port: int, timeout: float = 0.5) -> tuple[str, int]:
    """
    Detailed TCP socket check returning (outcome, errno_code).
    Enforces scope validation prior to creating any network socket.

    Outcomes:
      - 'open': TCP handshake completed (connection accepted)
      - 'closed': Connection refused by host (confirmed closed)
      - 'timeout': Connection timed out (inconclusive / network latency)
      - 'unreachable': Host / network unreachable or other socket error
    """
    ScopeManager.validate_target(host)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        if result == 0:
            return "open", 0
        # Windows WSAECONNREFUSED (10061), Linux/Unix ECONNREFUSED (111)
        elif result in (10061, 111):
            return "closed", result
        # Windows WSAETIMEDOUT (10060), Linux/Unix ETIMEDOUT (110)
        elif result in (10060, 110):
            return "timeout", result
        else:
            return "unreachable", result
    except socket.timeout:
        return "timeout", -1
    except (socket.error, OSError) as e:
        return "unreachable", getattr(e, "errno", -1)
    finally:
        sock.close()


def check_tcp_port(host: str, port: int, timeout: float = 0.5) -> bool:
    """
    Safely check if a TCP port is open locally.
    Enforces scope validation prior to socket creation.
    """
    ScopeManager.validate_target(host)
    outcome, _ = check_tcp_port_outcome(host, port, timeout=timeout)
    return outcome == "open"


def probe_http_service(
    host: str,
    port: int,
    timeout: float = 1.0,
    use_https: bool = False,
    allow_redirects: bool = False,
    max_redirects: int = 0,
    verify_tls: bool = True,
    check_security_txt: bool = True,
) -> Optional[dict[str, Any]]:
    """
    Probe a local endpoint over HTTP(S) to gather status and response headers safely.

    Security Controls:
      - Scope boundary enforced before request.
      - Disables automatic HTTP redirects by default (allow_redirects=False).
      - If redirect following is requested, validates every redirect destination
        with ScopeManager and strictly refuses external or out-of-scope targets.
      - Preserves TLS certificate verification by default without silently disabling it.
      - Automatically sanitizes sensitive headers (Set-Cookie, Authorization, API keys).
    """
    # Priority 1: Scope enforcement on direct entry point
    ScopeManager.validate_target(host)

    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}/"
    start_time = time.perf_counter()

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,  # Automatic redirects disabled by default
            verify=verify_tls,
            headers={"User-Agent": "ThreatLens-SafeScanner/1.0 (AIORI3-PS011)"},
        )
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        redirect_info = None

        # Priority 1: Validate redirect destination if redirect response received
        if 300 <= response.status_code < 400 and "Location" in response.headers:
            raw_location = response.headers["Location"]
            try:
                safe_destination = ScopeManager.validate_redirect(url, raw_location)
                redirect_info = {
                    "redirect_location": raw_location,
                    "safe_destination": safe_destination,
                    "in_scope": True,
                }
                if allow_redirects and max_redirects > 0:
                    r_host, r_port = ScopeManager.validate_target(safe_destination)
                    return probe_http_service(
                        host=r_host,
                        port=r_port or (443 if safe_destination.startswith("https") else 80),
                        timeout=timeout,
                        use_https=safe_destination.startswith("https"),
                        allow_redirects=True,
                        max_redirects=max_redirects - 1,
                        verify_tls=verify_tls,
                        check_security_txt=check_security_txt,
                    )
            except ScopeViolationError as exc:
                redirect_info = {
                    "redirect_location": raw_location,
                    "in_scope": False,
                    "blocked_reason": str(exc),
                }

        # Priority 2: Sanitize headers before returning
        headers_dict = sanitize_headers(dict(response.headers))
        raw_server = headers_dict.get("Server", headers_dict.get("server", ""))
        server_header = raw_server.strip(", ")
        content_type = headers_dict.get("Content-Type", headers_dict.get("content-type", ""))
        title = extract_title(response.text if "text" in content_type or "html" in content_type else "")

        now_iso = datetime.now(timezone.utc).isoformat()

        obs = {
            "host": host,
            "port": port,
            "protocol": scheme,
            "service": "http-web",
            "status_code": response.status_code,
            "server_header": server_header,
            "content_type": content_type,
            "title": title,
            "response_time_ms": elapsed_ms,
            "headers": headers_dict,
            "state": "open",
            "timestamp": now_iso,
        }
        if redirect_info:
            obs["redirect_info"] = redirect_info

        # Probe RFC 9116 security.txt on active web service
        if check_security_txt:
            try:
                obs["security_txt"] = probe_security_txt(
                    host=host,
                    port=port,
                    protocol=scheme,
                    timeout=timeout,
                    verify_tls=verify_tls,
                )
            except Exception:
                obs["security_txt"] = None
        else:
            obs["security_txt"] = None

        return obs

    except requests.exceptions.SSLError:
        if not use_https:
            return probe_http_service(
                host,
                port,
                timeout=timeout,
                use_https=True,
                allow_redirects=allow_redirects,
                max_redirects=max_redirects,
                verify_tls=verify_tls,
                check_security_txt=check_security_txt,
            )
        return None

    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        return None

    except requests.exceptions.RequestException:
        return None

    except Exception:
        return None


class AssetDiscovery:
    """
    Discovery coordinator that strictly validates scope before performing
    safe observation of local test services.
    """

    def __init__(self, db_path: str = database.DEFAULT_DB_PATH):
        self.db_path = db_path
        self.last_tested_ports: list[int] = []
        self.last_port_outcomes: dict[int, str] = {}

    def scan(
        self,
        target: str,
        ports: Optional[list[int]] = None,
        timeout: float = 1.0,
        max_workers: int = 8,
        verify_tls: bool = True,
    ) -> tuple[list[dict[str, Any]], float]:
        """
        Execute a safe discovery scan against an authorized target.
        """
        # Step 1: Pre-flight Scope Check
        try:
            host, specified_port = ScopeManager.validate_target(target)
        except ScopeViolationError as exc:
            database.log_audit_event(
                action="SCOPE_VALIDATION",
                target=target,
                status="REJECTED",
                details=f"Scope violation: {str(exc)[:200]}",
                db_path=self.db_path,
            )
            raise
        except InvalidTargetError as exc:
            database.log_audit_event(
                action="SCOPE_VALIDATION",
                target=target,
                status="INVALID",
                details=f"Invalid target: {str(exc)[:200]}",
                db_path=self.db_path,
            )
            raise

        database.log_audit_event(
            action="SCOPE_VALIDATION",
            target=target,
            status="ALLOWED",
            details=f"Authorized host '{host}' validated against strict localhost scope.",
            db_path=self.db_path,
        )

        if specified_port is not None:
            target_ports = [specified_port]
        elif ports:
            target_ports = sorted(list(set(ports)))
        else:
            target_ports = list(DEFAULT_LOCAL_PORTS)

        self.last_tested_ports = list(target_ports)
        self.last_port_outcomes = {}

        scan_start = time.perf_counter()
        observations: list[dict[str, Any]] = []

        def probe_port(port: int) -> tuple[int, str, Optional[dict[str, Any]]]:
            # Detailed TCP check
            outcome, _ = check_tcp_port_outcome(host, port, timeout=0.4)
            if outcome != "open":
                return port, outcome, None

            # If TCP open, probe HTTP with automatic redirects disabled
            http_obs = probe_http_service(
                host,
                port,
                timeout=timeout,
                allow_redirects=False,
                verify_tls=verify_tls,
            )
            if http_obs:
                return port, "open", http_obs

            # TCP open but non-HTTP service
            now_iso = datetime.now(timezone.utc).isoformat()
            tcp_obs = {
                "host": host,
                "port": port,
                "protocol": "tcp",
                "service": "tcp-open",
                "status_code": None,
                "server_header": "",
                "content_type": "",
                "title": "",
                "response_time_ms": 0.0,
                "headers": {},
                "security_txt": None,
                "state": "open",
                "timestamp": now_iso,
            }
            return port, "open", tcp_obs

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_port = {executor.submit(probe_port, p): p for p in target_ports}
                for future in concurrent.futures.as_completed(future_to_port):
                    try:
                        p, outcome, obs = future.result()
                        self.last_port_outcomes[p] = outcome
                        if obs is not None:
                            observations.append(obs)
                    except Exception:
                        continue

            observations.sort(key=lambda x: x["port"])
            duration = round(time.perf_counter() - scan_start, 3)

            database.log_audit_event(
                action="DISCOVERY_SCAN",
                target=host,
                status="SUCCESS",
                details=f"Scanned {len(target_ports)} ports on {host}. Found {len(observations)} active services in {duration}s.",
                db_path=self.db_path,
            )

            return observations, duration

        except Exception as exc:
            duration = round(time.perf_counter() - scan_start, 3)
            database.log_audit_event(
                action="DISCOVERY_SCAN",
                target=host,
                status="FAILED",
                details=f"Scan failed: {type(exc).__name__} ({str(exc)[:150]})",
                db_path=self.db_path,
            )
            raise

    def scan_and_save(
        self,
        target: str,
        ports: Optional[list[int]] = None,
        notes: str = "",
        timeout: float = 1.0,
        max_workers: int = 8,
        verify_tls: bool = True,
        **kwargs: Any,
    ) -> tuple[int, list[dict[str, Any]], float]:
        """
        Execute scan and automatically persist snapshot with tested_ports metadata.
        Returns: (snapshot_id, observations, duration)
        """
        observations, duration = self.scan(
            target=target,
            ports=ports,
            timeout=timeout,
            max_workers=max_workers,
            verify_tls=verify_tls,
        )
        snapshot_id = database.save_snapshot(
            target_host=target,
            observations=observations,
            scan_duration_sec=duration,
            notes=notes,
            tested_ports=self.last_tested_ports,
            db_path=self.db_path,
            **kwargs,
        )
        return snapshot_id, observations, duration


def save_snapshot(*args: Any, **kwargs: Any) -> int:
    """Convenience alias delegating directly to database.save_snapshot."""
    return database.save_snapshot(*args, **kwargs)
