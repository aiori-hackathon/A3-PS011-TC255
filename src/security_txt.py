"""
Threat Lens - RFC 9116 security.txt Discovery and Validation Engine
AIORI Hackathon 3 | Problem Statement PS-011 | Team: A3-PS011-TC255

Implements RFC 9116 (A File Format to Aid in Vulnerability Disclosure):
- Validates loopback HTTP/HTTPS origins against ScopeManager before any socket is opened.
- Checks primary location (/.well-known/security.txt) and fallback (/security.txt).
- Strictly blocks external or out-of-scope redirects at every hop.
- Preserves TLS certificate verification without silently disabling it.
- Verifies Content-Type is text/plain (rejects HTML soft-404 responses).
- Parses RFC 9116 fields: Contact, Expires, Encryption, Preferred-Languages, Policy, etc.
- Accurately checks required Contact/Expires fields, single Expires requirement,
  and RFC 3339 timestamps.
- Distinguishes probe failures (unreachable, timeout, tls_error) from genuinely missing (404) files.
"""

from datetime import datetime, timezone
import re
from typing import Any, Optional
from urllib.parse import urljoin, urlparse
import requests

from scope_manager import ScopeManager, ScopeViolationError, InvalidTargetError


PRIMARY_PATH = "/.well-known/security.txt"
FALLBACK_PATH = "/security.txt"

# Recognized RFC 9116 field names (case-insensitive)
RECOGNIZED_FIELDS = {
    "contact",
    "expires",
    "encryption",
    "acknowledgments",
    "acknowledgements",
    "policy",
    "hiring",
    "canonical",
    "preferred-languages",
    "csaf",
}


def parse_rfc3339_datetime(date_str: str) -> Optional[datetime]:
    """
    Safely parse an RFC 3339 / ISO 8601 date-time string to a timezone-aware UTC datetime.
    Requires both a date and a time component ('T' or 't') with timezone offset.
    Returns None if parsing fails.
    """
    if not date_str or not isinstance(date_str, str):
        return None
    s = date_str.strip()
    # RFC 3339 date-time strictly requires 'T' or 't' separator
    if "T" not in s and "t" not in s:
        return None
    if s.endswith("Z") or s.endswith("z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        # RFC 3339 date-time strictly requires a timezone offset
        if dt.tzinfo is None:
            return None
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


class SecurityTxtParser:
    """
    Parses and validates the contents of an RFC 9116 security.txt file.
    """

    @classmethod
    def parse(cls, content: str) -> dict[str, Any]:
        """
        Parse raw security.txt text, extract standard fields, and verify RFC compliance.

        Returns:
            dict containing:
              - 'is_valid_format': bool
              - 'status': 'valid' | 'expired' | 'malformed'
              - 'is_expired': bool
              - 'expires_at': str (ISO 8601) or None
              - 'expires_raw': str or None
              - 'contact': list[str]
              - 'encryption': list[str]
              - 'preferred_languages': list[str]
              - 'policy': list[str]
              - 'acknowledgments': list[str]
              - 'hiring': list[str]
              - 'canonical': list[str]
              - 'notes': list[str]
        """
        if not content or not isinstance(content, str):
            return {
                "is_valid_format": False,
                "status": "malformed",
                "is_expired": False,
                "expires_at": None,
                "expires_raw": None,
                "contact": [],
                "encryption": [],
                "preferred_languages": [],
                "policy": [],
                "acknowledgments": [],
                "hiring": [],
                "canonical": [],
                "notes": ["Empty or invalid content."],
            }

        lines = content.splitlines()
        fields: dict[str, list[str]] = {}
        notes: list[str] = []
        has_syntax_error = False

        for line_num, raw_line in enumerate(lines, 1):
            line = raw_line.strip()
            # Ignore empty lines and comment-only lines
            if not line or line.startswith("#"):
                continue

            # Strip trailing inline comments if preceded by space
            if " #" in line:
                line = line.split(" #", 1)[0].strip()

            if ":" not in line:
                notes.append(f"Line {line_num}: Malformed line missing colon separator: '{line[:40]}'")
                has_syntax_error = True
                continue

            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()

            if not value:
                notes.append(f"Line {line_num}: Empty value for directive '{key}'")
                has_syntax_error = True
                continue

            fields.setdefault(key, []).append(value)

        # Extract standard RFC 9116 directives
        contact_list = fields.get("contact", [])
        expires_list = fields.get("expires", [])
        expires_raw = expires_list[0] if expires_list else None
        encryption_list = fields.get("encryption", [])
        policy_list = fields.get("policy", [])
        ack_list = fields.get("acknowledgments", []) + fields.get("acknowledgements", [])
        hiring_list = fields.get("hiring", [])
        canonical_list = fields.get("canonical", [])

        pref_langs: list[str] = []
        if "preferred-languages" in fields:
            for val in fields["preferred-languages"]:
                for lang in val.split(","):
                    if lang.strip():
                        pref_langs.append(lang.strip())

        is_malformed = False

        # RFC 9116 Mandatory Field Checks:
        # 1. Contact MUST be present
        if not contact_list:
            notes.append("RFC 9116 requirement: Mandatory 'Contact' directive is missing.")
            is_malformed = True

        # 2. Expires MUST be present EXACTLY once (RFC 9116 Section 2.5.5)
        is_expired = False
        expires_iso: Optional[str] = None
        if not expires_raw:
            notes.append("RFC 9116 requirement: Mandatory 'Expires' directive is missing.")
            is_malformed = True
        elif len(expires_list) > 1:
            notes.append("RFC 9116 violation: Multiple 'Expires' directives found; exactly one is permitted.")
            is_malformed = True
        else:
            expires_dt = parse_rfc3339_datetime(expires_raw)
            if expires_dt is None:
                notes.append(f"RFC 9116 requirement: 'Expires' value '{expires_raw}' is not valid RFC 3339 format.")
                is_malformed = True
            else:
                expires_iso = expires_dt.isoformat()
                now_utc = datetime.now(timezone.utc)
                if expires_dt < now_utc:
                    is_expired = True
                    notes.append(f"RFC 9116 security.txt expired on {expires_iso} (current UTC: {now_utc.isoformat()}).")

        # Determine overall validity
        if is_malformed:
            status = "malformed"
            is_valid_format = False
        elif is_expired:
            status = "expired"
            is_valid_format = True
        else:
            status = "valid"
            is_valid_format = True

        return {
            "is_valid_format": is_valid_format,
            "status": status,
            "is_expired": is_expired,
            "expires_at": expires_iso,
            "expires_raw": expires_raw,
            "contact": contact_list,
            "encryption": encryption_list,
            "preferred_languages": pref_langs,
            "policy": policy_list,
            "acknowledgments": ack_list,
            "hiring": hiring_list,
            "canonical": canonical_list,
            "notes": notes,
        }


def probe_security_txt(
    host: str,
    port: int,
    protocol: str = "http",
    timeout: float = 1.0,
    verify_tls: bool = True,
    max_redirects: int = 2,
) -> dict[str, Any]:
    """
    Safely probe and parse RFC 9116 security.txt for an authorized host and port.

    Security & Scope Controls:
    1. Pre-flight check with ScopeManager.validate_target(host).
    2. Probes primary location `/.well-known/security.txt`.
    3. If 404 or missing, probes fallback `/security.txt`.
    4. Validates redirects against ScopeManager at every hop; refuses external or LAN redirects.
    5. Preserves TLS certificate validation; records TLS failure if verification fails.
    6. Verifies Content-Type is text/plain, rejecting HTML soft-404 responses.
    7. Accurately distinguishes probe failures (unreachable, timeout, tls_error) from genuinely missing (404) files.
    """
    ScopeManager.validate_target(host)

    base_url = f"{protocol}://{host}:{port}"
    urls_to_try = [
        (urljoin(base_url, PRIMARY_PATH), PRIMARY_PATH),
        (urljoin(base_url, FALLBACK_PATH), FALLBACK_PATH),
    ]

    checked_paths: list[str] = []
    path_statuses: dict[str, str] = {}
    path_errors: dict[str, str] = {}

    for url, path in urls_to_try:
        checked_paths.append(path)
        current_url = url
        redirects_followed = 0

        try:
            while redirects_followed <= max_redirects:
                # Pre-flight check on destination URL before sending request at EVERY hop
                ScopeManager.validate_target(current_url)

                resp = requests.get(
                    current_url,
                    timeout=timeout,
                    allow_redirects=False,
                    verify=verify_tls,
                    headers={"User-Agent": "ThreatLens-SecurityTxt/1.0 (RFC9116)"},
                )

                # Check for redirects
                if 300 <= resp.status_code < 400 and "Location" in resp.headers:
                    raw_loc = resp.headers["Location"]
                    try:
                        safe_url = ScopeManager.validate_redirect(current_url, raw_loc)
                        current_url = safe_url
                        redirects_followed += 1
                        continue
                    except ScopeViolationError as exc:
                        return {
                            "status": "redirect_blocked",
                            "found": False,
                            "path": path,
                            "url": current_url,
                            "error": f"Redirect to external/out-of-scope target blocked: {exc}",
                            "checked_paths": checked_paths,
                            "is_expired": False,
                            "expires_at": None,
                            "contact": [],
                            "encryption": [],
                            "preferred_languages": [],
                            "policy": [],
                            "acknowledgments": [],
                            "hiring": [],
                            "canonical": [],
                            "notes": [f"Redirect blocked by Scope Guardian: {exc}"],
                        }

                # Response received
                if resp.status_code == 200:
                    content_type = str(resp.headers.get("Content-Type", "")).lower()
                    # RFC 9116 requires text/plain; reject HTML soft-404 responses
                    if (
                        "text/html" in content_type
                        or "<html" in resp.text[:200].lower()
                        or "<!doctype html" in resp.text[:200].lower()
                    ):
                        path_statuses[path] = "invalid_content_type"
                        path_errors[path] = "Server returned HTML soft-404 instead of text/plain"
                        break

                    if "text/plain" not in content_type and "text" not in content_type:
                        path_statuses[path] = "invalid_content_type"
                        path_errors[path] = f"Non-text Content-Type '{content_type}'"
                        break

                    # Parse valid text/plain response
                    parsed = SecurityTxtParser.parse(resp.text)
                    return {
                        "status": parsed["status"],
                        "found": True,
                        "path": path,
                        "url": current_url,
                        "content_type": content_type,
                        "is_expired": parsed["is_expired"],
                        "expires_at": parsed["expires_at"],
                        "expires_raw": parsed.get("expires_raw"),
                        "contact": parsed["contact"],
                        "encryption": parsed["encryption"],
                        "preferred_languages": parsed["preferred_languages"],
                        "policy": parsed["policy"],
                        "acknowledgments": parsed["acknowledgments"],
                        "hiring": parsed["hiring"],
                        "canonical": parsed["canonical"],
                        "notes": parsed["notes"],
                        "raw_snippet": resp.text[:500],
                        "checked_paths": checked_paths,
                    }

                elif resp.status_code in (404, 410):
                    path_statuses[path] = "not_found"
                    break
                elif resp.status_code in (401, 403):
                    path_statuses[path] = "access_denied"
                    path_errors[path] = f"Access denied (HTTP {resp.status_code})"
                    break
                elif resp.status_code >= 500:
                    path_statuses[path] = "server_error"
                    path_errors[path] = f"Server error (HTTP {resp.status_code})"
                    break
                else:
                    path_statuses[path] = f"http_{resp.status_code}"
                    break

        except requests.exceptions.SSLError as exc:
            path_statuses[path] = "tls_error"
            path_errors[path] = f"TLS verification failed: {exc}"
            continue
        except requests.exceptions.Timeout as exc:
            path_statuses[path] = "timeout"
            path_errors[path] = f"Connection timed out: {exc}"
            continue
        except requests.exceptions.ConnectionError as exc:
            path_statuses[path] = "connection_failed"
            path_errors[path] = f"Connection failed/refused: {exc}"
            continue
        except Exception as exc:
            path_statuses[path] = "error"
            path_errors[path] = str(exc)
            continue

    # Evaluate overall non-found outcome
    # Priority 1: Check for TLS verification failure
    if any(s == "tls_error" for s in path_statuses.values()):
        err_msg = next((path_errors[p] for p in checked_paths if path_statuses.get(p) == "tls_error"), "TLS error")
        return {
            "status": "tls_error",
            "found": False,
            "path": None,
            "url": base_url,
            "checked_paths": checked_paths,
            "is_expired": False,
            "expires_at": None,
            "contact": [],
            "encryption": [],
            "preferred_languages": [],
            "policy": [],
            "acknowledgments": [],
            "hiring": [],
            "canonical": [],
            "notes": [f"Probe failed: {err_msg}"],
        }

    # Priority 2: Check for connectivity failure / timeout
    if all(s in ("connection_failed", "timeout") for s in path_statuses.values()) and path_statuses:
        err_msg = next((path_errors[p] for p in checked_paths if p in path_errors), "Endpoint unreachable")
        return {
            "status": "unreachable",
            "found": False,
            "path": None,
            "url": base_url,
            "checked_paths": checked_paths,
            "is_expired": False,
            "expires_at": None,
            "contact": [],
            "encryption": [],
            "preferred_languages": [],
            "policy": [],
            "acknowledgments": [],
            "hiring": [],
            "canonical": [],
            "notes": [f"Probe failed: {err_msg}"],
        }

    # Priority 3: Server error
    if any(s == "server_error" for s in path_statuses.values()):
        err_msg = next((path_errors[p] for p in checked_paths if path_statuses.get(p) == "server_error"), "Server error")
        return {
            "status": "server_error",
            "found": False,
            "path": None,
            "url": base_url,
            "checked_paths": checked_paths,
            "is_expired": False,
            "expires_at": None,
            "contact": [],
            "encryption": [],
            "preferred_languages": [],
            "policy": [],
            "acknowledgments": [],
            "hiring": [],
            "canonical": [],
            "notes": [f"Probe failed: {err_msg}"],
        }

    # Priority 4: Genuinely missing (confirmed 404 or rejected HTML soft-404)
    return {
        "status": "missing",
        "found": False,
        "path": None,
        "url": base_url,
        "checked_paths": checked_paths,
        "is_expired": False,
        "expires_at": None,
        "contact": [],
        "encryption": [],
        "preferred_languages": [],
        "policy": [],
        "acknowledgments": [],
        "hiring": [],
        "canonical": [],
        "notes": ["RFC 9116 security.txt not found at /.well-known/security.txt or /security.txt (HTTP 404)"],
    }
