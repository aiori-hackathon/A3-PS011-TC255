"""
Threat Lens - Scope Manager
AIORI Hackathon 3 | Problem Statement PS-011 | Team: A3-PS011-TC255

Strict authorization boundary manager.
Enforces that discovery scans are strictly confined to authorized local targets.
Initially permits ONLY '127.0.0.1' and 'localhost'.
All other hosts are rejected immediately prior to any network request.
"""

from urllib.parse import urlparse, urljoin
import ipaddress
import re


class ScopeViolationError(PermissionError):
    """Raised when a target host falls outside the strictly authorized scope."""
    pass


class InvalidTargetError(ValueError):
    """Raised when a target specification is malformed or invalid."""
    pass


class ScopeManager:
    """
    Manages and enforces the authorized scanning scope.

    In accordance with PS-011 and ethical discovery rules, Threat Lens enforces
    a strict authorization boundary. For the initial MVP, ONLY loopback targets
    ('127.0.0.1' and 'localhost') are permitted. Public and remote targets
    are unconditionally rejected.
    """

    # Strictly authorized hosts for MVP
    AUTHORIZED_HOSTS = frozenset({"127.0.0.1", "localhost"})
    ALLOWED_SCHEMES = frozenset({"http", "https"})

    @classmethod
    def get_authorized_scope(cls) -> list[str]:
        """Return a sorted list of all authorized target hosts."""
        return sorted(list(cls.AUTHORIZED_HOSTS))

    @classmethod
    def parse_target(cls, raw_target: str) -> tuple[str, int | None]:
        """
        Parse a raw target string into a normalized hostname and optional port.

        Accepts:
          - "127.0.0.1"
          - "localhost"
          - "127.0.0.1:8000"
          - "localhost:5000"
          - "http://127.0.0.1:8080"
          - "https://localhost:3000/api"

        Returns:
          tuple: (hostname: str, port: int | None)

        Raises:
          InvalidTargetError: If the input target is empty, malformed, or cannot be parsed.
        """
        if not raw_target or not isinstance(raw_target, str):
            raise InvalidTargetError("Target cannot be empty or non-string.")

        target = raw_target.strip()
        if not target:
            raise InvalidTargetError("Target cannot be whitespace-only.")

        # Check for disallowed schemes early
        if "://" in target:
            scheme = target.split("://", 1)[0].lower()
            if scheme not in cls.ALLOWED_SCHEMES:
                raise InvalidTargetError(f"Unsupported URI scheme '{scheme}'. Only HTTP and HTTPS are permitted.")
            target_to_parse = target
        else:
            target_to_parse = f"http://{target}"

        try:
            parsed = urlparse(target_to_parse)
            hostname = parsed.hostname
            port = parsed.port
        except Exception as exc:
            raise InvalidTargetError(f"Failed to parse target '{raw_target}': {exc}") from exc

        if not hostname:
            raise InvalidTargetError(f"Could not extract a valid hostname from '{raw_target}'.")

        # Normalize hostname (lowercase, stripped)
        hostname = hostname.lower().strip()

        # Validate port range if specified
        if port is not None and not (1 <= port <= 65535):
            raise InvalidTargetError(f"Port {port} out of valid range (1-65535).")

        return hostname, port

    @classmethod
    def is_in_scope(cls, raw_target: str) -> bool:
        """
        Check if a target is within the authorized scope without raising an exception.

        Returns:
          bool: True if authorized, False otherwise.
        """
        try:
            hostname, _ = cls.parse_target(raw_target)
            return hostname in cls.AUTHORIZED_HOSTS
        except (InvalidTargetError, ScopeViolationError):
            return False

    @classmethod
    def validate_target(cls, raw_target: str) -> tuple[str, int | None]:
        """
        Validate that the target is strictly within the authorized scope.

        Returns:
          tuple: (normalized_hostname: str, port: int | None)

        Raises:
          InvalidTargetError: If target is malformed.
          ScopeViolationError: If target is outside the authorized scope.
        """
        hostname, port = cls.parse_target(raw_target)

        if hostname not in cls.AUTHORIZED_HOSTS:
            raise ScopeViolationError(
                f"[SCOPE VIOLATION] Target '{hostname}' is NOT within the authorized scope! "
                f"Threat Lens MVP strictly restricts scans to {cls.get_authorized_scope()}. "
                f"External, private LAN, and link-local network requests are prohibited."
            )

        return hostname, port

    @classmethod
    def validate_redirect(cls, current_url: str, redirect_location: str) -> str:
        """
        Validate an HTTP redirect destination against the authorized scope.

        Resolves relative paths (e.g., '/login') against current_url,
        and ensures the resulting target host is strictly within scope.

        Returns:
          str: The resolved, safe target URL.

        Raises:
          ScopeViolationError: If redirect points to an external or out-of-scope host.
          InvalidTargetError: If redirect location is malformed.
        """
        if not redirect_location or not isinstance(redirect_location, str):
            raise InvalidTargetError("Redirect location cannot be empty.")

        # Resolve relative URLs
        resolved_url = urljoin(current_url, redirect_location.strip())

        # Validate target host of the resolved URL
        cls.validate_target(resolved_url)

        return resolved_url

    @classmethod
    def describe_scope_rules(cls) -> dict:
        """
        Provide metadata about the active scope enforcement policy.
        """
        return {
            "policy_name": "Strict Localhost MVP Policy",
            "enforcement_level": "PRE-FLIGHT STRICT",
            "allowed_hosts": cls.get_authorized_scope(),
            "allow_public_targets": False,
            "allow_rfc1918_private_ips": False,
            "allow_link_local": False,
            "description": (
                "Only loopback addresses (127.0.0.1 and localhost) are permitted. "
                "Any external target, private LAN IP, link-local metadata address, or public domain "
                "will be rejected before any network socket or HTTP request is initiated. "
                "HTTP redirects outside loopback are strictly blocked."
            ),
        }
