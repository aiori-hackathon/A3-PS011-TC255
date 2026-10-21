"""
Unit tests for Threat Lens ScopeManager.
AIORI Hackathon 3 | Problem Statement PS-011 | Team: A3-PS011-TC255
"""

import pytest
from scope_manager import ScopeManager, ScopeViolationError, InvalidTargetError


def test_allowed_hosts_in_scope():
    """Verify strictly authorized loopback hosts are accepted."""
    assert ScopeManager.is_in_scope("127.0.0.1") is True
    assert ScopeManager.is_in_scope("localhost") is True
    assert ScopeManager.is_in_scope("LOCALHOST") is True
    assert ScopeManager.is_in_scope("  127.0.0.1  ") is True


def test_validate_allowed_hosts():
    """Verify validate_target returns normalized host and port for allowed targets."""
    host, port = ScopeManager.validate_target("127.0.0.1")
    assert host == "127.0.0.1"
    assert port is None

    host, port = ScopeManager.validate_target("localhost:8080")
    assert host == "localhost"
    assert port == 8080

    host, port = ScopeManager.validate_target("http://127.0.0.1:3000/test")
    assert host == "127.0.0.1"
    assert port == 3000

    host, port = ScopeManager.validate_target("https://localhost:8501")
    assert host == "localhost"
    assert port == 8501


def test_public_and_external_hosts_rejected():
    """Verify public internet domains and IPs are strictly rejected."""
    disallowed_targets = [
        "google.com",
        "https://example.com",
        "api.github.com",
        "8.8.8.8",
        "1.1.1.1",
        "http://cloudflare.com:443",
    ]
    for target in disallowed_targets:
        assert ScopeManager.is_in_scope(target) is False
        with pytest.raises(ScopeViolationError) as exc_info:
            ScopeManager.validate_target(target)
        assert "NOT within the authorized scope" in str(exc_info.value)


def test_private_lan_and_wildcard_rejected():
    """Verify private LAN and wildcard addresses outside loopback are rejected."""
    disallowed_lan = [
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.5",
        "0.0.0.0",
        "http://0.0.0.0:8000",
    ]
    for target in disallowed_lan:
        assert ScopeManager.is_in_scope(target) is False
        with pytest.raises(ScopeViolationError):
            ScopeManager.validate_target(target)


def test_subdomain_and_spoofing_attempts_rejected():
    """Verify domain suffix tricks (e.g., localhost.attacker.com) are rejected."""
    tricky_targets = [
        "localhost.attacker.com",
        "127.0.0.1.nip.io",
        "fake-localhost",
        "http://not-localhost:8080",
    ]
    for target in tricky_targets:
        assert ScopeManager.is_in_scope(target) is False
        with pytest.raises(ScopeViolationError):
            ScopeManager.validate_target(target)


def test_invalid_target_inputs():
    """Verify empty or non-string inputs raise InvalidTargetError."""
    invalid_inputs = ["", "   ", None]
    for bad in invalid_inputs:
        assert ScopeManager.is_in_scope(bad) is False  # type: ignore
        with pytest.raises(InvalidTargetError):
            ScopeManager.validate_target(bad)  # type: ignore


def test_authorized_scope_metadata():
    """Verify get_authorized_scope returns the exact permitted list."""
    scope = ScopeManager.get_authorized_scope()
    assert scope == ["127.0.0.1", "localhost"]
    rules = ScopeManager.describe_scope_rules()
    assert rules["allow_public_targets"] is False
