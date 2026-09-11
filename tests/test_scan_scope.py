"""
Tests for MacGuard AI v1.1 ScanScope and TraversalLimits models.

Validates that discovery scopes are explicitly bounded, strictly read-only,
and completely decoupled from cleanup/mutation authority.
"""

import os
import threading
from pathlib import Path
import pytest
from pydantic import ValidationError

from app.models.scan_scope import (
    CANONICAL_SENSITIVE_EXCLUSIONS,
    ScanScope,
    ScopeIdentifier,
    TraversalLimits,
)


def test_scope_identifier_enum_values():
    """Verify standard v1.1 scope identifier values."""
    expected = {
        "HOME",
        "DESKTOP",
        "DOCUMENTS",
        "DOWNLOADS",
        "PICTURES",
        "MOVIES",
        "MUSIC",
        "DEVELOPER",
        "USER_CACHES",
        "CUSTOM",
    }
    actual = {s.value for s in ScopeIdentifier}
    assert actual == expected


def test_traversal_limits_defaults():
    """Verify default traversal safeguard limits match V1.1_PLAN.md specification."""
    limits = TraversalLimits()

    assert limits.max_depth == 8
    assert limits.max_entries == 250_000
    assert limits.timeout_seconds == 60.0
    assert limits.max_file_size_for_expensive_analysis == 5_368_709_120  # 5 GiB
    assert limits.follow_symlinks is False
    assert limits.stay_on_filesystem is True
    assert limits.cancellation_event is None
    assert limits.is_cancelled() is False


def test_traversal_limits_custom_valid():
    """Verify valid custom traversal limits construction."""
    event = threading.Event()
    limits = TraversalLimits(
        max_depth=4,
        max_entries=50_000,
        timeout_seconds=15.5,
        max_file_size_for_expensive_analysis=1_000_000,
        follow_symlinks=True,
        stay_on_filesystem=False,
        cancellation_event=event,
    )

    assert limits.max_depth == 4
    assert limits.max_entries == 50_000
    assert limits.timeout_seconds == 15.5
    assert limits.max_file_size_for_expensive_analysis == 1_000_000
    assert limits.follow_symlinks is True
    assert limits.stay_on_filesystem is False
    assert limits.is_cancelled() is False

    event.set()
    assert limits.is_cancelled() is True


def test_traversal_limits_validation_errors():
    """Verify invalid limit parameters raise validation errors."""
    with pytest.raises(ValidationError):
        TraversalLimits(max_depth=0)

    with pytest.raises(ValidationError):
        TraversalLimits(max_depth=-5)

    with pytest.raises(ValidationError):
        TraversalLimits(max_depth=65)

    with pytest.raises(ValidationError):
        TraversalLimits(max_entries=0)

    with pytest.raises(ValidationError):
        TraversalLimits(max_entries=-100)

    with pytest.raises(ValidationError):
        TraversalLimits(timeout_seconds=0.0)

    with pytest.raises(ValidationError):
        TraversalLimits(timeout_seconds=-10.0)

    with pytest.raises(ValidationError):
        TraversalLimits(max_file_size_for_expensive_analysis=-1)


def test_traversal_limits_immutability():
    """Verify TraversalLimits is frozen and forbids extra attributes."""
    limits = TraversalLimits()

    with pytest.raises(ValidationError):
        limits.max_depth = 12  # type: ignore[misc]

    with pytest.raises(ValidationError):
        TraversalLimits(extra_field="invalid")  # type: ignore[call-arg]


def test_scan_scope_valid_construction(tmp_path):
    """Verify valid ScanScope creation and path resolution."""
    scope = ScanScope(
        scope_id=ScopeIdentifier.DEVELOPER,
        root_path=str(tmp_path),
        description="Test developer directory",
        enabled=True,
    )

    assert scope.scope_id == ScopeIdentifier.DEVELOPER
    assert scope.root_path == str(tmp_path)
    assert scope.description == "Test developer directory"
    assert scope.enabled is True
    assert scope.read_only is True
    assert scope.limits.max_depth == 8
    assert scope.resolved_path() == tmp_path.resolve()
    assert scope.exclusions == CANONICAL_SENSITIVE_EXCLUSIONS


def test_scan_scope_home_expansion():
    """Verify user home tilde expansion in root path."""
    scope = ScanScope(
        scope_id=ScopeIdentifier.HOME,
        root_path="~/Downloads",
        description="Home downloads",
    )

    expected = str(Path.home() / "Downloads")
    assert scope.root_path == expected


def test_scan_scope_empty_root_rejected():
    """Verify empty or whitespace-only root paths are rejected."""
    with pytest.raises(ValidationError):
        ScanScope(
            scope_id=ScopeIdentifier.CUSTOM,
            root_path="",
            description="Empty root",
        )

    with pytest.raises(ValidationError):
        ScanScope(
            scope_id=ScopeIdentifier.CUSTOM,
            root_path="   ",
            description="Whitespace root",
        )


def test_scan_scope_read_only_invariant():
    """Verify ScanScope rejects any attempt to set read_only=False."""
    with pytest.raises(ValidationError):
        ScanScope(
            scope_id=ScopeIdentifier.DEVELOPER,
            root_path="/tmp",
            description="Invalid mutable scope",
            read_only=False,  # type: ignore[arg-type]
        )


def test_scan_scope_immutability(tmp_path):
    """Verify ScanScope is frozen and forbids extra fields."""
    scope = ScanScope(
        scope_id=ScopeIdentifier.CUSTOM,
        root_path=str(tmp_path),
        description="Immutable scope",
    )

    with pytest.raises(ValidationError):
        scope.enabled = False  # type: ignore[misc]

    with pytest.raises(ValidationError):
        ScanScope(
            scope_id=ScopeIdentifier.CUSTOM,
            root_path=str(tmp_path),
            description="Extra field test",
            unauthorized_mutation_flag=True,  # type: ignore[call-arg]
        )


def test_scan_scope_is_path_excluded(tmp_path):
    """Verify sensitive subpath exclusion checks."""
    scope = ScanScope(
        scope_id=ScopeIdentifier.HOME,
        root_path=str(tmp_path),
        description="Exclusion test scope",
        exclusions=(".ssh", ".aws", "Library/Keychains"),
    )

    # Path inside exclusion
    ssh_key = tmp_path / ".ssh" / "id_rsa"
    assert scope.is_path_excluded(ssh_key) is True

    # Path inside nested library exclusion
    keychain_db = tmp_path / "Library" / "Keychains" / "login.keychain-db"
    assert scope.is_path_excluded(keychain_db) is True

    # Safe unexcluded path
    safe_file = tmp_path / "Projects" / "myapp" / "main.py"
    assert scope.is_path_excluded(safe_file) is False


def test_scan_scope_create_default_scopes(tmp_path):
    """Verify factory generation of standard v1.1 read-only discovery scopes."""
    scopes = ScanScope.create_default_scopes(home_dir=tmp_path)

    assert len(scopes) == 9
    scope_map = {s.scope_id: s for s in scopes}

    assert ScopeIdentifier.HOME in scope_map
    assert ScopeIdentifier.USER_CACHES in scope_map
    assert ScopeIdentifier.DEVELOPER in scope_map
    assert ScopeIdentifier.DOWNLOADS in scope_map
    assert ScopeIdentifier.DOCUMENTS in scope_map
    assert ScopeIdentifier.DESKTOP in scope_map
    assert ScopeIdentifier.PICTURES in scope_map
    assert ScopeIdentifier.MOVIES in scope_map
    assert ScopeIdentifier.MUSIC in scope_map

    # By default, only USER_CACHES is enabled for conservative discovery
    assert scope_map[ScopeIdentifier.USER_CACHES].enabled is True
    assert scope_map[ScopeIdentifier.HOME].enabled is False
    assert scope_map[ScopeIdentifier.DOCUMENTS].enabled is False
    assert scope_map[ScopeIdentifier.DESKTOP].enabled is False

    # All scopes must strictly be read_only=True
    for s in scopes:
        assert s.read_only is True
        assert s.limits.follow_symlinks is False
        assert s.limits.stay_on_filesystem is True
        assert len(s.exclusions) > 0


def test_canonical_sensitive_exclusions_completeness():
    """Verify canonical sensitive exclusions list contains critical privacy roots."""
    expected_exclusions = {
        ".ssh",
        ".gnupg",
        ".aws",
        ".kube",
        ".config/gcloud",
        "Library/Keychains",
        "Library/Mail",
        "Library/Messages",
        "Library/Safari",
        "Library/Preferences",
    }
    for item in expected_exclusions:
        assert item in CANONICAL_SENSITIVE_EXCLUSIONS
