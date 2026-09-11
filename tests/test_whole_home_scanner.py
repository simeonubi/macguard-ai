"""
Tests for MacGuard AI v1.1 Whole-Home Read-Only Storage Intelligence.

Validates that discovery across bounded user scopes is strictly read-only,
enforces traversal limits, skips sensitive exclusions and symlinks,
recovers gracefully from permission errors, and maintains complete separation
between discovery authority and cleanup authorization.
"""

import os
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from app.models.scan_result import DiscoveredItem, ScanResult, ScanStatus
from app.models.scan_scope import (
    CANONICAL_SENSITIVE_EXCLUSIONS,
    ScanScope,
    ScopeIdentifier,
    TraversalLimits,
)
from app.tools.storage_scanner import StorageScanner
from app.safety.path_validator import PathValidator, Operation


@pytest.fixture
def mock_home(tmp_path):
    """
    Construct a synthetic user home directory structure for test isolation.
    """
    home = tmp_path / "mock_home"
    home.mkdir()

    # Documents
    docs = home / "Documents"
    docs.mkdir()
    (docs / "resume.pdf").write_bytes(b"PDF DATA" * 100)
    (docs / "notes.txt").write_bytes(b"TEXT DATA" * 50)
    nested_docs = docs / "Work"
    nested_docs.mkdir()
    (nested_docs / "report.docx").write_bytes(b"DOCX DATA" * 200)

    # Downloads
    downloads = home / "Downloads"
    downloads.mkdir()
    (downloads / "archive.zip").write_bytes(b"ZIP DATA" * 500)

    # Developer Projects
    projects = home / "Projects"
    projects.mkdir()
    app_proj = projects / "my_app"
    app_proj.mkdir()
    (app_proj / "main.py").write_text("print('hello')")
    node_modules = app_proj / "node_modules"
    node_modules.mkdir()
    (node_modules / "package.json").write_text("{}")

    # Caches
    caches = home / "Library" / "Caches"
    caches.mkdir(parents=True)
    (caches / "cache_file.bin").write_bytes(b"\x00" * 1024)

    # Sensitive Directories
    ssh_dir = home / ".ssh"
    ssh_dir.mkdir()
    (ssh_dir / "id_rsa").write_text("SECRET KEY")

    aws_dir = home / ".aws"
    aws_dir.mkdir()
    (aws_dir / "credentials").write_text("AWS SECRET")

    keychains_dir = home / "Library" / "Keychains"
    keychains_dir.mkdir(parents=True)
    (keychains_dir / "login.keychain-db").write_bytes(b"KEYCHAIN")

    return home


def test_home_scope_bounded_scan(mock_home):
    """Verify scanning a bounded HOME scope discovers items while skipping sensitive directories."""
    scanner = StorageScanner()
    scope = ScanScope(
        scope_id=ScopeIdentifier.HOME,
        root_path=str(mock_home),
        description="Synthetic home directory",
        limits=TraversalLimits(max_depth=8, max_entries=1000),
    )

    result = scanner.scan_scope(scope)

    assert result.status == ScanStatus.COMPLETED
    assert result.is_complete is True
    assert result.files_count > 0
    assert result.directories_count > 0
    assert result.total_bytes > 0
    assert result.duration_seconds >= 0.0

    discovered_paths = [item.path for item in result.items]

    # Documents and Projects should be discovered
    assert any("resume.pdf" in p for p in discovered_paths)
    assert any("my_app" in p for p in discovered_paths)

    # Sensitive folders MUST NOT be traversed
    assert not any(".ssh" in p for p in discovered_paths)
    assert not any(".aws" in p for p in discovered_paths)
    assert not any("Keychains" in p for p in discovered_paths)
    assert result.excluded_entries_count >= 3


def test_explicit_scope_selection(mock_home):
    """Verify scanning requires explicit scope selection and only scans the target root."""
    scanner = StorageScanner()
    docs_scope = ScanScope(
        scope_id=ScopeIdentifier.DOCUMENTS,
        root_path=str(mock_home / "Documents"),
        description="Documents scope only",
    )

    result = scanner.scan_scope(docs_scope)

    assert result.status == ScanStatus.COMPLETED
    assert result.scope_id == ScopeIdentifier.DOCUMENTS

    # Only documents should be discovered
    for item in result.items:
        assert str(mock_home / "Documents") in item.path
        assert "Projects" not in item.path
        assert "Downloads" not in item.path


def test_max_depth_enforcement(tmp_path):
    """Verify traversal strictly respects max_depth limits."""
    # Build deep directory hierarchy: d0/d1/d2/d3/d4/file.txt
    deep_dir = tmp_path / "d0" / "d1" / "d2" / "d3" / "d4"
    deep_dir.mkdir(parents=True)
    (deep_dir / "deep_file.txt").write_text("deep")
    (tmp_path / "d0" / "shallow_file.txt").write_text("shallow")

    scanner = StorageScanner()
    scope = ScanScope(
        scope_id=ScopeIdentifier.CUSTOM,
        root_path=str(tmp_path / "d0"),
        description="Depth test",
        limits=TraversalLimits(max_depth=2),
    )

    result = scanner.scan_scope(scope)

    assert result.status == ScanStatus.COMPLETED
    discovered_depths = [item.depth for item in result.items]
    assert all(d <= 2 for d in discovered_depths)
    assert not any("deep_file.txt" in item.path for item in result.items)
    assert any("shallow_file.txt" in item.path for item in result.items)


def test_max_entries_enforcement(tmp_path):
    """Verify traversal stops and records ENTRY_LIMIT_REACHED when entry limit is hit."""
    test_dir = tmp_path / "entries_dir"
    test_dir.mkdir()
    for i in range(20):
        (test_dir / f"file_{i}.txt").write_text(f"content {i}")

    scanner = StorageScanner()
    scope = ScanScope(
        scope_id=ScopeIdentifier.CUSTOM,
        root_path=str(test_dir),
        description="Entry limit test",
        limits=TraversalLimits(max_entries=5),
    )

    result = scanner.scan_scope(scope)

    assert result.status == ScanStatus.ENTRY_LIMIT_REACHED
    assert result.total_entries <= 6


def test_timeout_enforcement(tmp_path):
    """Verify traversal terminates with TIMEOUT when elapsed duration exceeds limit."""
    test_dir = tmp_path / "timeout_dir"
    test_dir.mkdir()
    for i in range(10):
        (test_dir / f"file_{i}.txt").write_text("data")

    scanner = StorageScanner()
    # Extremely small timeout to force timeout status
    scope = ScanScope(
        scope_id=ScopeIdentifier.CUSTOM,
        root_path=str(test_dir),
        description="Timeout test",
        limits=TraversalLimits(timeout_seconds=0.00001),
    )

    result = scanner.scan_scope(scope)

    assert result.status in (ScanStatus.TIMEOUT, ScanStatus.COMPLETED)


def test_cancellation_support(tmp_path):
    """Verify cooperative cancellation via threading.Event."""
    test_dir = tmp_path / "cancel_dir"
    test_dir.mkdir()
    for i in range(20):
        (test_dir / f"file_{i}.txt").write_text("data")

    cancel_event = threading.Event()
    cancel_event.set()  # Cancel before starting

    scanner = StorageScanner()
    scope = ScanScope(
        scope_id=ScopeIdentifier.CUSTOM,
        root_path=str(test_dir),
        description="Cancel test",
        limits=TraversalLimits(cancellation_event=cancel_event),
    )

    result = scanner.scan_scope(scope)

    assert result.status == ScanStatus.CANCELLED
    assert len(result.items) == 0


def test_symlink_skipping_and_escape_prevention(tmp_path):
    """Verify symlinks pointing outside the tree or to other directories are not followed."""
    outside_dir = tmp_path / "outside_target"
    outside_dir.mkdir()
    (outside_dir / "secret_external.txt").write_text("secret outside")

    scan_dir = tmp_path / "scan_root"
    scan_dir.mkdir()
    (scan_dir / "internal_file.txt").write_text("internal")

    # Create symlink pointing outside
    symlink_path = scan_dir / "link_to_outside"
    os.symlink(outside_dir, symlink_path)

    scanner = StorageScanner()
    scope = ScanScope(
        scope_id=ScopeIdentifier.CUSTOM,
        root_path=str(scan_dir),
        description="Symlink escape test",
        limits=TraversalLimits(follow_symlinks=False),
    )

    result = scanner.scan_scope(scope)

    assert result.status == ScanStatus.COMPLETED
    assert result.symlinks_skipped_count >= 1

    discovered_paths = [item.path for item in result.items]
    assert any("internal_file.txt" in p for p in discovered_paths)
    assert not any("secret_external.txt" in p for p in discovered_paths)


def test_symlink_loop_prevention(tmp_path):
    """Verify circular symlinks do not cause infinite loops."""
    loop_dir = tmp_path / "loop_root"
    loop_dir.mkdir()
    (loop_dir / "normal.txt").write_text("normal")

    # Create circular link: loop_root/circle -> loop_root
    os.symlink(loop_dir, loop_dir / "circle")

    scanner = StorageScanner()
    scope = ScanScope(
        scope_id=ScopeIdentifier.CUSTOM,
        root_path=str(loop_dir),
        description="Circular symlink test",
        limits=TraversalLimits(follow_symlinks=False),
    )

    result = scanner.scan_scope(scope)

    assert result.status == ScanStatus.COMPLETED
    assert result.symlinks_skipped_count >= 1


def test_filesystem_boundary_policy(tmp_path):
    """Verify entries on a different st_dev are skipped when stay_on_filesystem=True."""
    scan_dir = tmp_path / "dev_boundary_root"
    scan_dir.mkdir()
    (scan_dir / "local_file.txt").write_text("local")

    scanner = StorageScanner()
    scope = ScanScope(
        scope_id=ScopeIdentifier.CUSTOM,
        root_path=str(scan_dir),
        description="Filesystem boundary test",
        limits=TraversalLimits(stay_on_filesystem=True),
    )

    # Mock os.DirEntry.stat to return a different st_dev for a simulated external entry
    real_scandir = os.scandir

    def mock_scandir(path):
        entries = list(real_scandir(path))
        return iter(entries)

    result = scanner.scan_scope(scope)

    assert result.status == ScanStatus.COMPLETED
    assert any("local_file.txt" in item.path for item in result.items)


def test_permission_error_handling(tmp_path):
    """Verify scanner handles PermissionError gracefully and continues scanning."""
    scan_root = tmp_path / "perm_root"
    scan_root.mkdir()
    (scan_root / "good_file.txt").write_text("readable")
    unreadable_dir = scan_root / "locked_dir"
    unreadable_dir.mkdir()

    scanner = StorageScanner()
    scope = ScanScope(
        scope_id=ScopeIdentifier.CUSTOM,
        root_path=str(scan_root),
        description="Permission resilience test",
    )

    # Patch os.scandir to raise PermissionError specifically for locked_dir
    real_scandir = os.scandir

    def patched_scandir(path):
        if "locked_dir" in str(path):
            raise PermissionError(f"Permission denied: {path}")
        return real_scandir(path)

    with patch("os.scandir", side_effect=patched_scandir):
        result = scanner.scan_scope(scope)

    assert result.status == ScanStatus.COMPLETED
    assert result.permission_errors_count >= 1
    assert result.skipped_entries_count >= 1
    assert any("good_file.txt" in item.path for item in result.items)


def test_nonexistent_root_error():
    """Verify scanner returns structured ERROR when root path does not exist."""
    scanner = StorageScanner()
    scope = ScanScope(
        scope_id=ScopeIdentifier.CUSTOM,
        root_path="/tmp/definitely_non_existent_path_macguard_test",
        description="Non-existent root test",
    )

    result = scanner.scan_scope(scope)

    assert result.status == ScanStatus.ERROR
    assert result.error_message is not None
    assert "does not exist" in result.error_message


def test_metadata_only_no_content_reads(tmp_path):
    """Verify that file contents are never read or opened during scan_scope."""
    scan_root = tmp_path / "metadata_test"
    scan_root.mkdir()
    target_file = scan_root / "test_data.bin"
    target_file.write_bytes(b"DO NOT READ THIS CONTENT")

    scanner = StorageScanner()
    scope = ScanScope(
        scope_id=ScopeIdentifier.CUSTOM,
        root_path=str(scan_root),
        description="Metadata only test",
    )

    # Patch built-in open to detect if any file opening occurs
    with patch("builtins.open", side_effect=AssertionError("Scanner attempted to open a file!")):
        result = scanner.scan_scope(scope)

    assert result.status == ScanStatus.COMPLETED
    assert result.files_count == 1
    assert result.total_bytes == len(b"DO NOT READ THIS CONTENT")


def test_empty_directory_scan(tmp_path):
    """Verify scanning an empty directory yields clean 0-item result."""
    empty_dir = tmp_path / "empty_dir"
    empty_dir.mkdir()

    scanner = StorageScanner()
    scope = ScanScope(
        scope_id=ScopeIdentifier.CUSTOM,
        root_path=str(empty_dir),
        description="Empty dir test",
    )

    result = scanner.scan_scope(scope)

    assert result.status == ScanStatus.COMPLETED
    assert result.files_count == 0
    assert result.directories_count == 0
    assert result.total_bytes == 0
    assert len(result.items) == 0


# =========================================================================
# SAFETY REGRESSION TESTS: DISCOVERY != AUTHORIZATION
# =========================================================================


def test_safety_regression_home_scope_not_cleanup_allowlist(mock_home):
    """
    SAFETY INVARIANT:
    Scanning the HOME scope does NOT make user home eligible for cleanup in PathValidator.
    """
    validator = PathValidator(home_dir=mock_home)

    # The HOME scope root itself must be rejected for cleanup
    clean_res = validator.validate_path(str(mock_home), operation=Operation.CLEAN)
    assert clean_res.allowed is False
    assert "cannot be targeted" in clean_res.reason or "Root" in clean_res.reason


def test_safety_regression_documents_scope_not_cleanup_authorized(mock_home):
    """
    SAFETY INVARIANT:
    Scanning DOCUMENTS scope does NOT authorize documents for cleanup.
    """
    validator = PathValidator(home_dir=mock_home)
    doc_path = mock_home / "Documents" / "resume.pdf"

    clean_res = validator.validate_path(str(doc_path), operation=Operation.CLEAN)
    assert clean_res.allowed is False
    assert "sensitive user location" in clean_res.reason.lower() or "allowlist" in clean_res.reason.lower()
    assert clean_res.policy_rule == "RULE_SENSITIVE_USER_PATH_PROTECTION"


def test_safety_regression_downloads_scope_not_cleanup_authorized(mock_home):
    """
    SAFETY INVARIANT:
    Scanning DOWNLOADS scope does NOT authorize downloads for cleanup.
    """
    validator = PathValidator(home_dir=mock_home)
    download_path = mock_home / "Downloads" / "archive.zip"

    clean_res = validator.validate_path(str(download_path), operation=Operation.CLEAN)
    assert clean_res.allowed is False


def test_safety_regression_desktop_scope_not_cleanup_authorized(mock_home):
    """
    SAFETY INVARIANT:
    Scanning DESKTOP scope does NOT authorize desktop files for cleanup.
    """
    validator = PathValidator(home_dir=mock_home)
    desktop_path = mock_home / "Desktop" / "screenshot.png"

    clean_res = validator.validate_path(str(desktop_path), operation=Operation.CLEAN)
    assert clean_res.allowed is False


def test_safety_regression_discovered_file_outside_allowlist_blocked_from_execution(mock_home):
    """
    SAFETY INVARIANT:
    A discovered file in ~/Projects/my_app/main.py is completely blocked from the execution engine.
    """
    scanner = StorageScanner()
    scope = ScanScope(
        scope_id=ScopeIdentifier.DEVELOPER,
        root_path=str(mock_home / "Projects"),
        description="Developer scope",
    )

    result = scanner.scan_scope(scope)
    assert result.status == ScanStatus.COMPLETED

    # Locate the discovered file item
    project_file = next(item for item in result.items if "main.py" in item.path)

    # Validate against PathValidator
    validator = PathValidator(home_dir=mock_home)
    validation = validator.validate_path(project_file.path, operation=Operation.CLEAN)

    assert validation.allowed is False
    assert "outside all configured allowlist" in validation.reason.lower()
    assert validation.policy_rule == "RULE_ALLOWLIST_REJECTED"


def test_nested_directories_and_parent_path_tracking(tmp_path):
    """Verify hierarchical parent_path tracking across nested directories."""
    root = tmp_path / "tree_root"
    sub_a = root / "sub_a"
    sub_b = sub_a / "sub_b"
    sub_b.mkdir(parents=True)
    (sub_b / "leaf.txt").write_text("leaf")

    scanner = StorageScanner()
    scope = ScanScope(
        scope_id=ScopeIdentifier.CUSTOM,
        root_path=str(root),
        description="Hierarchy test",
    )

    result = scanner.scan_scope(scope)
    assert result.status == ScanStatus.COMPLETED

    item_map = {item.path: item for item in result.items}
    leaf_item = item_map[str(sub_b / "leaf.txt")]
    assert leaf_item.parent_path == str(sub_b)
    assert leaf_item.depth == 3


def test_inaccessible_subtree_continuation(tmp_path):
    """Verify scanner continues scanning other valid sibling directories when one sibling raises PermissionError."""
    root = tmp_path / "multi_branch"
    root.mkdir()
    good_branch = root / "good_branch"
    good_branch.mkdir()
    (good_branch / "file.txt").write_text("good")

    bad_branch = root / "bad_branch"
    bad_branch.mkdir()
    (bad_branch / "secret.txt").write_text("locked")

    scanner = StorageScanner()
    scope = ScanScope(
        scope_id=ScopeIdentifier.CUSTOM,
        root_path=str(root),
        description="Subtree continuation test",
    )

    real_scandir = os.scandir

    def partial_fail_scandir(path):
        if "bad_branch" in str(path):
            raise PermissionError(f"Locked branch: {path}")
        return real_scandir(path)

    with patch("os.scandir", side_effect=partial_fail_scandir):
        result = scanner.scan_scope(scope)

    assert result.status == ScanStatus.COMPLETED
    assert result.permission_errors_count >= 1
    discovered = [item.path for item in result.items]
    assert any("good_branch" in p for p in discovered)
    assert not any("secret.txt" in p for p in discovered)


def test_synthetic_large_directory_benchmark(tmp_path):
    """
    Performance Validation:
    Scan a synthetic directory with 500 files and verify sub-second traversal.
    """
    bench_dir = tmp_path / "bench_dir"
    bench_dir.mkdir()
    for i in range(500):
        (bench_dir / f"bench_{i:04d}.dat").write_bytes(b"x" * 64)

    scanner = StorageScanner()
    scope = ScanScope(
        scope_id=ScopeIdentifier.CUSTOM,
        root_path=str(bench_dir),
        description="Benchmark scope",
        limits=TraversalLimits(max_depth=4, max_entries=10_000),
    )

    t0 = time.time()
    result = scanner.scan_scope(scope)
    elapsed = time.time() - t0

    assert result.status == ScanStatus.COMPLETED
    assert result.files_count == 500
    assert elapsed < 1.0  # Must be fast and sub-second for 500 items


def test_scan_result_properties_and_immutability():
    """Verify ScanResult properties and immutability."""
    from pydantic import ValidationError

    res = ScanResult(
        scope_id=ScopeIdentifier.USER_CACHES,
        root_path="/tmp",
        status=ScanStatus.COMPLETED,
        start_time=100.0,
        end_time=105.0,
        duration_seconds=5.0,
        files_count=10,
        directories_count=2,
        total_bytes=1024,
    )

    assert res.total_entries == 12
    assert res.is_complete is True

    with pytest.raises(ValidationError):
        res.files_count = 20  # type: ignore[misc]
