"""
Tests for MacGuard AI v1.1 Developer Storage Analysis.

Validates deep diagnostic intelligence for developer tooling, virtual environments,
package caches, build outputs, and AI/ML model repositories, verifying strict read-only
metadata analysis, unique-byte accounting, and zero cleanup authorization.
"""

import time
from pathlib import Path
from unittest.mock import patch
import pytest

from app.analysis.developer_analyzer import DeveloperStorageAnalyzer
from app.models.category import ConfidenceLevel, SmartCategory
from app.models.developer import (
    DeveloperProjectSummary,
    DeveloperStorageFinding,
    DeveloperStorageGroup,
    DeveloperStorageSubtype,
    DeveloperStorageSummary,
    StaleStatus,
)
from app.models.scan_result import DiscoveredItem, ScanResult, ScanStatus
from app.models.scan_scope import ScopeIdentifier
from app.safety.path_validator import Operation, PathValidator


def make_discovered_item(
    path: str,
    size_bytes: int = 1024 * 1024,
    item_type: str = "directory",
    depth: int = 3,
    mtime: float = 1700000000.0,
    category: SmartCategory = SmartCategory.DEVELOPER_DATA,
) -> DiscoveredItem:
    """Helper to create synthetic DiscoveredItem objects."""
    return DiscoveredItem(
        path=path,
        size_bytes=size_bytes,
        item_type=item_type,
        depth=depth,
        mtime=mtime,
        st_ino=hash(path) & 0x7FFFFFFF,
        st_dev=1,
        category=category,
        confidence=ConfidenceLevel.HIGH,
        category_rule=f"rule:{category.value.lower()}",
    )


def test_python_virtual_environment_analysis():
    """Verify detection and aggregation of Python virtual environments."""
    items = [
        make_discovered_item("/Users/test/Projects/my_app/.venv", size_bytes=200 * 1024 * 1024, category=SmartCategory.VIRTUAL_ENVIRONMENTS),
        make_discovered_item("/Users/test/Projects/other_app/venv", size_bytes=150 * 1024 * 1024, category=SmartCategory.VIRTUAL_ENVIRONMENTS),
    ]

    analyzer = DeveloperStorageAnalyzer()
    summary = analyzer.analyze_items(items)

    assert summary.total_findings_count == 2
    assert summary.total_logical_bytes == 350 * 1024 * 1024

    venv_group = next(g for g in summary.groups if g.subtype == DeveloperStorageSubtype.PYTHON_VENV)
    assert venv_group.item_count == 2
    assert venv_group.total_logical_bytes == 350 * 1024 * 1024


def test_node_modules_analysis():
    """Verify detection and grouping of node_modules directories."""
    items = [
        make_discovered_item("/Users/test/Projects/webapp/node_modules", size_bytes=500 * 1024 * 1024, category=SmartCategory.PACKAGE_MANAGERS),
    ]

    analyzer = DeveloperStorageAnalyzer()
    summary = analyzer.analyze_items(items)

    node_group = next(g for g in summary.groups if g.subtype == DeveloperStorageSubtype.NODE_MODULES)
    assert node_group.item_count == 1
    assert node_group.total_logical_bytes == 500 * 1024 * 1024
    assert node_group.findings[0].project_name == "webapp"


def test_build_artifacts_and_xcode_derived_data():
    """Verify build outputs including Xcode DerivedData and target directories."""
    items = [
        make_discovered_item("/Users/test/Library/Developer/Xcode/DerivedData/App-xyz", size_bytes=1024 * 1024 * 1024, category=SmartCategory.BUILD_ARTIFACTS),
        make_discovered_item("/Users/test/Projects/rust_cli/target/debug", size_bytes=300 * 1024 * 1024, category=SmartCategory.BUILD_ARTIFACTS),
    ]

    analyzer = DeveloperStorageAnalyzer()
    summary = analyzer.analyze_items(items)

    build_group = next(g for g in summary.groups if g.subtype == DeveloperStorageSubtype.BUILD_OUTPUT)
    assert build_group.item_count == 2
    assert build_group.total_logical_bytes == 1324 * 1024 * 1024


def test_package_manager_cache_aggregation():
    """Verify aggregation across npm, Cargo, pip, and Gradle caches."""
    items = [
        make_discovered_item("/Users/test/.npm/_cacache", size_bytes=100 * 1024 * 1024, category=SmartCategory.PACKAGE_MANAGERS),
        make_discovered_item("/Users/test/.cargo/registry/cache", size_bytes=250 * 1024 * 1024, category=SmartCategory.PACKAGE_MANAGERS),
    ]

    analyzer = DeveloperStorageAnalyzer()
    summary = analyzer.analyze_items(items)

    pkg_group = next(g for g in summary.groups if g.subtype == DeveloperStorageSubtype.PACKAGE_CACHE)
    assert pkg_group.item_count == 2
    assert pkg_group.total_logical_bytes == 350 * 1024 * 1024


def test_ml_ai_storage_aggregation():
    """Verify machine learning model weights, datasets, and framework caches."""
    items = [
        make_discovered_item("/Users/test/.cache/huggingface/hub/models--meta--llama", size_bytes=4 * 1024 * 1024 * 1024, category=SmartCategory.ML_AI_DATA),
        make_discovered_item("/Users/test/.ollama/models/blobs/sha256-abc", size_bytes=2 * 1024 * 1024 * 1024, item_type="file", category=SmartCategory.ML_AI_DATA),
    ]

    analyzer = DeveloperStorageAnalyzer()
    summary = analyzer.analyze_items(items)

    ml_group = next(g for g in summary.groups if g.subtype == DeveloperStorageSubtype.ML_MODELS)
    assert ml_group.item_count == 2
    assert ml_group.total_logical_bytes == 6 * 1024 * 1024 * 1024


def test_docker_and_container_storage():
    """Verify Docker VM disk images and container artifacts."""
    items = [
        make_discovered_item("/Users/test/Library/Containers/com.docker.docker/Data/docker.raw", size_bytes=10 * 1024 * 1024 * 1024, item_type="file", category=SmartCategory.CONTAINERS),
    ]

    analyzer = DeveloperStorageAnalyzer()
    summary = analyzer.analyze_items(items)

    container_group = next(g for g in summary.groups if g.subtype == DeveloperStorageSubtype.CONTAINER_STORAGE)
    assert container_group.item_count == 1
    assert container_group.total_logical_bytes == 10 * 1024 * 1024 * 1024


def test_project_association_inference():
    """Verify deterministic project name inference from container folders and .git paths."""
    analyzer = DeveloperStorageAnalyzer()

    # Under ~/Projects/<project_name>/...
    f1 = analyzer.analyze_item(make_discovered_item("/Users/test/Projects/my_service/.venv"))
    assert f1 is not None
    assert f1.project_name == "my_service"

    # Under ~/Developer/<project_name>/...
    f2 = analyzer.analyze_item(make_discovered_item("/Users/test/Developer/ios_app/DerivedData"))
    assert f2 is not None
    assert f2.project_name == "ios_app"

    # Under ~/Workspace/<project_name>/...
    f3 = analyzer.analyze_item(make_discovered_item("/Users/test/Workspace/backend_api/node_modules"))
    assert f3 is not None
    assert f3.project_name == "backend_api"

    # With .git repository
    f4 = analyzer.analyze_item(make_discovered_item("/Users/test/my_custom_tool/.git"))
    assert f4 is not None
    assert f4.project_name == "my_custom_tool"


def test_unknown_project_association():
    """Verify non-project global caches return None for project_name."""
    analyzer = DeveloperStorageAnalyzer()

    f_npm = analyzer.analyze_item(make_discovered_item("/Users/test/.npm/_cacache"))
    assert f_npm is not None
    assert f_npm.project_name is None

    f_docker = analyzer.analyze_item(make_discovered_item("/Users/test/Library/Containers/com.docker.docker/Data/docker.raw"))
    assert f_docker is not None
    assert f_docker.project_name is None


def test_large_artifact_detection():
    """Verify identification of large artifacts exceeding threshold."""
    items = [
        make_discovered_item("/Users/test/models/large_weights.safetensors", size_bytes=500 * 1024 * 1024, item_type="file", category=SmartCategory.ML_AI_DATA),
        make_discovered_item("/Users/test/Projects/app/__pycache__/mod.pyc", size_bytes=10 * 1024, item_type="file", category=SmartCategory.BUILD_ARTIFACTS),
    ]

    analyzer = DeveloperStorageAnalyzer(large_artifact_threshold_bytes=100 * 1024 * 1024)  # 100 MB
    summary = analyzer.analyze_items(items)

    assert len(summary.large_artifacts) == 1
    assert "large_weights.safetensors" in summary.large_artifacts[0].path
    assert summary.large_artifacts[0].is_large is True


def test_age_and_staleness_analysis():
    """Verify age evaluation across recent, moderate, and stale tiers."""
    now = 1700000000.0  # reference time

    # 10 days old -> RECENT
    mtime_recent = now - (10 * 86400)
    # 60 days old -> MODERATE
    mtime_mod = now - (60 * 86400)
    # 120 days old -> POTENTIALLY_STALE_90D
    mtime_stale90 = now - (120 * 86400)
    # 200 days old -> POTENTIALLY_STALE_180D
    mtime_stale180 = now - (200 * 86400)

    items = [
        make_discovered_item("/Users/test/Projects/p1/.venv", mtime=mtime_recent, category=SmartCategory.VIRTUAL_ENVIRONMENTS),
        make_discovered_item("/Users/test/Projects/p2/.venv", mtime=mtime_mod, category=SmartCategory.VIRTUAL_ENVIRONMENTS),
        make_discovered_item("/Users/test/Projects/p3/.venv", mtime=mtime_stale90, category=SmartCategory.VIRTUAL_ENVIRONMENTS),
        make_discovered_item("/Users/test/Projects/p4/.venv", mtime=mtime_stale180, category=SmartCategory.VIRTUAL_ENVIRONMENTS),
    ]

    analyzer = DeveloperStorageAnalyzer(reference_time=now)
    summary = analyzer.analyze_items(items)

    findings_by_path = {f.path: f for f in summary.groups[0].findings}
    assert findings_by_path["/Users/test/Projects/p1/.venv"].stale_status == StaleStatus.RECENT
    assert findings_by_path["/Users/test/Projects/p2/.venv"].stale_status == StaleStatus.MODERATE
    assert findings_by_path["/Users/test/Projects/p3/.venv"].stale_status == StaleStatus.POTENTIALLY_STALE_90D
    assert findings_by_path["/Users/test/Projects/p4/.venv"].stale_status == StaleStatus.POTENTIALLY_STALE_180D

    assert len(summary.stale_findings) == 2


def test_hierarchical_unique_byte_accounting_no_double_counting():
    """
    CRITICAL INVARIANT:
    Nested developer items within a parent project candidate are not double-counted physically.
    total_unique_bytes <= total_logical_bytes.
    """
    items = [
        # Parent project root (10 GB)
        make_discovered_item("/Users/test/Projects/super_app", size_bytes=10 * 1024 * 1024 * 1024, depth=2, category=SmartCategory.DEVELOPER_DATA),
        # Child node_modules (4 GB)
        make_discovered_item("/Users/test/Projects/super_app/node_modules", size_bytes=4 * 1024 * 1024 * 1024, depth=3, category=SmartCategory.PACKAGE_MANAGERS),
        # Child .venv (2 GB)
        make_discovered_item("/Users/test/Projects/super_app/.venv", size_bytes=2 * 1024 * 1024 * 1024, depth=3, category=SmartCategory.VIRTUAL_ENVIRONMENTS),
    ]

    analyzer = DeveloperStorageAnalyzer()
    summary = analyzer.analyze_items(items)

    # Logical sum is 10 + 4 + 2 = 16 GB
    assert summary.total_logical_bytes == 16 * 1024 * 1024 * 1024

    # Unique physical coverage must be only 10 GB (the parent encompasses children)
    assert summary.total_unique_bytes == 10 * 1024 * 1024 * 1024
    assert summary.total_unique_bytes <= summary.total_logical_bytes


def test_mixed_developer_and_non_developer_filtering():
    """Verify non-developer files (documents, music) are cleanly ignored."""
    items = [
        make_discovered_item("/Users/test/Projects/app/.venv", size_bytes=100 * 1024, category=SmartCategory.VIRTUAL_ENVIRONMENTS),
        make_discovered_item("/Users/test/Documents/invoice.pdf", size_bytes=500 * 1024, category=SmartCategory.DOCUMENTS),
        make_discovered_item("/Users/test/Music/song.mp3", size_bytes=10 * 1024 * 1024, category=SmartCategory.MUSIC),
    ]

    analyzer = DeveloperStorageAnalyzer()
    summary = analyzer.analyze_items(items)

    assert summary.total_findings_count == 1
    assert summary.total_logical_bytes == 100 * 1024


def test_empty_scan_result_handling():
    """Verify analyzing an empty ScanResult returns clean empty summary."""
    empty_scan = ScanResult(
        scope_id=ScopeIdentifier.DEVELOPER,
        root_path="/Users/test/Projects",
        status=ScanStatus.COMPLETED,
        start_time=100.0,
        end_time=101.0,
        duration_seconds=1.0,
    )

    analyzer = DeveloperStorageAnalyzer()
    summary = analyzer.analyze_scan_result(empty_scan)

    assert summary.total_findings_count == 0
    assert summary.total_logical_bytes == 0
    assert summary.total_unique_bytes == 0
    assert len(summary.groups) == 0
    assert len(summary.projects) == 0


def test_determinism_and_reproducibility():
    """Verify repeated analysis runs yield identical results."""
    items = [
        make_discovered_item("/Users/test/Projects/a/node_modules", size_bytes=300),
        make_discovered_item("/Users/test/Projects/b/.venv", size_bytes=200),
    ]

    analyzer = DeveloperStorageAnalyzer()
    res1 = analyzer.analyze_items(items)
    res2 = analyzer.analyze_items(items)

    assert res1.total_logical_bytes == res2.total_logical_bytes
    assert res1.total_unique_bytes == res2.total_unique_bytes
    assert len(res1.groups) == len(res2.groups)
    assert len(res1.projects) == len(res2.projects)


def test_no_filesystem_mutation_and_read_only(tmp_path):
    """
    SAFETY INVARIANT:
    DeveloperStorageAnalyzer does not read file contents or modify files.
    """
    sample = tmp_path / "mod.py"
    sample.write_text("content")
    mtime_before = sample.stat().st_mtime

    item = make_discovered_item(str(sample), size_bytes=len("content"), item_type="file", category=SmartCategory.DEVELOPER_DATA)

    with patch("builtins.open", side_effect=AssertionError("File opened!")):
        analyzer = DeveloperStorageAnalyzer()
        finding = analyzer.analyze_item(item)
        assert finding is not None

    mtime_after = sample.stat().st_mtime
    assert mtime_before == mtime_after


def test_safety_regression_developer_finding_does_not_authorize_cleanup():
    """
    SAFETY INVARIANT:
    A developer storage finding (e.g. 5GB node_modules) does NOT authorize cleanup in PathValidator.
    """
    node_modules_path = "/Users/test/Projects/critical_app/node_modules"

    # PathValidator MUST reject node_modules for clean operation because it is not in DEFAULT_CLEAN_ALLOWLIST_ROOTS
    validator = PathValidator(home_dir="/Users/test")
    val_result = validator.validate_path(node_modules_path, operation=Operation.CLEAN)

    assert val_result.allowed is False
    assert val_result.policy_rule == "RULE_ALLOWLIST_REJECTED"


def test_security_invariants_no_subprocess_or_hmac_access():
    """
    SECURITY INVARIANT:
    DeveloperStorageAnalyzer does not import or call subprocesses, HMAC keys, or execution components.
    """
    import sys
    dev_module = sys.modules["app.analysis.developer_analyzer"]

    assert not hasattr(dev_module, "subprocess")
    assert not hasattr(dev_module, "ApprovalKeyManager")
    assert not hasattr(dev_module, "ApprovalService")
    assert not hasattr(dev_module, "TrashExecutor")


def test_property_unique_bytes_always_lte_logical_bytes():
    """
    PROPERTY INVARIANT:
    For any collection of developer items, total_unique_bytes <= total_logical_bytes.
    """
    items = [
        make_discovered_item("/Users/test/Projects/a", size_bytes=1000, depth=1),
        make_discovered_item("/Users/test/Projects/a/b", size_bytes=500, depth=2),
        make_discovered_item("/Users/test/Projects/a/b/c", size_bytes=250, depth=3),
        make_discovered_item("/Users/test/Projects/other", size_bytes=800, depth=1),
    ]

    analyzer = DeveloperStorageAnalyzer()
    summary = analyzer.analyze_items(items)

    assert summary.total_unique_bytes <= summary.total_logical_bytes
    assert summary.total_logical_bytes == 2550
    assert summary.total_unique_bytes == 1800  # 1000 for /a + 800 for /other


def test_property_analyzer_does_not_mutate_input_list():
    """
    PROPERTY INVARIANT:
    Analyzer does not mutate the input items list or item attributes.
    """
    original_item = make_discovered_item("/Users/test/Projects/a/.venv", size_bytes=100)
    items = [original_item]

    analyzer = DeveloperStorageAnalyzer()
    summary = analyzer.analyze_items(items)

    assert len(items) == 1
    assert items[0] == original_item


def test_sorting_and_ranking_stability():
    """Verify groups and projects are stably sorted by unique bytes descending."""
    items = [
        make_discovered_item("/Users/test/Projects/small_proj/dist", size_bytes=100, category=SmartCategory.BUILD_ARTIFACTS),
        make_discovered_item("/Users/test/Projects/large_proj/node_modules", size_bytes=10000, category=SmartCategory.PACKAGE_MANAGERS),
        make_discovered_item("/Users/test/Projects/med_proj/.venv", size_bytes=5000, category=SmartCategory.VIRTUAL_ENVIRONMENTS),
    ]

    analyzer = DeveloperStorageAnalyzer()
    summary = analyzer.analyze_items(items)

    # Projects should be ordered: large_proj (10000), med_proj (5000), small_proj (100)
    assert [p.project_name for p in summary.projects] == ["large_proj", "med_proj", "small_proj"]
    # Groups should be ordered by unique bytes descending
    assert [g.subtype for g in summary.groups] == [
        DeveloperStorageSubtype.NODE_MODULES,
        DeveloperStorageSubtype.PYTHON_VENV,
        DeveloperStorageSubtype.BUILD_OUTPUT,
    ]
