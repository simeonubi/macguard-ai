"""
Tests for MacGuard AI v1.1 Phase 5B — Deterministic Storage Trends Engine.

Validates volume growth calculations, category and developer trend analytics,
scope compatibility enforcement, first-scan handling, and deterministic explainability.
"""

from __future__ import annotations

import pytest

from app.analysis.storage_trends import (
    DEFAULT_STABLE_THRESHOLD_PERCENT,
    StorageTrendsEngine,
)
from app.models.category import ConfidenceLevel, SmartCategory
from app.models.developer import DeveloperStorageSubtype
from app.models.scan_result import ScanStatus
from app.models.scan_scope import ScopeIdentifier
from app.models.storage_history import (
    CategorySnapshotItem,
    DeveloperSnapshotItem,
    LargeConsumerSnapshotItem,
    StorageSnapshot,
    StorageTrendReport,
    TrendDirection,
)


def make_snapshot(
    snapshot_id: str,
    timestamp: float,
    total_bytes: int,
    scope_id: ScopeIdentifier = ScopeIdentifier.HOME,
    root_path: str = "/Users/test",
    status: ScanStatus = ScanStatus.COMPLETED,
    categories: list[CategorySnapshotItem] | None = None,
    developer_subtypes: list[DeveloperSnapshotItem] | None = None,
) -> StorageSnapshot:
    """Helper to produce structured StorageSnapshot instances."""
    return StorageSnapshot(
        snapshot_id=snapshot_id,
        scan_id=f"scan_{snapshot_id}",
        timestamp=timestamp,
        scope_id=scope_id,
        root_path=root_path,
        status=status,
        duration_seconds=5.0,
        files_count=100,
        directories_count=20,
        total_bytes=total_bytes,
        categories=categories or [],
        developer_subtypes=developer_subtypes or [],
        top_consumers=[],
    )


def test_first_scan_experience_no_baseline():
    """Verify first scan without previous baseline returns structured non-comparable state."""
    current = make_snapshot("snap1", 100.0, 100 * 1024 * 1024 * 1024)
    engine = StorageTrendsEngine()
    report = engine.compare_snapshots(current=current, previous=None)

    assert report.is_comparable is False
    assert report.previous_snapshot_id is None
    assert report.overall_trend.direction == TrendDirection.UNKNOWN
    assert report.overall_trend.percentage_change is None
    assert "first recorded scan" in report.overall_trend.explanation
    assert report.category_trends == []
    assert report.developer_trends == []


def test_scope_incompatibility_enforcement():
    """Verify comparing different scopes or root paths returns non-comparable UNKNOWN report."""
    snap_home = make_snapshot("snap1", 100.0, 50000, scope_id=ScopeIdentifier.HOME, root_path="/Users/test")
    snap_dev = make_snapshot("snap2", 200.0, 80000, scope_id=ScopeIdentifier.DEVELOPER, root_path="/Users/test/Projects")

    engine = StorageTrendsEngine()
    report = engine.compare_snapshots(current=snap_dev, previous=snap_home)

    assert report.is_comparable is False
    assert report.overall_trend.direction == TrendDirection.UNKNOWN
    assert report.overall_trend.percentage_change is None
    assert report.overall_trend.absolute_change == 0
    assert "The previous scan used a different scope" in report.overall_trend.explanation
    assert len(report.notes) == 1
    assert "Incompatible scan comparison" in report.notes[0]


def test_system_root_vs_user_home_incompatibility():
    """Verify system root scan (CUSTOM /) vs user home (HOME /Users/test) is non-comparable."""
    snap_system = make_snapshot("snap_root", 100.0, 474 * 1024 * 1024 * 1024, scope_id=ScopeIdentifier.CUSTOM, root_path="/")
    snap_home = make_snapshot("snap_home", 200.0, 9 * 1024 * 1024 * 1024, scope_id=ScopeIdentifier.HOME, root_path="/Users/test")

    engine = StorageTrendsEngine()
    report = engine.compare_snapshots(current=snap_home, previous=snap_system)

    assert report.is_comparable is False
    assert report.overall_trend.direction == TrendDirection.UNKNOWN
    assert report.overall_trend.percentage_change is None
    assert report.overall_trend.absolute_change == 0
    assert "The previous scan used a different scope, so MacGuard will not interpret the difference as storage growth or shrinkage." == report.overall_trend.explanation


def test_different_custom_directories_incompatibility():
    """Verify custom scans of different directory roots are non-comparable."""
    snap_dir1 = make_snapshot("snap_d1", 100.0, 1000000, scope_id=ScopeIdentifier.CUSTOM, root_path="/Users/test/FolderA")
    snap_dir2 = make_snapshot("snap_d2", 200.0, 2000000, scope_id=ScopeIdentifier.CUSTOM, root_path="/Users/test/FolderB")

    engine = StorageTrendsEngine()
    report = engine.compare_snapshots(current=snap_dir2, previous=snap_dir1)

    assert report.is_comparable is False
    assert report.overall_trend.direction == TrendDirection.UNKNOWN
    assert report.overall_trend.percentage_change is None
    assert report.overall_trend.absolute_change == 0


def test_repeated_scans_same_scope_shows_valid_trends():
    """Verify repeated scans of the exact same scope compute valid growth and shrinkage."""
    snap1 = make_snapshot("snap1", 100.0, 10 * 1024 * 1024 * 1024, scope_id=ScopeIdentifier.HOME, root_path="/Users/test")
    snap2 = make_snapshot("snap2", 200.0, 12 * 1024 * 1024 * 1024, scope_id=ScopeIdentifier.HOME, root_path="/Users/test")

    engine = StorageTrendsEngine()
    report = engine.compare_snapshots(current=snap2, previous=snap1)

    assert report.is_comparable is True
    assert report.overall_trend.direction == TrendDirection.GROWING
    assert report.overall_trend.percentage_change == 20.0
    assert report.overall_trend.absolute_change == 2 * 1024 * 1024 * 1024


def test_overall_volume_growth_trend():
    """Verify overall volume growth exceeding threshold is classified as GROWING."""
    # 100 GB -> 120 GB (+20.0%)
    prev = make_snapshot("prev", 100.0, 100 * 1024 * 1024 * 1024)
    curr = make_snapshot("curr", 200.0, 120 * 1024 * 1024 * 1024)

    engine = StorageTrendsEngine(stable_threshold_percent=5.0)
    report = engine.compare_snapshots(current=curr, previous=prev)

    assert report.is_comparable is True
    assert report.overall_trend.direction == TrendDirection.GROWING
    assert report.overall_trend.absolute_change == 20 * 1024 * 1024 * 1024
    assert report.overall_trend.percentage_change == 20.0
    assert "increased by 20.00 GB (+20.00%)" in report.overall_trend.explanation


def test_overall_volume_shrinkage_trend():
    """Verify overall volume shrinkage below threshold is classified as SHRINKING."""
    # 100 GB -> 85 GB (-15.0%)
    prev = make_snapshot("prev", 100.0, 100 * 1024 * 1024 * 1024)
    curr = make_snapshot("curr", 200.0, 85 * 1024 * 1024 * 1024)

    engine = StorageTrendsEngine(stable_threshold_percent=5.0)
    report = engine.compare_snapshots(current=curr, previous=prev)

    assert report.is_comparable is True
    assert report.overall_trend.direction == TrendDirection.SHRINKING
    assert report.overall_trend.absolute_change == -15 * 1024 * 1024 * 1024
    assert report.overall_trend.percentage_change == -15.0
    assert "decreased by 15.00 GB (-15.00%)" in report.overall_trend.explanation


def test_overall_volume_stable_trend():
    """Verify changes within stable threshold are classified as STABLE."""
    # 100 GB -> 102 GB (+2.0%, threshold is 5.0%)
    prev = make_snapshot("prev", 100.0, 100 * 1024 * 1024 * 1024)
    curr = make_snapshot("curr", 200.0, 102 * 1024 * 1024 * 1024)

    engine = StorageTrendsEngine(stable_threshold_percent=5.0)
    report = engine.compare_snapshots(current=curr, previous=prev)

    assert report.is_comparable is True
    assert report.overall_trend.direction == TrendDirection.STABLE
    assert report.overall_trend.percentage_change == 2.0
    assert "remained stable" in report.overall_trend.explanation


def test_zero_previous_bytes_safe_handling():
    """Verify zero previous bytes does not raise divide-by-zero errors."""
    prev = make_snapshot("prev", 100.0, 0)
    curr = make_snapshot("curr", 200.0, 50 * 1024 * 1024 * 1024)

    engine = StorageTrendsEngine()
    report = engine.compare_snapshots(current=curr, previous=prev)

    assert report.overall_trend.percentage_change == 100.0
    assert report.overall_trend.direction == TrendDirection.GROWING


def test_category_trends_and_largest_growing_category():
    """Verify category trends calculation, ranking, and largest growing category identification."""
    prev_cats = [
        CategorySnapshotItem(category=SmartCategory.CACHES, total_bytes=10 * 1024 * 1024 * 1024, item_count=50),
        CategorySnapshotItem(category=SmartCategory.MEDIA, total_bytes=30 * 1024 * 1024 * 1024, item_count=10),
    ]
    curr_cats = [
        CategorySnapshotItem(category=SmartCategory.CACHES, total_bytes=25 * 1024 * 1024 * 1024, item_count=90),  # +15 GB
        CategorySnapshotItem(category=SmartCategory.MEDIA, total_bytes=20 * 1024 * 1024 * 1024, item_count=8),     # -10 GB
        CategorySnapshotItem(category=SmartCategory.DOCUMENTS, total_bytes=5 * 1024 * 1024 * 1024, item_count=5),  # New +5 GB
    ]

    prev = make_snapshot("prev", 100.0, 40 * 1024 * 1024 * 1024, categories=prev_cats)
    curr = make_snapshot("curr", 200.0, 50 * 1024 * 1024 * 1024, categories=curr_cats)

    engine = StorageTrendsEngine()
    report = engine.compare_snapshots(current=curr, previous=prev)

    assert len(report.category_trends) == 3
    # Sorted by largest increase: CACHES (+15 GB), DOCUMENTS (+5 GB), MEDIA (-10 GB)
    assert report.category_trends[0].category == SmartCategory.CACHES
    assert report.category_trends[0].direction == TrendDirection.GROWING
    assert report.category_trends[0].absolute_change == 15 * 1024 * 1024 * 1024

    assert report.category_trends[1].category == SmartCategory.DOCUMENTS
    assert report.category_trends[1].direction == TrendDirection.GROWING
    assert report.category_trends[1].absolute_change == 5 * 1024 * 1024 * 1024

    assert report.category_trends[2].category == SmartCategory.MEDIA
    assert report.category_trends[2].direction == TrendDirection.SHRINKING
    assert report.category_trends[2].absolute_change == -10 * 1024 * 1024 * 1024

    assert report.largest_growing_category == SmartCategory.CACHES


def test_developer_trends_and_largest_growing_subtype():
    """Verify developer subtype trends calculation and largest growing subtype identification."""
    prev_dev = [
        DeveloperSnapshotItem(subtype=DeveloperStorageSubtype.NODE_MODULES, total_bytes=10 * 1024 * 1024 * 1024, unique_bytes=10 * 1024 * 1024 * 1024, item_count=5),
        DeveloperSnapshotItem(subtype=DeveloperStorageSubtype.PYTHON_VENV, total_bytes=8 * 1024 * 1024 * 1024, unique_bytes=8 * 1024 * 1024 * 1024, item_count=4),
    ]
    curr_dev = [
        DeveloperSnapshotItem(subtype=DeveloperStorageSubtype.NODE_MODULES, total_bytes=18 * 1024 * 1024 * 1024, unique_bytes=18 * 1024 * 1024 * 1024, item_count=8),  # +8 GB
        DeveloperSnapshotItem(subtype=DeveloperStorageSubtype.PYTHON_VENV, total_bytes=8 * 1024 * 1024 * 1024, unique_bytes=8 * 1024 * 1024 * 1024, item_count=4),     # 0 GB
    ]

    prev = make_snapshot("prev", 100.0, 18 * 1024 * 1024 * 1024, developer_subtypes=prev_dev)
    curr = make_snapshot("curr", 200.0, 26 * 1024 * 1024 * 1024, developer_subtypes=curr_dev)

    engine = StorageTrendsEngine()
    report = engine.compare_snapshots(current=curr, previous=prev)

    assert len(report.developer_trends) == 2
    assert report.developer_trends[0].subtype == DeveloperStorageSubtype.NODE_MODULES
    assert report.developer_trends[0].direction == TrendDirection.GROWING
    assert report.developer_trends[0].absolute_change == 8 * 1024 * 1024 * 1024

    assert report.developer_trends[1].subtype == DeveloperStorageSubtype.PYTHON_VENV
    assert report.developer_trends[1].direction == TrendDirection.STABLE

    assert report.largest_growing_developer_subtype == DeveloperStorageSubtype.NODE_MODULES


def test_incomplete_scan_comparison_warning():
    """Verify incomplete scan status generates explicit diagnostic warning notes."""
    prev = make_snapshot("prev", 100.0, 50000, status=ScanStatus.COMPLETED)
    curr = make_snapshot("curr", 200.0, 60000, status=ScanStatus.ENTRY_LIMIT_REACHED)

    engine = StorageTrendsEngine()
    report = engine.compare_snapshots(current=curr, previous=prev)

    assert report.is_comparable is True
    assert len(report.notes) == 1
    assert "not fully completed" in report.notes[0]
    assert "ENTRY_LIMIT_REACHED" in report.notes[0]


def test_invalid_engine_threshold():
    """Verify ValueError is raised if stable_threshold_percent is negative."""
    with pytest.raises(ValueError, match="stable_threshold_percent cannot be negative"):
        StorageTrendsEngine(stable_threshold_percent=-1.0)


def test_disappearing_category_and_developer_subtype():
    """Verify categories and developer subtypes absent in current scan report 100% shrinkage."""
    prev_cats = [
        CategorySnapshotItem(category=SmartCategory.CACHES, total_bytes=10000, item_count=5),
    ]
    curr_cats: list[CategorySnapshotItem] = []

    prev_dev = [
        DeveloperSnapshotItem(subtype=DeveloperStorageSubtype.BUILD_OUTPUT, total_bytes=5000, unique_bytes=5000, item_count=2),
    ]
    curr_dev: list[DeveloperSnapshotItem] = []

    prev = make_snapshot("prev", 100.0, 15000, categories=prev_cats, developer_subtypes=prev_dev)
    curr = make_snapshot("curr", 200.0, 0, categories=curr_cats, developer_subtypes=curr_dev)

    engine = StorageTrendsEngine()
    report = engine.compare_snapshots(current=curr, previous=prev)

    assert len(report.category_trends) == 1
    assert report.category_trends[0].category == SmartCategory.CACHES
    assert report.category_trends[0].direction == TrendDirection.SHRINKING
    assert report.category_trends[0].absolute_change == -10000
    assert report.category_trends[0].percentage_change == -100.0

    assert len(report.developer_trends) == 1
    assert report.developer_trends[0].subtype == DeveloperStorageSubtype.BUILD_OUTPUT
    assert report.developer_trends[0].direction == TrendDirection.SHRINKING
    assert report.developer_trends[0].absolute_change == -5000
    assert report.developer_trends[0].percentage_change == -100.0


def test_unknown_category_trend_preservation():
    """Verify UNKNOWN category changes are computed and preserved."""
    prev_cats = [
        CategorySnapshotItem(category=SmartCategory.UNKNOWN, total_bytes=5000, item_count=2),
    ]
    curr_cats = [
        CategorySnapshotItem(category=SmartCategory.UNKNOWN, total_bytes=15000, item_count=6),
    ]

    prev = make_snapshot("prev", 100.0, 5000, categories=prev_cats)
    curr = make_snapshot("curr", 200.0, 15000, categories=curr_cats)

    engine = StorageTrendsEngine()
    report = engine.compare_snapshots(current=curr, previous=prev)

    assert len(report.category_trends) == 1
    assert report.category_trends[0].category == SmartCategory.UNKNOWN
    assert report.category_trends[0].direction == TrendDirection.GROWING
    assert report.category_trends[0].absolute_change == 10000


def test_trend_report_immutability():
    """Verify StorageTrendReport and submodels are frozen."""
    prev = make_snapshot("prev", 100.0, 10000)
    curr = make_snapshot("curr", 200.0, 20000)

    engine = StorageTrendsEngine()
    report = engine.compare_snapshots(current=curr, previous=prev)

    with pytest.raises(Exception):
        report.is_comparable = False  # type: ignore

    with pytest.raises(Exception):
        report.overall_trend.absolute_change = 0  # type: ignore


def test_deterministic_trend_report_reproducibility():
    """Verify repeated trend comparisons on identical inputs produce identical reports."""
    prev = make_snapshot("prev", 100.0, 10000)
    curr = make_snapshot("curr", 200.0, 20000)

    engine = StorageTrendsEngine()
    run1 = engine.compare_snapshots(current=curr, previous=prev)
    run2 = engine.compare_snapshots(current=curr, previous=prev)

    assert run1.model_dump() == run2.model_dump()


def test_both_zero_category_trends():
    """Verify category with 0 bytes in both snapshots reports 0.0% change and STABLE."""
    prev = make_snapshot("prev", 100.0, 1000)
    curr = make_snapshot("curr", 200.0, 1000)

    engine = StorageTrendsEngine()
    trend = engine._compute_metric_trend("Test Metric", current_bytes=0, previous_bytes=0, threshold_pct=5.0)

    assert trend.absolute_change == 0
    assert trend.percentage_change == 0.0
    assert trend.direction == TrendDirection.STABLE


def test_empty_root_path_rejection_in_snapshot():
    """Verify Pydantic rejects empty root_path in StorageSnapshot."""
    with pytest.raises(Exception):
        StorageSnapshot(
            snapshot_id="snap1",
            scan_id="scan1",
            timestamp=100.0,
            scope_id=ScopeIdentifier.HOME,
            root_path="",
            status=ScanStatus.COMPLETED,
            duration_seconds=1.0,
            files_count=1,
            directories_count=1,
            total_bytes=100,
        )


def test_trends_engine_cannot_perform_actions():
    """Verify StorageTrendsEngine has no execution, approval, or deletion methods."""
    engine = StorageTrendsEngine()

    assert not hasattr(engine, "approve")
    assert not hasattr(engine, "delete")
    assert not hasattr(engine, "trash")
    assert not hasattr(engine, "execute")
    assert not hasattr(engine, "sign_hmac")


