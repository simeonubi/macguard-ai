"""
Tests for MacGuard AI v1.1 Phase 5B — Persistent Storage History Repository.

Validates atomic SQLite persistence, idempotency, bounded retention, foreign key cascade,
and strict read-only safety invariants.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
import time
from pathlib import Path
from unittest.mock import patch
import pytest

from app.analysis.storage_history import (
    DEFAULT_SNAPSHOT_RETENTION_COUNT,
    StorageHistoryRepository,
)
from app.models.category import ConfidenceLevel, SmartCategory
from app.models.developer import (
    DeveloperProjectSummary,
    DeveloperStorageFinding,
    DeveloperStorageGroup,
    DeveloperStorageSubtype,
    DeveloperStorageSummary,
    StaleStatus,
)
from app.models.large_file import (
    LargeFileCategorySummary,
    LargeFileFinding,
    LargeFileSummary,
)
from app.models.scan_result import DiscoveredItem, ScanResult, ScanStatus
from app.models.scan_scope import ScopeIdentifier
from app.models.storage_history import (
    CategorySnapshotItem,
    DeveloperSnapshotItem,
    LargeConsumerSnapshotItem,
    StorageSnapshot,
)


@pytest.fixture
def temp_db(tmp_path: Path) -> Path:
    """Fixture providing a temporary SQLite database path."""
    return tmp_path / "test_history.db"


@pytest.fixture
def repo(temp_db: Path) -> StorageHistoryRepository:
    """Fixture providing a StorageHistoryRepository instance."""
    return StorageHistoryRepository(db_path=temp_db)


def make_scan_result(
    scope_id: ScopeIdentifier = ScopeIdentifier.HOME,
    root_path: str = "/Users/test",
    total_bytes: int = 10 * 1024 * 1024 * 1024,
    files_count: int = 100,
    directories_count: int = 20,
    start_time: float = 1710000000.0,
    end_time: float = 1710000010.0,
    status: ScanStatus = ScanStatus.COMPLETED,
    items: Optional[List[DiscoveredItem]] = None,
) -> ScanResult:
    """Helper to produce synthetic ScanResult objects."""
    effective_items = (
        items
        if items is not None
        else [
            DiscoveredItem(
                path=f"{root_path}/Documents/file_1.dat",
                size_bytes=min(total_bytes, 1024 * 1024),
                item_type="file",
                depth=1,
                mtime=start_time,
                st_ino=1001,
                st_dev=1,
                category=SmartCategory.DOCUMENTS,
            )
        ]
    )
    return ScanResult(
        scope_id=scope_id,
        root_path=root_path,
        status=status,
        start_time=start_time,
        end_time=end_time,
        duration_seconds=end_time - start_time,
        files_count=files_count,
        directories_count=directories_count,
        total_bytes=total_bytes,
        items=effective_items,
    )


def test_snapshot_model_immutability():
    """Verify StorageSnapshot is frozen and rejects mutation and extra fields."""
    snapshot = StorageSnapshot(
        snapshot_id="snap-123",
        scan_id="scan-123",
        timestamp=1710000000.0,
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/test",
        status=ScanStatus.COMPLETED,
        duration_seconds=5.0,
        files_count=50,
        directories_count=10,
        total_bytes=5000000,
    )

    with pytest.raises(Exception):
        snapshot.total_bytes = 10000000  # type: ignore

    with pytest.raises(Exception):
        StorageSnapshot(
            snapshot_id="snap-123",
            scan_id="scan-123",
            timestamp=1710000000.0,
            scope_id=ScopeIdentifier.HOME,
            root_path="/Users/test",
            status=ScanStatus.COMPLETED,
            duration_seconds=5.0,
            files_count=50,
            directories_count=10,
            total_bytes=5000000,
            unauthorized_field="malicious",  # type: ignore
        )


def test_record_and_retrieve_basic_snapshot(repo: StorageHistoryRepository):
    """Verify recording and querying a minimal scan result."""
    scan = make_scan_result(total_bytes=20 * 1024 * 1024 * 1024)
    snapshot = repo.record_snapshot(scan)

    assert snapshot.total_bytes == 20 * 1024 * 1024 * 1024
    assert snapshot.scope_id == ScopeIdentifier.HOME
    assert snapshot.root_path == "/Users/test"

    # Query by ID
    retrieved = repo.get_snapshot_by_id(snapshot.snapshot_id)
    assert retrieved is not None
    assert retrieved.snapshot_id == snapshot.snapshot_id
    assert retrieved.total_bytes == snapshot.total_bytes

    # Query by scan_id
    by_scan = repo.get_snapshot_by_scan_id(snapshot.scan_id)
    assert by_scan is not None
    assert by_scan.snapshot_id == snapshot.snapshot_id


def test_record_snapshot_with_full_summaries(repo: StorageHistoryRepository):
    """Verify recording a snapshot with category, developer, and large-file summaries."""
    scan = make_scan_result(total_bytes=50 * 1024 * 1024 * 1024)

    # Category summaries
    cat_summaries = [
        LargeFileCategorySummary(
            category=SmartCategory.DEVELOPER_DATA,
            total_logical_bytes=30 * 1024 * 1024 * 1024,
            unique_physical_bytes=25 * 1024 * 1024 * 1024,
            item_count=15,
            percentage_of_large_storage=60.0,
        ),
        LargeFileCategorySummary(
            category=SmartCategory.CACHES,
            total_logical_bytes=20 * 1024 * 1024 * 1024,
            unique_physical_bytes=20 * 1024 * 1024 * 1024,
            item_count=10,
            percentage_of_large_storage=40.0,
        ),
    ]

    # Developer summary
    dev_summary = DeveloperStorageSummary(
        total_logical_bytes=30 * 1024 * 1024 * 1024,
        total_unique_bytes=25 * 1024 * 1024 * 1024,
        total_findings_count=15,
        groups=[
            DeveloperStorageGroup(
                subtype=DeveloperStorageSubtype.NODE_MODULES,
                title="Node Modules",
                total_logical_bytes=18 * 1024 * 1024 * 1024,
                unique_physical_bytes=18 * 1024 * 1024 * 1024,
                item_count=8,
                findings=[],
                stale_item_count=0,
                stale_bytes=0,
            ),
            DeveloperStorageGroup(
                subtype=DeveloperStorageSubtype.PYTHON_VENV,
                title="Python Virtual Environments",
                total_logical_bytes=12 * 1024 * 1024 * 1024,
                unique_physical_bytes=7 * 1024 * 1024 * 1024,
                item_count=7,
                findings=[],
                stale_item_count=2,
                stale_bytes=4 * 1024 * 1024 * 1024,
            ),
        ],
        projects=[],
        large_artifacts=[],
        stale_findings=[],
    )

    # Large file summary
    lf_findings = [
        LargeFileFinding(
            path="/Users/test/Projects/app/node_modules",
            size_bytes=8 * 1024 * 1024 * 1024,
            category=SmartCategory.DEVELOPER_DATA,
            confidence=ConfidenceLevel.HIGH,
            rank=1,
            size_threshold_bytes=50 * 1024 * 1024,
            attention_score=80.0,
            rationale="Large node_modules directory.",
        )
    ]
    lf_summary = LargeFileSummary(
        total_logical_bytes=8 * 1024 * 1024 * 1024,
        total_unique_bytes=8 * 1024 * 1024 * 1024,
        total_findings_count=1,
        size_threshold_bytes=50 * 1024 * 1024,
        findings=lf_findings,
        top_findings=lf_findings,
        category_summaries=[],
        developer_summaries=[],
    )

    snapshot = repo.record_snapshot(
        scan_result=scan,
        category_summaries=cat_summaries,
        developer_summary=dev_summary,
        large_file_summary=lf_summary,
    )

    retrieved = repo.get_snapshot_by_id(snapshot.snapshot_id)
    assert retrieved is not None
    assert len(retrieved.categories) == 2
    assert retrieved.categories[0].category == SmartCategory.DEVELOPER_DATA
    assert len(retrieved.developer_subtypes) == 2
    assert retrieved.developer_subtypes[0].subtype == DeveloperStorageSubtype.NODE_MODULES
    assert len(retrieved.top_consumers) == 1
    assert retrieved.top_consumers[0].path == "/Users/test/Projects/app/node_modules"


def test_idempotency_on_duplicate_scan_id(repo: StorageHistoryRepository):
    """Verify repeated recordings of the same scan_id do not create duplicates."""
    scan = make_scan_result(start_time=100.0, end_time=110.0, total_bytes=5000)
    snap1 = repo.record_snapshot(scan, scan_id="scan_fixed_id")
    snap2 = repo.record_snapshot(scan, scan_id="scan_fixed_id")

    assert snap1.snapshot_id == snap2.snapshot_id

    # Verify only 1 row in table
    history = repo.get_snapshot_history(ScopeIdentifier.HOME)
    assert len(history) == 1


def test_get_previous_snapshot_chronology(repo: StorageHistoryRepository):
    """Verify get_previous_snapshot returns the latest snapshot strictly prior to timestamp."""
    scan1 = make_scan_result(start_time=100.0, end_time=110.0, total_bytes=1000)
    scan2 = make_scan_result(start_time=200.0, end_time=210.0, total_bytes=2000)
    scan3 = make_scan_result(start_time=300.0, end_time=310.0, total_bytes=3000)

    snap1 = repo.record_snapshot(scan1, scan_id="scan1")
    snap2 = repo.record_snapshot(scan2, scan_id="scan2")
    snap3 = repo.record_snapshot(scan3, scan_id="scan3")

    # Previous of snap3 is snap2
    prev3 = repo.get_previous_snapshot(snap3)
    assert prev3 is not None
    assert prev3.snapshot_id == snap2.snapshot_id

    # Previous of snap2 is snap1
    prev2 = repo.get_previous_snapshot(snap2)
    assert prev2 is not None
    assert prev2.snapshot_id == snap1.snapshot_id

    # Previous of snap1 is None (first scan)
    prev1 = repo.get_previous_snapshot(snap1)
    assert prev1 is None


def test_get_latest_snapshot(repo: StorageHistoryRepository):
    """Verify get_latest_snapshot returns the most recent record."""
    scan1 = make_scan_result(start_time=100.0, end_time=110.0, total_bytes=1000)
    scan2 = make_scan_result(start_time=200.0, end_time=210.0, total_bytes=2000)

    repo.record_snapshot(scan1, scan_id="scan1")
    snap2 = repo.record_snapshot(scan2, scan_id="scan2")

    latest = repo.get_latest_snapshot(ScopeIdentifier.HOME)
    assert latest is not None
    assert latest.snapshot_id == snap2.snapshot_id


def test_retention_and_cascade_deletion(repo: StorageHistoryRepository, temp_db: Path):
    """Verify bounded retention removes oldest snapshots and cascades to child tables."""
    # Create 5 snapshots with retention limit 3
    for i in range(5):
        scan = make_scan_result(start_time=100.0 + (i * 50), end_time=110.0 + (i * 50), total_bytes=(i + 1) * 1000)
        repo.record_snapshot(scan, scan_id=f"scan_ret_{i}", max_retention=3)

    # History should contain only 3 snapshots (indices 4, 3, 2)
    history = repo.get_snapshot_history(ScopeIdentifier.HOME)
    assert len(history) == 3
    assert history[0].scan_id == "scan_ret_4"
    assert history[1].scan_id == "scan_ret_3"
    assert history[2].scan_id == "scan_ret_2"

    # Verify directly via SQL that child records for pruned snapshots (0 and 1) are gone
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM storage_snapshots")
    assert cursor.fetchone()[0] == 3
    conn.close()


def test_in_memory_database():
    """Verify repository functions properly in :memory: mode for transient test execution."""
    mem_repo = StorageHistoryRepository(db_path=":memory:")
    scan = make_scan_result()
    snap = mem_repo.record_snapshot(scan)

    retrieved = mem_repo.get_snapshot_by_id(snap.snapshot_id)
    assert retrieved is not None
    assert retrieved.snapshot_id == snap.snapshot_id


def test_no_filesystem_mutation_or_execution_access(repo: StorageHistoryRepository):
    """Verify repository never modifies files on disk or invokes execution executors."""
    scan = make_scan_result()

    with patch("os.remove") as mock_remove, \
         patch("shutil.rmtree") as mock_rmtree, \
         patch("subprocess.run") as mock_sub:

        repo.record_snapshot(scan)
        repo.get_latest_snapshot(ScopeIdentifier.HOME)
        repo.prune_history(ScopeIdentifier.HOME)

        mock_remove.assert_not_called()
        mock_rmtree.assert_not_called()
        mock_sub.assert_not_called()


def test_record_snapshot_without_summaries_aggregates_items(repo: StorageHistoryRepository):
    """Verify raw DiscoveredItem list is aggregated into categories when summaries are absent."""
    items = [
        DiscoveredItem(
            path="/Users/test/cache1.dat",
            size_bytes=1000,
            item_type="file",
            depth=2,
            mtime=1700000000.0,
            st_ino=1,
            st_dev=1,
            category=SmartCategory.CACHES,
            confidence=ConfidenceLevel.HIGH,
        ),
        DiscoveredItem(
            path="/Users/test/cache2.dat",
            size_bytes=2000,
            item_type="file",
            depth=2,
            mtime=1700000000.0,
            st_ino=2,
            st_dev=1,
            category=SmartCategory.CACHES,
            confidence=ConfidenceLevel.HIGH,
        ),
        DiscoveredItem(
            path="/Users/test/doc.pdf",
            size_bytes=5000,
            item_type="file",
            depth=2,
            mtime=1700000000.0,
            st_ino=3,
            st_dev=1,
            category=SmartCategory.DOCUMENTS,
            confidence=ConfidenceLevel.HIGH,
        ),
    ]

    scan = ScanResult(
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/test",
        status=ScanStatus.COMPLETED,
        start_time=100.0,
        end_time=110.0,
        duration_seconds=10.0,
        files_count=3,
        directories_count=1,
        total_bytes=8000,
        items=items,
    )

    snap = repo.record_snapshot(scan)
    assert len(snap.categories) == 2
    cat_map = {c.category: c for c in snap.categories}
    assert cat_map[SmartCategory.CACHES].total_bytes == 3000
    assert cat_map[SmartCategory.CACHES].item_count == 2
    assert cat_map[SmartCategory.DOCUMENTS].total_bytes == 5000
    assert cat_map[SmartCategory.DOCUMENTS].item_count == 1


def test_nonexistent_queries_return_none(repo: StorageHistoryRepository):
    """Verify querying non-existent snapshots returns None."""
    assert repo.get_snapshot_by_id("non_existent_id") is None
    assert repo.get_snapshot_by_scan_id("non_existent_scan_id") is None
    assert repo.get_latest_snapshot(ScopeIdentifier.DOWNLOADS) is None


def test_prune_history_when_count_less_than_max(repo: StorageHistoryRepository):
    """Verify prune_history returns 0 when count is below limit."""
    scan = make_scan_result()
    repo.record_snapshot(scan, scan_id="snap1")
    pruned = repo.prune_history(ScopeIdentifier.HOME, max_snapshots=10)
    assert pruned == 0


def test_storage_snapshot_unique_bytes_from_developer_summary(repo: StorageHistoryRepository):
    """Verify unique_bytes is taken from developer_summary if large_file_summary is None."""
    scan = make_scan_result(total_bytes=10000)
    dev_summary = DeveloperStorageSummary(
        total_logical_bytes=10000,
        total_unique_bytes=8500,
        total_findings_count=4,
        groups=[],
        projects=[],
        large_artifacts=[],
        stale_findings=[],
    )

    snap = repo.record_snapshot(scan, developer_summary=dev_summary)
    assert snap.unique_bytes == 8500


def test_custom_db_directory_created(tmp_path: Path):
    """Verify nested parent directory of custom DB path is automatically created."""
    nested_db = tmp_path / "deep" / "nested" / "dir" / "custom.db"
    assert not nested_db.parent.exists()

    repo = StorageHistoryRepository(db_path=nested_db)
    assert nested_db.parent.exists()
    assert nested_db.exists()


def test_large_consumer_rank_order_retrieval(repo: StorageHistoryRepository):
    """Verify top large consumers are persisted and retrieved in rank order."""
    scan = make_scan_result(total_bytes=100 * 1024 * 1024 * 1024)
    lf_findings = [
        LargeFileFinding(
            path="/Users/test/large3.iso",
            size_bytes=5 * 1024 * 1024 * 1024,
            category=SmartCategory.ARCHIVES,
            confidence=ConfidenceLevel.HIGH,
            rank=3,
            size_threshold_bytes=50 * 1024 * 1024,
            attention_score=70.0,
            rationale="Archive 3",
        ),
        LargeFileFinding(
            path="/Users/test/large1.iso",
            size_bytes=20 * 1024 * 1024 * 1024,
            category=SmartCategory.ARCHIVES,
            confidence=ConfidenceLevel.HIGH,
            rank=1,
            size_threshold_bytes=50 * 1024 * 1024,
            attention_score=90.0,
            rationale="Archive 1",
        ),
        LargeFileFinding(
            path="/Users/test/large2.iso",
            size_bytes=10 * 1024 * 1024 * 1024,
            category=SmartCategory.ARCHIVES,
            confidence=ConfidenceLevel.HIGH,
            rank=2,
            size_threshold_bytes=50 * 1024 * 1024,
            attention_score=80.0,
            rationale="Archive 2",
        ),
    ]

    lf_summary = LargeFileSummary(
        total_logical_bytes=35 * 1024 * 1024 * 1024,
        total_unique_bytes=35 * 1024 * 1024 * 1024,
        total_findings_count=3,
        size_threshold_bytes=50 * 1024 * 1024,
        findings=lf_findings,
        top_findings=sorted(lf_findings, key=lambda f: f.rank),
        category_summaries=[],
        developer_summaries=[],
    )

    snap = repo.record_snapshot(scan, large_file_summary=lf_summary)
    retrieved = repo.get_snapshot_by_id(snap.snapshot_id)
    assert retrieved is not None
    assert len(retrieved.top_consumers) == 3
    assert [c.rank for c in retrieved.top_consumers] == [1, 2, 3]
    assert retrieved.top_consumers[0].path == "/Users/test/large1.iso"
    assert retrieved.top_consumers[1].path == "/Users/test/large2.iso"
    assert retrieved.top_consumers[2].path == "/Users/test/large3.iso"


def test_foreign_key_cascade_on_raw_sql_delete(repo: StorageHistoryRepository, temp_db: Path):
    """Verify raw SQLite DELETE on snapshot cascades to all 3 child tables."""
    scan = make_scan_result(total_bytes=1000)
    cat_summary = [
        LargeFileCategorySummary(
            category=SmartCategory.CACHES,
            total_logical_bytes=1000,
            unique_physical_bytes=1000,
            item_count=1,
            percentage_of_large_storage=100.0,
        )
    ]
    snap = repo.record_snapshot(scan, category_summaries=cat_summary)

    conn = sqlite3.connect(temp_db)
    conn.execute("PRAGMA foreign_keys = ON;")
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM category_storage_history WHERE snapshot_id = ?", (snap.snapshot_id,))
    assert cursor.fetchone()[0] == 1

    # Delete parent snapshot row
    cursor.execute("DELETE FROM storage_snapshots WHERE snapshot_id = ?", (snap.snapshot_id,))
    conn.commit()

    # Child rows must be 0 via CASCADE
    cursor.execute("SELECT COUNT(*) FROM category_storage_history WHERE snapshot_id = ?", (snap.snapshot_id,))
    assert cursor.fetchone()[0] == 0
    conn.close()


def test_path_boundary_containment_semantics():
    """Verify path boundary containment avoids naive string prefix matching."""
    from app.analysis.storage_history import is_path_contained_in_root

    # Standard positive matches
    assert is_path_contained_in_root("/Users/mac/Library/Caches", "/Users/mac") is True
    assert is_path_contained_in_root("/Users/mac/Downloads/file.iso", "/Users/mac") is True
    assert is_path_contained_in_root("/Users/mac", "/Users/mac") is True

    # Path boundary false positives that naive str.startswith would wrongly allow
    assert is_path_contained_in_root("/Users/machine", "/Users/mac") is False
    assert is_path_contained_in_root("/Users/mac_backup", "/Users/mac") is False
    assert is_path_contained_in_root("/Users/macaroni/file.txt", "/Users/mac") is False

    # Out of boundary system paths
    assert is_path_contained_in_root("/System", "/Users/mac") is False
    assert is_path_contained_in_root("/Applications", "/Users/mac") is False
    assert is_path_contained_in_root("/Library", "/Users/mac") is False
    assert is_path_contained_in_root("/private/var", "/Users/mac") is False

    # Root scope target accepts all absolute paths
    assert is_path_contained_in_root("/System", "/") is True
    assert is_path_contained_in_root("/Applications", "/") is True
    assert is_path_contained_in_root("/Users/mac", "/") is True
    assert is_path_contained_in_root("/Library", "/") is True


def test_legacy_474gb_snapshot_excluded_from_home_scope(repo: StorageHistoryRepository):
    """
    Regression test reproducing the legacy Comprehensive scan stored under HOME with out-of-boundary consumers.
    Must be excluded from HOME history, latest baseline, and previous baseline.
    """
    # 1. Genuine HOME snapshot 1 (older)
    scan_home1 = make_scan_result(
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/mac",
        total_bytes=9 * 1024 * 1024 * 1024,
        start_time=1710000000.0,
        end_time=1710000010.0,
    )
    lf_home1 = LargeFileSummary(
        total_logical_bytes=9 * 1024 * 1024 * 1024,
        total_unique_bytes=9 * 1024 * 1024 * 1024,
        total_findings_count=1,
        size_threshold_bytes=50 * 1024 * 1024,
        findings=[],
        top_findings=[
            LargeFileFinding(
                path="/Users/mac/Downloads/huge.dmg",
                size_bytes=9 * 1024 * 1024 * 1024,
                category=SmartCategory.ARCHIVES,
                confidence=ConfidenceLevel.HIGH,
                rank=1,
                size_threshold_bytes=50 * 1024 * 1024,
                attention_score=90.0,
                rationale="User file",
            )
        ],
        category_summaries=[],
        developer_summaries=[],
    )
    snap_home1 = repo.record_snapshot(scan_home1, large_file_summary=lf_home1)

    # 2. Legacy Comprehensive scan recorded with scope_id=HOME, root_path=/Users/mac, 474 GB
    scan_legacy_root = make_scan_result(
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/mac",
        total_bytes=474 * 1024 * 1024 * 1024,
        start_time=1710000100.0,
        end_time=1710000150.0,
    )
    lf_legacy_root = LargeFileSummary(
        total_logical_bytes=474 * 1024 * 1024 * 1024,
        total_unique_bytes=474 * 1024 * 1024 * 1024,
        total_findings_count=3,
        size_threshold_bytes=50 * 1024 * 1024,
        findings=[],
        top_findings=[
            LargeFileFinding(
                path="/System/Library/Assets",
                size_bytes=200 * 1024 * 1024 * 1024,
                category=SmartCategory.SYSTEM_DATA,
                confidence=ConfidenceLevel.HIGH,
                rank=1,
                size_threshold_bytes=50 * 1024 * 1024,
                attention_score=95.0,
                rationale="System storage",
            ),
            LargeFileFinding(
                path="/Applications/Xcode.app",
                size_bytes=30 * 1024 * 1024 * 1024,
                category=SmartCategory.APPLICATIONS,
                confidence=ConfidenceLevel.HIGH,
                rank=2,
                size_threshold_bytes=50 * 1024 * 1024,
                attention_score=90.0,
                rationale="Application bundle",
            ),
            LargeFileFinding(
                path="/Library/Developer/CoreSimulator",
                size_bytes=20 * 1024 * 1024 * 1024,
                category=SmartCategory.DEVELOPER_DATA,
                confidence=ConfidenceLevel.HIGH,
                rank=3,
                size_threshold_bytes=50 * 1024 * 1024,
                attention_score=85.0,
                rationale="System developer cache",
            ),
        ],
        category_summaries=[],
        developer_summaries=[],
    )
    snap_legacy = repo.record_snapshot(scan_legacy_root, large_file_summary=lf_legacy_root)

    # 3. Genuine HOME snapshot 2 (latest)
    scan_home2 = make_scan_result(
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/mac",
        total_bytes=10 * 1024 * 1024 * 1024,
        start_time=1710000200.0,
        end_time=1710000210.0,
    )
    lf_home2 = LargeFileSummary(
        total_logical_bytes=10 * 1024 * 1024 * 1024,
        total_unique_bytes=10 * 1024 * 1024 * 1024,
        total_findings_count=1,
        size_threshold_bytes=50 * 1024 * 1024,
        findings=[],
        top_findings=[
            LargeFileFinding(
                path="/Users/mac/.cache/models.bin",
                size_bytes=5 * 1024 * 1024 * 1024,
                category=SmartCategory.CACHES,
                confidence=ConfidenceLevel.HIGH,
                rank=1,
                size_threshold_bytes=50 * 1024 * 1024,
                attention_score=90.0,
                rationale="User cache",
            )
        ],
        category_summaries=[],
        developer_summaries=[],
    )
    snap_home2 = repo.record_snapshot(scan_home2, large_file_summary=lf_home2)

    # 4. Verify get_snapshot_history excludes legacy 474 GB snapshot
    history = repo.get_snapshot_history(ScopeIdentifier.HOME, root_path="/Users/mac")
    assert len(history) == 2
    assert [s.snapshot_id for s in history] == [snap_home2.snapshot_id, snap_home1.snapshot_id]
    assert all(s.total_bytes < 20 * 1024 * 1024 * 1024 for s in history)
    assert snap_legacy.snapshot_id not in [s.snapshot_id for s in history]

    # 5. Verify get_latest_snapshot returns genuine snap_home2
    latest = repo.get_latest_snapshot(ScopeIdentifier.HOME, root_path="/Users/mac")
    assert latest is not None
    assert latest.snapshot_id == snap_home2.snapshot_id

    # 6. Verify get_previous_snapshot returns genuine snap_home1 (skipping legacy snap)
    prev = repo.get_previous_snapshot(snap_home2)
    assert prev is not None
    assert prev.snapshot_id == snap_home1.snapshot_id


def test_snapshot_scope_compatibility_triplet_cases():
    """
    Verify conservative scope containment validator behavior:
    1. Matching HOME scope/root + empty top_consumers => incompatible / excluded (False).
    2. Matching HOME scope/root + valid contained consumers => compatible (True).
    3. Matching HOME scope/root + one out-of-bound consumer => incompatible / excluded (False).
    4. Root scope target ("/") => compatible with absolute paths.
    """
    from app.analysis.storage_history import is_snapshot_scope_compatible

    # 1. Matching HOME scope/root + empty top_consumers
    snap_empty_consumers = StorageSnapshot(
        snapshot_id="snap-empty",
        scan_id="scan-empty",
        timestamp=1710000000.0,
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/mac",
        status=ScanStatus.COMPLETED,
        duration_seconds=1.0,
        files_count=10,
        directories_count=2,
        total_bytes=1000000,
        top_consumers=[],
    )
    assert is_snapshot_scope_compatible(snap_empty_consumers, ScopeIdentifier.HOME, "/Users/mac") is False

    # 2. Matching HOME scope/root + valid contained consumers
    snap_valid_consumers = StorageSnapshot(
        snapshot_id="snap-valid",
        scan_id="scan-valid",
        timestamp=1710000010.0,
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/mac",
        status=ScanStatus.COMPLETED,
        duration_seconds=1.0,
        files_count=100,
        directories_count=10,
        total_bytes=5000000000,
        top_consumers=[
            LargeConsumerSnapshotItem(
                rank=1,
                path="/Users/mac/Downloads/big_archive.zip",
                size_bytes=3000000000,
                category=SmartCategory.ARCHIVES,
                confidence=ConfidenceLevel.HIGH,
            ),
            LargeConsumerSnapshotItem(
                rank=2,
                path="/Users/mac/Library/Caches/com.apple.test",
                size_bytes=2000000000,
                category=SmartCategory.CACHES,
                confidence=ConfidenceLevel.HIGH,
            ),
        ],
    )
    assert is_snapshot_scope_compatible(snap_valid_consumers, ScopeIdentifier.HOME, "/Users/mac") is True

    # 3. Matching HOME scope/root + one out-of-bound consumer
    snap_out_of_bound_consumer = StorageSnapshot(
        snapshot_id="snap-oob",
        scan_id="scan-oob",
        timestamp=1710000020.0,
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/mac",
        status=ScanStatus.COMPLETED,
        duration_seconds=1.0,
        files_count=100,
        directories_count=10,
        total_bytes=5000000000,
        top_consumers=[
            LargeConsumerSnapshotItem(
                rank=1,
                path="/Users/mac/Downloads/big_archive.zip",
                size_bytes=3000000000,
                category=SmartCategory.ARCHIVES,
                confidence=ConfidenceLevel.HIGH,
            ),
            LargeConsumerSnapshotItem(
                rank=2,
                path="/System/Library/Assets",
                size_bytes=2000000000,
                category=SmartCategory.SYSTEM_DATA,
                confidence=ConfidenceLevel.HIGH,
            ),
        ],
    )
    assert is_snapshot_scope_compatible(snap_out_of_bound_consumer, ScopeIdentifier.HOME, "/Users/mac") is False

    # 4. Root scope ("/") allows root-contained system paths
    snap_root_scope = StorageSnapshot(
        snapshot_id="snap-root",
        scan_id="scan-root",
        timestamp=1710000030.0,
        scope_id=ScopeIdentifier.CUSTOM,
        root_path="/",
        status=ScanStatus.COMPLETED,
        duration_seconds=5.0,
        files_count=50000,
        directories_count=5000,
        total_bytes=250000000000,
        top_consumers=[
            LargeConsumerSnapshotItem(
                rank=1,
                path="/System/Library/Assets",
                size_bytes=100000000000,
                category=SmartCategory.SYSTEM_DATA,
                confidence=ConfidenceLevel.HIGH,
            )
        ],
    )
    assert is_snapshot_scope_compatible(snap_root_scope, ScopeIdentifier.CUSTOM, "/") is True
