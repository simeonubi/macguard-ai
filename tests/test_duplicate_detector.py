"""
MacGuard AI v1.1 — Duplicate & Redundancy Intelligence Tests (Phase 6).

Validates deterministic two-stage hash comparison, APFS hardlink recognition,
size pre-filtering (>= 1 MiB), resource bounds (> 5 GiB skipped), symlink isolation,
fail-closed error recovery, and zero mutation/execution authority invariants.
"""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from app.analysis.duplicate_detector import (
    DEFAULT_MAX_AUTO_HASH_SIZE_BYTES,
    DEFAULT_MIN_DUPLICATE_SIZE_BYTES,
    DuplicateDetector,
)
from app.models.category import ConfidenceLevel, SmartCategory
from app.models.duplicate import (
    DuplicateCluster,
    DuplicateFile,
    DuplicateGroup,
    DuplicateScanSummary,
)
from app.models.scan_result import DiscoveredItem, ScanResult, ScanStatus
from app.models.scan_scope import ScopeIdentifier


@pytest.fixture
def temp_dir():
    """Create an isolated temporary directory for synthetic test files."""
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp)


def _create_synthetic_file(path: Path, size_bytes: int, fill_byte: bytes = b"A") -> DiscoveredItem:
    """Helper to create a synthetic test file of specific byte size."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        # Write chunks to avoid large memory allocations in tests
        chunk = fill_byte * min(size_bytes, 65536)
        written = 0
        while written < size_bytes:
            to_write = min(len(chunk), size_bytes - written)
            f.write(chunk[:to_write])
            written += to_write

    st = os.lstat(path)
    return DiscoveredItem(
        path=str(path),
        size_bytes=size_bytes,
        item_type="file",
        depth=1,
        mtime=st.st_mtime,
        st_ino=st.st_ino,
        st_dev=st.st_dev,
        is_symlink=False,
        category=SmartCategory.ARCHIVES,
        confidence=ConfidenceLevel.HIGH,
    )


# =========================================================================
# 1-3. Size Pre-Filter & Thresholding
# =========================================================================

def test_files_below_1_mib_excluded(temp_dir):
    """Verify files strictly below 1 MiB (1,048,576 bytes) are excluded from duplicate hashing."""
    f1 = temp_dir / "small_1.bin"
    f2 = temp_dir / "small_2.bin"
    item1 = _create_synthetic_file(f1, 1024 * 1024 - 1, b"X")
    item2 = _create_synthetic_file(f2, 1024 * 1024 - 1, b"X")

    detector = DuplicateDetector()
    clusters, summary = detector.find_duplicates_from_items([item1, item2])

    assert len(clusters) == 0
    assert summary.total_clusters == 0
    assert summary.total_duplicate_files == 0
    assert summary.potential_reclaimable_bytes == 0


def test_files_exactly_at_1_mib_accepted(temp_dir):
    """Verify files exactly at 1 MiB boundary (1,048,576 bytes) are accepted."""
    f1 = temp_dir / "exact_1.bin"
    f2 = temp_dir / "exact_2.bin"
    size = 1024 * 1024
    item1 = _create_synthetic_file(f1, size, b"Z")
    item2 = _create_synthetic_file(f2, size, b"Z")

    detector = DuplicateDetector()
    clusters, summary = detector.find_duplicates_from_items([item1, item2])

    assert len(clusters) == 1
    assert summary.total_clusters == 1
    assert summary.total_duplicate_files == 2
    assert summary.potential_reclaimable_bytes == size
    assert clusters[0].file_size_bytes == size


def test_unique_size_files_eliminated_before_hashing(temp_dir):
    """Verify files with unique sizes are eliminated before partial/full hashing."""
    f1 = temp_dir / "file_1mb.bin"
    f2 = temp_dir / "file_2mb.bin"
    f3 = temp_dir / "file_3mb.bin"
    item1 = _create_synthetic_file(f1, 1024 * 1024, b"A")
    item2 = _create_synthetic_file(f2, 2 * 1024 * 1024, b"B")
    item3 = _create_synthetic_file(f3, 3 * 1024 * 1024, b"C")

    detector = DuplicateDetector()
    with patch.object(detector, "_compute_partial_hash") as mock_partial:
        clusters, summary = detector.find_duplicates_from_items([item1, item2, item3])
        # Since all 3 sizes are unique, _compute_partial_hash should NEVER be called
        assert not mock_partial.called
        assert len(clusters) == 0
        assert summary.total_clusters == 0


# =========================================================================
# 4-8. Two-Stage Hashing (Partial + Full SHA-256)
# =========================================================================

def test_equal_size_different_content_files_separated(temp_dir):
    """Verify files with identical size but different content are not clustered together."""
    f1 = temp_dir / "file_a.bin"
    f2 = temp_dir / "file_b.bin"
    size = 1024 * 1024
    item1 = _create_synthetic_file(f1, size, b"A")
    item2 = _create_synthetic_file(f2, size, b"B")

    detector = DuplicateDetector()
    clusters, summary = detector.find_duplicates_from_items([item1, item2])

    assert len(clusters) == 0
    assert summary.total_clusters == 0
    assert summary.potential_reclaimable_bytes == 0


def test_partial_hash_correctly_distinguishes_candidates(temp_dir):
    """
    Verify partial hashing (first 4KB + last 4KB) eliminates candidates before full hashing
    when prefix/suffix differ.
    """
    size = 1024 * 1024
    f1 = temp_dir / "diff_prefix_1.bin"
    f2 = temp_dir / "diff_prefix_2.bin"

    # Write identical middles but distinct prefix
    with open(f1, "wb") as f:
        f.write(b"1" * 4096)
        f.write(b"M" * (size - 8192))
        f.write(b"E" * 4096)

    with open(f2, "wb") as f:
        f.write(b"2" * 4096)
        f.write(b"M" * (size - 8192))
        f.write(b"E" * 4096)

    st1 = os.lstat(f1)
    st2 = os.lstat(f2)
    item1 = DiscoveredItem(path=str(f1), size_bytes=size, item_type="file", depth=1, mtime=st1.st_mtime, st_ino=st1.st_ino, st_dev=st1.st_dev, is_symlink=False)
    item2 = DiscoveredItem(path=str(f2), size_bytes=size, item_type="file", depth=1, mtime=st2.st_mtime, st_ino=st2.st_ino, st_dev=st2.st_dev, is_symlink=False)

    detector = DuplicateDetector()
    with patch.object(detector, "_compute_full_sha256") as mock_full:
        clusters, summary = detector.find_duplicates_from_items([item1, item2])
        # Because partial hashes differ, full SHA-256 should not be called
        assert not mock_full.called
        assert len(clusters) == 0


def test_matching_partial_hashes_trigger_full_sha256(temp_dir):
    """Verify matching partial hashes proceed to full SHA-256 evaluation."""
    size = 1024 * 1024
    f1 = temp_dir / "match_1.bin"
    f2 = temp_dir / "match_2.bin"
    item1 = _create_synthetic_file(f1, size, b"K")
    item2 = _create_synthetic_file(f2, size, b"K")

    detector = DuplicateDetector()
    with patch.object(detector, "_compute_full_sha256", wraps=detector._compute_full_sha256) as mock_full:
        clusters, summary = detector.find_duplicates_from_items([item1, item2])
        assert mock_full.call_count == 2
        assert len(clusters) == 1
        assert summary.total_clusters == 1


def test_exact_duplicate_files_form_one_deterministic_cluster(temp_dir):
    """Verify 3 identical files produce 1 cluster with (3-1)*size wasted bytes."""
    size = 2 * 1024 * 1024
    f1 = temp_dir / "copy_1.bin"
    f2 = temp_dir / "copy_2.bin"
    f3 = temp_dir / "copy_3.bin"
    item1 = _create_synthetic_file(f1, size, b"D")
    item2 = _create_synthetic_file(f2, size, b"D")
    item3 = _create_synthetic_file(f3, size, b"D")

    detector = DuplicateDetector()
    clusters, summary = detector.find_duplicates_from_items([item1, item2, item3])

    assert len(clusters) == 1
    cluster = clusters[0]
    assert cluster.file_size_bytes == size
    assert len(cluster.files) == 3
    assert cluster.wasted_bytes == (3 - 1) * size
    assert summary.potential_reclaimable_bytes == (3 - 1) * size


def test_full_sha256_prevents_false_duplicate_classification(temp_dir):
    """
    Verify that files with identical prefix and suffix but DIFFERENT middle content
    are caught by full SHA-256 and NOT placed in the same cluster.
    """
    size = 1024 * 1024
    f1 = temp_dir / "diff_middle_1.bin"
    f2 = temp_dir / "diff_middle_2.bin"

    # Same first 4KB and last 4KB, different middle
    with open(f1, "wb") as f:
        f.write(b"H" * 4096)
        f.write(b"A" * (size - 8192))
        f.write(b"T" * 4096)

    with open(f2, "wb") as f:
        f.write(b"H" * 4096)
        f.write(b"B" * (size - 8192))
        f.write(b"T" * 4096)

    st1 = os.lstat(f1)
    st2 = os.lstat(f2)
    item1 = DiscoveredItem(path=str(f1), size_bytes=size, item_type="file", depth=1, mtime=st1.st_mtime, st_ino=st1.st_ino, st_dev=st1.st_dev, is_symlink=False)
    item2 = DiscoveredItem(path=str(f2), size_bytes=size, item_type="file", depth=1, mtime=st2.st_mtime, st_ino=st2.st_ino, st_dev=st2.st_dev, is_symlink=False)

    detector = DuplicateDetector()
    clusters, summary = detector.find_duplicates_from_items([item1, item2])

    assert len(clusters) == 0
    assert summary.total_clusters == 0
    assert summary.potential_reclaimable_bytes == 0


# =========================================================================
# 9-11. APFS Hardlink Awareness & Wasted Bytes Calculation
# =========================================================================

def test_hardlinks_sharing_dev_ino_are_recognized(temp_dir):
    """Verify that multiple paths sharing (st_dev, st_ino) are recognized as hardlinks."""
    f1 = temp_dir / "original.bin"
    f2 = temp_dir / "hardlink_copy.bin"
    size = 2 * 1024 * 1024
    _create_synthetic_file(f1, size, b"H")

    # Create actual filesystem hardlink
    os.link(f1, f2)

    st1 = os.lstat(f1)
    st2 = os.lstat(f2)
    assert st1.st_ino == st2.st_ino
    assert st1.st_dev == st2.st_dev

    item1 = DiscoveredItem(path=str(f1), size_bytes=size, item_type="file", depth=1, mtime=st1.st_mtime, st_ino=st1.st_ino, st_dev=st1.st_dev, is_symlink=False)
    item2 = DiscoveredItem(path=str(f2), size_bytes=size, item_type="file", depth=1, mtime=st2.st_mtime, st_ino=st2.st_ino, st_dev=st2.st_dev, is_symlink=False)

    detector = DuplicateDetector()
    clusters, summary = detector.find_duplicates_from_items([item1, item2])

    assert len(clusters) == 1
    cluster = clusters[0]
    assert len(cluster.files) == 2
    assert cluster.hardlink_count == 1
    # Because both files point to the same physical inode, wasted bytes MUST be 0!
    assert cluster.wasted_bytes == 0
    assert summary.potential_reclaimable_bytes == 0


def test_hardlinks_do_not_inflate_reclaimable_bytes_with_independent_copy(temp_dir):
    """
    Verify scenario: 1 original + 1 hardlink + 1 independent duplicate copy.
    Total files = 3.
    Distinct physical copies = 2.
    Wasted bytes = (2 - 1) * size = 1 * size.
    """
    f1 = temp_dir / "orig.bin"
    f2 = temp_dir / "link.bin"
    f3 = temp_dir / "independent.bin"
    size = 3 * 1024 * 1024

    _create_synthetic_file(f1, size, b"W")
    os.link(f1, f2)
    _create_synthetic_file(f3, size, b"W")

    st1 = os.lstat(f1)
    st2 = os.lstat(f2)
    st3 = os.lstat(f3)

    item1 = DiscoveredItem(path=str(f1), size_bytes=size, item_type="file", depth=1, mtime=st1.st_mtime, st_ino=st1.st_ino, st_dev=st1.st_dev, is_symlink=False)
    item2 = DiscoveredItem(path=str(f2), size_bytes=size, item_type="file", depth=1, mtime=st2.st_mtime, st_ino=st2.st_ino, st_dev=st2.st_dev, is_symlink=False)
    item3 = DiscoveredItem(path=str(f3), size_bytes=size, item_type="file", depth=1, mtime=st3.st_mtime, st_ino=st3.st_ino, st_dev=st3.st_dev, is_symlink=False)

    detector = DuplicateDetector()
    clusters, summary = detector.find_duplicates_from_items([item1, item2, item3])

    assert len(clusters) == 1
    cluster = clusters[0]
    assert len(cluster.files) == 3
    assert cluster.hardlink_count == 1
    # Only 1 extra physical copy wasted!
    assert cluster.wasted_bytes == size
    assert summary.potential_reclaimable_bytes == size


def test_multiple_independent_copies_calculate_wasted_bytes_correctly(temp_dir):
    """Verify 4 independent identical files yield wasted_bytes = (4 - 1) * size."""
    size = 1024 * 1024
    items = [
        _create_synthetic_file(temp_dir / f"dup_{i}.bin", size, b"M")
        for i in range(4)
    ]

    detector = DuplicateDetector()
    clusters, summary = detector.find_duplicates_from_items(items)

    assert len(clusters) == 1
    assert clusters[0].wasted_bytes == 3 * size
    assert summary.potential_reclaimable_bytes == 3 * size


# =========================================================================
# 12-13. Symlinks & Large File Boundary (> 5 GiB)
# =========================================================================

def test_symlinks_are_skipped(temp_dir):
    """Verify symlinks are excluded from duplicate hashing."""
    f1 = temp_dir / "target.bin"
    f2 = temp_dir / "symlink_target.bin"
    size = 1024 * 1024
    _create_synthetic_file(f1, size, b"S")

    # Create symlink
    os.symlink(f1, f2)
    st1 = os.lstat(f1)
    st2 = os.lstat(f2)

    item1 = DiscoveredItem(path=str(f1), size_bytes=size, item_type="file", depth=1, mtime=st1.st_mtime, st_ino=st1.st_ino, st_dev=st1.st_dev, is_symlink=False)
    item2 = DiscoveredItem(path=str(f2), size_bytes=size, item_type="file", depth=1, mtime=st2.st_mtime, st_ino=st2.st_ino, st_dev=st2.st_dev, is_symlink=True)

    detector = DuplicateDetector()
    clusters, summary = detector.find_duplicates_from_items([item1, item2])

    assert len(clusters) == 0
    assert summary.total_clusters == 0


def test_large_files_over_5_gib_skipped_and_flagged():
    """Verify files exceeding 5 GiB are not bulk-hashed and are counted in skipped_large_files."""
    large_size = 6 * 1024 * 1024 * 1024  # 6 GiB
    item1 = DiscoveredItem(path="/dummy/large1.iso", size_bytes=large_size, item_type="file", depth=1, mtime=1700000000.0, st_ino=1001, st_dev=1, is_symlink=False)
    item2 = DiscoveredItem(path="/dummy/large2.iso", size_bytes=large_size, item_type="file", depth=1, mtime=1700000000.0, st_ino=1002, st_dev=1, is_symlink=False)

    detector = DuplicateDetector()
    clusters, summary = detector.find_duplicates_from_items([item1, item2])

    assert len(clusters) == 0
    assert summary.skipped_large_files == 2


# =========================================================================
# 14-15. Fail-Closed Error Handling
# =========================================================================

def test_permission_errors_fail_closed_without_aborting(temp_dir):
    """Verify unreadable files fail closed cleanly and do not crash the analysis."""
    f_ok1 = temp_dir / "ok1.bin"
    f_ok2 = temp_dir / "ok2.bin"
    f_unreadable = temp_dir / "unreadable.bin"
    size = 1024 * 1024

    item_ok1 = _create_synthetic_file(f_ok1, size, b"O")
    item_ok2 = _create_synthetic_file(f_ok2, size, b"O")
    item_unreadable = _create_synthetic_file(f_unreadable, size, b"O")

    # Make unreadable
    f_unreadable.chmod(0o000)

    try:
        detector = DuplicateDetector()
        clusters, summary = detector.find_duplicates_from_items([item_ok1, item_ok2, item_unreadable])

        # Valid 2 files should still cluster properly
        assert len(clusters) == 1
        assert len(clusters[0].files) == 2
    finally:
        f_unreadable.chmod(0o644)


def test_missing_or_raced_files_fail_closed(temp_dir):
    """Verify missing/deleted files during hashing fail closed cleanly."""
    f1 = temp_dir / "existing.bin"
    size = 1024 * 1024
    item1 = _create_synthetic_file(f1, size, b"E")
    item_missing = DiscoveredItem(path=str(temp_dir / "nonexistent.bin"), size_bytes=size, item_type="file", depth=1, mtime=1700000000.0, st_ino=9999, st_dev=1, is_symlink=False)

    detector = DuplicateDetector()
    clusters, summary = detector.find_duplicates_from_items([item1, item_missing])

    assert len(clusters) == 0
    assert summary.total_clusters == 0


# =========================================================================
# 16-17. Determinism & Stability
# =========================================================================

def test_deterministic_cluster_ordering_and_stable_paths(temp_dir):
    """Verify files inside clusters are sorted alphabetically by path, and clusters are sorted by wasted_bytes."""
    size_big = 4 * 1024 * 1024
    size_small = 1024 * 1024

    # Big duplicate pair (wasted = 4MB)
    b1 = temp_dir / "z_big.bin"
    b2 = temp_dir / "a_big.bin"
    item_b1 = _create_synthetic_file(b1, size_big, b"B")
    item_b2 = _create_synthetic_file(b2, size_big, b"B")

    # Small duplicate 3-tuple (wasted = 2 * 1MB = 2MB)
    s1 = temp_dir / "m_small.bin"
    s2 = temp_dir / "c_small.bin"
    s3 = temp_dir / "x_small.bin"
    item_s1 = _create_synthetic_file(s1, size_small, b"S")
    item_s2 = _create_synthetic_file(s2, size_small, b"S")
    item_s3 = _create_synthetic_file(s3, size_small, b"S")

    detector = DuplicateDetector()
    clusters, summary = detector.find_duplicates_from_items([item_s3, item_b2, item_s1, item_b1, item_s2])

    assert len(clusters) == 2
    # First cluster should be big (4MB wasted > 2MB wasted)
    assert clusters[0].file_size_bytes == size_big
    assert clusters[0].wasted_bytes == size_big
    # Files inside big cluster should be ordered: a_big.bin, z_big.bin
    assert clusters[0].files[0].path == str(b2)
    assert clusters[0].files[1].path == str(b1)

    # Second cluster should be small
    assert clusters[1].file_size_bytes == size_small
    assert clusters[1].wasted_bytes == 2 * size_small
    # Files inside small cluster ordered: c_small, m_small, x_small
    assert clusters[1].files[0].path == str(s2)
    assert clusters[1].files[1].path == str(s1)
    assert clusters[1].files[2].path == str(s3)


def test_repeated_unchanged_input_produces_identical_clusters(temp_dir):
    """Verify idempotency: running detection multiple times on same items yields identical results."""
    size = 1024 * 1024
    f1 = temp_dir / "f1.bin"
    f2 = temp_dir / "f2.bin"
    item1 = _create_synthetic_file(f1, size, b"X")
    item2 = _create_synthetic_file(f2, size, b"X")

    detector = DuplicateDetector()
    c1, s1 = detector.find_duplicates_from_items([item1, item2])
    c2, s2 = detector.find_duplicates_from_items([item1, item2])

    assert c1 == c2
    assert s1 == s2


def test_find_duplicates_from_scan_result_wrapper(temp_dir):
    """Verify find_duplicates correctly unpacks ScanResult discovered items."""
    size = 1024 * 1024
    f1 = temp_dir / "scan_1.bin"
    f2 = temp_dir / "scan_2.bin"
    item1 = _create_synthetic_file(f1, size, b"R")
    item2 = _create_synthetic_file(f2, size, b"R")

    scan_res = ScanResult(
        scope_id=ScopeIdentifier.HOME,
        root_path=str(temp_dir),
        status=ScanStatus.COMPLETED,
        start_time=1700000000.0,
        end_time=1700000001.0,
        duration_seconds=1.0,
        files_count=2,
        directories_count=1,
        total_bytes=2 * size,
        items=[item1, item2],
    )

    detector = DuplicateDetector()
    clusters, summary = detector.find_duplicates(scan_res)

    assert len(clusters) == 1
    assert summary.total_duplicate_files == 2


# =========================================================================
# 18-20. Safety & Zero Mutation Invariants
# =========================================================================

def test_no_temporary_files_created(temp_dir):
    """Verify duplicate detection creates zero temporary files on disk during analysis."""
    size = 1024 * 1024
    f1 = temp_dir / "a.bin"
    f2 = temp_dir / "b.bin"
    item1 = _create_synthetic_file(f1, size, b"T")
    item2 = _create_synthetic_file(f2, size, b"T")

    entries_before = set(temp_dir.iterdir())

    detector = DuplicateDetector()
    clusters, summary = detector.find_duplicates_from_items([item1, item2])

    entries_after = set(temp_dir.iterdir())
    assert entries_before == entries_after


def test_no_mutation_primitives_in_duplicate_detector():
    """Verify that DuplicateDetector does not contain or expose dangerous mutation methods."""
    import app.analysis.duplicate_detector as dup_mod

    assert not hasattr(dup_mod, "TrashExecutor")
    assert not hasattr(dup_mod, "ApprovalKeyManager")
    assert not hasattr(dup_mod, "ApprovalService")
    assert not hasattr(dup_mod, "unlink")
    assert not hasattr(dup_mod, "remove")
    assert not hasattr(dup_mod, "rmdir")
    assert not hasattr(dup_mod, "move")
    assert not hasattr(dup_mod, "execute")


def test_detector_has_no_approval_or_execution_authority():
    """Verify DuplicateDetector cannot generate approvals or tokens."""
    detector = DuplicateDetector()

    assert not hasattr(detector, "create_approval")
    assert not hasattr(detector, "sign_hmac")
    assert not hasattr(detector, "execute_cleanup")
    assert not hasattr(detector, "delete_duplicate")
