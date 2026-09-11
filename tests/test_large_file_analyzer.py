"""
Tests for MacGuard AI v1.1 Phase 5A — Large File Intelligence & Ranking.

Validates deterministic ranking, category-aware context, developer storage integration,
parent/child containment, unique-byte accounting, attention prioritization, and
strict read-only safety boundaries.
"""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import patch
import pytest

from app.analysis.large_file_analyzer import (
    DEFAULT_LARGE_FILE_THRESHOLD_BYTES,
    LargeFileAnalyzer,
)
from app.models.category import ConfidenceLevel, SmartCategory
from app.models.developer import DeveloperStorageSubtype, StaleStatus
from app.models.large_file import (
    LargeFileCategorySummary,
    LargeFileDeveloperSummary,
    LargeFileFinding,
    LargeFileSummary,
)
from app.models.scan_result import DiscoveredItem, ScanResult, ScanStatus
from app.models.scan_scope import ScopeIdentifier


def make_item(
    path: str,
    size_bytes: int,
    item_type: str = "file",
    depth: int = 2,
    mtime: float = 1700000000.0,
    category: SmartCategory = SmartCategory.MEDIA,
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH,
) -> DiscoveredItem:
    """Helper to create synthetic DiscoveredItem objects."""
    return DiscoveredItem(
        path=path,
        size_bytes=size_bytes,
        item_type=item_type,
        depth=depth,
        mtime=mtime,
        st_ino=abs(hash(path)) & 0x7FFFFFFF,
        st_dev=1,
        category=category,
        confidence=confidence,
        category_rule=f"rule:{category.value.lower()}",
    )


def test_empty_scan_result():
    """Verify analyzer gracefully handles an empty ScanResult."""
    scan_result = ScanResult(
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/test",
        status=ScanStatus.COMPLETED,
        start_time=100.0,
        end_time=101.0,
        duration_seconds=1.0,
        files_count=0,
        directories_count=0,
        total_bytes=0,
        items=[],
    )
    analyzer = LargeFileAnalyzer()
    summary = analyzer.analyze_scan_result(scan_result)

    assert summary.total_findings_count == 0
    assert summary.total_logical_bytes == 0
    assert summary.total_unique_bytes == 0
    assert summary.findings == []
    assert summary.top_findings == []
    assert summary.category_summaries == []
    assert summary.developer_summaries == []


def test_large_file_threshold_filtering():
    """Verify items below threshold are excluded and items >= threshold are included."""
    threshold = 100 * 1024 * 1024  # 100 MB
    items = [
        make_item("/Users/test/small.mp4", size_bytes=50 * 1024 * 1024),          # 50 MB (below)
        make_item("/Users/test/exact.mp4", size_bytes=100 * 1024 * 1024),         # 100 MB (exact)
        make_item("/Users/test/large.mp4", size_bytes=250 * 1024 * 1024),         # 250 MB (above)
    ]

    analyzer = LargeFileAnalyzer(default_threshold_bytes=threshold)
    summary = analyzer.analyze_items(items)

    assert summary.total_findings_count == 2
    paths = [f.path for f in summary.findings]
    assert "/Users/test/small.mp4" not in paths
    assert "/Users/test/exact.mp4" in paths
    assert "/Users/test/large.mp4" in paths


def test_top_n_ranking_by_size():
    """Verify findings are ranked in descending order of size with accurate 1-based ranks."""
    items = [
        make_item("/Users/test/video_b.mkv", size_bytes=2 * 1024 * 1024 * 1024),  # 2 GB
        make_item("/Users/test/video_c.mkv", size_bytes=5 * 1024 * 1024 * 1024),  # 5 GB
        make_item("/Users/test/video_a.mkv", size_bytes=1 * 1024 * 1024 * 1024),  # 1 GB
        make_item("/Users/test/video_d.mkv", size_bytes=3 * 1024 * 1024 * 1024),  # 3 GB
    ]

    analyzer = LargeFileAnalyzer(default_threshold_bytes=100 * 1024 * 1024, top_n_limit=3)
    summary = analyzer.analyze_items(items)

    assert summary.total_findings_count == 4
    assert len(summary.top_findings) == 3

    # Ranking check
    assert summary.findings[0].path == "/Users/test/video_c.mkv"
    assert summary.findings[0].rank == 1
    assert summary.findings[1].path == "/Users/test/video_d.mkv"
    assert summary.findings[1].rank == 2
    assert summary.findings[2].path == "/Users/test/video_b.mkv"
    assert summary.findings[2].rank == 3
    assert summary.findings[3].path == "/Users/test/video_a.mkv"
    assert summary.findings[3].rank == 4


def test_deterministic_tie_breaking():
    """Verify equal-sized items break ties via canonical path ascending."""
    items = [
        make_item("/Users/test/z_archive.zip", size_bytes=500 * 1024 * 1024),
        make_item("/Users/test/a_archive.zip", size_bytes=500 * 1024 * 1024),
        make_item("/Users/test/m_archive.zip", size_bytes=500 * 1024 * 1024),
    ]

    analyzer = LargeFileAnalyzer(default_threshold_bytes=100 * 1024 * 1024)
    summary = analyzer.analyze_items(items)

    assert [f.path for f in summary.findings] == [
        "/Users/test/a_archive.zip",
        "/Users/test/m_archive.zip",
        "/Users/test/z_archive.zip",
    ]
    assert summary.findings[0].rank == 1
    assert summary.findings[1].rank == 2
    assert summary.findings[2].rank == 3


def test_category_and_confidence_preservation():
    """Verify category and confidence are accurately preserved on large file findings."""
    items = [
        make_item(
            "/Users/test/weights.safetensors",
            size_bytes=10 * 1024 * 1024 * 1024,
            category=SmartCategory.ML_AI_DATA,
            confidence=ConfidenceLevel.HIGH,
        ),
        make_item(
            "/Users/test/Downloads/archive.tar.gz",
            size_bytes=500 * 1024 * 1024,
            category=SmartCategory.ARCHIVES,
            confidence=ConfidenceLevel.MEDIUM,
        ),
    ]

    analyzer = LargeFileAnalyzer(default_threshold_bytes=100 * 1024 * 1024)
    summary = analyzer.analyze_items(items)

    f1 = summary.findings[0]
    assert f1.category == SmartCategory.ML_AI_DATA
    assert f1.confidence == ConfidenceLevel.HIGH

    f2 = summary.findings[1]
    assert f2.category == SmartCategory.ARCHIVES
    assert f2.confidence == ConfidenceLevel.MEDIUM


def test_developer_storage_integration():
    """Verify developer subtype, project name, project root, and stale status are attached."""
    ref_time = 1710000000.0
    items = [
        make_item(
            "/Users/test/Projects/my_app/.venv",
            size_bytes=800 * 1024 * 1024,
            item_type="directory",
            mtime=ref_time - (200 * 86400),  # 200 days old -> POTENTIALLY_STALE_180D
            category=SmartCategory.VIRTUAL_ENVIRONMENTS,
        ),
        make_item(
            "/Users/test/Projects/my_app/node_modules",
            size_bytes=1200 * 1024 * 1024,
            item_type="directory",
            mtime=ref_time - (10 * 86400),   # 10 days old -> RECENT
            category=SmartCategory.DEVELOPER_DATA,
        ),
    ]

    analyzer = LargeFileAnalyzer(
        default_threshold_bytes=100 * 1024 * 1024,
        reference_time=ref_time,
    )
    summary = analyzer.analyze_items(items)

    assert summary.total_findings_count == 2
    # Node modules is larger (1200 MB), rank 1
    nm_finding = summary.findings[0]
    assert nm_finding.rank == 1
    assert nm_finding.developer_subtype == DeveloperStorageSubtype.NODE_MODULES
    assert nm_finding.project_name == "my_app"
    assert nm_finding.stale_status == StaleStatus.RECENT

    # Venv is rank 2
    venv_finding = summary.findings[1]
    assert venv_finding.rank == 2
    assert venv_finding.developer_subtype == DeveloperStorageSubtype.PYTHON_VENV
    assert venv_finding.project_name == "my_app"
    assert venv_finding.stale_status == StaleStatus.POTENTIALLY_STALE_180D


def test_parent_child_containment_and_unique_byte_accounting():
    """Verify parent/child relationships and ensure unique physical bytes != logical sum."""
    items = [
        make_item(
            "/Users/test/Projects/big_project",
            size_bytes=10 * 1024 * 1024 * 1024,  # 10 GB parent directory
            item_type="directory",
            category=SmartCategory.DEVELOPER_DATA,
        ),
        make_item(
            "/Users/test/Projects/big_project/node_modules",
            size_bytes=4 * 1024 * 1024 * 1024,   # 4 GB child directory
            item_type="directory",
            category=SmartCategory.DEVELOPER_DATA,
        ),
        make_item(
            "/Users/test/Projects/big_project/.venv",
            size_bytes=2 * 1024 * 1024 * 1024,   # 2 GB child directory
            item_type="directory",
            category=SmartCategory.VIRTUAL_ENVIRONMENTS,
        ),
        make_item(
            "/Users/test/Downloads/independent_video.mp4",
            size_bytes=3 * 1024 * 1024 * 1024,   # 3 GB independent file
            item_type="file",
            category=SmartCategory.MEDIA,
        ),
    ]

    analyzer = LargeFileAnalyzer(default_threshold_bytes=100 * 1024 * 1024)
    summary = analyzer.analyze_items(items)

    # Logical sum = 10 + 4 + 2 + 3 = 19 GB
    assert summary.total_logical_bytes == 19 * 1024 * 1024 * 1024

    # Unique physical sum = big_project (10 GB) + independent_video (3 GB) = 13 GB
    assert summary.total_unique_bytes == 13 * 1024 * 1024 * 1024
    assert summary.total_unique_bytes <= summary.total_logical_bytes

    # Check containment flags
    nm_finding = [f for f in summary.findings if "node_modules" in f.path][0]
    assert nm_finding.is_contained is True
    assert nm_finding.parent_candidate_path == "/Users/test/Projects/big_project"

    venv_finding = [f for f in summary.findings if ".venv" in f.path][0]
    assert venv_finding.is_contained is True
    assert venv_finding.parent_candidate_path == "/Users/test/Projects/big_project"

    parent_finding = [f for f in summary.findings if f.path == "/Users/test/Projects/big_project"][0]
    assert parent_finding.is_contained is False
    assert parent_finding.parent_candidate_path is None


def test_storage_percentage_calculation():
    """Verify accurate percentage calculation when total scanned bytes is known."""
    total_scanned = 100 * 1024 * 1024 * 1024  # 100 GB
    items = [
        make_item("/Users/test/large_1.iso", size_bytes=20 * 1024 * 1024 * 1024),  # 20 GB -> 20.0%
        make_item("/Users/test/large_2.iso", size_bytes=5 * 1024 * 1024 * 1024),   # 5 GB -> 5.0%
    ]

    analyzer = LargeFileAnalyzer(default_threshold_bytes=100 * 1024 * 1024)
    summary = analyzer.analyze_items(items, total_scanned_bytes=total_scanned)

    assert summary.findings[0].storage_percentage == 20.0
    assert summary.findings[1].storage_percentage == 5.0


def test_unavailable_percentage_handling():
    """Verify storage_percentage is None when total_scanned_bytes is 0 or None."""
    items = [
        make_item("/Users/test/large_1.iso", size_bytes=20 * 1024 * 1024 * 1024),
    ]

    analyzer = LargeFileAnalyzer(default_threshold_bytes=100 * 1024 * 1024)
    summary = analyzer.analyze_items(items, total_scanned_bytes=0)
    assert summary.findings[0].storage_percentage is None

    summary_none = analyzer.analyze_items(items, total_scanned_bytes=None)
    assert summary_none.findings[0].storage_percentage is None


def test_category_and_developer_summaries():
    """Verify category and developer subtype aggregation summaries."""
    items = [
        make_item("/Users/test/model.bin", size_bytes=6 * 1024 * 1024 * 1024, category=SmartCategory.ML_AI_DATA),
        make_item("/Users/test/Projects/app/node_modules", size_bytes=4 * 1024 * 1024 * 1024, item_type="directory", category=SmartCategory.DEVELOPER_DATA),
        make_item("/Users/test/movie.mkv", size_bytes=8 * 1024 * 1024 * 1024, category=SmartCategory.MEDIA),
    ]

    analyzer = LargeFileAnalyzer(default_threshold_bytes=100 * 1024 * 1024)
    summary = analyzer.analyze_items(items)

    assert len(summary.category_summaries) == 3
    cat_names = [cs.category for cs in summary.category_summaries]
    assert SmartCategory.MEDIA in cat_names
    assert SmartCategory.ML_AI_DATA in cat_names
    assert SmartCategory.DEVELOPER_DATA in cat_names

    # Developer summary
    assert len(summary.developer_summaries) == 2
    dev_subtypes = [ds.subtype for ds in summary.developer_summaries]
    assert DeveloperStorageSubtype.ML_MODELS in dev_subtypes
    assert DeveloperStorageSubtype.NODE_MODULES in dev_subtypes


def test_attention_prioritization_score():
    """Verify deterministic attention score computation reflects size, category, and age."""
    ref_time = 1710000000.0
    items = [
        # 12 GB stale ML model
        make_item(
            "/Users/test/old_model.onnx",
            size_bytes=12 * 1024 * 1024 * 1024,
            category=SmartCategory.ML_AI_DATA,
            mtime=ref_time - (200 * 86400),
        ),
        # 100 MB recent document
        make_item(
            "/Users/test/Documents/manual.pdf",
            size_bytes=100 * 1024 * 1024,
            category=SmartCategory.DOCUMENTS,
            mtime=ref_time - (5 * 86400),
        ),
    ]

    analyzer = LargeFileAnalyzer(
        default_threshold_bytes=50 * 1024 * 1024,
        reference_time=ref_time,
    )
    summary = analyzer.analyze_items(items)

    stale_model_finding = summary.findings[0]
    doc_finding = summary.findings[1]

    # Stale 12 GB ML model should have high attention score
    assert stale_model_finding.attention_score >= 80.0
    # User document should have lower attention score
    assert doc_finding.attention_score < stale_model_finding.attention_score


def test_configurable_category_thresholds():
    """Verify category-specific thresholds override default threshold."""
    custom_thresholds = {
        SmartCategory.MEDIA: 500 * 1024 * 1024,        # 500 MB for media
        SmartCategory.DEVELOPER_DATA: 50 * 1024 * 1024, # 50 MB for dev data
    }
    items = [
        make_item("/Users/test/clip.mp4", size_bytes=200 * 1024 * 1024, category=SmartCategory.MEDIA),  # 200 MB (< 500 MB) -> Excluded
        make_item("/Users/test/movie.mp4", size_bytes=800 * 1024 * 1024, category=SmartCategory.MEDIA), # 800 MB (>= 500 MB) -> Included
        make_item("/Users/test/dev.tar", size_bytes=80 * 1024 * 1024, category=SmartCategory.DEVELOPER_DATA), # 80 MB (>= 50 MB) -> Included
    ]

    analyzer = LargeFileAnalyzer(
        default_threshold_bytes=100 * 1024 * 1024,
        category_thresholds=custom_thresholds,
    )
    summary = analyzer.analyze_items(items)

    assert summary.total_findings_count == 2
    paths = [f.path for f in summary.findings]
    assert "/Users/test/clip.mp4" not in paths
    assert "/Users/test/movie.mp4" in paths
    assert "/Users/test/dev.tar" in paths


def test_deterministic_reproducibility():
    """Verify identical input items produce identical findings, ranks, scores, and order."""
    items = [
        make_item("/Users/test/b.bin", size_bytes=300 * 1024 * 1024),
        make_item("/Users/test/a.bin", size_bytes=700 * 1024 * 1024),
        make_item("/Users/test/c.bin", size_bytes=300 * 1024 * 1024),
    ]

    analyzer = LargeFileAnalyzer(default_threshold_bytes=50 * 1024 * 1024)
    run1 = analyzer.analyze_items(items)
    run2 = analyzer.analyze_items(items)

    assert run1.model_dump() == run2.model_dump()


def test_unknown_and_low_confidence_category_handling():
    """Verify items with UNKNOWN category or low confidence are analyzed safely."""
    items = [
        make_item(
            "/Users/test/mystery.blob",
            size_bytes=250 * 1024 * 1024,
            category=SmartCategory.UNKNOWN,
            confidence=ConfidenceLevel.LOW,
        ),
    ]

    analyzer = LargeFileAnalyzer(default_threshold_bytes=100 * 1024 * 1024)
    summary = analyzer.analyze_items(items)

    assert summary.total_findings_count == 1
    f = summary.findings[0]
    assert f.category == SmartCategory.UNKNOWN
    assert f.confidence == ConfidenceLevel.LOW
    assert f.size_bytes == 250 * 1024 * 1024


def test_no_filesystem_mutation_or_traversal():
    """Verify analyzer performs zero filesystem crawls, zero content reads, and zero mutations."""
    items = [
        make_item("/Users/test/safe_file.dat", size_bytes=500 * 1024 * 1024),
    ]

    analyzer = LargeFileAnalyzer()

    with patch("os.walk") as mock_walk, \
         patch("builtins.open") as mock_open, \
         patch("os.remove") as mock_remove, \
         patch("shutil.rmtree") as mock_rmtree:

        summary = analyzer.analyze_items(items)

        mock_walk.assert_not_called()
        mock_open.assert_not_called()
        mock_remove.assert_not_called()
        mock_rmtree.assert_not_called()

    assert summary.total_findings_count == 1


def test_no_cleanup_authority_imported_or_accessible():
    """Verify analyzer module contains no references or imports to mutation executors or HMAC."""
    import app.analysis.large_file_analyzer as lfa_module

    # Confirm critical execution/approval classes are NOT in module
    assert not hasattr(lfa_module, "TrashExecutor")
    assert not hasattr(lfa_module, "ApprovalService")
    assert not hasattr(lfa_module, "ApprovalKeyManager")
    assert not hasattr(lfa_module, "ExecutionPlanner")


def test_recommendation_and_safety_boundaries_untouched():
    """Verify findings cannot be used as approvals or bypass recommendation engine."""
    from app.analysis.models import StorageCandidate, StorageCategory
    from app.analysis.recommendations import RecommendationEngine
    from app.safety.path_validator import Operation, PathValidator

    finding = LargeFileFinding(
        path="/Users/test/large.iso",
        size_bytes=10 * 1024 * 1024 * 1024,
        category=SmartCategory.ARCHIVES,
        confidence=ConfidenceLevel.HIGH,
        rank=1,
        size_threshold_bytes=50 * 1024 * 1024,
        attention_score=85.0,
        rationale="Large archive item.",
    )

    # Finding cannot approve or execute actions
    with pytest.raises(AttributeError):
        finding.approve()  # type: ignore

    with pytest.raises(AttributeError):
        finding.execute()  # type: ignore

    # RecommendationEngine remains separate and authoritative
    engine = RecommendationEngine()
    assert hasattr(engine, "recommend")


def test_invalid_threshold_and_limit_inputs():
    """Verify ValueError is raised when initializing with invalid arguments."""
    with pytest.raises(ValueError, match="default_threshold_bytes cannot be negative"):
        LargeFileAnalyzer(default_threshold_bytes=-1)

    with pytest.raises(ValueError, match="top_n_limit must be at least 1"):
        LargeFileAnalyzer(top_n_limit=0)


def test_input_immutability_invariant():
    """Verify analyzing items does not mutate the input collection or items."""
    item1 = make_item("/Users/test/data1.bin", size_bytes=200 * 1024 * 1024)
    item2 = make_item("/Users/test/data2.bin", size_bytes=300 * 1024 * 1024)
    original_items = [item1, item2]
    items_copy = list(original_items)

    analyzer = LargeFileAnalyzer(default_threshold_bytes=50 * 1024 * 1024)
    summary = analyzer.analyze_items(original_items)

    assert original_items == items_copy
    assert len(original_items) == 2
    assert summary.total_findings_count == 2


def test_property_top_n_bounded_count():
    """Verify top_findings contains at most N items regardless of total findings."""
    items = [
        make_item(f"/Users/test/file_{i}.dat", size_bytes=(i + 1) * 100 * 1024 * 1024)
        for i in range(50)
    ]

    analyzer = LargeFileAnalyzer(default_threshold_bytes=50 * 1024 * 1024, top_n_limit=5)
    summary = analyzer.analyze_items(items, limit=5)

    assert summary.total_findings_count == 50
    assert len(summary.top_findings) == 5
    assert summary.top_findings[0].rank == 1
    assert summary.top_findings[4].rank == 5
    assert summary.top_findings[0].size_bytes == 50 * 100 * 1024 * 1024


def test_complex_hierarchy_unique_byte_invariant():
    """Verify total_unique_bytes <= total_logical_bytes on deeply nested multi-level trees."""
    items = [
        make_item("/Users/test/workspace", size_bytes=50 * 1024 * 1024 * 1024, item_type="directory"),
        make_item("/Users/test/workspace/projA", size_bytes=20 * 1024 * 1024 * 1024, item_type="directory"),
        make_item("/Users/test/workspace/projA/build", size_bytes=10 * 1024 * 1024 * 1024, item_type="directory"),
        make_item("/Users/test/workspace/projA/build/out.bin", size_bytes=5 * 1024 * 1024 * 1024, item_type="file"),
        make_item("/Users/test/workspace/projB", size_bytes=15 * 1024 * 1024 * 1024, item_type="directory"),
        make_item("/Users/test/other_dir/standalone.iso", size_bytes=8 * 1024 * 1024 * 1024, item_type="file"),
    ]

    analyzer = LargeFileAnalyzer(default_threshold_bytes=1 * 1024 * 1024 * 1024)
    summary = analyzer.analyze_items(items)

    # Logical sum = 50 + 20 + 10 + 5 + 15 + 8 = 108 GB
    assert summary.total_logical_bytes == 108 * 1024 * 1024 * 1024
    # Unique physical sum = workspace (50 GB) + standalone.iso (8 GB) = 58 GB
    assert summary.total_unique_bytes == 58 * 1024 * 1024 * 1024
    assert summary.total_unique_bytes <= summary.total_logical_bytes


def test_no_hmac_or_approval_capabilities():
    """Verify finding models have no HMAC signing, verification, or token generation methods."""
    finding = LargeFileFinding(
        path="/Users/test/sample.dat",
        size_bytes=100 * 1024 * 1024,
        category=SmartCategory.ARCHIVES,
        confidence=ConfidenceLevel.HIGH,
        rank=1,
        size_threshold_bytes=50 * 1024 * 1024,
        attention_score=50.0,
        rationale="Sample large item.",
    )

    assert not hasattr(finding, "sign_hmac")
    assert not hasattr(finding, "verify_hmac")
    assert not hasattr(finding, "create_token")
    assert not hasattr(finding, "generate_approval")

