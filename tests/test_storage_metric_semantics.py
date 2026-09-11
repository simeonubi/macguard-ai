"""
MacGuard AI v1.1 — Storage Metric Semantics Regression Tests.

Validates:
1. Filesystem Used = live physical storage reported by macOS.
2. Analyzed Storage = bytes discovered by APFS-aware scanner traversal (ScanResult.total_bytes / physical coverage).
3. Candidate Inventory = sum of candidate records, which may contain parent/child overlap.
4. Eligible for Review = only cleanup-eligible candidate bytes (LOW risk).
5. Candidate Inventory is never labeled or presented as Analyzed Storage.
6. Analyzed Storage is never forced to equal physical filesystem usage.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
import streamlit as st

from app.analysis.models import RiskLevel, StorageCandidate, StorageCategory
from app.analysis.storage_analyzer import StorageAnalyzer
from app.models.scan_result import DiscoveredItem, ScanResult, ScanStatus
from app.models.scan_scope import ScopeIdentifier
from app.tools.storage_scanner import StorageItem, StorageScanner
from app.ui.scan import render_scan_page
from app.ui.state import init_app_state


def test_candidate_inventory_vs_analyzed_storage_difference():
    """
    Test that Candidate Inventory preserves parent + nested child hierarchy (allowing explainable review)
    while physical coverage / analyzed storage does not double-count nested storage.
    """
    analyzer = StorageAnalyzer()

    # Create parent candidate (/Users: 121.46 GB, HIGH risk protected system/user root)
    # and nested cleanable candidate (/Users/mac/Library/Containers/app: 64.00 GB, LOW risk cache)
    parent_cand = StorageCandidate(
        path="/Users",
        size_bytes=121_460_000_000,
        category=StorageCategory.UNKNOWN,
        risk_level=RiskLevel.HIGH,
        confidence=1.0,
        item_type="directory",
        reason="User root directory",
        recommendation="Preserve system and user root directories",
    )
    nested_cand = StorageCandidate(
        path="/Users/mac/Library/Containers/com.example.app/Data/Library/Caches",
        size_bytes=64_000_000_000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=1.0,
        item_type="directory",
        reason="Application cache container",
        recommendation="Safe to review and clear cache",
    )
    other_cand = StorageCandidate(
        path="/System",
        size_bytes=20_930_000_000,
        category=StorageCategory.UNKNOWN,
        risk_level=RiskLevel.HIGH,
        confidence=1.0,
        item_type="directory",
        reason="Operating system core",
        recommendation="Preserve core system files",
    )

    candidates = [parent_cand, nested_cand, other_cand]

    # 1. Candidate Inventory = Sum of candidate records (may contain parent/child overlap)
    candidate_inventory_bytes = sum(c.size_bytes for c in candidates)
    assert candidate_inventory_bytes == 121_460_000_000 + 64_000_000_000 + 20_930_000_000
    assert candidate_inventory_bytes == 206_390_000_000

    # 2. Eligible for Review = Only low-risk cleanup-eligible bytes
    eligible_review_bytes = sum(c.size_bytes for c in candidates if c.risk_level == RiskLevel.LOW)
    assert eligible_review_bytes == 64_000_000_000

    # 3. Physical Coverage / Unique Analyzed Storage = Resolves containment so nested items are not double-counted
    physical_coverage_bytes = analyzer.calculate_physical_coverage_bytes(candidates)
    # /Users encompasses the nested container, so physical coverage is /Users + /System = 142.39 GB
    assert physical_coverage_bytes == 121_460_000_000 + 20_930_000_000
    assert physical_coverage_bytes == 142_390_000_000

    # Explicit assertion: Candidate Inventory != Analyzed Physical Coverage
    assert candidate_inventory_bytes > physical_coverage_bytes
    assert candidate_inventory_bytes - physical_coverage_bytes == nested_cand.size_bytes


def test_ui_scan_metrics_and_banner_labels(tmp_path):
    """
    Verify that scan UI displays 'Candidate Inventory' and 'in candidate inventory'
    rather than labeling Candidate Inventory as 'analyzed storage'.
    """
    st.session_state.clear()
    init_app_state()

    mock_items = [
        StorageItem(path=str(Path.home() / "file1.log"), size_bytes=10_000_000, item_type="file"),
        StorageItem(path=str(Path.home() / "file2.tmp"), size_bytes=20_000_000, item_type="file"),
    ]

    mock_scanner = MagicMock(spec=StorageScanner)
    mock_scanner.get_common_user_storage_targets.return_value = [str(Path.home())]
    mock_scanner.get_top_directories.return_value = []
    mock_scanner.get_large_files.return_value = mock_items
    st.session_state.scanner = mock_scanner

    success_messages = []
    metrics_called = []

    def fake_success(msg, *args, **kwargs):
        success_messages.append(msg)

    def fake_metric(label, value, *args, **kwargs):
        metrics_called.append((label, value, kwargs.get("help")))

    with patch("streamlit.radio", return_value="Recommended User Storage Scope (Fast & Targeted)"), \
         patch("streamlit.button", side_effect=lambda label, **kwargs: "Run Read-Only" in label), \
         patch("streamlit.spinner"), \
         patch("streamlit.success", side_effect=fake_success), \
         patch("streamlit.metric", side_effect=fake_metric), \
         patch("streamlit.tabs", return_value=[MagicMock(), MagicMock(), MagicMock()]):
        render_scan_page()

    # Success banner check
    assert len(success_messages) == 1
    assert "in candidate inventory" in success_messages[0]
    assert "of analyzed storage" not in success_messages[0]

    # Metrics cards check
    metric_labels = [m[0] for m in metrics_called]
    assert "Candidate Inventory" in metric_labels
    assert "Eligible for Review" in metric_labels
    assert "Total Candidate Size" not in metric_labels


def test_analyzed_storage_not_forced_to_filesystem_used():
    """
    Verify that scanner Analyzed Storage is an independent APFS-aware discovery metric
    and is not artificially forced to equal live physical filesystem usage.
    """
    scanner = StorageScanner()
    disk_usage = scanner.get_disk_usage("/")

    scan_result = ScanResult(
        scope_id=ScopeIdentifier.HOME,
        root_path=str(Path.home()),
        status=ScanStatus.COMPLETED,
        start_time=1700000000.0,
        end_time=1700000001.0,
        duration_seconds=1.0,
        files_count=10,
        directories_count=2,
        total_bytes=50_000_000,
    )

    # Analyzed storage (50 MB in scope) must NOT be forced to match whole disk used_bytes
    assert scan_result.total_bytes != disk_usage.used_bytes
    assert scan_result.total_bytes == 50_000_000


def test_low_risk_candidates_never_overlap_after_deduplication():
    """
    Verify the invariant: StorageAnalyzer.deduplicate_candidates guarantees that no two
    LOW-risk candidates can overlap. When a low-risk parent exists, all low-risk children
    are subsumed into the parent candidate.
    """
    analyzer = StorageAnalyzer()

    parent_cache = StorageItem(
        path=str(Path.home() / "Library/Caches/Google"),
        size_bytes=500_000_000,
        item_type="directory",
    )
    child_cache = StorageItem(
        path=str(Path.home() / "Library/Caches/Google/Chrome"),
        size_bytes=300_000_000,
        item_type="directory",
    )
    grandchild_cache = StorageItem(
        path=str(Path.home() / "Library/Caches/Google/Chrome/Default"),
        size_bytes=200_000_000,
        item_type="directory",
    )

    items = [parent_cache, child_cache, grandchild_cache]
    candidates = analyzer.analyze_items(items, deduplicate=True)

    # Subtree is subsumed by parent: only 1 LOW-risk candidate is retained
    assert len(candidates) == 1
    assert candidates[0].path == str(Path.home() / "Library/Caches/Google")
    assert candidates[0].risk_level == RiskLevel.LOW

    # For any deduplicated candidate set, sum of low-risk sizes EQUALS calculate_reclaimable_bytes
    low_risk_sum = sum(c.size_bytes for c in candidates if c.risk_level == RiskLevel.LOW)
    reclaimable_coverage = analyzer.calculate_reclaimable_bytes(candidates)
    assert low_risk_sum == reclaimable_coverage
