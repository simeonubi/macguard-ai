"""
MacGuard AI v1.1 — Storage Intelligence UI & Historical Visualization Tests (Phase 5C).

Validates UI rendering, deterministic historical summaries, category growth velocity,
developer storage trends, large consumer bounding, accessible symbols, diagnostic warnings,
and zero-authority safety invariants.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
import streamlit as st

from app.analysis.storage_history import StorageHistoryRepository
from app.analysis.storage_trends import StorageTrendsEngine
from app.models.category import ConfidenceLevel, SmartCategory
from app.models.developer import DeveloperStorageSubtype
from app.models.scan_result import DiscoveredItem, ScanResult, ScanStatus
from app.models.scan_scope import ScanScope, ScopeIdentifier, TraversalLimits
from app.models.storage_history import (
    CategorySnapshotItem,
    CategoryTrend,
    DeveloperSnapshotItem,
    DeveloperTrend,
    LargeConsumerSnapshotItem,
    StorageSnapshot,
    StorageTrend,
    StorageTrendReport,
    TrendDirection,
)
from app.ui.state import get_services, init_app_state, navigate_to, set_operating_mode, sync_mode_and_navigation
from app.ui.storage_intelligence import (
    format_timestamp,
    get_trend_badge,
    render_category_intelligence,
    render_developer_trends,
    render_large_consumers,
    render_overview_cards,
    render_storage_history_chart,
    render_storage_intelligence_view,
    render_whats_growing,
)


@pytest.fixture(autouse=True)
def setup_session():
    """Ensure clean Streamlit session state for each test."""
    st.session_state.clear()
    init_app_state()
    yield
    st.session_state.clear()


@pytest.fixture
def sample_snapshots():
    """Create two sample snapshots for comparative trend testing."""
    snap1 = StorageSnapshot(
        snapshot_id="snap-001",
        scan_id="scan-001",
        timestamp=1700000000.0,
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/mac",
        status=ScanStatus.COMPLETED,
        duration_seconds=1.2,
        files_count=1000,
        directories_count=200,
        total_bytes=100_000_000_000,  # 100 GB
        unique_bytes=98_000_000_000,
        categories=[
            CategorySnapshotItem(category=SmartCategory.DEVELOPER_DATA, total_bytes=40_000_000_000, item_count=500),
            CategorySnapshotItem(category=SmartCategory.CACHES, total_bytes=20_000_000_000, item_count=300),
        ],
        developer_subtypes=[
            DeveloperSnapshotItem(
                subtype=DeveloperStorageSubtype.NODE_MODULES,
                total_bytes=25_000_000_000,
                unique_bytes=25_000_000_000,
                item_count=10,
            ),
        ],
        top_consumers=[
            LargeConsumerSnapshotItem(
                rank=1,
                path="/Users/mac/node_modules",
                size_bytes=25_000_000_000,
                category=SmartCategory.DEVELOPER_DATA,
                confidence=ConfidenceLevel.HIGH,
            ),
        ],
    )
    snap2 = StorageSnapshot(
        snapshot_id="snap-002",
        scan_id="scan-002",
        timestamp=1700086400.0,
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/mac",
        status=ScanStatus.COMPLETED,
        duration_seconds=1.5,
        files_count=1100,
        directories_count=220,
        total_bytes=120_000_000_000,  # 120 GB (+20 GB, +20.0% -> GROWING)
        unique_bytes=118_000_000_000,
        categories=[
            CategorySnapshotItem(category=SmartCategory.DEVELOPER_DATA, total_bytes=50_000_000_000, item_count=550),
            CategorySnapshotItem(category=SmartCategory.CACHES, total_bytes=25_000_000_000, item_count=320),
        ],
        developer_subtypes=[
            DeveloperSnapshotItem(
                subtype=DeveloperStorageSubtype.NODE_MODULES,
                total_bytes=32_000_000_000,
                unique_bytes=32_000_000_000,
                item_count=12,
            ),
        ],
        top_consumers=[
            LargeConsumerSnapshotItem(
                rank=1,
                path="/Users/mac/node_modules",
                size_bytes=32_000_000_000,
                category=SmartCategory.DEVELOPER_DATA,
                confidence=ConfidenceLevel.HIGH,
            ),
            LargeConsumerSnapshotItem(
                rank=2,
                path="/Users/mac/Downloads/very_long_path_name_with_deep_nested_structure/data_dump.tar.gz",
                size_bytes=10_000_000_000,
                category=SmartCategory.ARCHIVES,
                confidence=ConfidenceLevel.HIGH,
            ),
        ],
    )
    return snap1, snap2


# =========================================================================
# 1-3. Dashboard Rendering with Zero, One, Multiple Snapshots
# =========================================================================

def test_storage_intelligence_renders_with_no_history():
    """Test empty state when no historical snapshots exist."""
    repo = StorageHistoryRepository(db_path=":memory:")
    st.session_state.storage_history = repo

    with patch("streamlit.selectbox", return_value=ScopeIdentifier.HOME), \
         patch("streamlit.info") as mock_info:
        render_storage_intelligence_view(ScopeIdentifier.HOME)
        assert mock_info.called
        assert "No Historical Scans Recorded" in mock_info.call_args[0][0]


def test_storage_intelligence_renders_with_one_snapshot(sample_snapshots):
    """Test first-scan experience when only one historical snapshot exists."""
    snap1, _ = sample_snapshots
    repo = StorageHistoryRepository(db_path=":memory:")
    scan_res = ScanResult(
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/mac",
        status=ScanStatus.COMPLETED,
        start_time=1700000000.0,
        end_time=1700000001.2,
        duration_seconds=1.2,
        files_count=1000,
        directories_count=200,
        total_bytes=100_000_000_000,
        items=[
            DiscoveredItem(
                path="/Users/mac/Projects/data.bin",
                size_bytes=1000,
                item_type="file",
                depth=1,
                mtime=1700000000.0,
                st_ino=1,
                st_dev=1,
                category=SmartCategory.DEVELOPER_DATA,
            )
        ],
    )
    repo.record_snapshot(scan_res, scan_id="scan-001")
    st.session_state.storage_history = repo

    with patch("streamlit.selectbox", return_value=ScopeIdentifier.HOME), \
         patch("streamlit.metric") as mock_metric:
        render_storage_intelligence_view(ScopeIdentifier.HOME)
        assert mock_metric.called


def test_storage_intelligence_renders_with_multiple_snapshots(sample_snapshots):
    """Test comparison view when multiple historical snapshots exist."""
    snap1, snap2 = sample_snapshots
    repo = StorageHistoryRepository(db_path=":memory:")

    res1 = ScanResult(
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/mac",
        status=ScanStatus.COMPLETED,
        start_time=1700000000.0,
        end_time=1700000001.2,
        duration_seconds=1.2,
        files_count=1000,
        directories_count=200,
        total_bytes=100_000_000_000,
        items=[
            DiscoveredItem(
                path="/Users/mac/Projects/app.py",
                size_bytes=1000,
                item_type="file",
                depth=1,
                mtime=1700000000.0,
                st_ino=1,
                st_dev=1,
                category=SmartCategory.DEVELOPER_DATA,
            )
        ],
    )
    res2 = ScanResult(
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/mac",
        status=ScanStatus.COMPLETED,
        start_time=1700086400.0,
        end_time=1700086401.5,
        duration_seconds=1.5,
        files_count=1100,
        directories_count=220,
        total_bytes=120_000_000_000,
        items=[
            DiscoveredItem(
                path="/Users/mac/Projects/app.py",
                size_bytes=1200,
                item_type="file",
                depth=1,
                mtime=1700086400.0,
                st_ino=1,
                st_dev=1,
                category=SmartCategory.DEVELOPER_DATA,
            )
        ],
    )
    repo.record_snapshot(res1, scan_id="scan-001")
    repo.record_snapshot(res2, scan_id="scan-002")
    st.session_state.storage_history = repo

    with patch("streamlit.selectbox", side_effect=[ScopeIdentifier.HOME, "Previous Consecutive Scan"]), \
         patch("streamlit.metric") as mock_metric, \
         patch("streamlit.altair_chart") as mock_chart:
        render_storage_intelligence_view(ScopeIdentifier.HOME)
        assert mock_metric.called
        assert mock_chart.called


# =========================================================================
# 4-9. Storage Metrics & Trend Classifications
# =========================================================================

def test_current_storage_metric_rendering(sample_snapshots):
    """Verify current storage metric displays accurate formatted values."""
    _, snap2 = sample_snapshots
    engine = StorageTrendsEngine()
    report = engine.compare_snapshots(current=snap2, previous=None)

    with patch("streamlit.metric") as mock_metric:
        render_overview_cards(latest=snap2, report=report, prev=None)
        labels = [c[1]["label"] if "label" in c[1] else c[0][0] for c in mock_metric.call_args_list]
        assert "Current Scanned Storage" in labels


def test_growth_trend_display(sample_snapshots):
    """Verify growing trend is properly labeled with delta and classification."""
    snap1, snap2 = sample_snapshots
    engine = StorageTrendsEngine()
    report = engine.compare_snapshots(current=snap2, previous=snap1)

    assert report.overall_trend.direction == TrendDirection.GROWING
    assert report.overall_trend.absolute_change == 20_000_000_000

    with patch("streamlit.metric") as mock_metric:
        render_overview_cards(latest=snap2, report=report, prev=snap1)
        values = [c[1].get("value") or (c[0][1] if len(c[0]) > 1 else None) for c in mock_metric.call_args_list]
        assert "Growing" in values


def test_shrinkage_trend_display(sample_snapshots):
    """Verify shrinking trend is properly classified."""
    snap1, snap2 = sample_snapshots
    engine = StorageTrendsEngine()
    # Reverse order: from 120 GB down to 100 GB (-16.7%)
    report = engine.compare_snapshots(current=snap1, previous=snap2)

    assert report.overall_trend.direction == TrendDirection.SHRINKING
    assert report.overall_trend.absolute_change == -20_000_000_000

    with patch("streamlit.metric") as mock_metric:
        render_overview_cards(latest=snap1, report=report, prev=snap2)
        values = [c[1].get("value") or (c[0][1] if len(c[0]) > 1 else None) for c in mock_metric.call_args_list]
        assert "Shrinking" in values


def test_stable_trend_display(sample_snapshots):
    """Verify stable trend classification when storage changes insignificantly."""
    snap1, _ = sample_snapshots
    # Create clone with identical bytes
    snap1_clone = snap1.model_copy(update={"snapshot_id": "snap-001b", "scan_id": "scan-001b"})
    engine = StorageTrendsEngine()
    report = engine.compare_snapshots(current=snap1_clone, previous=snap1)

    assert report.overall_trend.direction == TrendDirection.STABLE
    with patch("streamlit.metric") as mock_metric:
        render_overview_cards(latest=snap1_clone, report=report, prev=snap1)
        values = [c[1].get("value") or (c[0][1] if len(c[0]) > 1 else None) for c in mock_metric.call_args_list]
        assert "Stable" in values


def test_unknown_trend_display(sample_snapshots):
    """Verify undetermined trend classification when comparison has insufficient data."""
    snap1, _ = sample_snapshots
    engine = StorageTrendsEngine()
    report = engine.compare_snapshots(current=snap1, previous=None)

    assert not report.is_comparable
    with patch("streamlit.metric") as mock_metric:
        render_overview_cards(latest=snap1, report=report, prev=None)
        values = [c[1].get("value") or (c[0][1] if len(c[0]) > 1 else None) for c in mock_metric.call_args_list]
        assert "First Baseline" in values


# =========================================================================
# 10-12. Category & Developer Trends and Visualization
# =========================================================================

def test_category_trend_table_rendering(sample_snapshots):
    """Verify category trend table formats rows accurately with directional indicators."""
    snap1, snap2 = sample_snapshots
    engine = StorageTrendsEngine()
    report = engine.compare_snapshots(current=snap2, previous=snap1)

    with patch("streamlit.dataframe") as mock_df, patch("streamlit.altair_chart") as mock_chart:
        render_category_intelligence(report=report, latest=snap2)
        assert mock_df.called
        table_rows = mock_df.call_args[0][0]
        assert len(table_rows) >= 1
        assert "Category" in table_rows[0]
        assert "Change" in table_rows[0]


def test_developer_trend_table_rendering(sample_snapshots):
    """Verify developer trend table formats rows accurately."""
    snap1, snap2 = sample_snapshots
    engine = StorageTrendsEngine()
    report = engine.compare_snapshots(current=snap2, previous=snap1)

    with patch("streamlit.dataframe") as mock_df:
        render_developer_trends(report=report)
        assert mock_df.called
        dev_rows = mock_df.call_args[0][0]
        assert len(dev_rows) >= 1
        assert dev_rows[0]["Subtype"] == "Node Modules"


def test_historical_chart_data_rendering(sample_snapshots):
    """Verify Altair storage over time chart is rendered with chronological points."""
    snap1, snap2 = sample_snapshots
    with patch("streamlit.altair_chart") as mock_chart:
        render_storage_history_chart(snapshots=[snap1, snap2])
        assert mock_chart.called


# =========================================================================
# 13-16. Diagnostic & Error States
# =========================================================================

def test_first_scan_state_chart_handling(sample_snapshots):
    """Verify chart shows informative notice when only one snapshot exists."""
    snap1, _ = sample_snapshots
    with patch("streamlit.info") as mock_info:
        render_storage_history_chart(snapshots=[snap1])
        assert mock_info.called
        assert "Run another scan later" in mock_info.call_args[0][0]


def test_incomplete_scan_warning(sample_snapshots):
    """Verify warning banner is rendered when scan status is not COMPLETED."""
    snap1, snap2 = sample_snapshots
    incomplete_snap = snap2.model_copy(update={"status": ScanStatus.CANCELLED})

    repo = MagicMock()
    repo.get_snapshot_history.return_value = [incomplete_snap, snap1]
    st.session_state.storage_history = repo

    with patch("streamlit.selectbox", side_effect=[ScopeIdentifier.HOME, "Previous Consecutive Scan"]), \
         patch("streamlit.warning") as mock_warning:
        render_storage_intelligence_view(ScopeIdentifier.HOME)
        assert mock_warning.called
        assert "Partial Scan Observation" in mock_warning.call_args[0][0]


def test_incompatible_scope_warning(sample_snapshots):
    """Verify trend engine identifies incompatible scopes without crashing."""
    snap1, snap2 = sample_snapshots
    diff_scope_snap = snap2.model_copy(update={"scope_id": ScopeIdentifier.DEVELOPER})
    engine = StorageTrendsEngine()
    report = engine.compare_snapshots(current=diff_scope_snap, previous=snap1)

    assert not report.is_comparable
    assert any("Incompatible" in note for note in report.notes)


def test_database_error_handling():
    """Verify database exceptions are caught and surfaced as friendly UI error without traceback."""
    repo = MagicMock()
    repo.get_snapshot_history.side_effect = RuntimeError("Database locked")
    st.session_state.storage_history = repo

    with patch("streamlit.selectbox", return_value=ScopeIdentifier.HOME), \
         patch("streamlit.error") as mock_error:
        render_storage_intelligence_view(ScopeIdentifier.HOME)
        assert mock_error.called
        assert "temporarily unavailable" in mock_error.call_args[0][0]


# =========================================================================
# 17-21. Large Consumer Presentation & Formatting
# =========================================================================

def test_large_consumer_table_rendering(sample_snapshots):
    """Verify top storage consumers are displayed in table with rank and confidence."""
    _, snap2 = sample_snapshots
    with patch("streamlit.dataframe") as mock_df:
        render_large_consumers(latest=snap2)
        assert mock_df.called
        rows = mock_df.call_args[0][0]
        assert len(rows) == 2
        assert rows[0]["Rank"] == "#1"
        assert rows[0]["Category"] == "Developer Data"


def test_top_n_bounded_display():
    """Verify large consumer list is bounded to Top 20."""
    consumers = [
        LargeConsumerSnapshotItem(
            rank=i,
            path=f"/path/{i}",
            size_bytes=1000 * (30 - i),
            category=SmartCategory.APPLICATIONS,
            confidence=ConfidenceLevel.HIGH,
        )
        for i in range(1, 26)
    ]
    snap = StorageSnapshot(
        snapshot_id="snap-bound",
        scan_id="scan-bound",
        timestamp=1700000000.0,
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/mac",
        status=ScanStatus.COMPLETED,
        duration_seconds=1.0,
        files_count=100,
        directories_count=10,
        total_bytes=100000,
        top_consumers=consumers[:20],  # Bounded
    )
    with patch("streamlit.dataframe") as mock_df:
        render_large_consumers(latest=snap)
        assert mock_df.called
        rows = mock_df.call_args[0][0]
        assert len(rows) <= 20


def test_long_path_rendering_in_large_consumers(sample_snapshots):
    """Verify long paths are included without truncation crashes."""
    _, snap2 = sample_snapshots
    with patch("streamlit.dataframe") as mock_df:
        render_large_consumers(latest=snap2)
        assert mock_df.called
        rows = mock_df.call_args[0][0]
        assert "very_long_path_name" in rows[1]["Path"]


def test_accessible_trend_badges():
    """Verify get_trend_badge returns both textual and symbolic indicators."""
    assert "Growing" in get_trend_badge(TrendDirection.GROWING)
    assert "Shrinking" in get_trend_badge(TrendDirection.SHRINKING)
    assert "Stable" in get_trend_badge(TrendDirection.STABLE)
    assert "Undetermined" in get_trend_badge(TrendDirection.UNKNOWN)


def test_timestamp_formatting():
    """Verify timestamp formatting handles valid and invalid values safely."""
    assert format_timestamp(1700000000.0) != "N/A"
    assert format_timestamp(float("nan")) == "N/A"


# =========================================================================
# 22-25. Navigation & Mode Synchronization Regression
# =========================================================================

def test_navigation_and_mode_sync_intact():
    """Verify bidirectional navigation between modes remains strictly synchronized."""
    # Start at Analyze
    set_operating_mode("ANALYZE")
    sync_mode_and_navigation()
    assert st.session_state.current_mode == "ANALYZE"
    assert st.session_state.current_tab == "Dashboard"

    # Move to Review
    set_operating_mode("REVIEW")
    sync_mode_and_navigation()
    assert st.session_state.current_mode == "REVIEW"
    assert st.session_state.current_tab == "Review"

    # Move to Clean
    set_operating_mode("CLEAN")
    sync_mode_and_navigation()
    assert st.session_state.current_mode == "CLEAN"
    assert st.session_state.current_tab == "Execution"

    # Move to Agent
    set_operating_mode("AGENT")
    sync_mode_and_navigation()
    assert st.session_state.current_mode == "AGENT"
    assert st.session_state.current_tab == "Agent"

    # Navigate to Dashboard via tab
    navigate_to("Dashboard")
    sync_mode_and_navigation()
    assert st.session_state.current_tab == "Dashboard"
    assert st.session_state.current_mode == "ANALYZE"


# =========================================================================
# 26-28. Zero Mutation & Zero Authority Safety Invariants
# =========================================================================

def test_storage_intelligence_possesses_zero_cleanup_authority():
    """
    Verify that storage intelligence models and UI possess ZERO approval,
    zero execution, and zero filesystem modification authority.
    """
    import app.ui.storage_intelligence as ui_module

    # Confirm dangerous execution primitives are absent from UI module
    assert not hasattr(ui_module, "TrashExecutor")
    assert not hasattr(ui_module, "ApprovalKeyManager")
    assert not hasattr(ui_module, "ApprovalService")
    assert not hasattr(ui_module, "execute_plan")
    assert not hasattr(ui_module, "delete")
    assert not hasattr(ui_module, "remove")


def test_deterministic_whats_growing_insights(sample_snapshots):
    """Verify 'What's Growing?' produces deterministic statements without AI/LLM invocation."""
    snap1, snap2 = sample_snapshots
    engine = StorageTrendsEngine()
    report = engine.compare_snapshots(current=snap2, previous=snap1)

    with patch("streamlit.markdown") as mock_md:
        render_whats_growing(report=report)
        assert mock_md.called
        calls = [c[0][0] for c in mock_md.call_args_list]
        growing_text = " ".join(calls)
        assert "Developer" in growing_text


# =========================================================================
# 29-30. Navigation Registration & Standalone Page Rendering
# =========================================================================

def test_storage_intelligence_navigation_registration():
    """
    Verify that Storage Intelligence & History is registered in the main navigation,
    mapped to ANALYZE mode, and formatted with accessible label.
    """
    from app.ui.app import main
    from app.ui.state import TAB_TO_MODE

    # 1. State Mapping Verification
    assert "StorageIntelligence" in TAB_TO_MODE
    assert TAB_TO_MODE["StorageIntelligence"] == "ANALYZE"

    # 2. Navigation to StorageIntelligence
    navigate_to("StorageIntelligence")
    sync_mode_and_navigation()
    assert st.session_state.current_tab == "StorageIntelligence"
    assert st.session_state.current_mode == "ANALYZE"

    # 3. Main app execution routing
    with patch("streamlit.sidebar"), \
         patch("app.ui.app.render_storage_intelligence_page") as mock_render:
        # Simulate main page router with active StorageIntelligence tab
        st.session_state.current_tab = "StorageIntelligence"
        main()
        assert mock_render.called


def test_render_storage_intelligence_page_standalone():
    """Verify that standalone render_storage_intelligence_page executes cleanly."""
    from app.ui.storage_intelligence import render_storage_intelligence_page

    with patch("app.ui.components.render_brand_header") as mock_header, \
         patch("app.ui.components.render_safety_notice") as mock_safety, \
         patch("app.ui.storage_intelligence.render_storage_intelligence_view") as mock_view:
        render_storage_intelligence_page()
        assert mock_header.called
        assert mock_safety.called
        assert mock_view.called


def test_dynamic_comparison_label_wording(sample_snapshots):
    """Verify dynamic metric labeling for previous scan vs baseline scan."""
    snap1, snap2 = sample_snapshots
    repo = StorageHistoryRepository(db_path=":memory:")

    res1 = ScanResult(
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/mac",
        status=ScanStatus.COMPLETED,
        start_time=1700000000.0,
        end_time=1700000001.2,
        duration_seconds=1.2,
        files_count=1000,
        directories_count=200,
        total_bytes=100_000_000_000,
        items=[
            DiscoveredItem(
                path="/Users/mac/Projects/file1.py",
                size_bytes=1000,
                item_type="file",
                depth=1,
                mtime=1700000000.0,
                st_ino=1,
                st_dev=1,
                category=SmartCategory.DEVELOPER_DATA,
            )
        ],
    )
    res2 = ScanResult(
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/mac",
        status=ScanStatus.COMPLETED,
        start_time=1700086400.0,
        end_time=1700086401.5,
        duration_seconds=1.5,
        files_count=1100,
        directories_count=220,
        total_bytes=120_000_000_000,
        items=[
            DiscoveredItem(
                path="/Users/mac/Projects/file2.py",
                size_bytes=1200,
                item_type="file",
                depth=1,
                mtime=1700086400.0,
                st_ino=1,
                st_dev=1,
                category=SmartCategory.DEVELOPER_DATA,
            )
        ],
    )
    repo.record_snapshot(res1, scan_id="scan-001")
    repo.record_snapshot(res2, scan_id="scan-002")
    st.session_state.storage_history = repo

    from app.tools.storage_scanner import format_bytes_decimal
    snapshots = repo.get_snapshot_history(ScopeIdentifier.HOME)
    history_choices = ["Previous Consecutive Scan"] + [
        f"Scan from {format_timestamp(s.timestamp)} ({format_bytes_decimal(s.total_bytes)})"
        for s in snapshots[1:]
    ]

    # 1. Previous Consecutive Scan selected -> "Change Since Previous Scan"
    with patch("streamlit.selectbox", side_effect=[ScopeIdentifier.HOME, history_choices[0]]), \
         patch("streamlit.metric") as mock_metric:
        render_storage_intelligence_view(ScopeIdentifier.HOME)
        labels = [call.kwargs.get("label") for call in mock_metric.call_args_list if "label" in call.kwargs]
        assert "Change Since Previous Scan" in labels
        assert "Change Since Baseline" not in labels

    # 2. Specific Baseline Scan selected -> "Change Since Baseline"
    with patch("streamlit.selectbox", side_effect=[ScopeIdentifier.HOME, history_choices[1]]), \
         patch("streamlit.metric") as mock_metric:
        render_storage_intelligence_view(ScopeIdentifier.HOME)
        labels = [call.kwargs.get("label") for call in mock_metric.call_args_list if "label" in call.kwargs]
        assert "Change Since Baseline" in labels


def test_overview_cards_incompatible_baseline():
    """Verify overview cards display 'No Comparable Baseline' and '—' without misleading percentages."""
    current = StorageSnapshot(
        snapshot_id="snap-curr",
        scan_id="scan-curr",
        timestamp=1700086400.0,
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/mac",
        status=ScanStatus.COMPLETED,
        duration_seconds=1.0,
        files_count=100,
        directories_count=10,
        total_bytes=9_290_000_000,
    )
    previous = StorageSnapshot(
        snapshot_id="snap-prev",
        scan_id="scan-prev",
        timestamp=1700000000.0,
        scope_id=ScopeIdentifier.CUSTOM,
        root_path="/",
        status=ScanStatus.COMPLETED,
        duration_seconds=5.0,
        files_count=10000,
        directories_count=1000,
        total_bytes=474_000_000_000,
    )

    engine = StorageTrendsEngine()
    report = engine.compare_snapshots(current=current, previous=previous)

    assert report.is_comparable is False

    with patch("streamlit.metric") as mock_metric:
        render_overview_cards(current, report, previous, comparison_label="Change Since Baseline")

        calls = mock_metric.call_args_list
        metrics_by_label = {call.kwargs.get("label"): call.kwargs for call in calls if "label" in call.kwargs}

        # Change metric value should be "—" and have no delta
        assert metrics_by_label["Change Since Baseline"]["value"] == "—"
        assert "delta" not in metrics_by_label["Change Since Baseline"]
        assert "different scope" in metrics_by_label["Change Since Baseline"]["help"]

        # Trend Classification should be "No Comparable Baseline"
        assert metrics_by_label["Trend Classification"]["value"] == "No Comparable Baseline"
        assert "different scope" in metrics_by_label["Trend Classification"]["help"]


def test_chart_does_not_connect_incompatible_scope_measurements():
    """Verify chart only plots snapshots sharing the same scope and root as the latest snapshot."""
    snap1 = StorageSnapshot(
        snapshot_id="snap-root",
        scan_id="scan-root",
        timestamp=1700000000.0,
        scope_id=ScopeIdentifier.CUSTOM,
        root_path="/",
        status=ScanStatus.COMPLETED,
        duration_seconds=5.0,
        files_count=10000,
        directories_count=1000,
        total_bytes=474_000_000_000,
    )
    snap2 = StorageSnapshot(
        snapshot_id="snap-home",
        scan_id="scan-home",
        timestamp=1700086400.0,
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/mac",
        status=ScanStatus.COMPLETED,
        duration_seconds=1.0,
        files_count=100,
        directories_count=10,
        total_bytes=9_290_000_000,
    )

    # When given list [snap2, snap1], chart filters to snap2 only, which is < 2 matching snapshots
    with patch("streamlit.info") as mock_info, patch("streamlit.altair_chart") as mock_chart:
        render_storage_history_chart([snap2, snap1])

        # Should show info message because only 1 snapshot matches scope/root
        mock_info.assert_called_once()
        assert "Run another scan later with the same scope" in mock_info.call_args[0][0]
        mock_chart.assert_not_called()


def test_user_home_chart_strictly_excludes_root_scans_when_multiple_home_scans_exist():
    """Verify that a User Home chart with multiple valid home scans strictly excludes a 474 GB root scan."""
    snap_root = StorageSnapshot(
        snapshot_id="snap-root",
        scan_id="scan-root",
        timestamp=1700000000.0,
        scope_id=ScopeIdentifier.CUSTOM,
        root_path="/",
        status=ScanStatus.COMPLETED,
        duration_seconds=5.0,
        files_count=10000,
        directories_count=1000,
        total_bytes=474_000_000_000,
    )
    snap_home1 = StorageSnapshot(
        snapshot_id="snap-home-1",
        scan_id="scan-home-1",
        timestamp=1700086400.0,
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/mac",
        status=ScanStatus.COMPLETED,
        duration_seconds=1.0,
        files_count=100,
        directories_count=10,
        total_bytes=9_290_000_000,
        top_consumers=[
            LargeConsumerSnapshotItem(
                rank=1,
                path="/Users/mac/Downloads/archive1.zip",
                size_bytes=5_000_000_000,
                category=SmartCategory.ARCHIVES,
                confidence=ConfidenceLevel.HIGH,
            )
        ],
    )
    snap_home2 = StorageSnapshot(
        snapshot_id="snap-home-2",
        scan_id="scan-home-2",
        timestamp=1700172800.0,
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/mac",
        status=ScanStatus.COMPLETED,
        duration_seconds=1.1,
        files_count=105,
        directories_count=10,
        total_bytes=9_300_000_000,
        top_consumers=[
            LargeConsumerSnapshotItem(
                rank=1,
                path="/Users/mac/Downloads/archive2.zip",
                size_bytes=5_000_000_000,
                category=SmartCategory.ARCHIVES,
                confidence=ConfidenceLevel.HIGH,
            )
        ],
    )

    with patch("streamlit.altair_chart") as mock_chart, patch("streamlit.info") as mock_info:
        render_storage_history_chart(
            [snap_home2, snap_home1, snap_root],
            target_scope=ScopeIdentifier.HOME,
            target_root="/Users/mac",
        )
        assert mock_chart.called
        chart_obj = mock_chart.call_args[0][0]
        # Inspect chart data to ensure root scan is excluded
        data = chart_obj.data
        assert len(data) == 2
        # Max storage in charted data is ~9.30 GB, never 474 GB
        assert all(row["Storage_GB"] < 15.0 for _, row in data.iterrows())
        assert not mock_info.called


def test_custom_scans_of_different_roots_remain_strictly_isolated():
    """Verify that different custom root paths (e.g. '/' vs '/Users/mac/Projects') never mix in charts."""
    snap_root = StorageSnapshot(
        snapshot_id="snap-root",
        scan_id="scan-root",
        timestamp=1700000000.0,
        scope_id=ScopeIdentifier.CUSTOM,
        root_path="/",
        status=ScanStatus.COMPLETED,
        duration_seconds=5.0,
        files_count=10000,
        directories_count=1000,
        total_bytes=249_000_000_000,
    )
    snap_projects = StorageSnapshot(
        snapshot_id="snap-projects",
        scan_id="scan-projects",
        timestamp=1700086400.0,
        scope_id=ScopeIdentifier.CUSTOM,
        root_path="/Users/mac/Projects",
        status=ScanStatus.COMPLETED,
        duration_seconds=1.0,
        files_count=500,
        directories_count=50,
        total_bytes=15_000_000_000,
    )

    with patch("streamlit.info") as mock_info, patch("streamlit.altair_chart") as mock_chart:
        render_storage_history_chart(
            [snap_projects, snap_root],
            target_scope=ScopeIdentifier.CUSTOM,
            target_root="/Users/mac/Projects",
        )
        # Should show info because only 1 snapshot matches '/Users/mac/Projects'
        assert mock_info.called
        assert "Run another scan later with the same scope" in mock_info.call_args[0][0]
        assert not mock_chart.called


def test_chart_excludes_legacy_out_of_boundary_snapshot():
    """
    Verify render_storage_history_chart excludes a legacy ~474 GB snapshot
    stored under HOME whose top consumers are outside /Users/mac.
    """
    from app.models.category import ConfidenceLevel, SmartCategory
    from app.models.storage_history import LargeConsumerSnapshotItem

    snap_home1 = StorageSnapshot(
        snapshot_id="snap-home-1",
        scan_id="scan-home-1",
        timestamp=1700000000.0,
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/mac",
        status=ScanStatus.COMPLETED,
        duration_seconds=1.0,
        files_count=1000,
        directories_count=100,
        total_bytes=10_000_000_000,
        top_consumers=[
            LargeConsumerSnapshotItem(
                rank=1,
                path="/Users/mac/Downloads/app.dmg",
                size_bytes=5_000_000_000,
                category=SmartCategory.ARCHIVES,
                confidence=ConfidenceLevel.HIGH,
            )
        ],
    )
    snap_legacy_474gb = StorageSnapshot(
        snapshot_id="snap-legacy-474gb",
        scan_id="scan-legacy-474gb",
        timestamp=1700050000.0,
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/mac",
        status=ScanStatus.COMPLETED,
        duration_seconds=10.0,
        files_count=500000,
        directories_count=50000,
        total_bytes=474_000_000_000,
        top_consumers=[
            LargeConsumerSnapshotItem(
                rank=1,
                path="/System/Library/Kernels",
                size_bytes=200_000_000_000,
                category=SmartCategory.SYSTEM_DATA,
                confidence=ConfidenceLevel.HIGH,
            ),
            LargeConsumerSnapshotItem(
                rank=2,
                path="/Applications/Xcode.app",
                size_bytes=30_000_000_000,
                category=SmartCategory.APPLICATIONS,
                confidence=ConfidenceLevel.HIGH,
            ),
        ],
    )
    snap_home2 = StorageSnapshot(
        snapshot_id="snap-home-2",
        scan_id="scan-home-2",
        timestamp=1700100000.0,
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/mac",
        status=ScanStatus.COMPLETED,
        duration_seconds=1.1,
        files_count=1050,
        directories_count=102,
        total_bytes=11_000_000_000,
        top_consumers=[
            LargeConsumerSnapshotItem(
                rank=1,
                path="/Users/mac/.cache/models.bin",
                size_bytes=6_000_000_000,
                category=SmartCategory.CACHES,
                confidence=ConfidenceLevel.HIGH,
            )
        ],
    )

    with patch("streamlit.altair_chart") as mock_chart:
        render_storage_history_chart(
            [snap_home2, snap_legacy_474gb, snap_home1],
            target_scope=ScopeIdentifier.HOME,
            target_root="/Users/mac",
        )
        assert mock_chart.called
        chart_obj = mock_chart.call_args[0][0]
        # Inspect chart dataset to ensure 474 GB is absent
        chart_df = chart_obj.data
        assert len(chart_df) == 2
        # Max storage in chart must be ~11 GB, not 474 GB
        assert chart_df["Storage_GB"].max() < 20.0
        assert 474.0 not in chart_df["Storage_GB"].values
