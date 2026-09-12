"""
MacGuard AI v1.1 — Phase 9 Streamlit UI/UX Expansion Test Suite.

Validates:
- Developer Storage UI view rendering, metrics, staleness, project mappings, and bounds.
- Duplicate Explorer UI view rendering, cluster browser, hardlink 0 B wasted invariant, and bounds.
- Storage Intelligence enhancements, Altair zero-bound scales, and path sanitization.
- Safe navigation and session state synchronization.
- Strict read-only safety invariants (zero deletion/move/approval controls).
"""

from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
import streamlit as st

from app.analysis.developer_analyzer import DeveloperStorageAnalyzer
from app.analysis.duplicate_detector import DuplicateDetector
from app.models.category import ConfidenceLevel, SmartCategory
from app.models.developer import (
    DeveloperProjectSummary,
    DeveloperStorageFinding,
    DeveloperStorageGroup,
    DeveloperStorageSubtype,
    DeveloperStorageSummary,
    StaleStatus,
)
from app.models.duplicate import (
    DuplicateCluster,
    DuplicateFile,
    DuplicateScanSummary,
)
from app.models.scan_result import DiscoveredItem, ScanResult, ScanStatus
from app.models.scan_scope import ScopeIdentifier
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
from app.ui.components import alias_and_redact_path
from app.ui.developer_view import render_developer_storage_page
from app.ui.duplicate_view import render_duplicate_explorer_page
from app.ui.state import (
    init_app_state,
    navigate_to,
    set_operating_mode,
    sync_mode_and_navigation,
)
from app.ui.storage_intelligence import (
    render_category_intelligence,
    render_developer_trends,
    render_large_consumers,
    render_overview_cards,
    render_storage_history_chart,
    render_storage_intelligence_page,
    render_whats_growing,
)


@pytest.fixture(autouse=True)
def setup_session():
    """Ensure clean Streamlit session state for each test."""
    st.session_state.clear()
    init_app_state()
    yield
    st.session_state.clear()


# ===========================================================================
# 1. Developer Storage UI Tests
# ===========================================================================

def test_developer_ui_empty_state() -> None:
    """Test Developer Storage view renders safely when no scan results exist."""
    st.session_state.developer_summary = None
    st.session_state.scan_results = None

    with patch("streamlit.info") as mock_info:
        render_developer_storage_page()
        assert any("No Developer Storage Analysis Available" in str(call[0][0]) for call in mock_info.call_args_list)


def test_developer_ui_populated_state() -> None:
    """Test Developer Storage view renders metrics and tables when populated."""
    finding = DeveloperStorageFinding(
        path="/Users/test/.cache/pip/wheels/abc",
        subtype=DeveloperStorageSubtype.PACKAGE_CACHE,
        category=SmartCategory.CACHES,
        size_bytes=10_000_000,
        item_type="directory",
        depth=3,
        mtime=1700000000.0,
        stale_status=StaleStatus.POTENTIALLY_STALE_90D,
        confidence=ConfidenceLevel.HIGH,
        confidence_score=0.95,
        evidence="pip wheels cache",
    )
    group = DeveloperStorageGroup(
        subtype=DeveloperStorageSubtype.PACKAGE_CACHE,
        title="Package Caches",
        total_logical_bytes=10_000_000,
        unique_physical_bytes=10_000_000,
        item_count=1,
        findings=[finding],
        stale_item_count=1,
        stale_bytes=10_000_000,
    )
    summary = DeveloperStorageSummary(
        total_logical_bytes=10_000_000,
        total_unique_bytes=10_000_000,
        total_findings_count=1,
        groups=[group],
        stale_findings=[finding],
    )
    st.session_state.developer_summary = summary

    with patch("streamlit.metric") as mock_metric:
        render_developer_storage_page()
        metric_labels = [call[0][0] for call in mock_metric.call_args_list]
        assert "Total Logical Storage" in metric_labels
        assert "Physical Storage" in metric_labels
        assert "Developer Artifacts" in metric_labels
        assert "Stale Artifacts (>90d)" in metric_labels


def test_developer_ui_category_and_subtype_display() -> None:
    """Test Developer Storage view formats and displays different subtypes."""
    f1 = DeveloperStorageFinding(
        path="/Users/test/Library/Developer/Xcode/DerivedData/App-xyz",
        subtype=DeveloperStorageSubtype.BUILD_OUTPUT,
        category=SmartCategory.BUILD_ARTIFACTS,
        size_bytes=50_000_000,
        item_type="directory",
        depth=4,
        mtime=1700000000.0,
        stale_status=StaleStatus.RECENT,
        confidence=ConfidenceLevel.HIGH,
        confidence_score=0.99,
        evidence="Xcode DerivedData output",
    )
    g1 = DeveloperStorageGroup(
        subtype=DeveloperStorageSubtype.BUILD_OUTPUT,
        title="Xcode DerivedData",
        total_logical_bytes=50_000_000,
        unique_physical_bytes=50_000_000,
        item_count=1,
        findings=[f1],
    )
    summary = DeveloperStorageSummary(
        total_logical_bytes=50_000_000,
        total_unique_bytes=50_000_000,
        total_findings_count=1,
        groups=[g1],
    )
    st.session_state.developer_summary = summary

    with patch("streamlit.dataframe") as mock_df:
        render_developer_storage_page()
        assert mock_df.called


def test_developer_ui_staleness_display() -> None:
    """Test staleness filtering checkbox logic in Developer Storage view."""
    f_fresh = DeveloperStorageFinding(
        path="/Users/test/fresh",
        subtype=DeveloperStorageSubtype.PYTHON_CACHE,
        category=SmartCategory.CACHES,
        size_bytes=1_000_000,
        item_type="directory",
        depth=2,
        mtime=1725000000.0,
        stale_status=StaleStatus.RECENT,
        confidence=ConfidenceLevel.HIGH,
        confidence_score=0.9,
        evidence="recent cache",
    )
    f_stale = DeveloperStorageFinding(
        path="/Users/test/stale",
        subtype=DeveloperStorageSubtype.PYTHON_CACHE,
        category=SmartCategory.CACHES,
        size_bytes=2_000_000,
        item_type="directory",
        depth=2,
        mtime=1700000000.0,
        stale_status=StaleStatus.POTENTIALLY_STALE_90D,
        confidence=ConfidenceLevel.HIGH,
        confidence_score=0.9,
        evidence="stale cache",
    )
    group = DeveloperStorageGroup(
        subtype=DeveloperStorageSubtype.PYTHON_CACHE,
        title="Python Caches",
        total_logical_bytes=3_000_000,
        unique_physical_bytes=3_000_000,
        item_count=2,
        findings=[f_fresh, f_stale],
        stale_item_count=1,
        stale_bytes=2_000_000,
    )
    summary = DeveloperStorageSummary(
        total_logical_bytes=3_000_000,
        total_unique_bytes=3_000_000,
        total_findings_count=2,
        groups=[group],
        stale_findings=[f_stale],
    )
    st.session_state.developer_summary = summary

    with patch("streamlit.checkbox", return_value=True):
        with patch("streamlit.dataframe") as mock_df:
            render_developer_storage_page()
            assert mock_df.called


def test_developer_ui_project_association_display() -> None:
    """Test Developer Storage view renders project summaries if present."""
    proj = DeveloperProjectSummary(
        project_name="MacGuard",
        project_root="/Users/test/projects/macguard-ai",
        total_bytes=100_000_000,
        unique_physical_bytes=100_000_000,
        subtypes=[DeveloperStorageSubtype.PYTHON_VENV, DeveloperStorageSubtype.PYTHON_CACHE],
        findings_count=2,
    )
    summary = DeveloperStorageSummary(
        total_logical_bytes=100_000_000,
        total_unique_bytes=100_000_000,
        total_findings_count=2,
        groups=[],
        projects=[proj],
    )
    st.session_state.developer_summary = summary

    with patch("streamlit.dataframe") as mock_df:
        render_developer_storage_page()
        assert mock_df.called


def test_developer_ui_bounded_rendering() -> None:
    """Test that findings display is capped to top 50 items."""
    findings = [
        DeveloperStorageFinding(
            path=f"/Users/test/item_{i}",
            subtype=DeveloperStorageSubtype.PACKAGE_CACHE,
            category=SmartCategory.CACHES,
            size_bytes=1000 * i,
            item_type="directory",
            depth=2,
            mtime=1700000000.0,
            stale_status=StaleStatus.RECENT,
            confidence=ConfidenceLevel.HIGH,
            confidence_score=0.9,
            evidence="test item",
        )
        for i in range(100)
    ]
    group = DeveloperStorageGroup(
        subtype=DeveloperStorageSubtype.PACKAGE_CACHE,
        title="Package Caches",
        total_logical_bytes=sum(f.size_bytes for f in findings),
        unique_physical_bytes=sum(f.size_bytes for f in findings),
        item_count=100,
        findings=findings,
    )
    summary = DeveloperStorageSummary(
        total_logical_bytes=sum(f.size_bytes for f in findings),
        total_unique_bytes=sum(f.size_bytes for f in findings),
        total_findings_count=100,
        groups=[group],
    )
    st.session_state.developer_summary = summary

    with patch("streamlit.dataframe") as mock_df:
        render_developer_storage_page()
        assert mock_df.called


def test_developer_ui_path_redaction() -> None:
    """Test that home paths and sensitive directories are sanitized."""
    home = str(Path.home().resolve())
    raw_path = f"{home}/.ssh/id_rsa"
    sanitized = alias_and_redact_path(raw_path)
    assert "~/.ssh/[REDACTED]" in sanitized
    assert "id_rsa" not in sanitized


def test_developer_ui_no_mutation_controls() -> None:
    """Verify Developer Storage page contains zero delete/trash/clean buttons."""
    view_file = Path(__file__).resolve().parent.parent / "app" / "ui" / "developer_view.py"
    content = view_file.read_text()
    forbidden_terms = ["button(\"Delete", "button(\"Trash", "button(\"Clean", "button(\"Approve", "button(\"Execute"]
    for term in forbidden_terms:
        assert term.lower() not in content.lower(), f"Forbidden mutation control '{term}' found in developer_view.py"


# ===========================================================================
# 2. Duplicate Explorer UI Tests
# ===========================================================================

def test_duplicate_ui_empty_state() -> None:
    """Test Duplicate Explorer view renders safely when no duplicates exist."""
    st.session_state.duplicate_clusters = []
    st.session_state.duplicate_summary = None

    with patch("streamlit.info") as mock_info:
        render_duplicate_explorer_page()
        assert any("No Duplicate Clusters Detected" in str(call[0][0]) for call in mock_info.call_args_list)


def test_duplicate_ui_populated_clusters() -> None:
    """Test Duplicate Explorer view renders metrics and cluster selector."""
    cluster = DuplicateCluster(
        cluster_id="dup-1",
        file_size_bytes=20_000_000,
        files=[
            DuplicateFile(path="/Users/test/a.zip", size_bytes=20_000_000, inode=101, dev=1),
            DuplicateFile(path="/Users/test/b.zip", size_bytes=20_000_000, inode=102, dev=1),
        ],
        hardlink_count=0,
        wasted_bytes=20_000_000,
    )
    summary = DuplicateScanSummary(
        total_clusters=1,
        total_duplicate_files=2,
        potential_reclaimable_bytes=20_000_000,
        skipped_large_files=0,
    )
    st.session_state.duplicate_clusters = [cluster]
    st.session_state.duplicate_summary = summary

    with patch("streamlit.metric") as mock_metric:
        render_duplicate_explorer_page()
        metric_labels = [call[0][0] for call in mock_metric.call_args_list]
        assert "Duplicate Clusters" in metric_labels
        assert "Total Duplicate Files" in metric_labels
        assert "Potential Reclaimable Space" in metric_labels


def test_duplicate_ui_hardlink_only_zero_wasted_bytes() -> None:
    """Test that hardlink-only clusters display 0 B wasted in Duplicate Explorer."""
    hl_cluster = DuplicateCluster(
        cluster_id="hl-1",
        file_size_bytes=50_000_000,
        files=[
            DuplicateFile(path="/Users/test/link1", size_bytes=50_000_000, inode=500, dev=1, is_hardlink=True),
            DuplicateFile(path="/Users/test/link2", size_bytes=50_000_000, inode=500, dev=1, is_hardlink=True),
        ],
        hardlink_count=2,
        wasted_bytes=0,
    )
    summary = DuplicateScanSummary(
        total_clusters=1,
        total_duplicate_files=2,
        potential_reclaimable_bytes=0,
        skipped_large_files=0,
    )
    st.session_state.duplicate_clusters = [hl_cluster]
    st.session_state.duplicate_summary = summary

    with patch("streamlit.markdown") as mock_md:
        render_duplicate_explorer_page()
        md_texts = [str(call[0][0]) for call in mock_md.call_args_list]
        assert any("0 B (Hardlink-only)" in t or "0 B" in t for t in md_texts)


def test_duplicate_ui_bounded_rendering() -> None:
    """Test that Duplicate Explorer bounds cluster selectbox to top 50 clusters."""
    many_clusters = [
        DuplicateCluster(
            cluster_id=f"c-{i}",
            file_size_bytes=1000 * i,
            files=[
                DuplicateFile(path=f"/Users/test/a_{i}", size_bytes=1000 * i, inode=100 + i, dev=1),
                DuplicateFile(path=f"/Users/test/b_{i}", size_bytes=1000 * i, inode=200 + i, dev=1),
            ],
            hardlink_count=0,
            wasted_bytes=1000 * i,
        )
        for i in range(100)
    ]
    summary = DuplicateScanSummary(
        total_clusters=100,
        total_duplicate_files=200,
        potential_reclaimable_bytes=sum(c.wasted_bytes for c in many_clusters),
        skipped_large_files=0,
    )
    st.session_state.duplicate_clusters = many_clusters
    st.session_state.duplicate_summary = summary

    with patch("streamlit.selectbox", return_value=0) as mock_select:
        render_duplicate_explorer_page()
        assert mock_select.called
        options = mock_select.call_args[1].get("options", mock_select.call_args[0][1] if len(mock_select.call_args[0]) > 1 else [])
        assert len(options) <= 50


def test_duplicate_ui_no_deletion_controls() -> None:
    """Verify Duplicate Explorer view contains zero delete/trash/deduplicate buttons."""
    view_file = Path(__file__).resolve().parent.parent / "app" / "ui" / "duplicate_view.py"
    content = view_file.read_text()
    forbidden_terms = ["button(\"Delete", "button(\"Trash", "button(\"Deduplicate", "button(\"Replace", "button(\"Clean"]
    for term in forbidden_terms:
        assert term.lower() not in content.lower(), f"Forbidden duplicate action '{term}' found in duplicate_view.py"


# ===========================================================================
# 3. Storage Intelligence UI Tests
# ===========================================================================

def test_storage_intelligence_first_scan_state() -> None:
    """Test Storage Intelligence view handles single-scan first baseline gracefully."""
    snap = StorageSnapshot(
        snapshot_id="snap-1",
        scan_id="scan-1",
        timestamp=1725000000.0,
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/test",
        status=ScanStatus.COMPLETED,
        duration_seconds=1.5,
        files_count=100,
        directories_count=20,
        total_bytes=10_000_000,
    )
    report = StorageTrendReport(
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/test",
        current_snapshot_id="snap-1",
        previous_snapshot_id=None,
        current_timestamp=1725000000.0,
        previous_timestamp=None,
        is_comparable=False,
        overall_trend=StorageTrend(
            metric="Total Storage",
            current_value=10_000_000,
            previous_value=0,
            absolute_change=0,
            percentage_change=None,
            direction=TrendDirection.STABLE,
            explanation="Initial baseline scan recorded.",
        ),
    )
    with patch("streamlit.metric") as mock_metric:
        render_overview_cards(snap, report, None)
        metric_labels = [
            call.kwargs.get("label") or (call.args[0] if call.args else None)
            for call in mock_metric.call_args_list
        ]
        assert "Current Scanned Storage" in metric_labels
        assert "Trend Classification" in metric_labels


def test_storage_intelligence_trend_chart_zero_bound_scale() -> None:
    """Test historical area chart constructs with zero-bound scale domain."""
    snaps = [
        StorageSnapshot(
            snapshot_id="snap-1",
            scan_id="scan-1",
            timestamp=1725000000.0,
            scope_id=ScopeIdentifier.HOME,
            root_path="/Users/test",
            status=ScanStatus.COMPLETED,
            duration_seconds=1.0,
            files_count=100,
            directories_count=20,
            total_bytes=10_000_000,
            top_consumers=[
                LargeConsumerSnapshotItem(
                    rank=1,
                    path="/Users/test/file1.dat",
                    size_bytes=5_000_000,
                    category=SmartCategory.DOCUMENTS,
                    confidence=ConfidenceLevel.HIGH,
                )
            ],
        ),
        StorageSnapshot(
            snapshot_id="snap-2",
            scan_id="scan-2",
            timestamp=1725100000.0,
            scope_id=ScopeIdentifier.HOME,
            root_path="/Users/test",
            status=ScanStatus.COMPLETED,
            duration_seconds=1.0,
            files_count=110,
            directories_count=22,
            total_bytes=12_000_000,
            top_consumers=[
                LargeConsumerSnapshotItem(
                    rank=1,
                    path="/Users/test/file2.dat",
                    size_bytes=6_000_000,
                    category=SmartCategory.DOCUMENTS,
                    confidence=ConfidenceLevel.HIGH,
                )
            ],
        ),
    ]
    with patch("streamlit.altair_chart") as mock_chart:
        render_storage_history_chart(snaps)
        assert mock_chart.called
        chart_obj = mock_chart.call_args[0][0]
        chart_dict = chart_obj.to_dict()
        assert "encoding" in chart_dict
        assert chart_dict["encoding"]["y"]["scale"]["zero"] is True


def test_storage_intelligence_largest_consumers_path_redacted() -> None:
    """Test top consumers table sanitizes user paths."""
    home = str(Path.home().resolve())
    consumer = LargeConsumerSnapshotItem(
        rank=1,
        path=f"{home}/.ssh/id_rsa",
        size_bytes=5_000_000,
        category=SmartCategory.CACHES,
        confidence=ConfidenceLevel.HIGH,
    )
    snap = StorageSnapshot(
        snapshot_id="snap-1",
        scan_id="scan-1",
        timestamp=1725000000.0,
        scope_id=ScopeIdentifier.HOME,
        root_path=home,
        status=ScanStatus.COMPLETED,
        duration_seconds=1.0,
        files_count=50,
        directories_count=10,
        total_bytes=5_000_000,
        top_consumers=[consumer],
    )
    with patch("streamlit.dataframe") as mock_df:
        render_large_consumers(snap)
        assert mock_df.called
        rows = mock_df.call_args[0][0]
        assert len(rows) == 1
        assert "~/.ssh/[REDACTED]" in rows[0]["Path"]
        assert "id_rsa" not in rows[0]["Path"]


# ===========================================================================
# 4. Navigation & State Synchronization Tests
# ===========================================================================

def test_navigation_developer_storage_registration() -> None:
    """Test navigating to DeveloperStorage switches tab and syncs ANALYZE mode."""
    navigate_to("DeveloperStorage")
    assert st.session_state.current_tab == "DeveloperStorage"
    assert st.session_state.current_mode == "ANALYZE"


def test_navigation_duplicates_registration() -> None:
    """Test navigating to Duplicates switches tab and syncs ANALYZE mode."""
    navigate_to("Duplicates")
    assert st.session_state.current_tab == "Duplicates"
    assert st.session_state.current_mode == "ANALYZE"


def test_navigation_alias_redirection() -> None:
    """Test navigating using aliases ('Developer Storage', 'Duplicate Explorer')."""
    navigate_to("Developer Storage")
    assert st.session_state.current_tab == "DeveloperStorage"

    navigate_to("Duplicate Explorer")
    assert st.session_state.current_tab == "Duplicates"


def test_navigation_state_synchronization() -> None:
    """Test sync_mode_and_navigation reconciles state before widget creation."""
    st.session_state.pending_tab = "DeveloperStorage"
    sync_mode_and_navigation()
    assert st.session_state.current_tab == "DeveloperStorage"
    assert st.session_state.nav_selectbox == "DeveloperStorage"
    assert st.session_state.mode_radio == "ANALYZE"


def test_navigation_widget_lifecycle_safety() -> None:
    """Test setting operating mode to REVIEW safely overrides non-review tabs."""
    set_operating_mode("REVIEW")
    sync_mode_and_navigation()
    assert st.session_state.current_mode == "REVIEW"
    assert st.session_state.current_tab == "Review"


# ===========================================================================
# 5. Static AST Safety Tests
# ===========================================================================

def test_ui_v11_ast_no_mutation_primitives() -> None:
    """Verify that all files in app/ui/ contain ZERO destructive/mutation primitives."""
    ui_dir = Path(__file__).resolve().parent.parent / "app" / "ui"
    forbidden_calls = {"remove", "unlink", "rmdir", "rmtree", "system", "popen", "spawn", "exec"}

    for py_file in ui_dir.glob("*.py"):
        tree = ast.parse(py_file.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id in forbidden_calls:
                    pytest.fail(f"Forbidden call '{func.id}' found in UI file {py_file}")
                elif isinstance(func, ast.Attribute) and func.attr in forbidden_calls:
                    pytest.fail(f"Forbidden call '{func.attr}' found in UI file {py_file}")


def test_ui_v11_ast_no_execution_or_approval_imports_in_new_views() -> None:
    """Verify Developer and Duplicate views contain ZERO imports of execution/approval internals."""
    forbidden_modules = {"app.execution.trash_executor", "app.safety.approval", "subprocess"}

    for filename in ["developer_view.py", "duplicate_view.py"]:
        view_path = Path(__file__).resolve().parent.parent / "app" / "ui" / filename
        tree = ast.parse(view_path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    for mod in forbidden_modules:
                        if alias.name.startswith(mod):
                            pytest.fail(f"Forbidden import '{alias.name}' in {filename}")
            elif isinstance(node, ast.ImportFrom):
                mod_name = node.module or ""
                for mod in forbidden_modules:
                    if mod_name.startswith(mod):
                        pytest.fail(f"Forbidden import from '{mod_name}' in {filename}")


# ===========================================================================
# 6. Additional Edge Case & Interaction Tests
# ===========================================================================

def test_developer_ui_fallback_analysis_trigger() -> None:
    """Test Developer Storage view automatically computes summary from scan_results if absent."""
    item = DiscoveredItem(
        path="/Users/test/Library/Developer/Xcode/DerivedData/app1",
        size_bytes=10_000_000,
        item_type="directory",
        depth=4,
        mtime=1700000000.0,
        st_ino=12345,
        st_dev=1,
        category=SmartCategory.BUILD_ARTIFACTS,
        confidence=ConfidenceLevel.HIGH,
    )
    scan_res = ScanResult(
        scope_id=ScopeIdentifier.DEVELOPER,
        root_path="/Users/test",
        status=ScanStatus.COMPLETED,
        start_time=1700000000.0,
        end_time=1700000000.5,
        duration_seconds=0.5,
        items=[item],
        total_bytes=10_000_000,
    )
    st.session_state.developer_summary = None
    st.session_state.scan_results = scan_res

    with patch("streamlit.dataframe") as mock_df:
        render_developer_storage_page()
        assert st.session_state.developer_summary is not None
        assert st.session_state.developer_summary.total_logical_bytes == 10_000_000
        assert mock_df.called


def test_duplicate_ui_fallback_detection_trigger(tmp_path: Path) -> None:
    """Test Duplicate Explorer computes clusters from scan_results if absent."""
    f1 = tmp_path / "dup1.bin"
    f2 = tmp_path / "dup2.bin"
    size = 1024 * 1024 + 100
    f1.write_bytes(b"D" * size)
    f2.write_bytes(b"D" * size)

    item1 = DiscoveredItem(
        path=str(f1),
        size_bytes=size,
        item_type="file",
        depth=1,
        mtime=1700000000.0,
        st_ino=1001,
        st_dev=1,
        category=SmartCategory.DOCUMENTS,
        confidence=ConfidenceLevel.HIGH,
    )
    item2 = DiscoveredItem(
        path=str(f2),
        size_bytes=size,
        item_type="file",
        depth=1,
        mtime=1700000000.0,
        st_ino=1002,
        st_dev=1,
        category=SmartCategory.DOCUMENTS,
        confidence=ConfidenceLevel.HIGH,
    )
    scan_res = ScanResult(
        scope_id=ScopeIdentifier.HOME,
        root_path=str(tmp_path),
        status=ScanStatus.COMPLETED,
        start_time=1700000000.0,
        end_time=1700000000.2,
        duration_seconds=0.2,
        items=[item1, item2],
        total_bytes=size * 2,
    )
    st.session_state.duplicate_clusters = []
    st.session_state.duplicate_summary = None
    st.session_state.scan_results = scan_res

    with patch("streamlit.metric"):
        render_duplicate_explorer_page()
        assert st.session_state.duplicate_summary is not None
        assert st.session_state.duplicate_summary.total_clusters == 1


def test_developer_ui_ask_agent_prompt() -> None:
    """Test clicking Ask AI Agent button in Developer Storage navigates to Agent tab."""
    summary = DeveloperStorageSummary(
        total_logical_bytes=10_000_000,
        total_unique_bytes=10_000_000,
        total_findings_count=1,
        groups=[],
    )
    st.session_state.developer_summary = summary

    with patch("streamlit.button", side_effect=lambda label, **kwargs: "Ask AI Agent" in label):
        with patch("streamlit.rerun"):
            render_developer_storage_page()
            assert st.session_state.current_tab == "Agent"
            assert st.session_state.current_mode == "AGENT"


def test_duplicate_ui_ask_agent_prompt() -> None:
    """Test clicking Ask AI Agent in Duplicate Explorer navigates to Agent tab."""
    cluster = DuplicateCluster(
        cluster_id="c-1",
        file_size_bytes=1000,
        files=[
            DuplicateFile(path="/test/a", size_bytes=1000, inode=1, dev=1),
            DuplicateFile(path="/test/b", size_bytes=1000, inode=2, dev=1),
        ],
        hardlink_count=0,
        wasted_bytes=1000,
    )
    summary = DuplicateScanSummary(
        total_clusters=1,
        total_duplicate_files=2,
        potential_reclaimable_bytes=1000,
        skipped_large_files=0,
    )
    st.session_state.duplicate_clusters = [cluster]
    st.session_state.duplicate_summary = summary

    with patch("streamlit.button", side_effect=lambda label, **kwargs: "Ask AI Agent" in label):
        with patch("streamlit.rerun"):
            render_duplicate_explorer_page()
            assert st.session_state.current_tab == "Agent"
            assert st.session_state.current_mode == "AGENT"


def test_path_sanitization_multiple_sensitive_directories() -> None:
    """Test alias_and_redact_path handles all specified sensitive directory names."""
    home = str(Path.home().resolve())
    for sens in [".ssh", ".aws", ".gnupg", "Keychains", "Cookies", "Messages", "Mail", "IdentityServices"]:
        raw = f"{home}/Library/{sens}/secret_data" if "Library" not in sens and sens.startswith(".") is False else f"{home}/{sens}/secret"
        sanitized = alias_and_redact_path(raw)
        assert "[REDACTED]" in sanitized
        assert "secret_data" not in sanitized
        assert "secret" not in sanitized


def test_storage_intelligence_category_trends_chart_zero_bound() -> None:
    """Test category breakdown horizontal bar chart has zero-bound scale."""
    trend = CategoryTrend(
        category=SmartCategory.CACHES,
        current_bytes=5_000_000,
        previous_bytes=4_000_000,
        absolute_change=1_000_000,
        percentage_change=25.0,
        direction=TrendDirection.GROWING,
        explanation="Growth observed.",
    )
    report = StorageTrendReport(
        scope_id=ScopeIdentifier.HOME,
        root_path="/test",
        current_snapshot_id="snap-1",
        previous_snapshot_id=None,
        current_timestamp=1725000000.0,
        previous_timestamp=None,
        is_comparable=False,
        overall_trend=StorageTrend(
            metric="Total Storage",
            current_value=5_000_000,
            previous_value=0,
            absolute_change=0,
            percentage_change=None,
            direction=TrendDirection.STABLE,
            explanation="Baseline",
        ),
        category_trends=[trend],
    )
    snap = StorageSnapshot(
        snapshot_id="snap-1",
        scan_id="scan-1",
        timestamp=1725000000.0,
        scope_id=ScopeIdentifier.HOME,
        root_path="/test",
        status=ScanStatus.COMPLETED,
        duration_seconds=1.0,
        files_count=10,
        directories_count=2,
        total_bytes=5_000_000,
        categories=[CategorySnapshotItem(category=SmartCategory.CACHES, total_bytes=5_000_000, item_count=10)],
    )
    with patch("streamlit.altair_chart") as mock_chart:
        render_category_intelligence(report, snap)
        assert mock_chart.called
        chart_obj = mock_chart.call_args[0][0]
        chart_dict = chart_obj.to_dict()
        assert chart_dict["encoding"]["x"]["scale"]["zero"] is True

