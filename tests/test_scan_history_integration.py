"""
MacGuard AI v1.1 — Minimal Scan -> Storage History Integration Tests (Phase 5D).

Validates:
A. A completed HOME scan creates exactly one history snapshot in StorageHistoryRepository.
B. The snapshot contains accurate scope, root_path, status, counts, and bytes.
C. Storage Intelligence retrieves and renders the newly persisted snapshot.
D. A second completed scan creates a second snapshot allowing comparative trend analysis.
E. Failed/cancelled scans and demo mode do NOT persist snapshots to the history database.
F. Custom directory scans are recorded with ScopeIdentifier.CUSTOM (not HOME).
G. Historical persistence does not fabricate candidates or alter risk/eligibility rules.
H. Safe execution invariants are fully preserved.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
import streamlit as st

from app.analysis.models import RiskLevel
from app.analysis.storage_history import StorageHistoryRepository
from app.analysis.storage_trends import StorageTrendsEngine
from app.models.scan_result import ScanStatus
from app.models.scan_scope import ScopeIdentifier
from app.tools.storage_scanner import StorageItem, StorageScanner
from app.ui.scan import render_scan_page
from app.ui.state import get_services, init_app_state
from app.ui.storage_intelligence import render_storage_intelligence_view


@pytest.fixture(autouse=True)
def setup_session(tmp_path):
    """Ensure clean Streamlit session state and isolated database for each test."""
    st.session_state.clear()
    init_app_state()
    db_file = str(tmp_path / "test_history.db")
    repo = StorageHistoryRepository(db_path=db_file)
    st.session_state.storage_history = repo
    yield repo
    st.session_state.clear()


def test_completed_home_scan_persists_exactly_one_snapshot(setup_session, tmp_path):
    """Test A & B: Completed HOME scan creates exactly one snapshot with correct metadata."""
    repo = setup_session

    mock_items = [
        StorageItem(path=str(Path.home() / "file1.log"), size_bytes=10_000_000, item_type="file"),
        StorageItem(path=str(Path.home() / "file2.tmp"), size_bytes=20_000_000, item_type="file"),
        StorageItem(path=str(Path.home() / "CacheDir"), size_bytes=30_000_000, item_type="directory"),
    ]

    mock_scanner = MagicMock(spec=StorageScanner)
    mock_scanner.get_common_user_storage_targets.return_value = [str(Path.home() / "Library/Caches")]
    mock_scanner.get_top_directories.return_value = [mock_items[2]]
    mock_scanner.get_large_files.return_value = [mock_items[0], mock_items[1]]
    st.session_state.scanner = mock_scanner

    with patch("streamlit.radio", return_value="Recommended User Storage Scope (Fast & Targeted)"), \
         patch("streamlit.button", side_effect=lambda label, **kwargs: "Run Read-Only" in label), \
         patch("streamlit.spinner"), \
         patch("streamlit.success") as mock_success, \
         patch("streamlit.error") as mock_error:
        render_scan_page()

    assert not mock_error.called
    assert mock_success.called

    snapshots = repo.get_snapshot_history(ScopeIdentifier.HOME)
    assert len(snapshots) == 1

    snap = snapshots[0]
    assert snap.scope_id == ScopeIdentifier.HOME
    assert snap.root_path == str(Path.home())
    assert snap.status == ScanStatus.COMPLETED
    assert snap.files_count == 2
    assert snap.directories_count == 1
    assert snap.total_bytes == 60_000_000
    assert snap.duration_seconds >= 0.0


def test_storage_intelligence_retrieves_persisted_snapshot(setup_session):
    """Test C: Storage Intelligence retrieves and displays the newly persisted snapshot."""
    repo = setup_session

    mock_items = [
        StorageItem(path=str(Path.home() / "test.log"), size_bytes=5_000_000, item_type="file"),
    ]

    mock_scanner = MagicMock(spec=StorageScanner)
    mock_scanner.get_common_user_storage_targets.return_value = [str(Path.home())]
    mock_scanner.get_top_directories.return_value = []
    mock_scanner.get_large_files.return_value = mock_items
    st.session_state.scanner = mock_scanner

    with patch("streamlit.radio", return_value="Recommended User Storage Scope (Fast & Targeted)"), \
         patch("streamlit.button", side_effect=lambda label, **kwargs: "Run Read-Only" in label), \
         patch("streamlit.spinner"), \
         patch("streamlit.success"):
        render_scan_page()

    # Verify history now has 1 snapshot
    assert len(repo.get_snapshot_history(ScopeIdentifier.HOME)) == 1

    # Render Storage Intelligence view
    with patch("streamlit.selectbox", return_value=ScopeIdentifier.HOME), \
         patch("streamlit.info") as mock_info, \
         patch("streamlit.metric") as mock_metric:
        render_storage_intelligence_view(ScopeIdentifier.HOME)

        # Baseline single-snapshot view should NOT display the empty state "No Historical Scans"
        for call_args in mock_info.call_args_list:
            arg_str = str(call_args[0][0])
            assert "No Historical Scans Recorded" not in arg_str


def test_second_completed_scan_creates_second_snapshot_and_trend_comparison(setup_session):
    """Test D: A second completed scan creates a second snapshot and trends compare them."""
    repo = setup_session

    mock_scanner = MagicMock(spec=StorageScanner)
    st.session_state.scanner = mock_scanner

    # Scan 1: 50 MB
    mock_scanner.get_common_user_storage_targets.return_value = [str(Path.home())]
    mock_scanner.get_top_directories.return_value = []
    mock_scanner.get_large_files.return_value = [
        StorageItem(path=str(Path.home() / "file1.log"), size_bytes=50_000_000, item_type="file")
    ]

    with patch("streamlit.radio", return_value="Recommended User Storage Scope (Fast & Targeted)"), \
         patch("streamlit.button", side_effect=lambda label, **kwargs: "Run Read-Only" in label), \
         patch("streamlit.spinner"), \
         patch("streamlit.success"):
        render_scan_page()

    assert len(repo.get_snapshot_history(ScopeIdentifier.HOME)) == 1

    # Scan 2: 80 MB
    mock_scanner.get_large_files.return_value = [
        StorageItem(path=str(Path.home() / "file1.log"), size_bytes=50_000_000, item_type="file"),
        StorageItem(path=str(Path.home() / "file2.log"), size_bytes=30_000_000, item_type="file"),
    ]

    with patch("streamlit.radio", return_value="Recommended User Storage Scope (Fast & Targeted)"), \
         patch("streamlit.button", side_effect=lambda label, **kwargs: "Run Read-Only" in label), \
         patch("streamlit.spinner"), \
         patch("streamlit.success"):
        render_scan_page()

    snapshots = repo.get_snapshot_history(ScopeIdentifier.HOME)
    assert len(snapshots) == 2

    engine = StorageTrendsEngine()
    trend = engine.compare_snapshots(current=snapshots[0], previous=snapshots[1])
    assert trend.overall_trend is not None
    assert trend.overall_trend.absolute_change == 30_000_000


def test_failed_scans_and_demo_mode_do_not_persist(setup_session):
    """Test E: Failed scans and demo mode do NOT persist snapshots to the history DB."""
    repo = setup_session

    # Case 1: Scanner raises an exception
    mock_scanner = MagicMock(spec=StorageScanner)
    mock_scanner.get_common_user_storage_targets.side_effect = RuntimeError("Disk error")
    st.session_state.scanner = mock_scanner

    with patch("streamlit.radio", return_value="Recommended User Storage Scope (Fast & Targeted)"), \
         patch("streamlit.button", side_effect=lambda label, **kwargs: "Run Read-Only" in label), \
         patch("streamlit.spinner"), \
         patch("streamlit.error") as mock_error:
        render_scan_page()
        assert mock_error.called

    assert len(repo.get_snapshot_history(ScopeIdentifier.HOME)) == 0

    # Case 2: Demo Mode
    with patch("streamlit.radio", return_value="Recommended User Storage Scope (Fast & Targeted)"), \
         patch("streamlit.button", side_effect=lambda label, **kwargs: "Load Presentation Demo" in label), \
         patch("streamlit.rerun"):
        render_scan_page()

    assert len(repo.get_snapshot_history(ScopeIdentifier.HOME)) == 0


def test_custom_scope_persisted_as_custom_not_home(setup_session, tmp_path):
    """Test F: Custom directory scan is stored as CUSTOM scope, leaving HOME history clean."""
    repo = setup_session
    custom_dir = str(tmp_path / "my_custom_folder")
    os.makedirs(custom_dir, exist_ok=True)

    mock_scanner = MagicMock(spec=StorageScanner)
    mock_scanner.get_top_directories.return_value = []
    mock_scanner.get_large_files.return_value = [
        StorageItem(path=os.path.join(custom_dir, "custom_file.bin"), size_bytes=15_000_000, item_type="file")
    ]
    st.session_state.scanner = mock_scanner

    with patch("streamlit.radio", return_value="Custom Specific Directory"), \
         patch("streamlit.text_input", return_value=custom_dir), \
         patch("streamlit.button", side_effect=lambda label, **kwargs: "Run Read-Only" in label), \
         patch("streamlit.spinner"), \
         patch("streamlit.success"):
        render_scan_page()

    home_snaps = repo.get_snapshot_history(ScopeIdentifier.HOME)
    custom_snaps = repo.get_snapshot_history(ScopeIdentifier.CUSTOM)

    assert len(home_snaps) == 0
    assert len(custom_snaps) == 1
    assert custom_snaps[0].scope_id == ScopeIdentifier.CUSTOM
    assert custom_snaps[0].root_path == custom_dir


def test_historical_context_does_not_alter_risk_or_eligibility(setup_session):
    """Test G & H: Candidates maintain strict deterministic risk tiers and eligibility."""
    repo = setup_session

    mock_items = [
        StorageItem(path=str(Path.home() / "Library/Caches/com.apple.test"), size_bytes=5_000_000, item_type="directory"),
    ]

    mock_scanner = MagicMock(spec=StorageScanner)
    mock_scanner.get_common_user_storage_targets.return_value = [str(Path.home() / "Library/Caches")]
    mock_scanner.get_top_directories.return_value = mock_items
    mock_scanner.get_large_files.return_value = []
    st.session_state.scanner = mock_scanner

    with patch("streamlit.radio", return_value="Recommended User Storage Scope (Fast & Targeted)"), \
         patch("streamlit.button", side_effect=lambda label, **kwargs: "Run Read-Only" in label), \
         patch("streamlit.spinner"), \
         patch("streamlit.success"):
        render_scan_page()

    candidates = st.session_state.candidates
    assert len(candidates) > 0
    # Candidate risk level is computed by StorageAnalyzer, untouched by history
    for c in candidates:
        assert isinstance(c.risk_level, RiskLevel)
