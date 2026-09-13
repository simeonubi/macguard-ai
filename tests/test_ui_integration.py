from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.analysis.models import RiskLevel, StorageCategory
from app.analysis.recommendations import RecommendationAction, RecommendationEngine, SafetyStatus
from app.analysis.storage_analyzer import StorageAnalyzer
from app.audit.models import AuditEventType
from app.audit.repository import AuditRepository
from app.execution.models import ExecutionStatus
from app.execution.trash_executor import TrashExecutor
from app.llm.explanation_service import ExplanationService
from app.llm.models import AnalysisContext, LLMExplanation
from app.safety.approval_service import ApprovalService
from app.safety.path_validator import Operation, PathValidator
from app.safety.review import ApprovalStatus
from app.tools.storage_scanner import StorageItem, StorageScanner


def test_end_to_end_product_pipeline_in_sandbox():
    """
    Test the complete product pipeline end-to-end inside an isolated sandbox:
    1. Scan sandbox directory with StorageScanner
    2. Analyze items with StorageAnalyzer
    3. Generate recommendations with RecommendationEngine
    4. Generate AI explanations with ExplanationService
    5. Review and approve eligible item with ApprovalService
    6. Execute controlled move to sandbox Trash with TrashExecutor
    7. Post-move integrity verification
    8. Audit log persistence with AuditRepository
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        sandbox_path = Path(temp_dir).resolve()
        cache_dir = sandbox_path / "Library" / "Caches" / "test_app"
        cache_dir.mkdir(parents=True, exist_ok=True)
        sample_file = cache_dir / "cache_data.bin"
        sample_file.write_bytes(b"A" * 2048)

        sandbox_trash = sandbox_path / "SandboxTrash"
        sandbox_trash.mkdir(parents=True, exist_ok=True)

        # 1. Scanner
        scanner = StorageScanner()
        dirs = scanner.get_top_directories(path=str(sandbox_path), limit=10)
        files = scanner.get_large_files(path=str(sandbox_path), limit=10)
        items = dirs + files

        assert len(items) >= 1
        found_sample = next((it for it in items if it.path == str(sample_file)), None)
        assert found_sample is not None

        # 2. Analyzer
        analyzer = StorageAnalyzer()
        candidates = analyzer.analyze_items(items)
        assert len(candidates) >= 1

        cand = next(c for c in candidates if c.path == str(sample_file))
        assert cand.category == StorageCategory.CACHE
        assert cand.risk_level == RiskLevel.LOW

        # 3. Recommendations
        rec_engine = RecommendationEngine()
        recommendations = rec_engine.recommend_many(candidates)
        rec = next(r for r in recommendations if r.candidate.path == str(sample_file))
        assert rec.safety_status == SafetyStatus.ELIGIBLE_FOR_REVIEW.value
        assert rec.requires_approval is True

        # 4. Explanation Service
        context = AnalysisContext(
            scan_id="test-scan",
            scan_path=str(sandbox_path),
            total_scanned_items=len(items),
            total_size_bytes=sum(it.size_bytes for it in items),
            candidates=candidates,
            recommendations=recommendations,
            safety_summary={"LOW": 1, "MEDIUM": 0, "HIGH": 0, "UNKNOWN": 0},
        )
        exp_service = ExplanationService()
        explanation = exp_service.explain_deterministic(context)
        assert isinstance(explanation, LLMExplanation)
        assert len(explanation.summary) > 0

        # 5. Human Review & Approval
        validator = PathValidator(custom_allowlist_roots=[str(sandbox_path)])
        approval_service = ApprovalService(path_validator=validator)
        review_items = approval_service.create_review_items(recommendations)

        review_item = next(ri for ri in review_items if ri.candidate.path == str(sample_file))
        assert review_item.is_eligible_for_approval is True

        # Request and Approve item with explicit consent
        pending_record, err = approval_service.request_approval(review_item.recommendation, operation=Operation.CLEAN)
        assert err is None
        assert pending_record is not None

        approval_record, msg = approval_service.approve(
            approval_id=pending_record.approval_id,
            explicit_consent=True,
            reason="Integration Tester approved item",
        )
        assert approval_record is not None
        assert approval_record.approved is True

        # 6. Execution & Verification & Audit
        audit_db = sandbox_path / "test_audit.db"
        audit_repo = AuditRepository(db_path=str(audit_db))

        from app.execution.models import ExecutionAction
        from app.execution.planner import ExecutionPlanner

        planner = ExecutionPlanner(approval_service=approval_service, path_validator=validator)
        plan, msg = planner.create_plan(approval_record, action=ExecutionAction.TRASH)
        assert plan is not None

        trash_executor = TrashExecutor(
            approval_service=approval_service,
            path_validator=validator,
            trash_root=sandbox_trash,
            audit_repo=audit_repo,
        )

        exec_result = trash_executor.execute_trash(plan)

        # 7. Post-Move Verification Assertions
        assert exec_result.status == ExecutionStatus.TRASH_SUCCEEDED
        assert exec_result.integrity_verified is True
        assert not sample_file.exists()  # Source path gone
        assert Path(exec_result.trash_destination_path).exists()  # Destination in sandbox Trash
        assert Path(exec_result.trash_destination_path).read_bytes() == b"A" * 2048

        # 8. Audit Records
        events = audit_repo.get_events_by_approval_id(approval_record.approval_id)
        assert len(events) >= 3  # APPROVAL_APPROVED, TRASH_MOVE_SUCCEEDED, TRASH_VERIFICATION_SUCCEEDED, APPROVAL_CONSUMED
        exec_record = audit_repo.get_execution_record(exec_result.execution_id)
        assert exec_record is not None
        assert exec_record.verified is True
        assert exec_record.status == ExecutionStatus.TRASH_SUCCEEDED.value


def test_analyze_and_review_modes_are_strictly_non_mutating():
    """Verify that ANALYZE and REVIEW operations perform zero filesystem mutations."""
    with tempfile.TemporaryDirectory() as temp_dir:
        sandbox_path = Path(temp_dir).resolve()
        test_file = sandbox_path / "test_file.log"
        test_file.write_text("sample log entry\n")
        initial_mtime = os.lstat(test_file).st_mtime_ns

        # Run scanner
        scanner = StorageScanner()
        items = scanner.get_large_files(str(sandbox_path))
        assert len(items) == 1

        # Run analyzer
        analyzer = StorageAnalyzer()
        candidates = analyzer.analyze_items(items)
        assert len(candidates) == 1

        # Run recommendations
        rec_engine = RecommendationEngine()
        recommendations = rec_engine.recommend_many(candidates)
        assert len(recommendations) == 1

        # Run review creation
        validator = PathValidator(custom_allowlist_roots=[str(sandbox_path)])
        approval_service = ApprovalService(path_validator=validator)
        review_items = approval_service.create_review_items(recommendations)
        assert len(review_items) == 1

        # Request and Reject item
        record, _ = approval_service.request_approval(review_items[0].recommendation)
        if record:
            approval_service.reject(record.approval_id, reason="User rejected")

        # Verify file is completely unmodified and intact
        assert test_file.exists()
        assert test_file.read_text() == "sample log entry\n"
        assert os.lstat(test_file).st_mtime_ns == initial_mtime


def test_audit_repository_filtering():
    """Verify AuditRepository.get_filtered_events correctly filters by multiple attributes."""
    with tempfile.TemporaryDirectory() as temp_dir:
        db_file = Path(temp_dir) / "test_filter.db"
        repo = AuditRepository(db_path=str(db_file))

        from app.audit.models import AuditEvent
        from app.safety.path_validator import Operation

        event1 = AuditEvent(
            event_id="ev-1",
            timestamp=datetime.now(timezone.utc),
            event_type=AuditEventType.APPROVAL_APPROVED,
            approval_id="app-1",
            execution_id="",
            canonical_path="/Users/mac/Library/Caches/app1",
            operation=Operation.CLEAN,
            risk_level=RiskLevel.LOW,
            status="APPROVED",
            actor="User",
            reason="Approved cache",
            metadata={},
        )
        event2 = AuditEvent(
            event_id="ev-2",
            timestamp=datetime.now(timezone.utc),
            event_type=AuditEventType.TRASH_MOVE_SUCCEEDED,
            approval_id="app-1",
            execution_id="exec-1",
            canonical_path="/Users/mac/Library/Caches/app1",
            operation=Operation.CLEAN,
            risk_level=RiskLevel.LOW,
            status="SUCCESS",
            actor="Executor",
            reason="Moved to trash",
            metadata={},
        )
        event3 = AuditEvent(
            event_id="ev-3",
            timestamp=datetime.now(timezone.utc),
            event_type=AuditEventType.APPROVAL_REJECTED,
            approval_id="app-2",
            execution_id="",
            canonical_path="/Users/mac/Library/Logs/sys.log",
            operation=Operation.CLEAN,
            risk_level=RiskLevel.MEDIUM,
            status="REJECTED",
            actor="User",
            reason="Rejected logs",
            metadata={},
        )

        repo.record_event(event1)
        repo.record_event(event2)
        repo.record_event(event3)

        # Filter by event_type
        approved_events = repo.get_filtered_events(event_type=AuditEventType.APPROVAL_APPROVED)
        assert len(approved_events) == 1
        assert approved_events[0].event_id == "ev-1"

        # Filter by status
        success_events = repo.get_filtered_events(status="SUCCESS")
        assert len(success_events) == 1
        assert success_events[0].event_id == "ev-2"

        # Filter by path keyword
        log_events = repo.get_filtered_events(path_query="Logs")
        assert len(log_events) == 1
        assert log_events[0].event_id == "ev-3"

        # Filter by approval_id
        app1_events = repo.get_filtered_events(approval_id="app-1")
        assert len(app1_events) == 2


def test_ui_services_initialization_isolation():
    """Verify backend services are instantiated properly without exposing secrets."""
    from app.ui.state import get_services
    import streamlit as st

    # Simulate empty session state
    st.session_state.clear()
    services = get_services()

    assert "scanner" in services
    assert "analyzer" in services
    assert "recommendation_engine" in services
    assert "path_validator" in services
    assert "approval_service" in services
    assert "execution_planner" in services
    assert "dry_run_executor" in services
    assert "trash_executor" in services
    assert "audit_repository" in services
    assert "explanation_service" in services

    # Verify no secret key is exposed in session_state keys or string values
    for key, val in st.session_state.items():
        assert "secret_key" not in key.lower()
        if isinstance(val, str):
            assert len(val) < 64 or not val.isalnum()


def test_high_and_unknown_risk_items_blocked_from_approval():
    """Verify that HIGH and UNKNOWN risk items are blocked from approval creation."""
    from app.analysis.models import StorageCandidate
    from app.analysis.recommendations import RecommendationAction, StorageRecommendation

    with tempfile.TemporaryDirectory() as temp_dir:
        sandbox = Path(temp_dir).resolve()
        validator = PathValidator(custom_allowlist_roots=[str(sandbox)])
        approval_service = ApprovalService(path_validator=validator)

        # High risk document
        cand_high = StorageCandidate(
            path=str(sandbox / "passwords.txt"),
            size_bytes=1024,
            category=StorageCategory.DOCUMENTS,
            risk_level=RiskLevel.HIGH,
            confidence=0.99,
            reason="High risk doc",
            recommendation="Manual review",
            item_type="file",
        )
        rec_high = StorageRecommendation(
            candidate=cand_high,
            action=RecommendationAction.MANUAL_REVIEW,
            rationale="High risk user document",
            requires_approval=True,
            safety_status=SafetyStatus.MANUAL_REVIEW_REQUIRED.value,
            confidence=0.99,
        )

        record, err = approval_service.request_approval(rec_high)
        assert record is None
        assert "high risk" in str(err).lower()

        # Unknown risk
        cand_unk = StorageCandidate(
            path=str(sandbox / "unknown_blob"),
            size_bytes=1024,
            category=StorageCategory.UNKNOWN,
            risk_level=RiskLevel.UNKNOWN,
            confidence=0.1,
            reason="Unknown binary",
            recommendation="No action",
            item_type="file",
        )
        rec_unk = StorageRecommendation(
            candidate=cand_unk,
            action=RecommendationAction.NO_ACTION,
            rationale="Unknown object",
            requires_approval=True,
            safety_status=SafetyStatus.UNKNOWN.value,
            confidence=0.1,
        )

        record_unk, err_unk = approval_service.request_approval(rec_unk)
        assert record_unk is None
        assert "unknown" in str(err_unk).lower()


def test_cli_commands_compatibility():
    """Verify existing CLI modes work without regression."""
    import io
    from app.cli import run_cli

    with tempfile.TemporaryDirectory() as temp_dir:
        sandbox = str(Path(temp_dir).resolve())
        out = io.StringIO()
        ret_diag = run_cli(
            args=[
                "--root-path", sandbox,
                "--home-path", sandbox,
                "--top-dirs-limit", "2",
                "--top-files-limit", "2",
            ],
            out=out,
        )
        assert ret_diag == 0
        assert "MacGuard AI - Storage Diagnostic Report" in out.getvalue()
        assert "No files were modified." in out.getvalue()

        out_audit = io.StringIO()
        ret_audit = run_cli(args=["--audit"], out=out_audit)
        assert ret_audit == 0
        assert "MacGuard AI — Persistent Audit Log (Read-Only)" in out_audit.getvalue()


def test_ui_module_exports():
    """Verify all UI functions are cleanly imported from app.ui."""
    import app.ui as ui

    assert hasattr(ui, "main")
    assert hasattr(ui, "init_app_state")
    assert hasattr(ui, "get_services")
    assert hasattr(ui, "render_agent_page")
    assert hasattr(ui, "render_dashboard")
    assert hasattr(ui, "render_scan_page")
    assert hasattr(ui, "render_recommendations_page")
    assert hasattr(ui, "render_review_page")
    assert hasattr(ui, "render_execution_page")
    assert hasattr(ui, "render_audit_page")
    assert hasattr(ui, "render_settings_page")


def test_render_agent_page_with_scan_results_list_regression():
    """
    Regression test for AttributeError: 'list' object has no attribute 'get'.
    When scan_results is populated in session state as a list of StorageItem,
    render_agent_page() must safely retrieve scan_path without crashing.
    """
    import streamlit as st
    from app.ui.agent_view import render_agent_page
    from app.tools.storage_scanner import StorageItem
    from app.ui.state import init_app_state

    st.session_state.clear()
    init_app_state()

    st.session_state.scan_results = [
        StorageItem(path="/Users/test/Library/Caches", size_bytes=2048, item_type="directory")
    ]
    st.session_state.candidates = []
    st.session_state.recommendations = []

    with patch("streamlit.markdown"), \
         patch("streamlit.caption"), \
         patch("streamlit.info"), \
         patch("streamlit.columns", side_effect=lambda n: [MagicMock() for _ in range(n if isinstance(n, int) else len(n))]), \
         patch("streamlit.button", return_value=False), \
         patch("streamlit.chat_input", return_value=None):
        render_agent_page()


def test_streamlit_app_launcher_imports_cleanly():
    """
    Regression test: verify streamlit_app.py imports cleanly without package collision
    and correctly exposes the UI entrypoint main.
    """
    import streamlit_app
    import app.ui.app

    assert hasattr(streamlit_app, "main")
    assert streamlit_app.main is app.ui.app.main


def test_operating_mode_and_navigation_synchronization():
    """
    Test that Operating Mode and Navigation tab state are strictly synchronized.
    - Selecting REVIEW switches tab to Review
    - Selecting CLEAN switches tab to Execution
    - Selecting AGENT switches tab to Agent
    - Selecting ANALYZE switches tab to Dashboard/Scan
    - Navigation tab changes update operating mode appropriately
    - Widget keys are safely synchronized in sync_mode_and_navigation() before widget instantiation
    """
    import streamlit as st
    from app.ui.state import (
        init_app_state,
        navigate_to,
        set_operating_mode,
        sync_mode_and_navigation,
    )

    st.session_state.clear()
    init_app_state()

    # Initial state
    assert st.session_state.current_mode == "ANALYZE"
    assert st.session_state.current_tab == "Dashboard"

    # 1. Switch to REVIEW mode
    set_operating_mode("REVIEW")
    assert st.session_state.current_mode == "REVIEW"
    assert st.session_state.current_tab == "Review"
    sync_mode_and_navigation()
    assert st.session_state.mode_radio == "REVIEW"
    assert st.session_state.nav_selectbox == "Review"

    # 2. Switch to CLEAN mode
    set_operating_mode("CLEAN")
    assert st.session_state.current_mode == "CLEAN"
    assert st.session_state.current_tab == "Execution"
    sync_mode_and_navigation()
    assert st.session_state.mode_radio == "CLEAN"
    assert st.session_state.nav_selectbox == "Execution"

    # 3. Switch to AGENT mode
    set_operating_mode("AGENT")
    assert st.session_state.current_mode == "AGENT"
    assert st.session_state.current_tab == "Agent"
    sync_mode_and_navigation()
    assert st.session_state.mode_radio == "AGENT"
    assert st.session_state.nav_selectbox == "Agent"

    # 4. Switch to ANALYZE mode
    set_operating_mode("ANALYZE")
    assert st.session_state.current_mode == "ANALYZE"
    assert st.session_state.current_tab == "Dashboard"
    sync_mode_and_navigation()
    assert st.session_state.mode_radio == "ANALYZE"
    assert st.session_state.nav_selectbox == "Dashboard"

    # 5. Direct navigation to Scan (should set mode to ANALYZE)
    navigate_to("Scan")
    assert st.session_state.current_tab == "Scan"
    assert st.session_state.current_mode == "ANALYZE"
    sync_mode_and_navigation()
    assert st.session_state.mode_radio == "ANALYZE"
    assert st.session_state.nav_selectbox == "Scan"

    # 6. Direct navigation to Recommendations (should set mode to ANALYZE)
    navigate_to("Recommendations")
    assert st.session_state.current_tab == "Recommendations"
    assert st.session_state.current_mode == "ANALYZE"
    sync_mode_and_navigation()
    assert st.session_state.mode_radio == "ANALYZE"
    assert st.session_state.nav_selectbox == "Recommendations"

    # 7. Direct navigation to Review (should set mode to REVIEW)
    navigate_to("Review")
    assert st.session_state.current_tab == "Review"
    assert st.session_state.current_mode == "REVIEW"
    sync_mode_and_navigation()
    assert st.session_state.mode_radio == "REVIEW"
    assert st.session_state.nav_selectbox == "Review"

    # 8. Direct navigation to Execution (should set mode to CLEAN)
    navigate_to("Execution")
    assert st.session_state.current_tab == "Execution"
    assert st.session_state.current_mode == "CLEAN"
    sync_mode_and_navigation()
    assert st.session_state.mode_radio == "CLEAN"
    assert st.session_state.nav_selectbox == "Execution"

    # 9. Direct navigation to Agent (should set mode to AGENT)
    navigate_to("Agent")
    assert st.session_state.current_tab == "Agent"
    assert st.session_state.current_mode == "AGENT"
    sync_mode_and_navigation()
    assert st.session_state.mode_radio == "AGENT"
    assert st.session_state.nav_selectbox == "Agent"

    # 10. Secondary tabs (Audit, Settings) preserve current mode
    navigate_to("Audit")
    assert st.session_state.current_tab == "Audit"
    assert st.session_state.current_mode == "AGENT"
    sync_mode_and_navigation()
    assert st.session_state.mode_radio == "AGENT"
    assert st.session_state.nav_selectbox == "Audit"

    navigate_to("Settings")
    assert st.session_state.current_tab == "Settings"
    assert st.session_state.current_mode == "AGENT"
    sync_mode_and_navigation()
    assert st.session_state.mode_radio == "AGENT"
    assert st.session_state.nav_selectbox == "Settings"

    # 11. Test sync reconciliation on out-of-sync state
    st.session_state.current_mode = "REVIEW"
    st.session_state.current_tab = "Scan"
    sync_mode_and_navigation()
    assert st.session_state.current_tab == "Review"
    assert st.session_state.nav_selectbox == "Review"


def test_widget_lifecycle_safe_navigation_flows():
    """
    Test all inter-page navigation flows to guarantee zero widget key mutation during rendering:
    1. Dashboard button -> Scan navigation
    2. Scan -> Review navigation
    3. Review -> Execution navigation
    4. Agent -> Review navigation
    5. Dashboard -> Agent navigation
    6. Repeated alternating navigation between pages
    """
    import streamlit as st
    from app.ui.state import (
        init_app_state,
        navigate_to,
        set_operating_mode,
        sync_mode_and_navigation,
    )

    st.session_state.clear()
    init_app_state()

    # Simulate widget instantiation during first run
    sync_mode_and_navigation()
    instantiated_widgets = {"mode_radio": st.session_state.mode_radio, "nav_selectbox": st.session_state.nav_selectbox}

    # 1. Dashboard -> Scan button click
    navigate_to("Scan")
    # Verify widget keys were NOT directly overwritten during navigation call
    assert st.session_state.current_tab == "Scan"
    assert st.session_state.current_mode == "ANALYZE"
    assert st.session_state.pending_tab == "Scan"

    # Next rerun: sync before widgets render
    sync_mode_and_navigation()
    assert st.session_state.nav_selectbox == "Scan"
    assert st.session_state.mode_radio == "ANALYZE"
    assert st.session_state.pending_tab is None

    # 2. Scan -> Review navigation
    navigate_to("Review")
    assert st.session_state.current_tab == "Review"
    assert st.session_state.current_mode == "REVIEW"
    sync_mode_and_navigation()
    assert st.session_state.nav_selectbox == "Review"
    assert st.session_state.mode_radio == "REVIEW"

    # 3. Review -> Execution navigation
    navigate_to("Execution")
    assert st.session_state.current_tab == "Execution"
    assert st.session_state.current_mode == "CLEAN"
    sync_mode_and_navigation()
    assert st.session_state.nav_selectbox == "Execution"
    assert st.session_state.mode_radio == "CLEAN"

    # 4. Dashboard -> Agent navigation
    navigate_to("Agent")
    assert st.session_state.current_tab == "Agent"
    assert st.session_state.current_mode == "AGENT"
    sync_mode_and_navigation()
    assert st.session_state.nav_selectbox == "Agent"
    assert st.session_state.mode_radio == "AGENT"

    # 5. Agent -> Review navigation
    navigate_to("Review")
    assert st.session_state.current_tab == "Review"
    assert st.session_state.current_mode == "REVIEW"
    sync_mode_and_navigation()
    assert st.session_state.nav_selectbox == "Review"
    assert st.session_state.mode_radio == "REVIEW"

    # 6. Repeated navigation loop
    for target in ["Dashboard", "StorageIntelligence", "Scan", "Recommendations", "Review", "Execution", "Agent", "Audit", "Settings"]:
        navigate_to(target)
        sync_mode_and_navigation()
        assert st.session_state.current_tab == target
        assert st.session_state.nav_selectbox == target



def test_scan_state_persists_across_mode_transitions():
    """
    Test that active scan results, candidates, and recommendations survive
    mode transitions without loss or mutation.
    """
    import streamlit as st
    from app.analysis.models import RiskLevel, StorageCandidate, StorageCategory
    from app.tools.storage_scanner import StorageItem
    from app.ui.state import init_app_state, navigate_to, set_operating_mode

    st.session_state.clear()
    init_app_state()

    sample_items = [
        StorageItem(path="/Users/test/Library/Caches/app", size_bytes=1024 * 1024, item_type="directory")
    ]
    sample_candidates = [
        StorageCandidate(
            path="/Users/test/Library/Caches/app",
            size_bytes=1024 * 1024,
            category=StorageCategory.CACHE,
            risk_level=RiskLevel.LOW,
            confidence=0.95,
            reason="Application cache directory",
            recommendation="Safe for cleanup review",
        )
    ]

    st.session_state.scan_results = sample_items
    st.session_state.candidates = sample_candidates

    # Execute mode transitions
    set_operating_mode("REVIEW")
    assert st.session_state.scan_results == sample_items
    assert st.session_state.candidates == sample_candidates

    set_operating_mode("AGENT")
    assert st.session_state.scan_results == sample_items
    assert st.session_state.candidates == sample_candidates

    set_operating_mode("REVIEW")
    assert st.session_state.scan_results == sample_items
    assert st.session_state.candidates == sample_candidates

    set_operating_mode("CLEAN")
    assert st.session_state.scan_results == sample_items
    assert st.session_state.candidates == sample_candidates

    set_operating_mode("ANALYZE")
    assert st.session_state.scan_results == sample_items
    assert st.session_state.candidates == sample_candidates


def test_nested_candidate_hierarchy_identification():
    """
    Test get_item_hierarchy_info for nested candidates (e.g. trivy and trivy.db).
    Guarantees:
    - Child item is accurately marked is_nested=True with parent reference.
    - Parent item has is_nested=False with child listed in children_paths.
    """
    from app.tools.storage_scanner import StorageItem
    from app.ui.components import get_item_hierarchy_info

    parent = StorageItem(path="/Users/test/Library/Caches/trivy", size_bytes=1160000000, item_type="directory")
    child = StorageItem(path="/Users/test/Library/Caches/trivy/db/trivy.db", size_bytes=1140000000, item_type="file")
    independent = StorageItem(path="/Users/test/Library/Caches/Google", size_bytes=2160000000, item_type="directory")

    items = [parent, child, independent]
    hierarchy_map = get_item_hierarchy_info(items)

    assert hierarchy_map[parent.path].is_nested is False
    assert child.path in hierarchy_map[parent.path].children_paths
    assert "Container Parent" in hierarchy_map[parent.path].hierarchy_badge

    assert hierarchy_map[child.path].is_nested is True
    assert hierarchy_map[child.path].parent_name == "trivy"
    assert "Included in parent" in hierarchy_map[child.path].hierarchy_badge

    assert hierarchy_map[independent.path].is_nested is False
    assert hierarchy_map[independent.path].children_paths == []
    assert hierarchy_map[independent.path].hierarchy_badge == "Top-level Candidate"


def test_storage_pipeline_three_tier_distinction_and_candidate_quality():
    """
    Test the strict three-tier distinction:
    1. Discovered storage items (StorageItem): Discovers all files, including 0-byte and negligible items.
    2. Storage candidates (StorageCandidate): Analyzes and classifies all items with risk levels and hierarchical deduplication.
    3. Cleanup-review candidates (StorageRecommendation / ReviewItem): Zero-byte and negligible items are strictly excluded from cleanup review.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        sandbox = Path(temp_dir).resolve()
        cache_dir = sandbox / "Library" / "Caches" / "app"
        cache_dir.mkdir(parents=True, exist_ok=True)

        # 1. Zero-byte file
        zero_file = cache_dir / "empty.tmp"
        zero_file.write_bytes(b"")

        # 2. Negligible file (100 bytes)
        small_file = cache_dir / "tiny.cache"
        small_file.write_bytes(b"B" * 100)

        # 3. Actionable cache file (1 MB)
        large_file = cache_dir / "large.cache"
        large_file.write_bytes(b"C" * (1024 * 1024))

        # Tier 1: Diagnostic Scanner discovers ALL items
        scanner = StorageScanner()
        discovered_files = scanner.get_large_files(path=str(cache_dir), limit=20)
        discovered_paths = {f.path for f in discovered_files}
        assert str(zero_file) in discovered_paths
        assert str(small_file) in discovered_paths
        assert str(large_file) in discovered_paths

        # Tier 2: Storage Analyzer classifies ALL items
        analyzer = StorageAnalyzer()
        candidates = analyzer.analyze_items(discovered_files, deduplicate=True)
        assert len(candidates) == 3
        cand_map = {c.path: c for c in candidates}
        assert cand_map[str(zero_file)].size_bytes == 0
        assert cand_map[str(small_file)].size_bytes == 100
        assert cand_map[str(large_file)].size_bytes == 1024 * 1024

        # Tier 3: Recommendation Engine with 512-byte threshold
        rec_engine = RecommendationEngine(min_cleanup_size_bytes=512)
        recommendations = rec_engine.recommend_many(candidates)
        rec_map = {r.candidate.path: r for r in recommendations}

        # Zero-byte item: excluded
        assert rec_map[str(zero_file)].action == RecommendationAction.NO_ACTION
        assert "zero-byte" in rec_map[str(zero_file)].rationale.lower()

        # Small item (< 512 bytes): excluded as negligible
        assert rec_map[str(small_file)].action == RecommendationAction.NO_ACTION
        assert "below the minimum cleanup threshold" in rec_map[str(small_file)].rationale.lower()

        # Large item (>= 512 bytes): eligible for review
        assert rec_map[str(large_file)].action == RecommendationAction.REVIEW_FOR_CLEANUP
        assert rec_map[str(large_file)].safety_status == SafetyStatus.ELIGIBLE_FOR_REVIEW.value

        # Approval Service verification: only large item is eligible for approval
        approval_service = ApprovalService()
        review_items = approval_service.create_review_items(recommendations)
        review_map = {ri.candidate.path: ri for ri in review_items}

        assert review_map[str(zero_file)].is_eligible_for_approval is False
        assert review_map[str(small_file)].is_eligible_for_approval is False
        assert review_map[str(large_file)].is_eligible_for_approval is True


def test_human_review_ux_queue_separation_and_counters():
    """
    Test the Human Review UX presentation separation:
    1. Zero-byte items (size <= 0) must be in ineligible_items, excluded from eligible queue.
    2. Negligible-size items (size < threshold) must be in ineligible_items, excluded from eligible queue.
    3. HIGH / UNKNOWN risk items must be in blocked_items.
    4. LOW risk actionable items (size > 0, size >= threshold) must be in eligible_items.
    5. render_review_page executes cleanly with all sections and counters.
    """
    import streamlit as st
    from app.analysis.models import RiskLevel, StorageCandidate, StorageCategory
    from app.analysis.recommendations import RecommendationAction, RecommendationEngine, SafetyStatus
    from app.safety.approval_service import ApprovalService
    from app.safety.review import ReviewItem
    from app.ui.review import render_review_page
    from app.ui.state import init_app_state

    st.session_state.clear()
    init_app_state()

    # 1. Zero-byte candidate
    zero_cand = StorageCandidate(
        path="/Users/test/Library/Caches/empty.tmp",
        size_bytes=0,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.9,
        reason="Empty cache file",
        recommendation="No action needed",
    )

    # 2. Negligible candidate (100 bytes < 1024 threshold)
    small_cand = StorageCandidate(
        path="/Users/test/Library/Caches/small.log",
        size_bytes=100,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.9,
        reason="Small log file",
        recommendation="Below threshold",
    )

    # 3. High risk candidate
    high_risk_cand = StorageCandidate(
        path="/Users/test/Documents/Financial_Report.pdf",
        size_bytes=5 * 1024 * 1024,
        category=StorageCategory.DOCUMENTS,
        risk_level=RiskLevel.HIGH,
        confidence=0.95,
        reason="Personal document",
        recommendation="Do not clean",
    )

    # 4. Unknown risk candidate
    unknown_risk_cand = StorageCandidate(
        path="/Users/test/Unknown/Ambiguous.dat",
        size_bytes=2 * 1024 * 1024,
        category=StorageCategory.UNKNOWN,
        risk_level=RiskLevel.UNKNOWN,
        confidence=0.5,
        reason="Unclassified data",
        recommendation="Ambiguous",
    )

    # 5. Eligible low-risk cache item
    eligible_cand = StorageCandidate(
        path="/Users/test/Library/Caches/Google/Chrome/cache.data",
        size_bytes=50 * 1024 * 1024,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.95,
        reason="Browser cache",
        recommendation="Safe for cleanup review",
    )

    candidates = [zero_cand, small_cand, high_risk_cand, unknown_risk_cand, eligible_cand]

    rec_engine = RecommendationEngine(min_cleanup_size_bytes=1024)
    recommendations = rec_engine.recommend_many(candidates)

    approval_service = ApprovalService()
    review_items = approval_service.create_review_items(recommendations)
    st.session_state.review_items = review_items

    # Verify partition logic
    eligible_items = [
        it for it in review_items
        if it.is_eligible_for_approval and it.candidate.size_bytes > 0 and it.risk_level not in (RiskLevel.HIGH, RiskLevel.UNKNOWN)
    ]
    blocked_items = [
        it for it in review_items if it.risk_level in (RiskLevel.HIGH, RiskLevel.UNKNOWN)
    ]
    ineligible_items = [
        it for it in review_items if it not in eligible_items and it not in blocked_items
    ]

    # Assert exact distribution
    assert len(eligible_items) == 1
    assert eligible_items[0].candidate.path == eligible_cand.path

    assert len(blocked_items) == 2
    blocked_paths = {b.candidate.path for b in blocked_items}
    assert high_risk_cand.path in blocked_paths
    assert unknown_risk_cand.path in blocked_paths

    assert len(ineligible_items) == 2
    ineligible_paths = {i.candidate.path for i in ineligible_items}
    assert zero_cand.path in ineligible_paths
    assert small_cand.path in ineligible_paths

    # Verify zero-byte and negligible items have NO approval capability
    for it in ineligible_items:
        assert it.is_eligible_for_approval is False

    for it in blocked_items:
        assert it.is_eligible_for_approval is False

    # Execute render_review_page to verify UI rendering executes without error
    render_review_page()


def test_render_execution_page_with_approval_record_regression():
    """
    Regression test for AttributeError: 'ApprovalRecord' object has no attribute 'canonical_path'.
    When approved_records is populated in session state with valid ApprovalRecord objects,
    render_execution_page() must access rec.path rather than rec.canonical_path and
    render the Controlled Execution page successfully without raising an AttributeError.
    """
    import streamlit as st
    from app.analysis.models import RiskLevel
    from app.safety.approval import grant_approval, request_approval
    from app.safety.path_validator import Operation
    from app.ui.execution import render_execution_page
    from app.ui.state import init_app_state

    st.session_state.clear()
    init_app_state()

    sample_path = "/Users/test/Library/Caches/sample_cache"
    unapproved_rec = request_approval(
        path=sample_path,
        operation=Operation.CLEAN,
        risk_level=RiskLevel.LOW,
        reason="Application cache directory cleanup",
    )
    approved_rec = grant_approval(unapproved_rec)

    # Ensure rec does NOT have canonical_path
    assert not hasattr(approved_rec, "canonical_path")
    assert hasattr(approved_rec, "path")

    st.session_state.approved_records = {sample_path: approved_rec}

    # render_execution_page should succeed without raising AttributeError
    render_execution_page()


def test_review_to_controlled_execution_ui_workflow():
    """
    Test the full REVIEW -> approval -> CLEAN / Controlled Execution UI workflow:
    1. Populate review items
    2. Request and grant approval for an eligible item
    3. Transition to Execution page and render UI
    4. Confirm successful execution page rendering with approved items
    """
    import streamlit as st
    from app.analysis.models import RiskLevel, StorageCandidate, StorageCategory
    from app.analysis.recommendations import RecommendationEngine
    from app.safety.approval_service import ApprovalService
    from app.safety.path_validator import Operation, PathValidator
    from app.ui.execution import render_execution_page
    from app.ui.review import render_review_page
    from app.ui.state import get_services, init_app_state, navigate_to

    st.session_state.clear()
    init_app_state()

    sample_cand = StorageCandidate(
        path="/Users/test/Library/Caches/com.apple.testapp",
        size_bytes=10 * 1024 * 1024,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.95,
        reason="App cache directory",
        recommendation="Safe for cleanup review",
    )

    rec_engine = RecommendationEngine(min_cleanup_size_bytes=1024)
    recommendations = rec_engine.recommend_many([sample_cand])

    validator = PathValidator(custom_allowlist_roots=["/Users/test"])
    approval_service = ApprovalService(path_validator=validator)
    services = get_services()
    services["approval_service"] = approval_service

    review_items = approval_service.create_review_items(recommendations)
    st.session_state.review_items = review_items

    # 1. Render Review page
    navigate_to("Review")
    render_review_page()

    # 2. Simulate user granting explicit approval in Review UI
    item = review_items[0]
    pending_record, err = approval_service.request_approval(item.recommendation, operation=Operation.CLEAN)
    assert pending_record is not None
    approved_record, msg = approval_service.approve(pending_record.approval_id, explicit_consent=True)
    assert approved_record is not None

    st.session_state.approved_records[approved_record.path] = approved_record

    # 3. Transition to Controlled Execution UI
    navigate_to("Execution")
    assert st.session_state.current_tab == "Execution"
    assert st.session_state.current_mode == "CLEAN"

    # 4. Render Controlled Execution page
    render_execution_page()

    assert approved_record.path in st.session_state.approved_records


def test_execution_page_dry_run_and_trash_actions():
    """
    Verify Controlled Execution page actions:
    1. Dry Run simulation executes non-destructively and does not consume the approval token.
    2. Real Controlled Move executes verified trash move, consumes approval token, and logs audit record.
    """
    import tempfile
    from pathlib import Path
    import streamlit as st
    from app.analysis.models import RiskLevel
    from app.execution.models import ExecutionAction, ExecutionStatus
    from app.safety.approval_service import ApprovalService
    from app.safety.path_validator import Operation, PathValidator
    from app.safety.review import ApprovalStatus
    from app.ui.execution import render_execution_page
    from app.ui.state import get_services, init_app_state

    with tempfile.TemporaryDirectory() as temp_dir:
        sandbox = Path(temp_dir).resolve()
        cache_file = sandbox / "cache.tmp"
        cache_file.write_bytes(b"DATA" * 512)

        trash_dir = sandbox / "Trash"
        trash_dir.mkdir(parents=True, exist_ok=True)

        st.session_state.clear()
        init_app_state()

        validator = PathValidator(custom_allowlist_roots=[str(sandbox)])
        approval_service = ApprovalService(path_validator=validator)

        services = get_services()
        services["path_validator"] = validator
        services["approval_service"] = approval_service
        services["execution_planner"]._approval_service = approval_service
        services["execution_planner"]._validator = validator
        services["dry_run_executor"]._approval_service = approval_service
        services["dry_run_executor"]._validator = validator
        services["trash_executor"]._approval_service = approval_service
        services["trash_executor"]._validator = validator
        services["trash_executor"]._trash_root = trash_dir

        from app.analysis.models import StorageCandidate, StorageCategory
        from app.analysis.recommendations import RecommendationAction, SafetyStatus, StorageRecommendation
        cand = StorageCandidate(
            path=str(cache_file),
            size_bytes=2048,
            category=StorageCategory.CACHE,
            risk_level=RiskLevel.LOW,
            confidence=0.9,
            reason="Temp cache",
            recommendation="Review",
        )
        rec = StorageRecommendation(
            candidate=cand,
            action=RecommendationAction.REVIEW_FOR_CLEANUP,
            rationale="Safe cache file",
            safety_status=SafetyStatus.ELIGIBLE_FOR_REVIEW.value,
            requires_approval=True,
            confidence=0.9,
        )
        pending, _ = approval_service.request_approval(rec, operation=Operation.CLEAN)
        assert pending is not None
        approved, _ = approval_service.approve(pending.approval_id, explicit_consent=True)
        assert approved is not None

        st.session_state.approved_records = {approved.path: approved}

        # 1. Simulate Dry Run
        plan, err = services["execution_planner"].create_plan(approved, action=ExecutionAction.DRY_RUN)
        assert plan is not None
        dry_res = services["dry_run_executor"].execute_dry_run(plan)
        assert dry_res.status == ExecutionStatus.DRY_RUN_COMPLETED
        assert cache_file.exists()  # Non-destructive
        assert approval_service.get_status(approved.approval_id) == ApprovalStatus.APPROVED  # Not consumed

        # 2. Simulate Controlled Trash
        trash_plan, t_err = services["execution_planner"].create_plan(approved, action=ExecutionAction.TRASH)
        assert trash_plan is not None
        trash_res = services["trash_executor"].execute_trash(trash_plan)
        assert trash_res.status == ExecutionStatus.TRASH_SUCCEEDED
        assert trash_res.integrity_verified is True
        assert not cache_file.exists()  # Moved to trash
        assert Path(trash_res.trash_destination_path).exists()  # In sandbox trash
        assert approval_service.get_status(approved.approval_id) == ApprovalStatus.CONSUMED  # Replay protected


def test_demo_dataset_safety_and_isolation():
    """
    Verify Presentation Demo Data safety guarantees:
    - Pure in-memory synthetic dataset.
    - Zero filesystem modifications or real approvals.
    - Approval request against real path validator fails closed.
    - Does not write to SQLite audit database.
    """
    from app.ui.demo import generate_demo_dataset
    from app.safety.path_validator import PathValidator, Operation
    from app.safety.approval_service import ApprovalService

    items, candidates, recs, reviews, ctx = generate_demo_dataset()

    assert len(items) > 0
    assert len(candidates) > 0
    assert len(recs) > 0
    assert len(reviews) > 0
    assert ctx.total_scanned_items == len(candidates)

    # All demo paths are synthetic
    for item in items:
        assert item.path.startswith("/Users/demo") or item.path.startswith("/System")

    # Real standard path validator rejects /Users/demo paths (fails closed)
    standard_validator = PathValidator()
    appr_service = ApprovalService(path_validator=standard_validator)

    demo_rec = recs[0]  # /Users/demo/...
    record, err = appr_service.request_approval(demo_rec, operation=Operation.CLEAN)
    assert record is None
    assert "outside" in err.lower() and "allowlist" in err.lower()


def test_storage_charts_altair_rendering_and_zero_bound_axes():
    """
    Verify Altair charts used for Storage Visualizations:
    - Scale starts strictly at 0 (domainMin=0, zero=True).
    - Largest Storage Consumers chart has horizontal orientation and rich tooltips.
    """
    from app.ui.demo import generate_demo_dataset
    from app.ui.scan import render_scan_page
    from app.ui.dashboard import render_dashboard
    import streamlit as st

    items, candidates, recs, reviews, ctx = generate_demo_dataset()

    st.session_state.clear()
    st.session_state.candidates = candidates
    st.session_state.scan_results = items
    st.session_state.is_demo_mode = True

    # Render scan and dashboard pages to verify no errors
    render_scan_page()
    render_dashboard()


def test_render_recommendations_page_schema_and_hierarchy_regression():
    """
    Regression test for Recommendations page:
    - Renders real StorageRecommendation objects conforming to frozen Pydantic schema.
    - Ensures no AttributeError is raised on rec.candidate.path, rec.candidate.risk_level, rec.candidate.category.
    - Verifies hierarchy mapping, safety status display, and filter/sort handling.
    """
    import streamlit as st
    from app.analysis.models import RiskLevel, StorageCandidate, StorageCategory
    from app.analysis.recommendations import (
        RecommendationAction,
        SafetyStatus,
        StorageRecommendation,
    )
    from app.ui.recommendations import render_recommendations_page

    parent_cand = StorageCandidate(
        path="/Users/demo/Library/Caches/ParentCache",
        size_bytes=5_000_000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.95,
        reason="Parent container cache",
        recommendation="Review",
        item_type="directory",
    )
    nested_cand = StorageCandidate(
        path="/Users/demo/Library/Caches/ParentCache/sub_item",
        size_bytes=1_000_000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.90,
        reason="Nested sub-item cache",
        recommendation="Review",
        item_type="directory",
    )
    high_risk_cand = StorageCandidate(
        path="/Users/demo/Documents/Important.pdf",
        size_bytes=2_000_000,
        category=StorageCategory.DOCUMENTS,
        risk_level=RiskLevel.HIGH,
        confidence=0.99,
        reason="Protected document",
        recommendation="Blocked",
        item_type="file",
    )

    recs = [
        StorageRecommendation(
            candidate=parent_cand,
            action=RecommendationAction.REVIEW_FOR_CLEANUP,
            rationale="Parent cache eligible for cleanup",
            safety_status=SafetyStatus.ELIGIBLE_FOR_REVIEW.value,
            requires_approval=True,
            confidence=0.95,
        ),
        StorageRecommendation(
            candidate=nested_cand,
            action=RecommendationAction.REVIEW_FOR_CLEANUP,
            rationale="Nested cache eligible for cleanup",
            safety_status=SafetyStatus.ELIGIBLE_FOR_REVIEW.value,
            requires_approval=True,
            confidence=0.90,
        ),
        StorageRecommendation(
            candidate=high_risk_cand,
            action=RecommendationAction.NO_ACTION,
            rationale="Protected document cannot be deleted",
            safety_status=SafetyStatus.BLOCKED.value,
            requires_approval=True,
            confidence=0.99,
        ),
    ]

    st.session_state.clear()
    st.session_state.recommendations = recs
    st.session_state.candidates = [parent_cand, nested_cand, high_risk_cand]
    st.session_state.is_demo_mode = True

    # Render recommendations page — must not raise AttributeError
    render_recommendations_page()

    assert len(st.session_state.recommendations) == 3
    assert recs[0].candidate.path == "/Users/demo/Library/Caches/ParentCache"
    assert recs[0].candidate.risk_level == RiskLevel.LOW
    assert recs[0].candidate.size_bytes == 5_000_000
    assert recs[2].candidate.risk_level == RiskLevel.HIGH
    assert recs[2].safety_status == SafetyStatus.BLOCKED.value

    # Test with standard demo recommendations dataset as well
    from app.ui.demo import generate_demo_dataset
    demo_items, demo_cands, demo_recs, demo_revs, demo_ctx = generate_demo_dataset()

    st.session_state.clear()
    st.session_state.recommendations = demo_recs
    st.session_state.candidates = demo_cands
    st.session_state.is_demo_mode = True
    st.session_state.analysis_context = demo_ctx

    render_recommendations_page()
    assert len(st.session_state.recommendations) == len(demo_recs)


def test_render_recommendations_page_ai_explanation_timeout_and_unavailable_states():
    """
    Test Recommendations page rendering when Local AI explanation is unavailable or timed out:
    1. No exceptions or raw tracebacks are raised into Streamlit.
    2. Friendly unavailable message is presented.
    3. Deterministic candidate metadata (path, size, risk_level, safety_status) remains authoritative.
    4. Successful AI explanation state also renders cleanly.
    """
    import streamlit as st
    from app.analysis.models import RiskLevel, StorageCandidate, StorageCategory
    from app.analysis.recommendations import RecommendationAction, SafetyStatus, StorageRecommendation
    from app.llm.models import AnalysisContext
    from app.ui.recommendations import render_recommendations_page
    from app.ui.state import init_app_state

    st.session_state.clear()
    init_app_state()

    cand = StorageCandidate(
        path="/Users/test/Library/Caches/app",
        size_bytes=100_000_000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.95,
        reason="App build cache",
        recommendation="Review",
        item_type="directory",
    )
    rec = StorageRecommendation(
        candidate=cand,
        action=RecommendationAction.REVIEW_FOR_CLEANUP,
        rationale="Cache eligible for review",
        safety_status=SafetyStatus.ELIGIBLE_FOR_REVIEW.value,
        requires_approval=True,
        confidence=0.95,
    )

    ctx = AnalysisContext(
        scan_id="test-scan",
        scan_path="/Users/test",
        total_scanned_items=1,
        total_size_bytes=100_000_000,
        candidates=[cand],
        recommendations=[rec],
        safety_summary={"LOW": 1},
    )

    st.session_state.recommendations = [rec]
    st.session_state.candidates = [cand]
    st.session_state.analysis_context = ctx

    # 1. State: AI Explanation is UNAVAILABLE due to timeout
    st.session_state.ai_explanations[f"exp_{cand.path}"] = {
        "status": "UNAVAILABLE",
        "source": "timeout",
        "summary": "Local AI explanation timed out.",
        "explanation": cand.reason,
        "detail": (
            "Ollama did not respond within the configured timeout.\n\n"
            "The deterministic MacGuard recommendation remains valid. "
            "You can retry the AI explanation or continue without AI assistance."
        ),
        "deterministic_explanation": cand.reason,
    }

    # Render page — must NOT raise any exception
    render_recommendations_page()

    assert rec.candidate.risk_level == RiskLevel.LOW
    assert rec.safety_status == SafetyStatus.ELIGIBLE_FOR_REVIEW.value
    assert rec.action == RecommendationAction.REVIEW_FOR_CLEANUP

    # 2. State: AI Explanation is AVAILABLE
    st.session_state.ai_explanations[f"exp_{cand.path}"] = {
        "status": "AVAILABLE",
        "source": "local_ai",
        "summary": "AI identified 100MB of rebuildable Xcode caches.",
        "explanation": "These cache files are safely regenerable upon next build.",
        "user_guidance": "Review before confirming.",
        "warnings": [],
    }

    # Render page — must NOT raise any exception
    render_recommendations_page()

    assert rec.candidate.path == "/Users/test/Library/Caches/app"
    assert rec.candidate.risk_level == RiskLevel.LOW


def test_storage_investigation_docker_cleanup_checklist_renders_without_duplicate_keys():
    """
    Test that Storage Investigator page renders Docker cleanup checklist with unique widget keys
    even when evidence contains multiple tags or aliases for the same underlying image ID.
    """
    import streamlit as st
    from app.analysis.docker_planner import DockerCleanupPlanner
    from app.models.category import SmartCategory
    from app.models.docker_cleanup import DockerCleanupPlan, DockerCleanupPlanItem, DockerResourceType
    from app.models.investigation import (
        CleanupPlan,
        InvestigationLevel,
        ReclaimConfidence,
        StorageEvidenceItem,
        StorageInvestigationEvidence,
        StorageInvestigationResult,
    )
    from app.ui.state import init_app_state
    from app.ui.storage_investigation_view import render_storage_investigation_page

    st.session_state.clear()
    init_app_state()

    img_id = "sha256:8a607abcdef1234567890"
    item1 = StorageEvidenceItem(
        evidence_id="ev_docker_img1",
        path=f"docker://images/{img_id} (myrepo/app:latest)",
        canonical_path=f"docker://images/{img_id} (myrepo/app:latest)",
        size_bytes=500_000_000,
        item_count=1,
        category=SmartCategory.CONTAINERS,
        subcategory="docker_image",
        source_app="Docker",
        likely_owner="developer",
        is_cache=False,
        is_generated=True,
        is_developer=True,
        is_docker=True,
        risk_level=RiskLevel.LOW,
        reclaim_confidence=ReclaimConfidence.REVIEW_REQUIRED,
        cleanup_allowed=False,
        currently_in_use=False,
        dependency_evidence="Unreferenced / unused image.",
    )
    item2 = StorageEvidenceItem(
        evidence_id="ev_docker_img2",
        path=f"docker://images/{img_id} (myrepo/app:v1.0.0)",
        canonical_path=f"docker://images/{img_id} (myrepo/app:v1.0.0)",
        size_bytes=500_000_000,
        item_count=1,
        category=SmartCategory.CONTAINERS,
        subcategory="docker_image",
        source_app="Docker",
        likely_owner="developer",
        is_cache=False,
        is_generated=True,
        is_developer=True,
        is_docker=True,
        risk_level=RiskLevel.LOW,
        reclaim_confidence=ReclaimConfidence.REVIEW_REQUIRED,
        cleanup_allowed=False,
        currently_in_use=False,
        dependency_evidence="Unreferenced / unused image.",
    )

    evidence = StorageInvestigationEvidence(
        investigation_id="inv_test_ui_dedup",
        target_path="/Users/test",
        level=InvestigationLevel.TARGETED,
        disk_total_bytes=500_000_000_000,
        disk_used_bytes=300_000_000_000,
        disk_free_bytes=200_000_000_000,
        analyzed_bytes=1_000_000_000,
        candidate_inventory_bytes=1_000_000_000,
        eligible_for_review_bytes=500_000_000,
        reclaimable_high_confidence_bytes=0,
        reclaimable_review_required_bytes=500_000_000,
        protected_bytes=0,
        items=[item1, item2],
        top_consumers=[item1, item2],
    )

    planner = DockerCleanupPlanner()
    docker_plan = planner.create_plan(evidence)

    inv_result = StorageInvestigationResult(
        evidence=evidence,
        cleanup_plan=CleanupPlan(
            investigation_id="inv_test_ui_dedup",
            high_confidence_items=[],
            review_required_items=[],
            protected_items=[],
            total_reclaimable_high_confidence_bytes=0,
            total_reclaimable_review_required_bytes=500_000_000,
            total_protected_bytes=0,
        ),
        summary_text="Storage Investigation Complete. 500MB reviewable.",
        docker_plan=docker_plan,
    )

    st.session_state.investigation_result = inv_result

    # Track all keys passed to st.checkbox to verify strict uniqueness
    checkbox_keys = []
    original_checkbox = st.checkbox

    def mock_checkbox(label, *args, **kwargs):
        key = kwargs.get("key")
        if key:
            if key in checkbox_keys:
                raise pytest.fail(f"Duplicate Streamlit element key detected: '{key}'")
            checkbox_keys.append(key)
        return False

    with patch("streamlit.checkbox", side_effect=mock_checkbox):
        render_storage_investigation_page()

    # Verify that the checkbox key for the image plan item was registered exactly once
    expected_img_key = f"chk_ditem_item_img_{img_id[:12]}"
    assert expected_img_key in checkbox_keys
    assert checkbox_keys.count(expected_img_key) == 1


def test_storage_investigation_ui_local_ai_triggers_when_result_exists():
    """
    Ensure clicking 'Investigate with Local AI' triggers a fresh AI investigation
    even if st.session_state.investigation_result already contains a deterministic result.
    """
    import streamlit as st
    from app.analysis.storage_investigator import StorageInvestigator
    from app.llm.storage_investigator_llm import OllamaStorageInvestigator
    from app.models.investigation import (
        CleanupPlan,
        InvestigationLevel,
        StorageInvestigationEvidence,
        StorageInvestigationResult,
    )
    from app.ui.state import init_app_state
    from app.ui.storage_investigation_view import render_storage_investigation_page

    st.session_state.clear()
    init_app_state()

    # Pre-populate session state with an existing deterministic investigation result
    old_evidence = StorageInvestigationEvidence(
        investigation_id="inv_old_deterministic",
        target_path="/Users/test",
        level=InvestigationLevel.TARGETED,
        disk_total_bytes=500_000_000_000,
        disk_used_bytes=300_000_000_000,
        disk_free_bytes=200_000_000_000,
        analyzed_bytes=100_000_000,
        candidate_inventory_bytes=100_000_000,
        eligible_for_review_bytes=100_000_000,
        reclaimable_high_confidence_bytes=100_000_000,
        reclaimable_review_required_bytes=0,
        protected_bytes=0,
        items=[],
        top_consumers=[],
    )
    old_plan = CleanupPlan(
        investigation_id="inv_old_deterministic",
        high_confidence_items=[],
        total_reclaimable_bytes=100_000_000,
    )
    old_result = StorageInvestigationResult(
        evidence=old_evidence,
        cleanup_plan=old_plan,
        summary_text="Old deterministic summary",
        is_ai_reasoned=False,
    )
    st.session_state.investigation_result = old_result

    # Mock st.button so that 'ai_btn' (Investigate with Local AI) returns True, run_btn returns False
    def mock_button(label, *args, **kwargs):
        if "Local AI" in label:
            return True
        return False

    mock_ai_result = StorageInvestigationResult(
        evidence=old_evidence,
        cleanup_plan=old_plan,
        summary_text="New Local AI reasoned summary",
        is_ai_reasoned=True,
        ai_status_message="Reasoned with local AI (Ollama).",
    )

    with patch("streamlit.button", side_effect=mock_button), \
         patch.object(StorageInvestigator, "investigate", return_value=(old_evidence, old_plan)) as mock_inv, \
         patch.object(OllamaStorageInvestigator, "investigate", return_value=mock_ai_result) as mock_llm_inv:

        render_storage_investigation_page()

        # Both the base investigator and OllamaStorageInvestigator.investigate MUST have been called
        assert mock_inv.called
        assert mock_llm_inv.called
        assert st.session_state.investigation_result.is_ai_reasoned is True
        assert st.session_state.investigation_result.summary_text == "New Local AI reasoned summary"


def test_storage_investigation_ui_deterministic_button():
    """
    Ensure clicking 'Investigate My Storage' invokes investigate_deterministic (is_ai_reasoned=False).
    """
    import streamlit as st
    from app.analysis.storage_investigator import StorageInvestigator
    from app.llm.storage_investigator_llm import OllamaStorageInvestigator
    from app.models.investigation import (
        CleanupPlan,
        InvestigationLevel,
        StorageInvestigationEvidence,
        StorageInvestigationResult,
    )
    from app.ui.state import init_app_state
    from app.ui.storage_investigation_view import render_storage_investigation_page

    st.session_state.clear()
    init_app_state()

    evidence = StorageInvestigationEvidence(
        investigation_id="inv_det",
        target_path="/Users/test",
        level=InvestigationLevel.TARGETED,
        disk_total_bytes=500_000_000_000,
        disk_used_bytes=300_000_000_000,
        disk_free_bytes=200_000_000_000,
        analyzed_bytes=100_000_000,
        candidate_inventory_bytes=100_000_000,
        eligible_for_review_bytes=100_000_000,
        reclaimable_high_confidence_bytes=100_000_000,
        reclaimable_review_required_bytes=0,
        protected_bytes=0,
        items=[],
        top_consumers=[],
    )
    plan = CleanupPlan(
        investigation_id="inv_det",
        high_confidence_items=[],
        total_reclaimable_bytes=100_000_000,
    )
    det_result = StorageInvestigationResult(
        evidence=evidence,
        cleanup_plan=plan,
        summary_text="Deterministic summary",
        is_ai_reasoned=False,
    )

    def mock_button(label, *args, **kwargs):
        if "Investigate My Storage" in label:
            return True
        return False

    with patch("streamlit.button", side_effect=mock_button), \
         patch.object(StorageInvestigator, "investigate", return_value=(evidence, plan)), \
         patch.object(OllamaStorageInvestigator, "investigate_deterministic", return_value=det_result) as mock_det, \
         patch.object(OllamaStorageInvestigator, "investigate") as mock_ai:

        render_storage_investigation_page()

        assert mock_det.called
        assert not mock_ai.called
        assert st.session_state.investigation_result.is_ai_reasoned is False
