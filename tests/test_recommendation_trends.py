"""
MacGuard AI v1.1 — Storage Intelligence to Actionable Recommendations Tests (Phase 5D).

Validates deterministic connection between historical storage trends and current candidates,
strict candidate grounding (trends never invent candidates), safety domination (risk and
allowlists always override historical signals), and zero-authority execution boundaries.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

import streamlit as st

from app.analysis.models import RiskLevel, StorageCandidate, StorageCategory
from app.analysis.recommendations import (
    HistoricalRecommendationContext,
    RecommendationAction,
    RecommendationEngine,
    SafetyStatus,
    StorageRecommendation,
)
from app.models.category import ConfidenceLevel, SmartCategory
from app.models.developer import DeveloperStorageSubtype
from app.models.scan_result import ScanStatus
from app.models.scan_scope import ScopeIdentifier
from app.models.storage_history import (
    CategorySnapshotItem,
    CategoryTrend,
    DeveloperSnapshotItem,
    DeveloperTrend,
    StorageSnapshot,
    StorageTrend,
    StorageTrendReport,
    TrendDirection,
)
from app.safety.approval_service import ApprovalService
from app.safety.path_validator import Operation, PathValidator
from app.safety.review import ReviewItem
from app.ui.state import init_app_state


@pytest.fixture(autouse=True)
def setup_session():
    """Ensure clean Streamlit session state for each test."""
    st.session_state.clear()
    init_app_state()
    yield
    st.session_state.clear()


@pytest.fixture
def sample_trend_report():
    """Create a sample comparable trend report with a growing CACHE category."""
    return StorageTrendReport(
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/mac",
        current_snapshot_id="snap-curr",
        previous_snapshot_id="snap-prev",
        current_timestamp=1700086400.0,
        previous_timestamp=1700000000.0,
        is_comparable=True,
        overall_trend=StorageTrend(
            metric="Total Storage",
            current_value=120_000_000_000,
            previous_value=100_000_000_000,
            absolute_change=20_000_000_000,
            percentage_change=20.0,
            direction=TrendDirection.GROWING,
            explanation="Storage increased by 20.0 GB (+20.0%).",
        ),
        category_trends=[
            CategoryTrend(
                category=SmartCategory.CACHES,
                current_bytes=25_000_000_000,
                previous_bytes=15_000_000_000,
                absolute_change=10_000_000_000,
                percentage_change=66.7,
                direction=TrendDirection.GROWING,
                explanation="Caches grew by 10.0 GB.",
            ),
            CategoryTrend(
                category=SmartCategory.DEVELOPER_DATA,
                current_bytes=40_000_000_000,
                previous_bytes=40_000_000_000,
                absolute_change=0,
                percentage_change=0.0,
                direction=TrendDirection.STABLE,
                explanation="Developer data is stable.",
            ),
            CategoryTrend(
                category=SmartCategory.LOGS,
                current_bytes=2_000_000_000,
                previous_bytes=5_000_000_000,
                absolute_change=-3_000_000_000,
                percentage_change=-60.0,
                direction=TrendDirection.SHRINKING,
                explanation="Logs shrank by 3.0 GB.",
            ),
        ],
        developer_trends=[
            DeveloperTrend(
                subtype=DeveloperStorageSubtype.NODE_MODULES,
                current_bytes=20_000_000_000,
                previous_bytes=10_000_000_000,
                absolute_change=10_000_000_000,
                percentage_change=100.0,
                direction=TrendDirection.GROWING,
                explanation="Node modules grew by 10.0 GB.",
            ),
        ],
        largest_growing_category=SmartCategory.CACHES,
        largest_growing_developer_subtype=DeveloperStorageSubtype.NODE_MODULES,
        notes=[],
    )


# =========================================================================
# A-B. No History & Single Snapshot Behavior
# =========================================================================

def test_recommendation_without_history_behaves_as_baseline():
    """Verify that RecommendationEngine behaves identically to baseline when trend_report is None."""
    engine = RecommendationEngine()
    cand = StorageCandidate(
        path="/Users/mac/Library/Caches/com.app.cache",
        size_bytes=500_000_000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.95,
        reason="Application cache directory",
        recommendation="Review cache for cleanup",
    )
    rec = engine.recommend(cand, trend_report=None)

    assert rec.action == RecommendationAction.REVIEW_FOR_CLEANUP
    assert rec.safety_status == SafetyStatus.ELIGIBLE_FOR_REVIEW.value
    assert rec.requires_approval is True
    assert rec.historical_context is None


def test_recommendation_with_incomparable_single_snapshot_report():
    """Verify single snapshot report (no baseline) attaches no historical context."""
    engine = RecommendationEngine()
    incomparable_report = StorageTrendReport(
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/mac",
        current_snapshot_id="snap-1",
        previous_snapshot_id=None,
        current_timestamp=1700000000.0,
        previous_timestamp=None,
        is_comparable=False,
        overall_trend=StorageTrend(
            metric="Total Storage",
            current_value=100_000_000_000,
            previous_value=0,
            absolute_change=0,
            percentage_change=None,
            direction=TrendDirection.UNKNOWN,
            explanation="First scan.",
        ),
        notes=["First recorded scan."],
    )
    cand = StorageCandidate(
        path="/Users/mac/Library/Caches/app",
        size_bytes=100_000_000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.9,
        reason="Cache",
        recommendation="Review cache",
    )
    rec = engine.recommend(cand, trend_report=incomparable_report)

    assert rec.historical_context is None
    assert rec.action == RecommendationAction.REVIEW_FOR_CLEANUP


# =========================================================================
# C-F. Historical Trend Context (Growing, Stable, Shrinking, Unknown)
# =========================================================================

def test_growing_category_attaches_context_and_priority_boost(sample_trend_report):
    """Verify growing category attaches informative context and priority boost."""
    engine = RecommendationEngine()
    cand = StorageCandidate(
        path="/Users/mac/Library/Caches/browser_cache",
        size_bytes=5_000_000_000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.9,
        reason="Browser cache",
        recommendation="Review for cleanup",
    )
    rec = engine.recommend(cand, trend_report=sample_trend_report)

    assert rec.historical_context is not None
    assert rec.historical_context.trend_direction == TrendDirection.GROWING
    assert rec.historical_context.priority_boost is True
    assert "increased by" in rec.historical_context.context_summary
    assert rec.action == RecommendationAction.REVIEW_FOR_CLEANUP


def test_stable_category_attaches_stable_context_without_boost(sample_trend_report):
    """Verify stable category attaches stable context without priority boost."""
    engine = RecommendationEngine()
    cand = StorageCandidate(
        path="/Users/mac/projects/rust_app/src",
        size_bytes=1_000_000_000,
        category=StorageCategory.DEVELOPMENT,
        risk_level=RiskLevel.MEDIUM,
        confidence=0.85,
        reason="Rust project source",
        recommendation="Manual review",
    )
    rec = engine.recommend(cand, trend_report=sample_trend_report)

    assert rec.historical_context is not None
    assert rec.historical_context.trend_direction == TrendDirection.STABLE
    assert rec.historical_context.priority_boost is False
    assert "broadly stable" in rec.historical_context.context_summary
    assert rec.action == RecommendationAction.MANUAL_REVIEW


def test_shrinking_category_attaches_shrinking_context(sample_trend_report):
    """Verify shrinking category attaches shrinking explanation."""
    engine = RecommendationEngine()
    cand = StorageCandidate(
        path="/Users/mac/Library/Logs/diagnostic.log",
        size_bytes=50_000_000,
        category=StorageCategory.LOGS,
        risk_level=RiskLevel.LOW,
        confidence=0.9,
        reason="System log",
        recommendation="Review log",
    )
    rec = engine.recommend(cand, trend_report=sample_trend_report)

    assert rec.historical_context is not None
    assert rec.historical_context.trend_direction == TrendDirection.SHRINKING
    assert rec.historical_context.priority_boost is False
    assert "decreased by" in rec.historical_context.context_summary


# =========================================================================
# G-H. Incompatible & Incomplete History Safety
# =========================================================================

def test_incompatible_scope_report_rejected(sample_trend_report):
    """Verify that an incompatible scope report attaches no context."""
    engine = RecommendationEngine()
    incompatible = sample_trend_report.model_copy(update={"is_comparable": False, "notes": ["Incompatible scope comparison."]})
    cand = StorageCandidate(
        path="/Users/mac/Library/Caches/app",
        size_bytes=100_000_000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.9,
        reason="Cache",
        recommendation="Review cache",
    )
    rec = engine.recommend(cand, trend_report=incompatible)

    assert rec.historical_context is None


def test_incomplete_scan_history_handled_conservatively(sample_trend_report):
    """Verify that incomplete scans receive zero priority boost and are explicitly marked."""
    engine = RecommendationEngine()
    incomplete_report = sample_trend_report.model_copy(
        update={"notes": ["Comparison includes incomplete scan observations."]}
    )
    cand = StorageCandidate(
        path="/Users/mac/Library/Caches/app",
        size_bytes=100_000_000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.9,
        reason="Cache",
        recommendation="Review cache",
    )
    rec = engine.recommend(cand, trend_report=incomplete_report)

    assert rec.historical_context is not None
    assert rec.historical_context.is_incomplete_scan is True
    assert rec.historical_context.priority_boost is False
    assert "incomplete" in rec.historical_context.context_summary.lower()


# =========================================================================
# I-J. Current Candidate Grounding (No Invention of Candidates)
# =========================================================================

def test_growing_category_without_current_candidate_creates_zero_recommendations(sample_trend_report):
    """
    CRITICAL INVARIANT:
    A growing historical category with NO current candidate must produce ZERO recommendations.
    Historical trends must never invent candidate items.
    """
    engine = RecommendationEngine()
    # Provide an empty candidate list
    current_candidates: list[StorageCandidate] = []
    recs = engine.recommend_many(current_candidates, trend_report=sample_trend_report)

    assert len(recs) == 0


def test_current_candidate_grounding_preserves_candidate_count(sample_trend_report):
    """Verify 1-to-1 correspondence between current candidates and generated recommendations."""
    engine = RecommendationEngine()
    cands = [
        StorageCandidate(
            path=f"/Users/mac/Library/Caches/app_{i}",
            size_bytes=10_000_000 * i,
            category=StorageCategory.CACHE,
            risk_level=RiskLevel.LOW,
            confidence=0.9,
            reason="Cache",
            recommendation="Review",
        )
        for i in range(1, 4)
    ]
    recs = engine.recommend_many(cands, trend_report=sample_trend_report)

    assert len(recs) == len(cands)
    for r in recs:
        assert r.historical_context is not None
        assert r.historical_context.trend_direction == TrendDirection.GROWING


# =========================================================================
# K-N. Safety Rules ALWAYS Dominate Priority
# =========================================================================

def test_high_risk_candidate_with_massive_historical_growth_remains_blocked(sample_trend_report):
    """
    SAFETY INVARIANT:
    HIGH risk candidate must remain MANUAL_REVIEW / BLOCKED regardless of massive historical growth.
    """
    engine = RecommendationEngine()
    cand_high = StorageCandidate(
        path="/Users/mac/Documents/ImportantVault",
        size_bytes=50_000_000_000,
        category=StorageCategory.DOCUMENTS,
        risk_level=RiskLevel.HIGH,
        confidence=0.99,
        reason="User document directory",
        recommendation="Manual user review only",
    )
    rec = engine.recommend(cand_high, trend_report=sample_trend_report)

    assert rec.action == RecommendationAction.MANUAL_REVIEW
    assert rec.safety_status == SafetyStatus.MANUAL_REVIEW_REQUIRED.value
    assert rec.action != RecommendationAction.REVIEW_FOR_CLEANUP


def test_unknown_risk_candidate_with_historical_growth_remains_blocked(sample_trend_report):
    """
    SAFETY INVARIANT:
    UNKNOWN risk candidate must remain NO_ACTION / UNKNOWN safety status.
    """
    engine = RecommendationEngine()
    cand_unknown = StorageCandidate(
        path="/Users/mac/mysterious_file.dat",
        size_bytes=20_000_000_000,
        category=StorageCategory.UNKNOWN,
        risk_level=RiskLevel.UNKNOWN,
        confidence=0.1,
        reason="Unknown binary structure",
        recommendation="Do not clean",
    )
    rec = engine.recommend(cand_unknown, trend_report=sample_trend_report)

    assert rec.action == RecommendationAction.NO_ACTION
    assert rec.safety_status == SafetyStatus.UNKNOWN.value


def test_negligible_size_item_with_growth_remains_ineligible(sample_trend_report):
    """Verify items below minimum threshold remain excluded despite category growth."""
    engine = RecommendationEngine(min_cleanup_size_bytes=1_000_000)
    cand_tiny = StorageCandidate(
        path="/Users/mac/Library/Caches/tiny.cache",
        size_bytes=500,  # Below 1 MB threshold
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.9,
        reason="Cache",
        recommendation="Review",
    )
    rec = engine.recommend(cand_tiny, trend_report=sample_trend_report)

    assert rec.action == RecommendationAction.NO_ACTION
    assert "below the minimum cleanup threshold" in rec.rationale


# =========================================================================
# O-R. Approval & Execution Invariants
# =========================================================================

def test_historical_context_does_not_create_approval(sample_trend_report):
    """Verify that creating recommendations with historical context does not generate approval records."""
    engine = RecommendationEngine()
    cand = StorageCandidate(
        path="/Users/mac/Library/Caches/app.cache",
        size_bytes=50_000_000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.9,
        reason="Cache",
        recommendation="Review",
    )
    rec = engine.recommend(cand, trend_report=sample_trend_report)

    assert rec.requires_approval is True
    # Verify no approval record or token was manufactured
    assert not hasattr(rec, "approval_token")
    assert not hasattr(rec, "signature")


def test_review_item_creation_preserves_historical_context(sample_trend_report):
    """Verify ApprovalService.create_review_items safely preserves attached historical context."""
    engine = RecommendationEngine()
    cand = StorageCandidate(
        path="/Users/mac/Library/Caches/app.cache",
        size_bytes=50_000_000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.9,
        reason="Cache",
        recommendation="Review",
    )
    rec = engine.recommend(cand, trend_report=sample_trend_report)
    approval_service = ApprovalService(path_validator=PathValidator())

    review_items = approval_service.create_review_items([rec])
    assert len(review_items) == 1
    assert review_items[0].recommendation.historical_context is not None
    assert review_items[0].recommendation.historical_context.trend_direction == TrendDirection.GROWING


# =========================================================================
# S-U. Zero Mutation & Static Safety Invariants
# =========================================================================

def test_recommendation_trends_zero_mutation_invariants():
    """Verify that recommendation trend models and engine possess zero execution authority."""
    import app.analysis.recommendations as rec_mod

    assert not hasattr(rec_mod, "TrashExecutor")
    assert not hasattr(rec_mod, "DryRunExecutor")
    assert not hasattr(rec_mod, "ApprovalKeyManager")
    assert not hasattr(rec_mod, "execute")
    assert not hasattr(rec_mod, "unlink")
    assert not hasattr(rec_mod, "rmdir")


# =========================================================================
# V-Z. Extended Phase 5D Tests (Developer Trends, Protected Paths, UI & Agent)
# =========================================================================

def test_developer_subtype_trend_context_attachment(sample_trend_report):
    """Verify that developer candidate paths matching developer subtype attach developer-specific context."""
    engine = RecommendationEngine()
    cand_node = StorageCandidate(
        path="/Users/mac/projects/web-app/node_modules",
        size_bytes=4_000_000_000,
        category=StorageCategory.DEVELOPMENT,
        risk_level=RiskLevel.MEDIUM,
        confidence=0.9,
        reason="Node modules dependency cache",
        recommendation="Review for cleanup",
    )
    rec = engine.recommend(cand_node, trend_report=sample_trend_report)

    assert rec.historical_context is not None
    assert rec.historical_context.category_name == "Development (node_modules)"
    assert rec.historical_context.trend_direction == TrendDirection.GROWING
    assert rec.historical_context.priority_boost is True
    assert "node modules" in rec.historical_context.context_summary.lower()


def test_protected_path_candidate_rejected_despite_growth(sample_trend_report):
    """
    PROTECTED PATH INVARIANT:
    System protected paths must be rejected and never marked eligible for cleanup,
    even if the category has huge historical growth.
    """
    engine = RecommendationEngine()
    cand_system = StorageCandidate(
        path="/System/Library/Caches/com.apple.kernelcaches",
        size_bytes=10_000_000_000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.HIGH,
        confidence=0.99,
        reason="System kernel cache",
        recommendation="Do not clean",
    )
    rec = engine.recommend(cand_system, trend_report=sample_trend_report)

    assert rec.action == RecommendationAction.MANUAL_REVIEW
    assert rec.safety_status != SafetyStatus.ELIGIBLE_FOR_REVIEW.value


def test_historical_context_model_serialization():
    """Verify HistoricalRecommendationContext and StorageRecommendation serialization with Pydantic."""
    ctx = HistoricalRecommendationContext(
        trend_direction=TrendDirection.GROWING,
        category_name="Caches",
        absolute_change_bytes=5_000_000_000,
        percentage_change=50.0,
        comparison_available=True,
        is_incomplete_scan=False,
        priority_boost=True,
        context_summary="Category Caches increased by 5.0 GB (+50.0%) since the previous comparable scan.",
        source_scope=ScopeIdentifier.HOME,
        source_snapshot_id="snap-curr",
    )
    cand = StorageCandidate(
        path="/Users/mac/Library/Caches/com.test.app",
        size_bytes=500_000_000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.9,
        reason="App cache directory",
        recommendation="Review for cleanup",
    )
    rec = StorageRecommendation(
        candidate=cand,
        action=RecommendationAction.REVIEW_FOR_CLEANUP,
        rationale="App cache directory",
        safety_status=SafetyStatus.ELIGIBLE_FOR_REVIEW.value,
        requires_approval=True,
        confidence=0.9,
        historical_context=ctx,
    )
    data = rec.model_dump()
    assert data["historical_context"]["trend_direction"] == "GROWING"
    assert data["historical_context"]["priority_boost"] is True

    # Roundtrip rebuild
    restored = StorageRecommendation.model_validate(data)
    assert restored.historical_context is not None
    assert restored.historical_context.absolute_change_bytes == 5_000_000_000


def test_unknown_category_candidate_no_trend_match(sample_trend_report):
    """Verify candidate with UNKNOWN category does not attach irrelevant category trend."""
    engine = RecommendationEngine()
    cand = StorageCandidate(
        path="/Users/mac/unrecognized_folder",
        size_bytes=500_000_000,
        category=StorageCategory.UNKNOWN,
        risk_level=RiskLevel.UNKNOWN,
        confidence=0.2,
        reason="Unknown folder",
        recommendation="Manual review",
    )
    rec = engine.recommend(cand, trend_report=sample_trend_report)

    assert rec.historical_context is None
    assert rec.action == RecommendationAction.NO_ACTION


def test_recommendations_ui_page_rendering_with_historical_context():
    """Verify UI recommendations page safely formats and renders historical context badge."""
    from app.ui.recommendations import render_recommendations_page

    ctx = HistoricalRecommendationContext(
        trend_direction=TrendDirection.GROWING,
        category_name="Caches",
        absolute_change_bytes=3_000_000_000,
        percentage_change=30.0,
        comparison_available=True,
        is_incomplete_scan=False,
        priority_boost=True,
        context_summary="Category Caches increased by 3.0 GB (+30.0%) since the previous comparable scan.",
        source_scope=ScopeIdentifier.HOME,
        source_snapshot_id="snap-123",
    )
    cand = StorageCandidate(
        path="/Users/mac/Library/Caches/com.test.app",
        size_bytes=1_000_000_000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.9,
        reason="App cache directory",
        recommendation="Review",
    )
    rec = StorageRecommendation(
        candidate=cand,
        action=RecommendationAction.REVIEW_FOR_CLEANUP,
        rationale="Safe to clean",
        safety_status=SafetyStatus.ELIGIBLE_FOR_REVIEW.value,
        requires_approval=True,
        confidence=0.9,
        historical_context=ctx,
    )

    st.session_state.recommendations = [rec]
    st.session_state.is_demo_mode = False

    with patch("streamlit.markdown") as mock_md, \
         patch("streamlit.info") as mock_info, \
         patch("streamlit.selectbox", side_effect=["All Risks", "All Categories", "All Statuses", "Largest Size First"]):
        render_recommendations_page()
        assert mock_info.called


def test_review_ui_page_rendering_with_historical_context():
    """Verify Human Review UI module correctly displays historical context without breaking."""
    from app.ui.review import render_review_page

    ctx = HistoricalRecommendationContext(
        trend_direction=TrendDirection.GROWING,
        category_name="Developer Data",
        absolute_change_bytes=6_000_000_000,
        percentage_change=40.0,
        comparison_available=True,
        is_incomplete_scan=False,
        priority_boost=True,
        context_summary="Developer Data grew by 6.0 GB.",
        source_scope=ScopeIdentifier.HOME,
        source_snapshot_id="snap-abc",
    )
    cand = StorageCandidate(
        path="/Users/mac/projects/old_app/node_modules",
        size_bytes=2_000_000_000,
        category=StorageCategory.DEVELOPMENT,
        risk_level=RiskLevel.LOW,
        confidence=0.9,
        reason="Stale node modules",
        recommendation="Review",
    )
    rec = StorageRecommendation(
        candidate=cand,
        action=RecommendationAction.REVIEW_FOR_CLEANUP,
        rationale="Stale node modules",
        safety_status=SafetyStatus.ELIGIBLE_FOR_REVIEW.value,
        requires_approval=True,
        confidence=0.9,
        historical_context=ctx,
    )
    approval_service = ApprovalService(path_validator=PathValidator())
    items = approval_service.create_review_items([rec])

    st.session_state.review_items = items
    st.session_state.approved_records = {}
    st.session_state.rejected_paths = set()

    render_review_page()
    # Should execute cleanly without raising exception


def test_storage_intelligence_ui_candidate_linkage(sample_trend_report):
    """Verify render_whats_growing displays available candidate counts and navigation."""
    from app.ui.storage_intelligence import render_whats_growing

    cands = [
        StorageCandidate(
            path="/Users/mac/Library/Caches/com.app.cache",
            size_bytes=500_000_000,
            category=StorageCategory.CACHE,
            risk_level=RiskLevel.LOW,
            confidence=0.9,
            reason="Cache",
            recommendation="Review",
        )
    ]

    with patch("streamlit.container"), \
         patch("streamlit.columns", return_value=(MagicMock(), MagicMock())), \
         patch("streamlit.markdown") as mock_md, \
         patch("streamlit.caption") as mock_cap, \
         patch("streamlit.button", return_value=False):
        render_whats_growing(sample_trend_report, current_candidates=cands)
        # Verify markdown calls include candidate count
        md_calls = [call[0][0] for call in mock_md.call_args_list if call[0]]
        assert any("candidate(s) available for review" in text for text in md_calls)


def test_storage_intelligence_ui_no_candidate_display(sample_trend_report):
    """Verify render_whats_growing gracefully indicates 0 candidates when none match."""
    from app.ui.storage_intelligence import render_whats_growing

    with patch("streamlit.container"), \
         patch("streamlit.columns", return_value=(MagicMock(), MagicMock())), \
         patch("streamlit.markdown") as mock_md, \
         patch("streamlit.caption") as mock_cap, \
         patch("streamlit.button", return_value=False):
        render_whats_growing(sample_trend_report, current_candidates=[])
        md_calls = [call[0][0] for call in mock_md.call_args_list if call[0]]
        assert any("No active cleanup candidates" in text for text in md_calls)


def test_agent_read_only_boundary_with_trends(sample_trend_report):
    """Verify that agent tools provide read-only recommendations with trend context without modification authority."""
    from app.agent.tools import AgentToolRegistry

    registry = AgentToolRegistry()
    cand = StorageCandidate(
        path="/Users/mac/Library/Caches/com.app.cache",
        size_bytes=500_000_000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.9,
        reason="Cache",
        recommendation="Review",
    )
    engine = RecommendationEngine()
    rec = engine.recommend(cand, trend_report=sample_trend_report)

    obs = registry.execute_tool("get_recommendations", recommendations=[rec])

    assert obs.tool_name == "get_recommendations"
    assert isinstance(obs.data, list)
    assert len(obs.data) == 1
    assert obs.data[0]["historical_context"] is not None
    assert obs.data[0]["historical_context"]["trend_direction"] == "GROWING"
    # Ensure tool registry contains zero execution/mutation tools
    for forbidden in ["delete_files", "approve_cleanup", "execute_trash", "execute_dry_run"]:
        assert not registry.is_tool_allowed(forbidden)


def test_recommend_many_deterministic_priority_sorting(sample_trend_report):
    """Verify recommend_many attaches historical context to all candidates deterministically."""
    engine = RecommendationEngine()
    cands = [
        StorageCandidate(
            path="/Users/mac/Library/Caches/cache_a",
            size_bytes=100_000_000,
            category=StorageCategory.CACHE,
            risk_level=RiskLevel.LOW,
            confidence=0.9,
            reason="Cache A",
            recommendation="Review",
        ),
        StorageCandidate(
            path="/Users/mac/Library/Logs/log_b",
            size_bytes=100_000_000,
            category=StorageCategory.LOGS,
            risk_level=RiskLevel.LOW,
            confidence=0.9,
            reason="Log B",
            recommendation="Review",
        ),
    ]
    recs = engine.recommend_many(cands, trend_report=sample_trend_report)

    assert len(recs) == 2
    assert recs[0].historical_context.priority_boost is True  # Cache is GROWING
    assert recs[1].historical_context.priority_boost is False  # Logs is SHRINKING


def test_historical_context_immutability():
    """Verify that HistoricalRecommendationContext is frozen and rejects attribute mutation."""
    ctx = HistoricalRecommendationContext(
        trend_direction=TrendDirection.GROWING,
        category_name="Caches",
        absolute_change_bytes=5_000_000_000,
        percentage_change=50.0,
        comparison_available=True,
        is_incomplete_scan=False,
        priority_boost=True,
        context_summary="Growing",
        source_scope=ScopeIdentifier.HOME,
        source_snapshot_id="snap-1",
    )
    with pytest.raises(Exception):
        ctx.priority_boost = False  # type: ignore


def test_python_venv_developer_trend_matching(sample_trend_report):
    """Verify that python virtual environments match python_venv developer trends."""
    venv_report = sample_trend_report.model_copy(
        update={
            "developer_trends": [
                DeveloperTrend(
                    subtype=DeveloperStorageSubtype.PYTHON_VENV,
                    current_bytes=6_000_000_000,
                    previous_bytes=2_000_000_000,
                    absolute_change=4_000_000_000,
                    percentage_change=200.0,
                    direction=TrendDirection.GROWING,
                    explanation="Python venvs grew by 4.0 GB.",
                )
            ]
        }
    )
    engine = RecommendationEngine()
    cand = StorageCandidate(
        path="/Users/mac/projects/ai_app/.venv",
        size_bytes=3_000_000_000,
        category=StorageCategory.DEVELOPMENT,
        risk_level=RiskLevel.MEDIUM,
        confidence=0.9,
        reason="Python virtual environment",
        recommendation="Review",
    )
    rec = engine.recommend(cand, trend_report=venv_report)

    assert rec.historical_context is not None
    assert "python_venv" in rec.historical_context.category_name
    assert rec.historical_context.trend_direction == TrendDirection.GROWING


def test_build_output_developer_trend_matching(sample_trend_report):
    """Verify that build artifacts match build_output developer trends."""
    build_report = sample_trend_report.model_copy(
        update={
            "developer_trends": [
                DeveloperTrend(
                    subtype=DeveloperStorageSubtype.BUILD_OUTPUT,
                    current_bytes=8_000_000_000,
                    previous_bytes=3_000_000_000,
                    absolute_change=5_000_000_000,
                    percentage_change=166.7,
                    direction=TrendDirection.GROWING,
                    explanation="Build output grew by 5.0 GB.",
                )
            ]
        }
    )
    engine = RecommendationEngine()
    cand = StorageCandidate(
        path="/Users/mac/projects/rust_app/target/release",
        size_bytes=4_000_000_000,
        category=StorageCategory.DEVELOPMENT,
        risk_level=RiskLevel.LOW,
        confidence=0.9,
        reason="Rust build target directory",
        recommendation="Review",
    )
    rec = engine.recommend(cand, trend_report=build_report)

    assert rec.historical_context is not None
    assert "build_output" in rec.historical_context.category_name
    assert rec.historical_context.priority_boost is True


def test_empty_trend_category_list_fails_closed():
    """Verify that a trend report with empty categories safely returns None context."""
    empty_report = StorageTrendReport(
        scope_id=ScopeIdentifier.HOME,
        root_path="/Users/mac",
        current_snapshot_id="snap-curr",
        previous_snapshot_id="snap-prev",
        current_timestamp=1700086400.0,
        previous_timestamp=1700000000.0,
        is_comparable=True,
        overall_trend=StorageTrend(
            metric="Total Storage",
            current_value=100_000_000_000,
            previous_value=100_000_000_000,
            absolute_change=0,
            percentage_change=0.0,
            direction=TrendDirection.STABLE,
            explanation="Stable.",
        ),
        category_trends=[],
        developer_trends=[],
        notes=[],
    )
    engine = RecommendationEngine()
    cand = StorageCandidate(
        path="/Users/mac/Library/Caches/com.app",
        size_bytes=50_000_000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.9,
        reason="Cache",
        recommendation="Review",
    )
    rec = engine.recommend(cand, trend_report=empty_report)

    assert rec.historical_context is None
    assert rec.action == RecommendationAction.REVIEW_FOR_CLEANUP


def test_first_scan_without_trend_report_processes_multiple_candidates():
    """Verify first scan without trend report processes multiple candidates with zero regression."""
    engine = RecommendationEngine()
    cands = [
        StorageCandidate(
            path=f"/Users/mac/Library/Caches/cache_{i}",
            size_bytes=10_000_000 * i,
            category=StorageCategory.CACHE,
            risk_level=RiskLevel.LOW,
            confidence=0.9,
            reason="Cache",
            recommendation="Review",
        )
        for i in range(1, 5)
    ]
    recs = engine.recommend_many(cands, trend_report=None)

    assert len(recs) == 4
    for r in recs:
        assert r.historical_context is None
        assert r.action == RecommendationAction.REVIEW_FOR_CLEANUP


# =========================================================================
# Semantic Accuracy & Evidence Level Tests
# =========================================================================

def test_category_level_history_does_not_imply_path_level_change(sample_trend_report):
    """
    SEMANTIC ACCURACY INVARIANT:
    Category-level evidence must explicitly identify itself as category context
    and must not claim that the specific candidate path grew or changed.
    """
    from app.models.historical_recommendation import HistoricalContextLevel

    engine = RecommendationEngine()
    cand = StorageCandidate(
        path="/Users/mac/Library/Caches/Google/Chrome/Cache",
        size_bytes=2_000_000_000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.95,
        reason="Chrome cache",
        recommendation="Review cache",
    )
    rec = engine.recommend(cand, trend_report=sample_trend_report)

    assert rec.historical_context is not None
    assert rec.historical_context.context_type == HistoricalContextLevel.CATEGORY
    assert rec.historical_context.context_summary.startswith("Historical category context:")
    # Ensure it describes the category, not claiming the specific Google cache path grew
    assert "Historical category context: Caches storage increased by" in rec.historical_context.context_summary
    assert "Google/Chrome/Cache increased" not in rec.historical_context.context_summary


def test_developer_subtype_history_does_not_imply_path_level_change(sample_trend_report):
    """
    SEMANTIC ACCURACY INVARIANT:
    Developer-subtype evidence must explicitly identify itself as developer context
    and must not claim that the specific project path grew.
    """
    from app.models.historical_recommendation import HistoricalContextLevel

    engine = RecommendationEngine()
    cand = StorageCandidate(
        path="/Users/mac/projects/my_project/node_modules",
        size_bytes=3_500_000_000,
        category=StorageCategory.DEVELOPMENT,
        risk_level=RiskLevel.MEDIUM,
        confidence=0.9,
        reason="Project node_modules",
        recommendation="Review dependencies",
    )
    rec = engine.recommend(cand, trend_report=sample_trend_report)

    assert rec.historical_context is not None
    assert rec.historical_context.context_type == HistoricalContextLevel.DEVELOPER_SUBTYPE
    assert rec.historical_context.context_summary.startswith("Historical developer context:")
    assert "Historical developer context: Node Modules storage increased by" in rec.historical_context.context_summary
    assert "my_project/node_modules increased" not in rec.historical_context.context_summary


def test_historical_context_level_and_informational_immutability(sample_trend_report):
    """Verify that historical context type enum and fields remain strictly informational and immutable."""
    from app.models.historical_recommendation import HistoricalContextLevel

    engine = RecommendationEngine()
    cand = StorageCandidate(
        path="/Users/mac/Library/Logs/system.log",
        size_bytes=50_000_000,
        category=StorageCategory.LOGS,
        risk_level=RiskLevel.LOW,
        confidence=0.9,
        reason="System log",
        recommendation="Review",
    )
    rec = engine.recommend(cand, trend_report=sample_trend_report)

    assert rec.historical_context is not None
    assert rec.historical_context.context_type == HistoricalContextLevel.CATEGORY
    assert rec.historical_context.context_summary.startswith("Historical category context: Logs")
    # Verify immutability
    with pytest.raises(Exception):
        rec.historical_context.context_type = HistoricalContextLevel.PATH


def test_historical_context_preserves_risk_and_eligibility_invariants(sample_trend_report):
    """
    SAFETY INVARIANT:
    Historical context cannot elevate risk, lower risk, or alter review eligibility.
    """
    engine = RecommendationEngine()

    # High-risk candidate remains blocked
    high_risk_cand = StorageCandidate(
        path="/System/Library/Caches/com.apple.kernelcaches",
        size_bytes=10_000_000_000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.HIGH,
        confidence=0.99,
        reason="Kernel cache",
        recommendation="Do not delete",
    )
    rec_high = engine.recommend(high_risk_cand, trend_report=sample_trend_report)
    assert rec_high.safety_status != SafetyStatus.ELIGIBLE_FOR_REVIEW.value
    assert rec_high.action == RecommendationAction.MANUAL_REVIEW

    # Low-risk candidate remains eligible
    low_risk_cand = StorageCandidate(
        path="/Users/mac/Library/Caches/com.app.cache",
        size_bytes=500_000_000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.95,
        reason="App cache",
        recommendation="Review cache",
    )
    rec_low = engine.recommend(low_risk_cand, trend_report=sample_trend_report)
    assert rec_low.safety_status == SafetyStatus.ELIGIBLE_FOR_REVIEW.value
    assert rec_low.action == RecommendationAction.REVIEW_FOR_CLEANUP


def test_historical_records_still_cannot_create_candidates(sample_trend_report):
    """
    SAFETY INVARIANT:
    Passing an empty candidate list returns zero recommendations,
    regardless of how many growing categories/subtypes exist in trend_report.
    """
    engine = RecommendationEngine()
    recs = engine.recommend_many([], trend_report=sample_trend_report)
    assert recs == []




