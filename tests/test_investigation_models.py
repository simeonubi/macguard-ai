"""
Unit tests for Phase 12 Storage Investigation & Evidence Models.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.analysis.models import RiskLevel
from app.models.category import SmartCategory
from app.models.investigation import (
    CleanupPlan,
    CleanupPlanItem,
    InvestigationLevel,
    LLMReasonedFinding,
    ReclaimConfidence,
    StorageEvidenceItem,
    StorageInvestigationEvidence,
    StorageInvestigationResult,
)


def test_storage_evidence_item_creation() -> None:
    item = StorageEvidenceItem(
        evidence_id="ev_cache_001",
        path="/Users/test/Library/Caches/com.apple.Safari",
        canonical_path="/Users/test/Library/Caches/com.apple.Safari",
        size_bytes=104857600,  # 100MB
        item_count=42,
        category=SmartCategory.CACHES,
        subcategory="browser_cache",
        source_app="Safari",
        risk_level=RiskLevel.LOW,
        reclaim_confidence=ReclaimConfidence.HIGH_CONFIDENCE,
        cleanup_allowed=True,
        currently_in_use=False,
        associated_processes=[],
        associated_application_running=False,
        recently_modified=True,
        reproducible_or_redownloadable=True,
        cleanup_consequence="Safari will recreate caches on launch.",
        evidence_notes="Safari browser cache.",
    )

    assert item.evidence_id == "ev_cache_001"
    assert item.size_human == "100.00 MB"
    assert item.reclaim_confidence == ReclaimConfidence.HIGH_CONFIDENCE
    assert item.cleanup_allowed is True
    assert item.currently_in_use is False
    assert item.associated_application_running is False


def test_storage_evidence_item_usage_signals_default_to_none() -> None:
    """Ensure runtime usage and dependency signals default to None (UNKNOWN) and are not falsely inferred."""
    item = StorageEvidenceItem(
        evidence_id="ev_unknown_001",
        path="/Users/test/.cache/misc",
        canonical_path="/Users/test/.cache/misc",
        size_bytes=52428800,
        category=SmartCategory.CACHES,
        risk_level=RiskLevel.LOW,
        reclaim_confidence=ReclaimConfidence.REVIEW_REQUIRED,
    )

    assert item.currently_in_use is None
    assert item.associated_application_running is None
    assert item.active_dependency_detected is None
    assert item.referenced_by_active_project is None
    assert item.mounted_or_active is None
    assert item.recently_modified is None
    assert item.reproducible_or_redownloadable is None
    assert item.dependency_evidence is None
    assert item.usage_evidence is None


def test_storage_investigation_evidence_metrics_calculation() -> None:
    item1 = StorageEvidenceItem(
        evidence_id="ev_001",
        path="/path/1",
        canonical_path="/path/1",
        size_bytes=1000,
        category=SmartCategory.CACHES,
        risk_level=RiskLevel.LOW,
        reclaim_confidence=ReclaimConfidence.HIGH_CONFIDENCE,
        cleanup_allowed=True,
    )
    item2 = StorageEvidenceItem(
        evidence_id="ev_002",
        path="/path/2",
        canonical_path="/path/2",
        size_bytes=2000,
        category=SmartCategory.DEVELOPER_DATA,
        risk_level=RiskLevel.LOW,
        reclaim_confidence=ReclaimConfidence.REVIEW_REQUIRED,
        cleanup_allowed=True,
    )

    evidence = StorageInvestigationEvidence(
        investigation_id="inv_test_001",
        level=InvestigationLevel.TARGETED,
        target_path="/Users/test",
        disk_total_bytes=500_000_000_000,
        disk_used_bytes=400_000_000_000,
        disk_free_bytes=100_000_000_000,
        analyzed_bytes=3000,
        candidate_inventory_bytes=3000,
        eligible_for_review_bytes=3000,
        reclaimable_high_confidence_bytes=1000,
        reclaimable_review_required_bytes=2000,
        protected_bytes=0,
        items=[item1, item2],
    )

    assert evidence.total_reclaimable_bytes == 3000
    assert evidence.disk_free_human is not None
    assert len(evidence.items) == 2


def test_cleanup_plan_models() -> None:
    item = CleanupPlanItem(
        evidence_id="ev_001",
        path="/path/cache",
        canonical_path="/path/cache",
        size_bytes=5000,
        category=SmartCategory.CACHES,
        subcategory="test_cache",
        tier=ReclaimConfidence.HIGH_CONFIDENCE,
        requires_review=False,
    )

    plan = CleanupPlan(
        high_confidence_items=[item],
        total_reclaimable_bytes=5000,
        high_confidence_bytes=5000,
    )

    assert plan.total_reclaimable_bytes == 5000
    assert len(plan.high_confidence_items) == 1
    assert plan.high_confidence_items[0].size_human == "4.88 KB"
