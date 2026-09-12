"""
Unit tests for Phase 12 Evidence Aggregator.
"""

from __future__ import annotations

import pytest

from app.analysis.detectors.evidence_aggregator import EvidenceAggregator
from app.analysis.models import RiskLevel
from app.models.category import SmartCategory
from app.models.investigation import (
    InvestigationLevel,
    ReclaimConfidence,
    StorageEvidenceItem,
)
from app.tools.storage_scanner import DiskUsage


def test_evidence_aggregator_nested_path_double_counting_prevention() -> None:
    """
    Ensure child paths inside an already aggregated parent directory are not double-counted in analyzed_bytes.
    """
    aggregator = EvidenceAggregator()
    disk_usage = DiskUsage(path="/Users/test", total_bytes=500_000_000_000, used_bytes=300_000_000_000, free_bytes=200_000_000_000)

    parent_item = StorageEvidenceItem(
        evidence_id="ev_parent",
        path="/Users/test/Library/Caches/com.spotify.client",
        canonical_path="/Users/test/Library/Caches/com.spotify.client",
        size_bytes=500_000_000,  # 500 MB
        category=SmartCategory.CACHES,
        risk_level=RiskLevel.LOW,
        reclaim_confidence=ReclaimConfidence.HIGH_CONFIDENCE,
        cleanup_allowed=True,
    )

    child_item = StorageEvidenceItem(
        evidence_id="ev_child",
        path="/Users/test/Library/Caches/com.spotify.client/storage",
        canonical_path="/Users/test/Library/Caches/com.spotify.client/storage",
        size_bytes=400_000_000,  # 400 MB (nested inside parent)
        category=SmartCategory.CACHES,
        risk_level=RiskLevel.LOW,
        reclaim_confidence=ReclaimConfidence.HIGH_CONFIDENCE,
        cleanup_allowed=True,
    )

    evidence, plan = aggregator.aggregate(
        investigation_id="inv_test_nested",
        level=InvestigationLevel.TARGETED,
        target_path="/Users/test",
        disk_usage=disk_usage,
        raw_items=[parent_item, child_item],
    )

    # Analyzed bytes must reflect top-level unique items only (500 MB), not 500 MB + 400 MB
    assert evidence.analyzed_bytes == 500_000_000


def test_evidence_aggregator_reclaimability_breakdown() -> None:
    aggregator = EvidenceAggregator()
    disk_usage = DiskUsage(path="/Users/test", total_bytes=500_000_000_000, used_bytes=300_000_000_000, free_bytes=200_000_000_000)

    item_high = StorageEvidenceItem(
        evidence_id="ev_high",
        path="/Users/test/Library/Caches/pip",
        canonical_path="/Users/test/Library/Caches/pip",
        size_bytes=100_000_000,
        category=SmartCategory.PACKAGE_MANAGERS,
        risk_level=RiskLevel.LOW,
        reclaim_confidence=ReclaimConfidence.HIGH_CONFIDENCE,
        cleanup_allowed=True,
    )

    item_review = StorageEvidenceItem(
        evidence_id="ev_review",
        path="/Users/test/Library/Developer/Xcode/DerivedData",
        canonical_path="/Users/test/Library/Developer/Xcode/DerivedData",
        size_bytes=250_000_000,
        category=SmartCategory.DEVELOPER_DATA,
        risk_level=RiskLevel.LOW,
        reclaim_confidence=ReclaimConfidence.REVIEW_REQUIRED,
        cleanup_allowed=True,
    )

    item_protected = StorageEvidenceItem(
        evidence_id="ev_protected",
        path="/Users/test/Library/Containers/com.docker.docker",
        canonical_path="/Users/test/Library/Containers/com.docker.docker",
        size_bytes=500_000_000,
        category=SmartCategory.CONTAINERS,
        risk_level=RiskLevel.HIGH,
        reclaim_confidence=ReclaimConfidence.PROTECTED,
        cleanup_allowed=False,
    )

    evidence, plan = aggregator.aggregate(
        investigation_id="inv_test_breakdown",
        level=InvestigationLevel.TARGETED,
        target_path="/Users/test",
        disk_usage=disk_usage,
        raw_items=[item_high, item_review, item_protected],
    )

    assert evidence.reclaimable_high_confidence_bytes == 100_000_000
    assert evidence.reclaimable_review_required_bytes == 250_000_000
    assert evidence.protected_bytes == 500_000_000
    assert evidence.total_reclaimable_bytes == 350_000_000

    # Verify CleanupPlan items
    assert len(plan.high_confidence_items) == 1
    assert len(plan.review_required_items) == 1
    assert len(plan.protected_items) == 1
    assert plan.total_reclaimable_bytes == 350_000_000


def test_evidence_aggregator_accounting_reconciliation() -> None:
    """
    Ensure candidate_inventory_bytes == sum(all confidence buckets) and
    category_summaries sum == candidate_inventory_bytes exactly.
    """
    aggregator = EvidenceAggregator()
    disk_usage = DiskUsage(path="/Users/test", total_bytes=500_000_000_000, used_bytes=300_000_000_000, free_bytes=200_000_000_000)

    items = [
        StorageEvidenceItem(
            evidence_id="ev_1",
            path="/Users/test/Library/Caches/app1",
            canonical_path="/Users/test/Library/Caches/app1",
            size_bytes=100_000_000,
            category=SmartCategory.CACHES,
            risk_level=RiskLevel.LOW,
            reclaim_confidence=ReclaimConfidence.HIGH_CONFIDENCE,
            cleanup_allowed=True,
        ),
        StorageEvidenceItem(
            evidence_id="ev_2",
            path="/Users/test/anaconda3/pkgs",
            canonical_path="/Users/test/anaconda3/pkgs",
            size_bytes=200_000_000,
            category=SmartCategory.PACKAGE_MANAGERS,
            risk_level=RiskLevel.HIGH,
            reclaim_confidence=ReclaimConfidence.REVIEW_REQUIRED,
            cleanup_allowed=False,
        ),
        StorageEvidenceItem(
            evidence_id="ev_3",
            path="/Users/test/Library/Containers/Docker.raw",
            canonical_path="/Users/test/Library/Containers/Docker.raw",
            size_bytes=300_000_000,
            category=SmartCategory.CONTAINERS,
            risk_level=RiskLevel.HIGH,
            reclaim_confidence=ReclaimConfidence.PROTECTED,
            cleanup_allowed=False,
        ),
        StorageEvidenceItem(
            evidence_id="ev_4",
            path="/Users/test/Downloads/ambiguous",
            canonical_path="/Users/test/Downloads/ambiguous",
            size_bytes=50_000_000,
            category=SmartCategory.USER_DATA,
            risk_level=RiskLevel.UNKNOWN,
            reclaim_confidence=ReclaimConfidence.LOW_CONFIDENCE,
            cleanup_allowed=False,
        ),
    ]

    evidence, plan = aggregator.aggregate(
        investigation_id="inv_reconciliation",
        level=InvestigationLevel.TARGETED,
        target_path="/Users/test",
        disk_usage=disk_usage,
        raw_items=items,
    )

    # 1. Candidate Inventory must match sum of individual items
    assert evidence.candidate_inventory_bytes == 650_000_000

    # 2. Sum of all confidence tiers must EQUAL candidate_inventory_bytes exactly
    buckets_sum = (
        evidence.reclaimable_high_confidence_bytes
        + evidence.reclaimable_review_required_bytes
        + evidence.reclaimable_low_confidence_bytes
        + evidence.protected_bytes
    )
    assert buckets_sum == evidence.candidate_inventory_bytes

    # 3. Sum of category summaries must EQUAL candidate_inventory_bytes exactly
    category_sum = sum(evidence.category_summaries.values())
    assert category_sum == evidence.candidate_inventory_bytes
    assert evidence.analyzed_bytes == evidence.candidate_inventory_bytes
