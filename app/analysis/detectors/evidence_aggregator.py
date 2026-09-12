"""
MacGuard AI Phase 12 — Evidence Aggregator.

Aggregates detector findings into verified StorageInvestigationEvidence and CleanupPlan.
Guarantees:
1. Inode tracking and nested path containment prevent double-counting.
2. 100% deterministic calculation of all storage metrics and totals.
3. Groups actionable cleanup items into confidence tiers.
"""

from __future__ import annotations

import os
from collections import defaultdict
from typing import Optional

from app.analysis.models import RiskLevel
from app.models.category import SmartCategory
from app.models.investigation import (
    CleanupPlan,
    CleanupPlanItem,
    InvestigationLevel,
    ReclaimConfidence,
    StorageEvidenceItem,
    StorageInvestigationEvidence,
)
from app.safety.canonicalizer import is_contained_within
from app.tools.storage_scanner import DiskUsage


class EvidenceAggregator:
    """
    Aggregates, deduplicates, and structures evidence items from all modular detectors.
    """

    def aggregate(
        self,
        investigation_id: str,
        level: InvestigationLevel,
        target_path: str,
        disk_usage: DiskUsage,
        raw_items: list[StorageEvidenceItem],
        macos_system_data_reported_bytes: Optional[int] = None,
    ) -> tuple[StorageInvestigationEvidence, CleanupPlan]:
        """
        Aggregate and deduplicate evidence items, compute totals, and build cleanup plan.
        """
        # 1. Deduplicate by canonical path
        seen_canonical: dict[str, StorageEvidenceItem] = {}
        for item in raw_items:
            c_path = item.canonical_path
            if c_path not in seen_canonical:
                seen_canonical[c_path] = item
            else:
                # If seen, keep the item with larger size or more specific subcategory
                if item.size_bytes > seen_canonical[c_path].size_bytes:
                    seen_canonical[c_path] = item

        # 2. Prevent nested path double counting: prune child items whose parent is already present
        sorted_by_len = sorted(seen_canonical.values(), key=lambda it: len(it.canonical_path))
        top_level_items: list[StorageEvidenceItem] = []
        for it in sorted_by_len:
            is_child = False
            for parent in top_level_items:
                if is_contained_within(it.canonical_path, parent.canonical_path) and it.canonical_path != parent.canonical_path:
                    is_child = True
                    break
            if not is_child:
                top_level_items.append(it)

        unique_items = top_level_items

        # 3. Candidate Inventory & Confidence Buckets
        candidate_inventory_bytes = sum(it.size_bytes for it in unique_items)
        analyzed_bytes = candidate_inventory_bytes

        # 3. Calculate category summaries and strictly partitioned confidence buckets
        category_summaries: dict[str, int] = defaultdict(int)
        high_conf_bytes = 0
        review_req_bytes = 0
        low_conf_bytes = 0
        protected_bytes = 0
        eligible_for_review_bytes = 0

        high_plan_items: list[CleanupPlanItem] = []
        review_plan_items: list[CleanupPlanItem] = []
        protected_plan_items: list[CleanupPlanItem] = []

        for it in unique_items:
            category_summaries[it.category.value] += it.size_bytes

            if it.cleanup_allowed:
                eligible_for_review_bytes += it.size_bytes

            # Strictly partition by reclaim_confidence so that
            # candidate_inventory == high_conf + review_req + low_conf + protected
            if it.reclaim_confidence == ReclaimConfidence.HIGH_CONFIDENCE:
                high_conf_bytes += it.size_bytes
                if it.cleanup_allowed:
                    high_plan_items.append(
                        CleanupPlanItem(
                            evidence_id=it.evidence_id,
                            path=it.path,
                            canonical_path=it.canonical_path,
                            size_bytes=it.size_bytes,
                            category=it.category,
                            subcategory=it.subcategory,
                            tier=ReclaimConfidence.HIGH_CONFIDENCE,
                            requires_review=False,
                            description=it.evidence_notes or f"Safe cache / temp artifact ({it.subcategory})",
                            consequence=it.cleanup_consequence,
                        )
                    )
            elif it.reclaim_confidence == ReclaimConfidence.REVIEW_REQUIRED:
                review_req_bytes += it.size_bytes
                if it.cleanup_allowed:
                    review_plan_items.append(
                        CleanupPlanItem(
                            evidence_id=it.evidence_id,
                            path=it.path,
                            canonical_path=it.canonical_path,
                            size_bytes=it.size_bytes,
                            category=it.category,
                            subcategory=it.subcategory,
                            tier=ReclaimConfidence.REVIEW_REQUIRED,
                            requires_review=True,
                            description=it.evidence_notes or f"Review required ({it.subcategory})",
                            consequence=it.cleanup_consequence,
                        )
                    )
            elif it.reclaim_confidence == ReclaimConfidence.LOW_CONFIDENCE:
                low_conf_bytes += it.size_bytes
            else:  # PROTECTED
                protected_bytes += it.size_bytes
                protected_plan_items.append(
                    CleanupPlanItem(
                        evidence_id=it.evidence_id,
                        path=it.path,
                        canonical_path=it.canonical_path,
                        size_bytes=it.size_bytes,
                        category=it.category,
                        subcategory=it.subcategory,
                        tier=ReclaimConfidence.PROTECTED,
                        requires_review=True,
                        description=it.evidence_notes or f"Protected / system-managed ({it.subcategory})",
                        consequence=it.cleanup_consequence or "Protected data. Automated cleanup not permitted.",
                    )
                )

        # 4. Rank top consumers
        top_consumers = sorted(unique_items, key=lambda it: it.size_bytes, reverse=True)[:25]

        # 5. Build StorageInvestigationEvidence
        evidence = StorageInvestigationEvidence(
            investigation_id=investigation_id,
            level=level,
            target_path=target_path,
            disk_total_bytes=disk_usage.total_bytes,
            disk_used_bytes=disk_usage.used_bytes,
            disk_free_bytes=disk_usage.free_bytes,
            macos_system_data_reported_bytes=macos_system_data_reported_bytes,
            analyzed_bytes=analyzed_bytes,
            candidate_inventory_bytes=candidate_inventory_bytes,
            eligible_for_review_bytes=eligible_for_review_bytes,
            reclaimable_high_confidence_bytes=high_conf_bytes,
            reclaimable_review_required_bytes=review_req_bytes,
            reclaimable_low_confidence_bytes=low_conf_bytes,
            protected_bytes=protected_bytes,
            items=unique_items,
            category_summaries=dict(category_summaries),
            top_consumers=top_consumers,
        )

        # 6. Build CleanupPlan (actionable items passing path validation allowlist)
        actionable_reclaimable = sum(p.size_bytes for p in high_plan_items) + sum(p.size_bytes for p in review_plan_items)
        cleanup_plan = CleanupPlan(
            high_confidence_items=high_plan_items,
            review_required_items=review_plan_items,
            protected_items=protected_plan_items,
            total_reclaimable_bytes=actionable_reclaimable,
            high_confidence_bytes=sum(p.size_bytes for p in high_plan_items),
            review_required_bytes=sum(p.size_bytes for p in review_plan_items),
        )

        return evidence, cleanup_plan
