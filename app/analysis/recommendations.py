from __future__ import annotations

from enum import Enum
from typing import Optional, Sequence

from pydantic import BaseModel, ConfigDict, Field

from app.analysis.models import RiskLevel, StorageCandidate, StorageCategory
from app.models.duplicate import DuplicateCluster
from app.models.duplicate_recommendation import DuplicateRecommendationContext
from app.models.historical_recommendation import (
    HistoricalContextLevel,
    HistoricalRecommendationContext,
)
from app.models.scan_result import ScanStatus
from app.models.storage_history import StorageTrendReport, TrendDirection
from app.tools.storage_scanner import format_bytes, format_bytes_decimal

DEFAULT_MIN_CLEANUP_SIZE_BYTES: int = 0


class RecommendationAction(str, Enum):
    """
    Action suggested by the RecommendationEngine.

    Note: These actions are purely advisory. They do NOT represent permission
    or authorization to delete, modify, or clean files.
    """

    REVIEW_FOR_CLEANUP = "review_for_cleanup"
    MANUAL_REVIEW = "manual_review"
    IGNORE = "ignore"
    NO_ACTION = "no_action"


class SafetyStatus(str, Enum):
    """Structured safety status indicator for a recommendation."""

    ELIGIBLE_FOR_REVIEW = "eligible_for_review"
    MANUAL_REVIEW_REQUIRED = "manual_review_required"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


class StorageRecommendation(BaseModel):
    """
    Structured, immutable storage recommendation derived from a StorageCandidate.

    This model is strictly advisory and read-only.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    candidate: StorageCandidate = Field(
        ...,
        description="The analyzed storage candidate.",
    )
    action: RecommendationAction = Field(
        ...,
        description="Advisory recommendation action.",
    )
    rationale: str = Field(
        ...,
        min_length=1,
        description="Clear, explainable reason for the recommendation.",
    )
    requires_approval: bool = Field(
        default=True,
        description="Whether explicit human approval is mandatory prior to any future action.",
    )
    safety_status: str = Field(
        ...,
        min_length=1,
        description="Structured safety status (e.g., eligible_for_review, manual_review_required).",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score between 0.0 and 1.0.",
    )
    historical_context: Optional[HistoricalRecommendationContext] = Field(
        default=None,
        description="Optional deterministic historical context derived from storage trends.",
    )
    duplicate_context: Optional[DuplicateRecommendationContext] = Field(
        default=None,
        description="Optional deterministic duplicate evidence derived from duplicate clusters.",
    )


class RecommendationEngine:
    """
    Deterministic Recommendation Engine.

    Transforms StorageCandidate objects into explainable StorageRecommendation
    structures without performing any filesystem operations or granting authorization.

    Candidate Quality Rules:
    - Zero-byte items (size_bytes <= 0) do not yield reclaimable space and are excluded
      from automated cleanup review.
    - Negligible-size items (size_bytes < min_cleanup_size_bytes) are excluded from cleanup review.
    - High-risk and Unknown items are strictly blocked from cleanup recommendations.
    - Historical trends provide explainable context and investigation prioritization,
      but NEVER override safety constraints, allowlists, risk ratings, or human review.
    """

    def __init__(self, min_cleanup_size_bytes: int = DEFAULT_MIN_CLEANUP_SIZE_BYTES) -> None:
        """
        Initialize RecommendationEngine with configurable minimum candidate size threshold.

        Args:
            min_cleanup_size_bytes: Minimum item size in bytes required for cleanup review eligibility.
                                    Items below this threshold or zero-byte items are excluded
                                    from cleanup review (default: 1024 bytes / 1 KB).
        """
        if min_cleanup_size_bytes < 0:
            raise ValueError("min_cleanup_size_bytes cannot be negative.")
        self.min_cleanup_size_bytes = min_cleanup_size_bytes

    def _derive_historical_context(
        self,
        candidate: StorageCandidate,
        trend_report: Optional[StorageTrendReport],
    ) -> Optional[HistoricalRecommendationContext]:
        """
        Derive deterministic historical intelligence context for a current candidate.

        Guarantees:
        - Purely observational; does NOT change risk level, action, or eligibility.
        - Fails closed to None if trend report is missing, incomparable, or incompatible.
        - Incomplete scans are explicitly marked and receive zero priority boost.
        """
        if trend_report is None or not trend_report.is_comparable:
            return None

        # Check if the report or snapshots are incomplete
        is_incomplete = any("incomplete" in note.lower() for note in trend_report.notes)
        if hasattr(trend_report, "current_snapshot_status"):
            if getattr(trend_report, "current_snapshot_status") != ScanStatus.COMPLETED:
                is_incomplete = True

        # Match category trend or specific developer trend
        matching_cat_trend = None
        matching_dev_trend = None

        if candidate.category == StorageCategory.DEVELOPMENT and trend_report.developer_trends:
            cand_path_lower = candidate.path.lower()
            for dt in trend_report.developer_trends:
                subtype_key = dt.subtype.value.lower()
                if (
                    subtype_key in cand_path_lower
                    or (subtype_key == "node_modules" and "node_modules" in cand_path_lower)
                    or (subtype_key == "python_venv" and ("venv" in cand_path_lower or ".venv" in cand_path_lower or "virtualenv" in cand_path_lower))
                    or (subtype_key == "build_output" and ("build" in cand_path_lower or "dist" in cand_path_lower or "target" in cand_path_lower))
                ):
                    matching_dev_trend = dt
                    break

        for ct in trend_report.category_trends:
            if ct.category.to_legacy_storage_category() == candidate.category:
                matching_cat_trend = ct
                break

        if matching_dev_trend is not None:
            context_type = HistoricalContextLevel.DEVELOPER_SUBTYPE
            cat_title = f"Development ({matching_dev_trend.subtype.value.lower()})"
            prefix = f"Historical developer context: {matching_dev_trend.subtype.value.replace('_', ' ').title()}"
            abs_change = matching_dev_trend.absolute_change
            pct_change = matching_dev_trend.percentage_change
            direction = matching_dev_trend.direction
            prev_bytes = getattr(matching_dev_trend, "previous_bytes", None)
            curr_bytes = getattr(matching_dev_trend, "current_bytes", None)
        elif matching_cat_trend is not None:
            context_type = HistoricalContextLevel.CATEGORY
            cat_title = matching_cat_trend.category.value.replace("_", " ").title()
            prefix = f"Historical category context: {cat_title}"
            abs_change = matching_cat_trend.absolute_change
            pct_change = matching_cat_trend.percentage_change
            direction = matching_cat_trend.direction
            prev_bytes = getattr(matching_cat_trend, "previous_bytes", None)
            curr_bytes = getattr(matching_cat_trend, "current_bytes", None)
        else:
            return None

        if is_incomplete:
            summary = (
                f"{prefix} showed historical change of {format_bytes_decimal(abs_change)}, "
                "but the scan was incomplete. Treat trend as indicative only."
            )
            boost = False
            priority_label = "UNKNOWN"
            trend_class = "Undetermined (Partial Scan)"
            hist_status = "Partial Scan"
        elif direction == TrendDirection.GROWING:
            pct_str = f" (+{pct_change:.1f}%)" if pct_change is not None else ""
            summary = (
                f"{prefix} storage increased by {format_bytes_decimal(abs_change)}{pct_str} "
                "since the previous comparable scan."
            )
            boost = True
            priority_label = "ATTENTION"
            trend_class = "Growing"
            hist_status = "Growing"
        elif direction == TrendDirection.SHRINKING:
            pct_str = f" ({pct_change:.1f}%)" if pct_change is not None else ""
            summary = (
                f"{prefix} storage decreased by {format_bytes_decimal(abs(abs_change))}{pct_str} "
                "since the previous comparable scan."
            )
            boost = False
            priority_label = "LOW"
            trend_class = "Shrinking"
            hist_status = "Shrinking"
        elif direction == TrendDirection.STABLE:
            summary = f"{prefix} storage is broadly stable since the previous scan."
            boost = False
            priority_label = "NORMAL"
            trend_class = "Stable"
            hist_status = "Stable"
        else:
            summary = f"{prefix} storage trend is undetermined."
            boost = False
            priority_label = "UNKNOWN"
            trend_class = "Undetermined"
            hist_status = "Undetermined"

        scope_val = trend_report.scope_id.value if hasattr(trend_report.scope_id, "value") else str(trend_report.scope_id)

        return HistoricalRecommendationContext(
            trend_direction=direction,
            category_name=cat_title,
            context_type=context_type,
            absolute_change_bytes=abs_change,
            percentage_change=pct_change,
            comparison_available=True,
            is_incomplete_scan=is_incomplete,
            priority_boost=boost,
            context_summary=summary,
            source_scope=scope_val,
            source_snapshot_id=trend_report.current_snapshot_id,
            current_path=candidate.path,
            historical_status=hist_status,
            comparison_type="Previous Consecutive Scan" if trend_report.previous_snapshot_id else "Baseline Scan",
            previous_size_bytes=prev_bytes,
            current_size_bytes=curr_bytes or candidate.size_bytes,
            change_bytes=abs_change,
            change_percent=pct_change,
            trend_classification=trend_class,
            observation_count=2 if trend_report.is_comparable else 1,
            contextual_priority=priority_label,
            explanation=summary,
        )

    def _derive_duplicate_context(
        self,
        candidate: StorageCandidate,
        duplicate_clusters: Optional[Sequence[DuplicateCluster]],
    ) -> Optional[DuplicateRecommendationContext]:
        """
        Derive deterministic duplicate evidence context for a current candidate.

        Guarantees:
        - Purely observational; does NOT change risk level, action, or eligibility.
        - Fails closed to None if duplicate clusters are missing or no match found.
        - Accurately differentiates independent physical copies from APFS hardlinks.
        """
        if not duplicate_clusters:
            return None

        # Look for matching cluster containing candidate.path
        cand_path = candidate.path
        matching_cluster: Optional[DuplicateCluster] = None

        for cluster in duplicate_clusters:
            for f in cluster.files:
                if f.path == cand_path:
                    matching_cluster = cluster
                    break
            if matching_cluster is not None:
                break

        if matching_cluster is None:
            return None

        other_paths = [f.path for f in matching_cluster.files if f.path != cand_path]
        is_hardlink_only = (matching_cluster.wasted_bytes == 0)

        # Calculate distinct physical inode count from cluster files
        seen_inodes = set()
        distinct_inodes = 0
        for f in matching_cluster.files:
            if f.dev is not None and f.inode is not None:
                if (f.dev, f.inode) not in seen_inodes:
                    seen_inodes.add((f.dev, f.inode))
                    distinct_inodes += 1
            else:
                distinct_inodes += 1

        if distinct_inodes < 1:
            distinct_inodes = max(1, len(matching_cluster.files) - matching_cluster.hardlink_count)

        if is_hardlink_only:
            explanation = (
                f"Exact content match across {len(matching_cluster.files)} paths, but all share a single "
                "physical inode. No additional physical storage is reclaimable."
            )
        else:
            explanation = (
                f"Exact duplicate: {len(matching_cluster.files)} identical copies identified across "
                f"{distinct_inodes} independent physical storage locations "
                f"({format_bytes_decimal(matching_cluster.wasted_bytes)} potential reclaimable space)."
            )

        return DuplicateRecommendationContext(
            cluster_id=matching_cluster.cluster_id,
            file_size_bytes=matching_cluster.file_size_bytes,
            duplicate_file_count=len(matching_cluster.files),
            physical_inode_count=distinct_inodes,
            hardlink_count=matching_cluster.hardlink_count,
            wasted_bytes=matching_cluster.wasted_bytes,
            duplicate_paths=other_paths if other_paths else [cand_path],
            is_hardlink_only=is_hardlink_only,
            explanation=explanation,
        )

    def recommend(
        self,
        candidate: StorageCandidate,
        min_cleanup_size_bytes: Optional[int] = None,
        trend_report: Optional[StorageTrendReport] = None,
        duplicate_clusters: Optional[Sequence[DuplicateCluster]] = None,
    ) -> StorageRecommendation:
        """
        Generate a deterministic, safety-first recommendation for a StorageCandidate.
        """
        threshold = self.min_cleanup_size_bytes if min_cleanup_size_bytes is None else min_cleanup_size_bytes
        category = candidate.category
        risk_level = candidate.risk_level
        confidence = candidate.confidence
        size_bytes = candidate.size_bytes
        hist_ctx = self._derive_historical_context(candidate, trend_report)
        dup_ctx = self._derive_duplicate_context(candidate, duplicate_clusters)

        # Invariant: UNKNOWN category or UNKNOWN risk level -> NO_ACTION
        if category == StorageCategory.UNKNOWN or risk_level == RiskLevel.UNKNOWN:
            return StorageRecommendation(
                candidate=candidate,
                action=RecommendationAction.NO_ACTION,
                rationale="Unclassified or ambiguous storage item. MacGuard AI cannot determine a safe action; manual review required.",
                requires_approval=True,
                safety_status=SafetyStatus.UNKNOWN.value,
                confidence=confidence,
                historical_context=hist_ctx,
                duplicate_context=dup_ctx,
            )

        # Invariant: HIGH risk items must NEVER receive REVIEW_FOR_CLEANUP
        if risk_level == RiskLevel.HIGH:
            if category == StorageCategory.MEDIA:
                rationale = (
                    "Media files are personal user assets. Retain file unless explicitly "
                    "reviewed and confirmed disposable by the user."
                )
            elif category == StorageCategory.DOCUMENTS:
                rationale = (
                    "Documents are user-owned content. Retain file; manual user inspection "
                    "required before considering any action."
                )
            elif category == StorageCategory.APPLICATION_DATA:
                rationale = (
                    "Application data contains active application state, local databases, or "
                    "configurations. Manual user inspection required."
                )
            else:
                rationale = (
                    "High-risk storage item. Manual inspection required; automated cleanup "
                    "is not recommended."
                )

            return StorageRecommendation(
                candidate=candidate,
                action=RecommendationAction.MANUAL_REVIEW,
                rationale=rationale,
                requires_approval=True,
                safety_status=SafetyStatus.MANUAL_REVIEW_REQUIRED.value,
                confidence=confidence,
                historical_context=hist_ctx,
                duplicate_context=dup_ctx,
            )

        # Invariant: DEVELOPMENT / MEDIUM risk items -> MANUAL_REVIEW
        if category == StorageCategory.DEVELOPMENT or risk_level == RiskLevel.MEDIUM:
            return StorageRecommendation(
                candidate=candidate,
                action=RecommendationAction.MANUAL_REVIEW,
                rationale=(
                    "Development dependencies and build artifacts can be large but may be "
                    "required by active projects or tools. Manual review recommended before removal."
                ),
                requires_approval=True,
                safety_status=SafetyStatus.MANUAL_REVIEW_REQUIRED.value,
                confidence=confidence,
                historical_context=hist_ctx,
                duplicate_context=dup_ctx,
            )

        # Candidate Quality Invariant: Zero-byte items -> NO_ACTION (excluded from cleanup review)
        if size_bytes <= 0:
            return StorageRecommendation(
                candidate=candidate,
                action=RecommendationAction.NO_ACTION,
                rationale="Zero-byte item yields no reclaimable storage. Excluded from cleanup review.",
                requires_approval=True,
                safety_status=SafetyStatus.MANUAL_REVIEW_REQUIRED.value,
                confidence=confidence,
                historical_context=hist_ctx,
                duplicate_context=dup_ctx,
            )

        # Candidate Quality Invariant: Negligible-size items below configurable threshold -> NO_ACTION
        if threshold > 0 and size_bytes < threshold:
            return StorageRecommendation(
                candidate=candidate,
                action=RecommendationAction.NO_ACTION,
                rationale=(
                    f"Item size ({size_bytes} B) is below the minimum cleanup threshold ({threshold} B). "
                    "Excluded from cleanup review."
                ),
                requires_approval=True,
                safety_status=SafetyStatus.MANUAL_REVIEW_REQUIRED.value,
                confidence=confidence,
                historical_context=hist_ctx,
                duplicate_context=dup_ctx,
            )

        # Invariant: CACHE + LOW risk + adequate size -> REVIEW_FOR_CLEANUP
        if category == StorageCategory.CACHE and risk_level == RiskLevel.LOW:
            return StorageRecommendation(
                candidate=candidate,
                action=RecommendationAction.REVIEW_FOR_CLEANUP,
                rationale=(
                    "This item is classified as cache data and may be a candidate for cleanup, "
                    "but explicit human approval is required."
                ),
                requires_approval=True,
                safety_status=SafetyStatus.ELIGIBLE_FOR_REVIEW.value,
                confidence=confidence,
                historical_context=hist_ctx,
                duplicate_context=dup_ctx,
            )

        # Invariant: LOGS + LOW risk + adequate size -> REVIEW_FOR_CLEANUP
        if category == StorageCategory.LOGS and risk_level == RiskLevel.LOW:
            return StorageRecommendation(
                candidate=candidate,
                action=RecommendationAction.REVIEW_FOR_CLEANUP,
                rationale=(
                    "This item contains log data which can consume storage. Older logs may be "
                    "reviewed for cleanup if no longer needed for troubleshooting."
                ),
                requires_approval=True,
                safety_status=SafetyStatus.ELIGIBLE_FOR_REVIEW.value,
                confidence=confidence,
                historical_context=hist_ctx,
                duplicate_context=dup_ctx,
            )

        # Fallback conservative review
        return StorageRecommendation(
            candidate=candidate,
            action=RecommendationAction.MANUAL_REVIEW,
            rationale="Manual review recommended before considering any action.",
            requires_approval=True,
            safety_status=SafetyStatus.MANUAL_REVIEW_REQUIRED.value,
            confidence=confidence,
            historical_context=hist_ctx,
            duplicate_context=dup_ctx,
        )

    def recommend_many(
        self,
        candidates: Sequence[StorageCandidate],
        min_cleanup_size_bytes: Optional[int] = None,
        trend_report: Optional[StorageTrendReport] = None,
        duplicate_clusters: Optional[Sequence[DuplicateCluster]] = None,
    ) -> list[StorageRecommendation]:
        """
        Generate recommendations for a sequence of StorageCandidate objects.
        """
        return [
            self.recommend(
                candidate,
                min_cleanup_size_bytes=min_cleanup_size_bytes,
                trend_report=trend_report,
                duplicate_clusters=duplicate_clusters,
            )
            for candidate in candidates
        ]
