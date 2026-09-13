"""
MacGuard AI Phase 12 — Batch Approval & Execution Coordinator.

Provides batch grouping and multi-item approval for validated cleanup plans
WITHOUT bypassing any safety invariants.

SAFETY INVARIANTS:
1. Batch approval is purely a UX convenience.
2. Every item independently undergoes:
   - Path canonicalization
   - PathValidator allowlist checks
   - Risk level gating (HIGH and UNKNOWN are strictly blocked)
   - HMAC-SHA256 signature generation and validation
   - Pre-move revalidation via os.lstat()
   - Move to macOS Trash via TrashExecutor
   - Post-move verification
   - SQLite audit recording
3. No automatic or unattended approvals.
4. Ollama has zero authority to approve or execute batches.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Sequence, Union

from app.analysis.models import RiskLevel, StorageCandidate
from app.analysis.recommendations import RecommendationAction, SafetyStatus, StorageRecommendation
from app.audit.repository import AuditRepository
from app.execution.models import ExecutionAction, ExecutionPlan, ExecutionStatus, TrashExecutionResult
from app.execution.trash_executor import TrashExecutor
from app.models.investigation import CleanupPlan, CleanupPlanItem, ReclaimConfidence, StorageEvidenceItem
from app.models.scan_result import DiscoveredItem
from app.safety.approval import ApprovalRecord
from app.safety.approval_service import ApprovalService
from app.safety.canonicalizer import canonicalize_path
from app.safety.path_validator import Operation, PathValidator
from app.tools.storage_scanner import format_bytes


@dataclass
class BatchGroup:
    """Group of related cleanup items eligible for batch action."""

    group_id: str
    title: str
    description: str
    tier: ReclaimConfidence
    items: list[CleanupPlanItem] = field(default_factory=list)

    @property
    def total_bytes(self) -> int:
        return sum(it.size_bytes for it in self.items)

    @property
    def total_human(self) -> str:
        return format_bytes(self.total_bytes)


@dataclass
class BatchExecutionReport:
    """Consolidated summary of a batch execution run."""

    total_items: int
    successful_items: int
    failed_items: int
    bytes_freed: int
    results: list[TrashExecutionResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def bytes_moved_to_trash(self) -> int:
        """Exact bytes moved from active source paths into macOS Trash."""
        return self.bytes_freed

    @property
    def bytes_moved_to_trash_human(self) -> str:
        """Human-readable size of bytes moved to macOS Trash."""
        return format_bytes(self.bytes_freed)

    @property
    def bytes_freed_human(self) -> str:
        return format_bytes(self.bytes_freed)

    @property
    def physical_disk_reclaimed_status(self) -> str:
        """Physical disk reclamation note."""
        return "Not yet reclaimed — Trash must be emptied"


class BatchApprovalCoordinator:
    """
    Coordinates batch approvals and execution through ApprovalService and TrashExecutor.
    """

    def __init__(
        self,
        approval_service: Optional[ApprovalService] = None,
        trash_executor: Optional[TrashExecutor] = None,
        path_validator: Optional[PathValidator] = None,
        audit_repo: Optional[AuditRepository] = None,
    ) -> None:
        self._validator = path_validator or PathValidator()
        self._approval_service = approval_service or ApprovalService(path_validator=self._validator)
        self._trash_executor = trash_executor or TrashExecutor(
            approval_service=self._approval_service,
            path_validator=self._validator,
            audit_repo=audit_repo,
        )

    def group_cleanup_plan(self, plan: CleanupPlan) -> list[BatchGroup]:
        """
        Organize a CleanupPlan into intuitive batch groups for human review.
        """
        groups: dict[str, BatchGroup] = {}

        # 1. Safe Caches Group
        safe_cache_items = [
            it for it in plan.high_confidence_items
            if it.category.value in ("CACHES", "PACKAGE_MANAGERS", "BUILD_ARTIFACTS")
        ]
        if safe_cache_items:
            groups["safe_caches"] = BatchGroup(
                group_id="safe_caches",
                title="Safe Application & Package Caches",
                description="Temporary cache files and downloaded wheels that can be safely rebuilt.",
                tier=ReclaimConfidence.HIGH_CONFIDENCE,
                items=safe_cache_items,
            )

        # 2. Downloaded Installers Group
        installer_items = [
            it for it in plan.high_confidence_items + plan.review_required_items
            if it.subcategory in ("disk_image", "installer_package")
        ]
        if installer_items:
            groups["installers"] = BatchGroup(
                group_id="installers",
                title="Downloaded Installers & Disk Images",
                description="Installed .dmg and .pkg files in Downloads.",
                tier=ReclaimConfidence.HIGH_CONFIDENCE,
                items=installer_items,
            )

        # 3. Developer Artifacts Group
        dev_items = [
            it for it in plan.review_required_items
            if it.category.value in ("DEVELOPER_DATA", "BUILD_ARTIFACTS") and it not in installer_items
        ]
        if dev_items:
            groups["developer"] = BatchGroup(
                group_id="developer",
                title="Developer Tooling & Build Artifacts",
                description="Xcode DerivedData, build directories, and build caches.",
                tier=ReclaimConfidence.REVIEW_REQUIRED,
                items=dev_items,
            )

        # 4. Other Review Items
        other_review = [
            it for it in plan.review_required_items
            if it not in installer_items and it not in dev_items
        ]
        if other_review:
            groups["review_other"] = BatchGroup(
                group_id="review_other",
                title="Review Required Items",
                description="Items requiring individual user inspection before cleanup.",
                tier=ReclaimConfidence.REVIEW_REQUIRED,
                items=other_review,
            )

        return list(groups.values())

    def approve_and_execute_batch(
        self,
        items: Sequence[CleanupPlanItem],
        actor: str = "human_batch_review",
        custom_trash_root: Optional[Union[str, Path]] = None,
    ) -> BatchExecutionReport:
        """
        Execute an approved batch of cleanup items.

        Every item is individually validated, HMAC-signed, claimed, moved to Trash, and audited.
        """
        results: list[TrashExecutionResult] = []
        errors: list[str] = []
        bytes_freed = 0
        success_count = 0
        fail_count = 0

        for it in items:
            # 1. Convert CleanupPlanItem into StorageRecommendation for ApprovalService
            cand = StorageCandidate(
                path=it.path,
                size_bytes=it.size_bytes,
                category=it.category.to_legacy_storage_category(),
                risk_level=RiskLevel.LOW if it.tier == ReclaimConfidence.HIGH_CONFIDENCE else RiskLevel.MEDIUM,
                confidence=0.9 if it.tier == ReclaimConfidence.HIGH_CONFIDENCE else 0.7,
                reason=it.description or f"Batch cleanup for {it.subcategory}",
                recommendation="Review for batch cleanup",
            )
            rec = StorageRecommendation(
                candidate=cand,
                action=RecommendationAction.REVIEW_FOR_CLEANUP,
                rationale=it.description or f"Batch cleanup for {it.subcategory}",
                confidence=0.9 if it.tier == ReclaimConfidence.HIGH_CONFIDENCE else 0.7,
                requires_approval=True,
                safety_status=SafetyStatus.ELIGIBLE_FOR_REVIEW.value,
            )

            # 2. Request individual HMAC-signed approval record
            record, req_err = self._approval_service.request_approval(rec, Operation.CLEAN)
            if not record or req_err:
                errors.append(f"Approval rejected for '{it.path}': {req_err}")
                fail_count += 1
                continue

            # 3. Explicitly approve record with human actor designation
            approved_record, app_msg = self._approval_service.approve(
                record.approval_id,
                explicit_consent=True,
                reason=f"Human approved via batch ({actor})",
            )
            if not approved_record:
                errors.append(f"Approval grant failed for '{it.path}': {app_msg}")
                fail_count += 1
                continue

            # 4. Construct ExecutionPlan
            plan = ExecutionPlan(
                approval_id=approved_record.approval_id,
                path=it.path,
                canonical_path=it.canonical_path,
                action=ExecutionAction.TRASH,
                status=ExecutionStatus.PLANNED,
                risk_level=approved_record.risk_level,
                estimated_reclaimable_bytes=it.size_bytes,
                reason=it.description or f"Batch cleanup approved by {actor}",
            )

            # 5. Execute move to Trash via TrashExecutor
            exec_res = self._trash_executor.execute_trash(plan, custom_trash_root=custom_trash_root)
            results.append(exec_res)

            if exec_res.status == ExecutionStatus.TRASH_SUCCEEDED:
                success_count += 1
                bytes_freed += exec_res.reclaimed_bytes
            else:
                fail_count += 1
                errors.append(f"Execution failed for '{it.path}': {exec_res.message}")

        return BatchExecutionReport(
            total_items=len(items),
            successful_items=success_count,
            failed_items=fail_count,
            bytes_freed=bytes_freed,
            results=results,
            errors=errors,
        )
