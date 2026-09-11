from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from app.analysis.models import RiskLevel, StorageCategory
from app.analysis.recommendations import RecommendationAction, SafetyStatus
from app.execution.models import ExecutionAction, ExecutionPlan, ExecutionStatus
from app.safety.approval import ApprovalRecord
from app.safety.approval_service import ApprovalService
from app.safety.canonicalizer import canonicalize_path
from app.safety.path_validator import Operation, PathValidator
from app.safety.review import ApprovalStatus, ReviewItem
from app.tools.storage_scanner import StorageScanner


class ExecutionPlanner:
    """
    Deterministic Execution Planner for Phase 6A (DRY-RUN ONLY).

    Responsibilities:
    1. Ingest approved ReviewItem or ApprovalRecord.
    2. Re-canonicalize target path and verify against strict PathValidator rules.
    3. Re-verify cryptographic HMAC-SHA256 authorization and lifecycle status via ApprovalService.
    4. Enforce strict risk gating (HIGH and UNKNOWN risk items are permanently blocked).
    5. Ensure allowlist roots themselves are never targeted for execution.
    6. Generate an immutable, non-destructive ExecutionPlan with action=DRY_RUN.

    Safety Guarantee:
    - Performs ZERO filesystem mutations.
    """

    def __init__(
        self,
        approval_service: Optional[ApprovalService] = None,
        path_validator: Optional[PathValidator] = None,
        scanner: Optional[StorageScanner] = None,
    ) -> None:
        self._approval_service = approval_service or ApprovalService()
        self._validator = path_validator or PathValidator()
        self._scanner = scanner or StorageScanner()

    def create_plan(
        self,
        approval_record: Optional[ApprovalRecord] = None,
        review_item: Optional[ReviewItem] = None,
        operation: Operation = Operation.CLEAN,
        action: ExecutionAction = ExecutionAction.DRY_RUN,
    ) -> tuple[Optional[ExecutionPlan], str]:
        """
        Create a deterministic, verified ExecutionPlan for a dry-run simulation or controlled trash move.

        Returns:
            (ExecutionPlan, message)
        """
        now = datetime.now(timezone.utc)

        # 0. Validate requested action
        if action not in (ExecutionAction.DRY_RUN, ExecutionAction.TRASH):
            err = f"Planning blocked: Action '{action}' is not supported. Permanent deletion is strictly forbidden."
            return None, err

        # 1. Resolve ApprovalRecord
        record = approval_record
        if record is None and review_item is not None:
            # Attempt to find record in approval service if review_item was approved
            pass

        if record is None:
            err = "Planning blocked: No ApprovalRecord provided."
            return None, err

        # 2. Check in-memory lifecycle registry status & Replay Protection
        status = self._approval_service.get_status(record.approval_id)
        if status is None:
            # If not in registry, attempt to check basic approved flag
            if not record.approved:
                err = f"Planning blocked: Approval '{record.approval_id}' has not been approved."
                return self._make_blocked_plan(record, err, action), err
        elif status == ApprovalStatus.CONSUMED:
            err = f"Planning blocked: Approval '{record.approval_id}' has already been CONSUMED (Replay Protection)."
            return self._make_blocked_plan(record, err, action), err
        elif status == ApprovalStatus.EXECUTION_CLAIMED:
            err = f"Planning blocked: Approval '{record.approval_id}' is currently EXECUTION_CLAIMED."
            return self._make_blocked_plan(record, err, action), err
        elif status == ApprovalStatus.REJECTED:
            err = f"Planning blocked: Approval '{record.approval_id}' was REJECTED."
            return self._make_blocked_plan(record, err, action), err
        elif status == ApprovalStatus.EXPIRED:
            err = f"Planning blocked: Approval '{record.approval_id}' has EXPIRED."
            return self._make_blocked_plan(record, err, action), err
        elif status == ApprovalStatus.FAILED:
            err = f"Planning blocked: Approval '{record.approval_id}' previously FAILED."
            return self._make_blocked_plan(record, err, action), err
        elif status != ApprovalStatus.APPROVED:
            err = f"Planning blocked: Approval is in '{status.value}' state, expected 'approved'."
            return self._make_blocked_plan(record, err, action), err

        # 3. Check expiration timestamp
        if now > record.expires_at:
            err = f"Planning blocked: Approval expired at {record.expires_at.isoformat()}."
            return self._make_blocked_plan(record, err, action), err

        # 4. Check explicit approval state
        if not record.approved:
            err = "Planning blocked: ApprovalRecord indicates approved=False."
            return self._make_blocked_plan(record, err, action), err

        # 5. Risk Gate Invariants
        if record.risk_level in (RiskLevel.HIGH, RiskLevel.UNKNOWN):
            err = (
                f"Planning blocked: Risk level '{record.risk_level.value}' is ineligible for cleanup execution. "
                "MacGuard AI mandates manual user inspection."
            )
            return self._make_blocked_plan(record, err, action), err

        # 6. Re-canonicalize target path
        try:
            canonical_info = canonicalize_path(record.path)
            canonical_str = canonical_info.path_str
        except Exception as exc:
            err = f"Planning blocked: Path canonicalization failed ({exc})."
            return self._make_blocked_plan(record, err, action), err

        # Canonical path must match the approved record's path
        if canonical_str != record.path:
            err = f"Planning blocked: Canonical path mismatch (approved for '{record.path}', resolved to '{canonical_str}')."
            return self._make_blocked_plan(record, err, action), err

        # 7. Safety Engine Policy Revalidation (Defense in Depth)
        val_res = self._validator.validate_path(canonical_str, operation=operation)
        if not val_res.allowed:
            err = f"Planning blocked by Safety Engine: {val_res.reason}"
            return self._make_blocked_plan(record, err, action), err

        # 8. Allowlist Root Protection Check
        # The allowlist root itself (~/Library/Caches) must NOT be targeted for cleanup, only descendants.
        resolved_path = Path(canonical_str)
        for root in self._validator.allowlist_roots:
            if resolved_path == root:
                err = f"Planning blocked: Target path '{canonical_str}' is an allowlist root itself. Only sub-items can be targeted."
                return self._make_blocked_plan(record, err, action), err

        # 9. Cryptographic HMAC Verification
        is_valid, v_msg = self._approval_service.verify_and_authorize(
            approval_record=record,
            target_path=canonical_str,
            operation=operation,
            current_time=now,
        )
        if not is_valid:
            err = f"Planning blocked: Cryptographic authorization verification failed ({v_msg})."
            return self._make_blocked_plan(record, err, action), err

        # 10. Estimate Reclaimable Space (Read-Only)
        reclaimable_bytes = 0
        if resolved_path.exists():
            try:
                if resolved_path.is_file():
                    reclaimable_bytes = resolved_path.stat().st_size
                elif resolved_path.is_dir():
                    reclaimable_bytes = self._scanner.get_directory_size(canonical_str)
            except (OSError, PermissionError):
                reclaimable_bytes = 0

        plan = ExecutionPlan(
            approval_id=record.approval_id,
            path=record.path,
            canonical_path=canonical_str,
            operation=operation,
            risk_level=record.risk_level,
            action=action,
            status=ExecutionStatus.PLANNED,
            estimated_reclaimable_bytes=reclaimable_bytes,
            reason=f"Verified plan for {record.reason}. Action: {action.value}.",
            created_at=now,
        )

        return plan, f"Execution plan created successfully for {action.value} on '{canonical_str}'."

    def _make_blocked_plan(
        self,
        record: ApprovalRecord,
        reason: str,
        action: ExecutionAction = ExecutionAction.DRY_RUN,
    ) -> ExecutionPlan:
        """Helper to construct a deterministic BLOCKED ExecutionPlan."""
        return ExecutionPlan(
            approval_id=record.approval_id,
            path=record.path,
            canonical_path=record.path,
            operation=record.operation,
            risk_level=record.risk_level,
            action=action,
            status=ExecutionStatus.BLOCKED,
            estimated_reclaimable_bytes=0,
            reason=reason,
            created_at=datetime.now(timezone.utc),
        )
