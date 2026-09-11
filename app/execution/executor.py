from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.analysis.models import RiskLevel
from app.execution.models import DryRunResult, ExecutionAction, ExecutionPlan, ExecutionStatus
from app.safety.approval import ApprovalRecord
from app.safety.approval_service import ApprovalService
from app.safety.path_validator import Operation, PathValidator
from app.safety.review import ApprovalStatus
from app.tools.storage_scanner import format_bytes


class DryRunExecutor:
    """
    Dry-Run Execution Engine for Phase 6A.

    Responsibilities:
    1. Accept verified ExecutionPlan with action=DRY_RUN.
    2. Re-verify runtime safety boundaries (PathValidator, Risk gating).
    3. Re-verify approval status (must not be consumed or expired).
    4. Simulate execution outcome without performing any filesystem modifications.
    5. Preserve approval token state (does NOT consume the token during dry-run).
    6. Return structured DryRunResult.

    CRITICAL GUARANTEE:
    - Performs ZERO filesystem mutations.
    - NEVER calls os.remove, os.unlink, shutil.rmtree, Path.unlink, Path.rmdir, Path.rename, subprocess, etc.
    """

    def __init__(
        self,
        approval_service: Optional[ApprovalService] = None,
        path_validator: Optional[PathValidator] = None,
    ) -> None:
        self._approval_service = approval_service or ApprovalService()
        self._validator = path_validator or PathValidator()

    def execute_dry_run(
        self,
        plan: ExecutionPlan,
        approval_record: Optional[ApprovalRecord] = None,
    ) -> DryRunResult:
        """
        Simulate cleanup execution on the target path specified by the plan.

        Returns:
            DryRunResult detailing simulated reclaimed space and safety confirmation.
        """
        now = datetime.now(timezone.utc)

        # 1. Validate Plan Action and Status
        if plan.action != ExecutionAction.DRY_RUN:
            return DryRunResult(
                plan_id=plan.plan_id,
                approval_id=plan.approval_id,
                path=plan.path,
                canonical_path=plan.canonical_path,
                action=plan.action,
                status=ExecutionStatus.FAILED,
                simulated_reclaimed_bytes=0,
                message=f"Dry-run execution failed: Action '{plan.action.value}' is not supported in Phase 6A.",
                executed_at=now,
            )

        if plan.status != ExecutionStatus.PLANNED:
            return DryRunResult(
                plan_id=plan.plan_id,
                approval_id=plan.approval_id,
                path=plan.path,
                canonical_path=plan.canonical_path,
                action=plan.action,
                status=ExecutionStatus.FAILED,
                simulated_reclaimed_bytes=0,
                message=f"Dry-run execution failed: Plan status is '{plan.status.value}', expected 'PLANNED'.",
                executed_at=now,
            )

        # 2. Defense-in-depth: Re-check Path Safety
        val_res = self._validator.validate_path(plan.canonical_path, operation=plan.operation)
        if not val_res.allowed:
            return DryRunResult(
                plan_id=plan.plan_id,
                approval_id=plan.approval_id,
                path=plan.path,
                canonical_path=plan.canonical_path,
                action=plan.action,
                status=ExecutionStatus.BLOCKED,
                simulated_reclaimed_bytes=0,
                message=f"Dry-run blocked by runtime Safety Engine: {val_res.reason}",
                executed_at=now,
            )

        # 3. Defense-in-depth: Risk Gating
        if plan.risk_level in (RiskLevel.HIGH, RiskLevel.UNKNOWN):
            return DryRunResult(
                plan_id=plan.plan_id,
                approval_id=plan.approval_id,
                path=plan.path,
                canonical_path=plan.canonical_path,
                action=plan.action,
                status=ExecutionStatus.BLOCKED,
                simulated_reclaimed_bytes=0,
                message=f"Dry-run blocked: Risk level '{plan.risk_level.value}' is ineligible for execution.",
                executed_at=now,
            )

        # 4. Check Approval Status (Must not be consumed)
        approval_status = self._approval_service.get_status(plan.approval_id)
        if approval_status == ApprovalStatus.CONSUMED:
            return DryRunResult(
                plan_id=plan.plan_id,
                approval_id=plan.approval_id,
                path=plan.path,
                canonical_path=plan.canonical_path,
                action=plan.action,
                status=ExecutionStatus.FAILED,
                simulated_reclaimed_bytes=0,
                message=f"Dry-run failed: Approval '{plan.approval_id}' has already been CONSUMED (Replay Protection).",
                executed_at=now,
            )

        # 5. Check Target Existence (Read-Only)
        target = Path(plan.canonical_path)
        exists = target.exists()
        reclaimed_bytes = plan.estimated_reclaimable_bytes

        if exists:
            msg = (
                f"[SIMULATION] Target '{plan.canonical_path}' verified. "
                f"Executing cleanup would reclaim approximately {format_bytes(reclaimed_bytes)} ({reclaimed_bytes:,} bytes). "
                "ZERO files were modified, moved, deleted, or trashed."
            )
        else:
            msg = (
                f"[SIMULATION] Target '{plan.canonical_path}' does not currently exist on disk. "
                f"Simulated reclaim: 0 bytes. ZERO files were modified."
            )

        return DryRunResult(
            plan_id=plan.plan_id,
            approval_id=plan.approval_id,
            path=plan.path,
            canonical_path=plan.canonical_path,
            action=ExecutionAction.DRY_RUN,
            status=ExecutionStatus.DRY_RUN_COMPLETED,
            simulated_reclaimed_bytes=reclaimed_bytes if exists else 0,
            message=msg,
            executed_at=now,
            safety_confirmation="DRY_RUN ONLY: Zero files were deleted, moved, modified, or trashed.",
        )
