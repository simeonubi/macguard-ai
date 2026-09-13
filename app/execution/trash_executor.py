from __future__ import annotations

import os
import secrets
import shutil
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from app.analysis.models import RiskLevel
from app.audit.models import AuditEvent, AuditEventType
from app.audit.repository import AuditRepository
from app.execution.integrity import (
    PathIntegritySnapshot,
    capture_integrity_snapshot,
    verify_post_execution_integrity,
    verify_pre_execution_integrity,
)
from app.execution.models import ExecutionAction, ExecutionPlan, ExecutionStatus, TrashExecutionResult
from app.safety.approval import ApprovalRecord, validate_approval
from app.safety.approval_service import ApprovalService
from app.safety.canonicalizer import canonicalize_path, is_contained_within
from app.safety.path_validator import Operation, PathValidator
from app.safety.review import ApprovalStatus
from app.tools.storage_scanner import StorageScanner, format_bytes


class TrashExecutor:
    """
    Controlled macOS Trash Execution Engine for Phase 6C.

    Core Safety Guarantees:
    - Zero Permanent Deletion: NEVER calls os.remove, os.unlink, Path.unlink, Path.rmdir,
      shutil.rmtree, or any subprocess/shell deletion command.
    - Controlled Trash Destination: Items are moved ONLY to ~/.Trash (or an isolated sandbox Trash root in tests).
      Destination paths are computed internally and never accepted from LLM or external input.
    - Atomic Execution Claim: Claims approval token atomically before mutation to prevent concurrent double-execution.
    - Pre-Execution Integrity Snapshot: Captures physical metadata & SHA-256 hash before mutation.
    - Immediate Pre-Mutation Revalidation: Re-verifies HMAC, risk, canonical paths, PathValidator rules,
      and uses os.lstat() to reject unexpected symlinks and modified objects right before executing the move.
    - Collision Avoidance: Uses isolated unique subfolder structures in Trash and never overwrites existing items.
    - Post-Move Verification: Verifies source absence, destination presence in Trash, and metadata/hash match.
    - Persistent SQLite Audit: Records all lifecycle events and execution correlation without secrets.
    - Fail-Closed Behavior: If any check or move fails, source remains untouched and approval transitions to FAILED.
    """

    def __init__(
        self,
        approval_service: Optional[ApprovalService] = None,
        path_validator: Optional[PathValidator] = None,
        scanner: Optional[StorageScanner] = None,
        audit_repo: Optional[AuditRepository] = None,
        trash_root: Optional[Union[str, Path]] = None,
    ) -> None:
        self._approval_service = approval_service or ApprovalService()
        self._validator = path_validator or PathValidator()
        self._scanner = scanner or StorageScanner()
        self._audit_repo = audit_repo
        self._default_trash_root = Path(trash_root) if trash_root is not None else Path.home() / ".Trash"

    def _record_audit(
        self,
        event_type: AuditEventType,
        approval_id: str,
        execution_id: str,
        canonical_path: str,
        status: str,
        risk_level: RiskLevel = RiskLevel.LOW,
        reason: str = "",
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        """Safely record an audit event if repository is configured."""
        if self._audit_repo is None:
            return
        try:
            event = AuditEvent(
                event_type=event_type,
                approval_id=approval_id,
                execution_id=execution_id,
                canonical_path=canonical_path,
                operation=Operation.CLEAN,
                risk_level=risk_level,
                status=status,
                actor="trash_executor",
                reason=reason,
                metadata=metadata or {},
            )
            self._audit_repo.record_event(event)
        except Exception:
            # Audit logging failures must not leak secrets or crash safety path
            pass

    def execute_trash(
        self,
        plan: ExecutionPlan,
        custom_trash_root: Optional[Union[str, Path]] = None,
    ) -> TrashExecutionResult:
        """
        Execute an approved, verified move to macOS Trash with integrity and audit guarantees.

        Parameters:
            plan: The verified ExecutionPlan with action=ExecutionAction.TRASH.
            custom_trash_root: Optional custom trash root path for isolated sandbox testing.

        Returns:
            TrashExecutionResult with execution details and verified status.
        """
        now = datetime.now(timezone.utc)
        execution_id = secrets.token_hex(8)

        # 1. Validate Plan Action and Status
        if plan.action != ExecutionAction.TRASH:
            return TrashExecutionResult(
                execution_id=execution_id,
                plan_id=plan.plan_id,
                approval_id=plan.approval_id,
                source_path=plan.path,
                canonical_source_path=plan.canonical_path,
                action=plan.action,
                status=ExecutionStatus.FAILED,
                reclaimed_bytes=0,
                message=f"Trash execution failed: Action '{plan.action.value}' is not supported by TrashExecutor.",
                executed_at=now,
                verified=False,
                integrity_verified=False,
            )

        if plan.status != ExecutionStatus.PLANNED:
            return TrashExecutionResult(
                execution_id=execution_id,
                plan_id=plan.plan_id,
                approval_id=plan.approval_id,
                source_path=plan.path,
                canonical_source_path=plan.canonical_path,
                action=plan.action,
                status=ExecutionStatus.FAILED,
                reclaimed_bytes=0,
                message=f"Trash execution failed: Plan status is '{plan.status.value}', expected 'PLANNED'.",
                executed_at=now,
                verified=False,
                integrity_verified=False,
            )

        # 2. Atomic Execution Claim (Thread-safe check-and-set)
        claimed_record, claim_msg = self._approval_service.claim_for_execution(plan.approval_id, current_time=now)
        if claimed_record is None:
            self._record_audit(
                event_type=AuditEventType.EXECUTION_BLOCKED,
                approval_id=plan.approval_id,
                execution_id=execution_id,
                canonical_path=plan.canonical_path,
                status="BLOCKED",
                reason=f"Failed to claim approval: {claim_msg}",
            )
            return TrashExecutionResult(
                execution_id=execution_id,
                plan_id=plan.plan_id,
                approval_id=plan.approval_id,
                source_path=plan.path,
                canonical_source_path=plan.canonical_path,
                action=plan.action,
                status=ExecutionStatus.FAILED,
                reclaimed_bytes=0,
                message=f"Trash execution blocked: Failed to claim approval ({claim_msg}).",
                executed_at=now,
                verified=False,
                integrity_verified=False,
            )

        # Record Execution Start in Audit DB
        if self._audit_repo is not None:
            try:
                self._audit_repo.record_execution_start(
                    execution_id=execution_id,
                    approval_id=plan.approval_id,
                    canonical_path=claimed_record.path,
                    action="TRASH",
                    start_time=now,
                )
            except Exception:
                pass

        self._record_audit(
            event_type=AuditEventType.EXECUTION_CLAIMED,
            approval_id=plan.approval_id,
            execution_id=execution_id,
            canonical_path=claimed_record.path,
            status="CLAIMED",
            risk_level=claimed_record.risk_level,
            reason="Approval claimed successfully for execution.",
        )

        # 3. Immediate Pre-Mutation Revalidation: Risk Gating (Only LOW risk allowed)
        if claimed_record.risk_level in (RiskLevel.HIGH, RiskLevel.UNKNOWN, RiskLevel.MEDIUM):
            fail_reason = f"Trash execution blocked: Risk level '{claimed_record.risk_level.value}' is ineligible for cleanup execution."
            self._approval_service.complete_execution(plan.approval_id, success=False, reason=fail_reason)
            self._record_audit(
                event_type=AuditEventType.EXECUTION_BLOCKED,
                approval_id=plan.approval_id,
                execution_id=execution_id,
                canonical_path=claimed_record.path,
                status="BLOCKED",
                risk_level=claimed_record.risk_level,
                reason=fail_reason,
            )
            if self._audit_repo is not None:
                try:
                    self._audit_repo.record_execution_finish(
                        execution_id=execution_id,
                        status="BLOCKED",
                        reclaimed_bytes=0,
                        destination_path="",
                        verified=False,
                        message=fail_reason,
                    )
                except Exception:
                    pass
            return TrashExecutionResult(
                execution_id=execution_id,
                plan_id=plan.plan_id,
                approval_id=plan.approval_id,
                source_path=plan.path,
                canonical_source_path=plan.canonical_path,
                action=plan.action,
                status=ExecutionStatus.BLOCKED,
                reclaimed_bytes=0,
                message=fail_reason,
                executed_at=now,
                verified=False,
                integrity_verified=False,
            )

        # 4. Immediate Pre-Mutation Revalidation: Re-canonicalize Source Path
        try:
            canonical_source_info = canonicalize_path(claimed_record.path)
            canonical_source_str = canonical_source_info.path_str
            canonical_source_path = canonical_source_info.canonical_path
        except Exception as exc:
            fail_reason = f"Trash execution blocked: Source path canonicalization failed ({exc})."
            self._approval_service.complete_execution(plan.approval_id, success=False, reason=fail_reason)
            self._record_audit(
                event_type=AuditEventType.EXECUTION_BLOCKED,
                approval_id=plan.approval_id,
                execution_id=execution_id,
                canonical_path=claimed_record.path,
                status="BLOCKED",
                risk_level=claimed_record.risk_level,
                reason=fail_reason,
            )
            if self._audit_repo is not None:
                try:
                    self._audit_repo.record_execution_finish(
                        execution_id=execution_id,
                        status="BLOCKED",
                        reclaimed_bytes=0,
                        destination_path="",
                        verified=False,
                        message=fail_reason,
                    )
                except Exception:
                    pass
            return TrashExecutionResult(
                execution_id=execution_id,
                plan_id=plan.plan_id,
                approval_id=plan.approval_id,
                source_path=plan.path,
                canonical_source_path=plan.canonical_path,
                action=plan.action,
                status=ExecutionStatus.BLOCKED,
                reclaimed_bytes=0,
                message=fail_reason,
                executed_at=now,
                verified=False,
                integrity_verified=False,
            )

        # Canonical path must exactly match approved path and plan canonical path
        if canonical_source_str != claimed_record.path or canonical_source_str != plan.canonical_path:
            fail_reason = (
                f"Trash execution blocked: Canonical path mismatch (approved: '{claimed_record.path}', "
                f"plan: '{plan.canonical_path}', resolved: '{canonical_source_str}')."
            )
            self._approval_service.complete_execution(plan.approval_id, success=False, reason=fail_reason)
            self._record_audit(
                event_type=AuditEventType.EXECUTION_BLOCKED,
                approval_id=plan.approval_id,
                execution_id=execution_id,
                canonical_path=canonical_source_str,
                status="BLOCKED",
                risk_level=claimed_record.risk_level,
                reason=fail_reason,
            )
            if self._audit_repo is not None:
                try:
                    self._audit_repo.record_execution_finish(
                        execution_id=execution_id,
                        status="BLOCKED",
                        reclaimed_bytes=0,
                        destination_path="",
                        verified=False,
                        message=fail_reason,
                    )
                except Exception:
                    pass
            return TrashExecutionResult(
                execution_id=execution_id,
                plan_id=plan.plan_id,
                approval_id=plan.approval_id,
                source_path=plan.path,
                canonical_source_path=canonical_source_str,
                action=plan.action,
                status=ExecutionStatus.BLOCKED,
                reclaimed_bytes=0,
                message=fail_reason,
                executed_at=now,
                verified=False,
                integrity_verified=False,
            )

        # 5. Immediate Pre-Mutation Revalidation: Safety Engine Policy
        val_res = self._validator.validate_path(canonical_source_str, operation=Operation.CLEAN)
        if not val_res.allowed:
            fail_reason = f"Trash execution blocked by Safety Engine: {val_res.reason}"
            self._approval_service.complete_execution(plan.approval_id, success=False, reason=fail_reason)
            self._record_audit(
                event_type=AuditEventType.EXECUTION_BLOCKED,
                approval_id=plan.approval_id,
                execution_id=execution_id,
                canonical_path=canonical_source_str,
                status="BLOCKED",
                risk_level=claimed_record.risk_level,
                reason=fail_reason,
            )
            if self._audit_repo is not None:
                try:
                    self._audit_repo.record_execution_finish(
                        execution_id=execution_id,
                        status="BLOCKED",
                        reclaimed_bytes=0,
                        destination_path="",
                        verified=False,
                        message=fail_reason,
                    )
                except Exception:
                    pass
            return TrashExecutionResult(
                execution_id=execution_id,
                plan_id=plan.plan_id,
                approval_id=plan.approval_id,
                source_path=plan.path,
                canonical_source_path=canonical_source_str,
                action=plan.action,
                status=ExecutionStatus.BLOCKED,
                reclaimed_bytes=0,
                message=fail_reason,
                executed_at=now,
                verified=False,
                integrity_verified=False,
            )

        # 6. Immediate Pre-Mutation Revalidation: Allowlist Root Protection
        for root in self._validator.allowlist_roots:
            if canonical_source_path == root:
                fail_reason = f"Trash execution blocked: Source path '{canonical_source_str}' is an allowlist root itself."
                self._approval_service.complete_execution(plan.approval_id, success=False, reason=fail_reason)
                self._record_audit(
                    event_type=AuditEventType.EXECUTION_BLOCKED,
                    approval_id=plan.approval_id,
                    execution_id=execution_id,
                    canonical_path=canonical_source_str,
                    status="BLOCKED",
                    risk_level=claimed_record.risk_level,
                    reason=fail_reason,
                )
                if self._audit_repo is not None:
                    try:
                        self._audit_repo.record_execution_finish(
                            execution_id=execution_id,
                            status="BLOCKED",
                            reclaimed_bytes=0,
                            destination_path="",
                            verified=False,
                            message=fail_reason,
                        )
                    except Exception:
                        pass
                return TrashExecutionResult(
                    execution_id=execution_id,
                    plan_id=plan.plan_id,
                    approval_id=plan.approval_id,
                    source_path=plan.path,
                    canonical_source_path=canonical_source_str,
                    action=plan.action,
                    status=ExecutionStatus.BLOCKED,
                    reclaimed_bytes=0,
                    message=fail_reason,
                    executed_at=now,
                    verified=False,
                    integrity_verified=False,
                )

        # 7. Capture Pre-Execution Integrity Snapshot & Re-verify Target Metadata
        self._record_audit(
            event_type=AuditEventType.INTEGRITY_CHECK_STARTED,
            approval_id=plan.approval_id,
            execution_id=execution_id,
            canonical_path=canonical_source_str,
            status="IN_PROGRESS",
            risk_level=claimed_record.risk_level,
            reason="Starting pre-execution integrity snapshot and validation.",
        )

        try:
            source_lstat = os.lstat(canonical_source_str)
        except FileNotFoundError:
            fail_reason = f"Trash execution failed: Source path '{canonical_source_str}' does not exist on disk."
            self._approval_service.complete_execution(plan.approval_id, success=False, reason=fail_reason)
            self._record_audit(
                event_type=AuditEventType.INTEGRITY_CHECK_FAILED,
                approval_id=plan.approval_id,
                execution_id=execution_id,
                canonical_path=canonical_source_str,
                status="FAILED",
                risk_level=claimed_record.risk_level,
                reason=fail_reason,
            )
            if self._audit_repo is not None:
                try:
                    self._audit_repo.record_execution_finish(
                        execution_id=execution_id,
                        status="FAILED",
                        reclaimed_bytes=0,
                        destination_path="",
                        verified=False,
                        message=fail_reason,
                    )
                except Exception:
                    pass
            return TrashExecutionResult(
                execution_id=execution_id,
                plan_id=plan.plan_id,
                approval_id=plan.approval_id,
                source_path=plan.path,
                canonical_source_path=canonical_source_str,
                action=plan.action,
                status=ExecutionStatus.FAILED,
                reclaimed_bytes=0,
                message=fail_reason,
                executed_at=now,
                verified=False,
                integrity_verified=False,
            )
        except OSError as exc:
            fail_reason = f"Trash execution failed: Unable to inspect source path '{canonical_source_str}' ({exc})."
            self._approval_service.complete_execution(plan.approval_id, success=False, reason=fail_reason)
            self._record_audit(
                event_type=AuditEventType.INTEGRITY_CHECK_FAILED,
                approval_id=plan.approval_id,
                execution_id=execution_id,
                canonical_path=canonical_source_str,
                status="FAILED",
                risk_level=claimed_record.risk_level,
                reason=fail_reason,
            )
            if self._audit_repo is not None:
                try:
                    self._audit_repo.record_execution_finish(
                        execution_id=execution_id,
                        status="FAILED",
                        reclaimed_bytes=0,
                        destination_path="",
                        verified=False,
                        message=fail_reason,
                    )
                except Exception:
                    pass
            return TrashExecutionResult(
                execution_id=execution_id,
                plan_id=plan.plan_id,
                approval_id=plan.approval_id,
                source_path=plan.path,
                canonical_source_path=canonical_source_str,
                action=plan.action,
                status=ExecutionStatus.FAILED,
                reclaimed_bytes=0,
                message=fail_reason,
                executed_at=now,
                verified=False,
                integrity_verified=False,
            )

        # Symlink Safety: Fail closed on any symlink source to prevent retargeting attacks
        if stat.S_ISLNK(source_lstat.st_mode) or os.path.islink(canonical_source_str):
            fail_reason = f"Trash execution blocked: Source '{canonical_source_str}' is a symbolic link. Symlink cleanup is strictly blocked."
            self._approval_service.complete_execution(plan.approval_id, success=False, reason=fail_reason)
            self._record_audit(
                event_type=AuditEventType.INTEGRITY_CHECK_FAILED,
                approval_id=plan.approval_id,
                execution_id=execution_id,
                canonical_path=canonical_source_str,
                status="BLOCKED",
                risk_level=claimed_record.risk_level,
                reason=fail_reason,
            )
            if self._audit_repo is not None:
                try:
                    self._audit_repo.record_execution_finish(
                        execution_id=execution_id,
                        status="BLOCKED",
                        reclaimed_bytes=0,
                        destination_path="",
                        verified=False,
                        message=fail_reason,
                    )
                except Exception:
                    pass
            return TrashExecutionResult(
                execution_id=execution_id,
                plan_id=plan.plan_id,
                approval_id=plan.approval_id,
                source_path=plan.path,
                canonical_source_path=canonical_source_str,
                action=plan.action,
                status=ExecutionStatus.BLOCKED,
                reclaimed_bytes=0,
                message=fail_reason,
                executed_at=now,
                verified=False,
                integrity_verified=False,
            )

        # Ensure source is a regular file or directory
        is_regular_file = stat.S_ISREG(source_lstat.st_mode)
        is_directory = stat.S_ISDIR(source_lstat.st_mode)
        if not is_regular_file and not is_directory:
            fail_reason = f"Trash execution blocked: Source '{canonical_source_str}' is neither a regular file nor a directory."
            self._approval_service.complete_execution(plan.approval_id, success=False, reason=fail_reason)
            self._record_audit(
                event_type=AuditEventType.INTEGRITY_CHECK_FAILED,
                approval_id=plan.approval_id,
                execution_id=execution_id,
                canonical_path=canonical_source_str,
                status="BLOCKED",
                risk_level=claimed_record.risk_level,
                reason=fail_reason,
            )
            if self._audit_repo is not None:
                try:
                    self._audit_repo.record_execution_finish(
                        execution_id=execution_id,
                        status="BLOCKED",
                        reclaimed_bytes=0,
                        destination_path="",
                        verified=False,
                        message=fail_reason,
                    )
                except Exception:
                    pass
            return TrashExecutionResult(
                execution_id=execution_id,
                plan_id=plan.plan_id,
                approval_id=plan.approval_id,
                source_path=plan.path,
                canonical_source_path=canonical_source_str,
                action=plan.action,
                status=ExecutionStatus.BLOCKED,
                reclaimed_bytes=0,
                message=fail_reason,
                executed_at=now,
                verified=False,
                integrity_verified=False,
            )

        # Capture integrity snapshot
        snapshot = capture_integrity_snapshot(
            path=canonical_source_str,
            approval_id=plan.approval_id,
            compute_hash=True,
        )

        # Verify pre-execution integrity against snapshot
        integrity_ok, integrity_reason = verify_pre_execution_integrity(
            snapshot=snapshot,
            target_path=canonical_source_str,
            compute_hash=True,
        )
        if not integrity_ok:
            fail_reason = f"Trash execution blocked by integrity verification: {integrity_reason}"
            self._approval_service.complete_execution(plan.approval_id, success=False, reason=fail_reason)
            self._record_audit(
                event_type=AuditEventType.INTEGRITY_CHECK_FAILED,
                approval_id=plan.approval_id,
                execution_id=execution_id,
                canonical_path=canonical_source_str,
                status="BLOCKED",
                risk_level=claimed_record.risk_level,
                reason=fail_reason,
            )
            if self._audit_repo is not None:
                try:
                    self._audit_repo.record_execution_finish(
                        execution_id=execution_id,
                        status="BLOCKED",
                        reclaimed_bytes=0,
                        destination_path="",
                        verified=False,
                        message=fail_reason,
                    )
                except Exception:
                    pass
            return TrashExecutionResult(
                execution_id=execution_id,
                plan_id=plan.plan_id,
                approval_id=plan.approval_id,
                source_path=plan.path,
                canonical_source_path=canonical_source_str,
                action=plan.action,
                status=ExecutionStatus.BLOCKED,
                reclaimed_bytes=0,
                message=fail_reason,
                executed_at=now,
                verified=False,
                integrity_verified=False,
            )

        self._record_audit(
            event_type=AuditEventType.INTEGRITY_CHECK_SUCCEEDED,
            approval_id=plan.approval_id,
            execution_id=execution_id,
            canonical_path=canonical_source_str,
            status="SUCCEEDED",
            risk_level=claimed_record.risk_level,
            reason="Pre-execution integrity verification passed.",
            metadata={"item_type": snapshot.item_type, "size_bytes": snapshot.size_bytes},
        )

        # Measure size before move for reclaim accounting
        actual_reclaim_bytes = 0
        try:
            if is_regular_file:
                actual_reclaim_bytes = source_lstat.st_size
            elif is_directory:
                actual_reclaim_bytes = self._scanner.get_directory_size(canonical_source_str)
        except Exception:
            actual_reclaim_bytes = plan.estimated_reclaimable_bytes

        # 8. Compute and Validate Controlled Trash Destination
        raw_trash_root = custom_trash_root if custom_trash_root is not None else self._default_trash_root
        try:
            trash_root_path = Path(raw_trash_root).resolve()
            trash_root_path.mkdir(parents=True, exist_ok=True)
            canonical_trash_root_info = canonicalize_path(trash_root_path)
            canonical_trash_root = canonical_trash_root_info.canonical_path
        except Exception as exc:
            fail_reason = f"Trash execution failed: Unable to resolve Trash root ({exc})."
            self._approval_service.complete_execution(plan.approval_id, success=False, reason=fail_reason)
            self._record_audit(
                event_type=AuditEventType.EXECUTION_FAILED,
                approval_id=plan.approval_id,
                execution_id=execution_id,
                canonical_path=canonical_source_str,
                status="FAILED",
                risk_level=claimed_record.risk_level,
                reason=fail_reason,
            )
            if self._audit_repo is not None:
                try:
                    self._audit_repo.record_execution_finish(
                        execution_id=execution_id,
                        status="FAILED",
                        reclaimed_bytes=0,
                        destination_path="",
                        verified=False,
                        message=fail_reason,
                    )
                except Exception:
                    pass
            return TrashExecutionResult(
                execution_id=execution_id,
                plan_id=plan.plan_id,
                approval_id=plan.approval_id,
                source_path=plan.path,
                canonical_source_path=canonical_source_str,
                action=plan.action,
                status=ExecutionStatus.FAILED,
                reclaimed_bytes=0,
                message=fail_reason,
                executed_at=now,
                verified=False,
                integrity_verified=False,
            )

        # Generate collision-isolated internal destination
        source_name = canonical_source_path.name
        unique_token = secrets.token_hex(4)
        isolation_subdir_name = f"MacGuard_{plan.approval_id[:8]}_{unique_token}"
        isolation_dir = canonical_trash_root / isolation_subdir_name
        dest_path = isolation_dir / source_name

        # Destination Containment Validation: Confirm canonical destination is strictly inside canonical Trash root
        if not is_contained_within(dest_path, canonical_trash_root):
            fail_reason = f"Trash execution blocked: Destination '{dest_path}' escapes Trash root '{canonical_trash_root}'."
            self._approval_service.complete_execution(plan.approval_id, success=False, reason=fail_reason)
            self._record_audit(
                event_type=AuditEventType.EXECUTION_BLOCKED,
                approval_id=plan.approval_id,
                execution_id=execution_id,
                canonical_path=canonical_source_str,
                status="BLOCKED",
                risk_level=claimed_record.risk_level,
                reason=fail_reason,
            )
            if self._audit_repo is not None:
                try:
                    self._audit_repo.record_execution_finish(
                        execution_id=execution_id,
                        status="BLOCKED",
                        reclaimed_bytes=0,
                        destination_path="",
                        verified=False,
                        message=fail_reason,
                    )
                except Exception:
                    pass
            return TrashExecutionResult(
                execution_id=execution_id,
                plan_id=plan.plan_id,
                approval_id=plan.approval_id,
                source_path=plan.path,
                canonical_source_path=canonical_source_str,
                action=plan.action,
                status=ExecutionStatus.BLOCKED,
                reclaimed_bytes=0,
                message=fail_reason,
                executed_at=now,
                verified=False,
                integrity_verified=False,
            )

        # Collision Check: Never overwrite existing items in Trash
        if dest_path.exists() or isolation_dir.exists():
            fail_reason = f"Trash execution blocked: Destination '{dest_path}' already exists (collision protection)."
            self._approval_service.complete_execution(plan.approval_id, success=False, reason=fail_reason)
            self._record_audit(
                event_type=AuditEventType.EXECUTION_BLOCKED,
                approval_id=plan.approval_id,
                execution_id=execution_id,
                canonical_path=canonical_source_str,
                status="BLOCKED",
                risk_level=claimed_record.risk_level,
                reason=fail_reason,
            )
            if self._audit_repo is not None:
                try:
                    self._audit_repo.record_execution_finish(
                        execution_id=execution_id,
                        status="BLOCKED",
                        reclaimed_bytes=0,
                        destination_path="",
                        verified=False,
                        message=fail_reason,
                    )
                except Exception:
                    pass
            return TrashExecutionResult(
                execution_id=execution_id,
                plan_id=plan.plan_id,
                approval_id=plan.approval_id,
                source_path=plan.path,
                canonical_source_path=canonical_source_str,
                action=plan.action,
                status=ExecutionStatus.FAILED,
                reclaimed_bytes=0,
                message=fail_reason,
                executed_at=now,
                verified=False,
                integrity_verified=False,
            )

        # 9. Controlled Filesystem Move Operation (shutil.move)
        self._record_audit(
            event_type=AuditEventType.TRASH_MOVE_STARTED,
            approval_id=plan.approval_id,
            execution_id=execution_id,
            canonical_path=canonical_source_str,
            status="IN_PROGRESS",
            risk_level=claimed_record.risk_level,
            reason="Starting physical move to controlled Trash root.",
            metadata={"destination": str(dest_path)},
        )

        try:
            isolation_dir.mkdir(parents=True, exist_ok=False)
            shutil.move(str(canonical_source_path), str(dest_path))
        except Exception as exc:
            fail_reason = f"Trash execution failed during move operation: {exc}. Source remains intact."
            self._approval_service.complete_execution(plan.approval_id, success=False, reason=fail_reason)
            self._record_audit(
                event_type=AuditEventType.TRASH_MOVE_FAILED,
                approval_id=plan.approval_id,
                execution_id=execution_id,
                canonical_path=canonical_source_str,
                status="FAILED",
                risk_level=claimed_record.risk_level,
                reason=fail_reason,
            )
            if self._audit_repo is not None:
                try:
                    self._audit_repo.record_execution_finish(
                        execution_id=execution_id,
                        status="FAILED",
                        reclaimed_bytes=0,
                        destination_path="",
                        verified=False,
                        message=fail_reason,
                    )
                except Exception:
                    pass
            return TrashExecutionResult(
                execution_id=execution_id,
                plan_id=plan.plan_id,
                approval_id=plan.approval_id,
                source_path=plan.path,
                canonical_source_path=canonical_source_str,
                trash_destination_path="",
                action=plan.action,
                status=ExecutionStatus.FAILED,
                reclaimed_bytes=0,
                message=fail_reason,
                executed_at=now,
                verified=False,
                integrity_verified=False,
            )

        self._record_audit(
            event_type=AuditEventType.TRASH_MOVE_SUCCEEDED,
            approval_id=plan.approval_id,
            execution_id=execution_id,
            canonical_path=canonical_source_str,
            status="SUCCEEDED",
            risk_level=claimed_record.risk_level,
            reason="Physical move to controlled Trash root succeeded.",
            metadata={"destination": str(dest_path)},
        )

        # 10. Post-Move Verification & Integrity Verification
        self._record_audit(
            event_type=AuditEventType.TRASH_VERIFICATION_STARTED,
            approval_id=plan.approval_id,
            execution_id=execution_id,
            canonical_path=canonical_source_str,
            status="IN_PROGRESS",
            risk_level=claimed_record.risk_level,
            reason="Starting post-move verification.",
            metadata={"destination": str(dest_path)},
        )

        post_ok, post_reason = verify_post_execution_integrity(
            snapshot=snapshot,
            canonical_source_path=canonical_source_path,
            destination_path=dest_path,
            trash_root=canonical_trash_root,
        )

        if not post_ok:
            verification_fail_msg = f"Post-move verification failed: {post_reason}. No permanent deletion was attempted."
            self._approval_service.complete_execution(plan.approval_id, success=False, reason=verification_fail_msg)
            self._record_audit(
                event_type=AuditEventType.TRASH_VERIFICATION_FAILED,
                approval_id=plan.approval_id,
                execution_id=execution_id,
                canonical_path=canonical_source_str,
                status="FAILED",
                risk_level=claimed_record.risk_level,
                reason=verification_fail_msg,
            )
            if self._audit_repo is not None:
                try:
                    self._audit_repo.record_execution_finish(
                        execution_id=execution_id,
                        status="FAILED",
                        reclaimed_bytes=0,
                        destination_path=str(dest_path) if dest_path.exists() else "",
                        verified=False,
                        message=verification_fail_msg,
                    )
                except Exception:
                    pass
            return TrashExecutionResult(
                execution_id=execution_id,
                plan_id=plan.plan_id,
                approval_id=plan.approval_id,
                source_path=plan.path,
                canonical_source_path=canonical_source_str,
                trash_destination_path=str(dest_path) if dest_path.exists() else "",
                action=plan.action,
                status=ExecutionStatus.FAILED,
                reclaimed_bytes=0,
                message=verification_fail_msg,
                executed_at=now,
                verified=False,
                integrity_verified=False,
            )

        self._record_audit(
            event_type=AuditEventType.TRASH_VERIFICATION_SUCCEEDED,
            approval_id=plan.approval_id,
            execution_id=execution_id,
            canonical_path=canonical_source_str,
            status="SUCCEEDED",
            risk_level=claimed_record.risk_level,
            reason="Post-move verification and integrity checks confirmed.",
            metadata={"destination": str(dest_path)},
        )

        # 11. Success: Complete and Consume Approval
        success_msg = (
            f"Successfully moved '{canonical_source_str}' to macOS Trash at '{dest_path}'. "
            f"Moved to Trash: {format_bytes(actual_reclaim_bytes)} ({actual_reclaim_bytes:,} bytes). "
            "Active-path storage removed. Physical disk space will be reclaimed when Trash is emptied. "
            "Verified source absence, destination presence, and snapshot integrity. No permanent deletion occurred."
        )
        self._approval_service.complete_execution(plan.approval_id, success=True, reason=success_msg)

        self._record_audit(
            event_type=AuditEventType.APPROVAL_CONSUMED,
            approval_id=plan.approval_id,
            execution_id=execution_id,
            canonical_path=canonical_source_str,
            status="CONSUMED",
            risk_level=claimed_record.risk_level,
            reason="Approval token consumed.",
        )

        self._record_audit(
            event_type=AuditEventType.EXECUTION_SUCCEEDED,
            approval_id=plan.approval_id,
            execution_id=execution_id,
            canonical_path=canonical_source_str,
            status="SUCCEEDED",
            risk_level=claimed_record.risk_level,
            reason=success_msg,
            metadata={"reclaimed_bytes": actual_reclaim_bytes, "destination": str(dest_path)},
        )

        if self._audit_repo is not None:
            try:
                self._audit_repo.record_execution_finish(
                    execution_id=execution_id,
                    status="TRASH_SUCCEEDED",
                    reclaimed_bytes=actual_reclaim_bytes,
                    destination_path=str(dest_path),
                    verified=True,
                    message=success_msg,
                )
            except Exception:
                pass

        return TrashExecutionResult(
            execution_id=execution_id,
            plan_id=plan.plan_id,
            approval_id=plan.approval_id,
            source_path=plan.path,
            canonical_source_path=canonical_source_str,
            trash_destination_path=str(dest_path),
            action=ExecutionAction.TRASH,
            status=ExecutionStatus.TRASH_SUCCEEDED,
            reclaimed_bytes=actual_reclaim_bytes,
            message=success_msg,
            executed_at=now,
            verified=True,
            integrity_verified=True,
            safety_confirmation="CONTROLLED TRASH EXECUTION: Item was moved to macOS Trash. No permanent deletion occurred.",
        )
