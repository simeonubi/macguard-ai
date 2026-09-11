import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence, Union

from app.analysis.models import RiskLevel
from app.analysis.recommendations import RecommendationAction, SafetyStatus, StorageRecommendation
from app.safety.approval import (
    ApprovalKeyManager,
    ApprovalRecord,
    get_default_key_manager,
    grant_approval,
    request_approval as crypto_request_approval,
    validate_approval,
)
from app.safety.canonicalizer import canonicalize_path
from app.safety.path_validator import Operation, PathValidator
from app.safety.review import ApprovalAuditEvent, ApprovalDecision, ApprovalStatus, ReviewItem


class ApprovalService:
    """
    Coordinates human review, explicit approval workflows, cryptographic HMAC verification,
    audit event logging, atomic execution claiming, and replay protection.

    Safety Invariants:
    - Authoritative Safety Engine: The LLM/planner has ZERO authority over approvals.
    - Explicit Human Action: No implicit or automatic approvals are permitted. Default is rejection.
    - Risk Gating: HIGH and UNKNOWN risk items are blocked from approval.
    - Replay Protection: Consumed approval records cannot be re-authorized or re-consumed.
    - Atomic Claim: Thread-safe check-and-set prevents concurrent double-execution.
    - Cryptographic Integrity: Validates HMAC-SHA256 signatures with runtime ApprovalKeyManager.
    - Non-Destructive: Never modifies, deletes, moves, or renames filesystem objects.
    """

    def __init__(
        self,
        key_manager: Optional[ApprovalKeyManager] = None,
        path_validator: Optional[PathValidator] = None,
    ) -> None:
        self._key_manager = key_manager or get_default_key_manager()
        self._validator = path_validator or PathValidator()
        self._lock = threading.Lock()
        self._registry: dict[str, ApprovalRecord] = {}
        self._statuses: dict[str, ApprovalStatus] = {}
        self._decisions: dict[str, ApprovalDecision] = {}
        self._audit_log: list[ApprovalAuditEvent] = []

    def create_review_items(
        self,
        recommendations: Sequence[StorageRecommendation],
    ) -> list[ReviewItem]:
        """
        Convert deterministic StorageRecommendation objects into structured ReviewItems
        for human presentation and decision-making.
        """
        review_items: list[ReviewItem] = []
        for rec in recommendations:
            candidate = rec.candidate
            risk = candidate.risk_level
            safety_status = rec.safety_status

            is_eligible = (
                rec.action == RecommendationAction.REVIEW_FOR_CLEANUP
                and safety_status == SafetyStatus.ELIGIBLE_FOR_REVIEW.value
                and risk == RiskLevel.LOW
            )

            if is_eligible:
                msg = (
                    f"Eligible for human review. Classified as {candidate.category.value} with "
                    f"LOW risk. Human approval is required before any future cleanup can be authorized."
                )
            elif risk in (RiskLevel.HIGH, RiskLevel.UNKNOWN):
                msg = (
                    f"Blocked from automated review. Risk level is {risk.value}. "
                    f"MacGuard AI mandates manual user inspection; cleanup approval cannot be requested."
                )
            else:
                msg = (
                    f"Manual inspection required. Status: {safety_status}. "
                    f"Action: {rec.action.value}. Not eligible for automated cleanup approval."
                )

            review_items.append(
                ReviewItem(
                    candidate=candidate,
                    recommendation=rec,
                    safety_status=safety_status,
                    risk_level=risk,
                    requires_approval=rec.requires_approval,
                    is_eligible_for_approval=is_eligible,
                    review_message=msg,
                )
            )
        return review_items

    def request_approval(
        self,
        recommendation: StorageRecommendation,
        operation: Operation = Operation.CLEAN,
        validity_minutes: int = 15,
    ) -> tuple[Optional[ApprovalRecord], Optional[str]]:
        """
        Create an unapproved, pending ApprovalRecord for an eligible recommendation.

        Validates:
        - Recommendation eligibility (action must be REVIEW_FOR_CLEANUP, risk must be LOW).
        - Path safety via PathValidator (ensures path is canonical, not system protected, in allowlist).

        Returns:
            (ApprovalRecord, None) if successful, or (None, error_reason) if rejected.
        """
        candidate = recommendation.candidate
        risk = candidate.risk_level

        # Invariant 1: HIGH and UNKNOWN risk items must NEVER be requested for cleanup approval
        if risk in (RiskLevel.HIGH, RiskLevel.UNKNOWN):
            err = (
                f"Approval request blocked: Items with {risk.value} risk cannot be approved for cleanup. "
                "Manual user inspection is required."
            )
            self._log_audit(
                approval_id="N/A",
                path=candidate.path,
                operation=operation,
                risk_level=risk,
                decision="request_blocked",
                actor="safety_engine",
                result="BLOCKED",
                reason=err,
            )
            return None, err

        # Invariant 2: Action must be REVIEW_FOR_CLEANUP and safety status must be ELIGIBLE_FOR_REVIEW
        if (
            recommendation.action != RecommendationAction.REVIEW_FOR_CLEANUP
            or recommendation.safety_status != SafetyStatus.ELIGIBLE_FOR_REVIEW.value
        ):
            err = (
                f"Approval request blocked: Recommendation action '{recommendation.action.value}' "
                f"with safety status '{recommendation.safety_status}' is not eligible for cleanup approval."
            )
            self._log_audit(
                approval_id="N/A",
                path=candidate.path,
                operation=operation,
                risk_level=risk,
                decision="request_blocked",
                actor="safety_engine",
                result="BLOCKED",
                reason=err,
            )
            return None, err

        # Invariant 3: Validate filesystem safety policy on the path
        validation_res = self._validator.validate_path(candidate.path, operation=operation)
        if not validation_res.allowed:
            err = f"Approval request blocked by Safety Engine: {validation_res.reason}"
            self._log_audit(
                approval_id="N/A",
                path=candidate.path,
                operation=operation,
                risk_level=risk,
                decision="request_blocked",
                actor="safety_engine",
                result="BLOCKED",
                reason=err,
            )
            return None, err

        # Generate HMAC-signed unapproved ApprovalRecord
        record = crypto_request_approval(
            path=candidate.path,
            operation=operation,
            risk_level=risk,
            reason=recommendation.rationale,
            validity_minutes=validity_minutes,
            key_manager=self._key_manager,
        )

        with self._lock:
            self._registry[record.approval_id] = record
            self._statuses[record.approval_id] = ApprovalStatus.PENDING

            self._log_audit(
                approval_id=record.approval_id,
                path=record.path,
                operation=record.operation,
                risk_level=record.risk_level,
                decision="requested",
                actor="human",
                result="SUCCESS",
                reason=f"Approval request created pending explicit human decision (expires in {validity_minutes}m).",
            )

        return record, None

    def approve(
        self,
        approval_id: str,
        explicit_consent: bool = False,
        reason: str = "Human user explicitly granted approval",
    ) -> tuple[Optional[ApprovalRecord], str]:
        """
        Explicitly grant human approval for a pending approval request.

        Safety Rules:
        - explicit_consent MUST be True. If False, default is rejection.
        - Approval must exist and be in PENDING state.
        - Approval must not be expired.
        """
        now = datetime.now(timezone.utc)

        # Invariant: Explicit action required; default is rejection
        if not explicit_consent:
            err = "Approval rejected: Explicit human consent checkbox/confirmation was not provided. Default is rejection."
            return None, err

        with self._lock:
            record = self._registry.get(approval_id)
            if record is None:
                return None, f"Approval rejected: Approval ID '{approval_id}' not found in registry."

            current_status = self._statuses.get(approval_id)
            if current_status != ApprovalStatus.PENDING:
                return None, f"Approval rejected: Cannot approve request in '{current_status.value}' state."

            # Check expiration
            if now > record.expires_at:
                self._statuses[approval_id] = ApprovalStatus.EXPIRED
                self._log_audit(
                    approval_id=approval_id,
                    path=record.path,
                    operation=record.operation,
                    risk_level=record.risk_level,
                    decision="expired",
                    actor="safety_engine",
                    result="EXPIRED",
                    reason=f"Approval request expired at {record.expires_at.isoformat()}.",
                )
                return None, f"Approval rejected: Request expired at {record.expires_at.isoformat()}."

            # Cryptographically sign the approved state
            approved_record = grant_approval(record, key_manager=self._key_manager)
            self._registry[approval_id] = approved_record
            self._statuses[approval_id] = ApprovalStatus.APPROVED

            decision = ApprovalDecision(
                approval_id=approval_id,
                path=approved_record.path,
                operation=approved_record.operation,
                risk_level=approved_record.risk_level,
                approved=True,
                requested_at=approved_record.requested_at,
                expires_at=approved_record.expires_at,
                decision_at=now,
                reason=reason,
            )
            self._decisions[approval_id] = decision

            self._log_audit(
                approval_id=approval_id,
                path=approved_record.path,
                operation=approved_record.operation,
                risk_level=approved_record.risk_level,
                decision="approved",
                actor="human",
                result="SUCCESS",
                reason=reason,
            )

            return approved_record, f"Approval explicitly granted and HMAC-signed for '{approved_record.path}'."

    def reject(
        self,
        approval_id: str,
        reason: str = "User explicitly rejected approval request",
    ) -> tuple[Optional[ApprovalRecord], str]:
        """
        Explicitly reject a pending approval request.
        """
        now = datetime.now(timezone.utc)
        with self._lock:
            record = self._registry.get(approval_id)
            if record is None:
                return None, f"Rejection failed: Approval ID '{approval_id}' not found."

            self._statuses[approval_id] = ApprovalStatus.REJECTED

            decision = ApprovalDecision(
                approval_id=approval_id,
                path=record.path,
                operation=record.operation,
                risk_level=record.risk_level,
                approved=False,
                requested_at=record.requested_at,
                expires_at=record.expires_at,
                decision_at=now,
                reason=reason,
            )
            self._decisions[approval_id] = decision

            self._log_audit(
                approval_id=approval_id,
                path=record.path,
                operation=record.operation,
                risk_level=record.risk_level,
                decision="rejected",
                actor="human",
                result="REJECTED",
                reason=reason,
            )

            return record, f"Approval request '{approval_id}' explicitly rejected for '{record.path}'."

    def verify_and_authorize(
        self,
        approval_record: ApprovalRecord,
        target_path: Union[str, Path],
        operation: Operation,
        current_time: Optional[datetime] = None,
    ) -> tuple[bool, str]:
        """
        Verify that an approval record is valid, untampered, unexpired, in APPROVED state,
        and not previously consumed (Replay Protection).

        Returns:
            (True, "Approval verified and authorized for future execution") or (False, rejection_reason)
        """
        approval_id = approval_record.approval_id
        with self._lock:
            current_status = self._statuses.get(approval_id)

            # 1. Replay Protection & Registry State Check
            if current_status is None:
                err = f"Authorization rejected: Approval ID '{approval_id}' is not registered."
                return False, err

            if current_status == ApprovalStatus.CONSUMED:
                err = (
                    f"Replay attack prevented: Approval ID '{approval_id}' has already been CONSUMED "
                    "and cannot be reused."
                )
                self._log_audit(
                    approval_id=approval_id,
                    path=approval_record.path,
                    operation=operation,
                    risk_level=approval_record.risk_level,
                    decision="replay_rejected",
                    actor="safety_engine",
                    result="REJECTED",
                    reason=err,
                )
                return False, err

            if current_status != ApprovalStatus.APPROVED:
                err = f"Authorization rejected: Approval is in '{current_status.value}' state, expected 'approved'."
                return False, err

            # 2. Cryptographic and parameter validation via app.safety.approval.validate_approval
            is_valid, reason = validate_approval(
                record=approval_record,
                target_path=target_path,
                expected_operation=operation,
                expected_risk=approval_record.risk_level,
                current_time=current_time,
                key_manager=self._key_manager,
            )

            if not is_valid:
                self._log_audit(
                    approval_id=approval_id,
                    path=approval_record.path,
                    operation=operation,
                    risk_level=approval_record.risk_level,
                    decision="verification_failed",
                    actor="safety_engine",
                    result="FAILED",
                    reason=reason,
                )
                return False, reason

            # 3. Defensive runtime path validation check
            path_res = self._validator.validate_path(target_path, operation=operation)
            if not path_res.allowed:
                err = f"Authorization rejected by runtime Safety Engine: {path_res.reason}"
                self._log_audit(
                    approval_id=approval_id,
                    path=approval_record.path,
                    operation=operation,
                    risk_level=approval_record.risk_level,
                    decision="verification_failed",
                    actor="safety_engine",
                    result="FAILED",
                    reason=err,
                )
                return False, err

            self._log_audit(
                approval_id=approval_id,
                path=approval_record.path,
                operation=operation,
                risk_level=approval_record.risk_level,
                decision="verified",
                actor="safety_engine",
                result="SUCCESS",
                reason="Approval verified and authorized for future execution.",
            )

            return True, f"Approval verified and authorized for future execution on '{approval_record.path}'."

    def claim_for_execution(
        self,
        approval_id: str,
        current_time: Optional[datetime] = None,
    ) -> tuple[Optional[ApprovalRecord], str]:
        """
        Atomically claim an approved record for execution (Phase 6B).

        Requirements:
        1. Thread-safe lock prevents concurrent workers from double-claiming.
        2. Must be in APPROVED status (not CONSUMED, EXECUTION_CLAIMED, PENDING, REJECTED, EXPIRED, FAILED).
        3. Must not be expired.
        4. Must pass cryptographic HMAC verification.
        5. Transitions state to EXECUTION_CLAIMED.

        Returns:
            (ApprovalRecord, message) if claim succeeds, or (None, rejection_reason) if blocked.
        """
        now = current_time or datetime.now(timezone.utc)
        with self._lock:
            record = self._registry.get(approval_id)
            if record is None:
                err = f"Claim rejected: Approval ID '{approval_id}' is not registered."
                return None, err

            current_status = self._statuses.get(approval_id)
            if current_status is None:
                err = f"Claim rejected: Approval ID '{approval_id}' has no recorded status."
                return None, err

            if current_status == ApprovalStatus.CONSUMED:
                err = f"Claim rejected: Approval '{approval_id}' has already been CONSUMED (Replay Protection)."
                self._log_audit(
                    approval_id=approval_id,
                    path=record.path,
                    operation=record.operation,
                    risk_level=record.risk_level,
                    decision="claim_rejected",
                    actor="safety_engine",
                    result="REJECTED",
                    reason=err,
                )
                return None, err

            if current_status == ApprovalStatus.EXECUTION_CLAIMED:
                err = f"Claim rejected: Approval '{approval_id}' is already EXECUTION_CLAIMED by another worker."
                self._log_audit(
                    approval_id=approval_id,
                    path=record.path,
                    operation=record.operation,
                    risk_level=record.risk_level,
                    decision="claim_rejected",
                    actor="safety_engine",
                    result="REJECTED",
                    reason=err,
                )
                return None, err

            if current_status != ApprovalStatus.APPROVED:
                err = f"Claim rejected: Approval '{approval_id}' is in '{current_status.value}' state, expected 'approved'."
                self._log_audit(
                    approval_id=approval_id,
                    path=record.path,
                    operation=record.operation,
                    risk_level=record.risk_level,
                    decision="claim_rejected",
                    actor="safety_engine",
                    result="REJECTED",
                    reason=err,
                )
                return None, err

            # Verify expiration
            if now > record.expires_at:
                self._statuses[approval_id] = ApprovalStatus.EXPIRED
                err = f"Claim rejected: Approval '{approval_id}' expired at {record.expires_at.isoformat()}."
                self._log_audit(
                    approval_id=approval_id,
                    path=record.path,
                    operation=record.operation,
                    risk_level=record.risk_level,
                    decision="expired",
                    actor="safety_engine",
                    result="EXPIRED",
                    reason=err,
                )
                return None, err

            # Verify HMAC signature
            is_valid, v_msg = validate_approval(
                record=record,
                target_path=record.path,
                expected_operation=record.operation,
                expected_risk=record.risk_level,
                current_time=now,
                key_manager=self._key_manager,
            )
            if not is_valid:
                self._statuses[approval_id] = ApprovalStatus.FAILED
                err = f"Claim rejected: Cryptographic verification failed ({v_msg})."
                self._log_audit(
                    approval_id=approval_id,
                    path=record.path,
                    operation=record.operation,
                    risk_level=record.risk_level,
                    decision="claim_failed",
                    actor="safety_engine",
                    result="FAILED",
                    reason=err,
                )
                return None, err

            # Atomic transition to EXECUTION_CLAIMED
            self._statuses[approval_id] = ApprovalStatus.EXECUTION_CLAIMED

            self._log_audit(
                approval_id=approval_id,
                path=record.path,
                operation=record.operation,
                risk_level=record.risk_level,
                decision="claimed",
                actor="execution_engine",
                result="SUCCESS",
                reason="Approval successfully claimed for execution.",
            )

            return record, f"Approval '{approval_id}' claimed for execution."

    def complete_execution(
        self,
        approval_id: str,
        success: bool,
        reason: str = "",
    ) -> tuple[bool, str]:
        """
        Complete an execution transaction (Phase 6B).

        If success is True:
            Transitions status from EXECUTION_CLAIMED to CONSUMED.
        If success is False:
            Transitions status to FAILED.
        """
        with self._lock:
            record = self._registry.get(approval_id)
            if record is None:
                return False, f"Complete execution failed: Approval ID '{approval_id}' not found."

            current_status = self._statuses.get(approval_id)
            if current_status != ApprovalStatus.EXECUTION_CLAIMED and current_status != ApprovalStatus.APPROVED:
                return False, f"Complete execution failed: Approval is in '{current_status.value if current_status else 'unknown'}' state."

            if success:
                self._statuses[approval_id] = ApprovalStatus.CONSUMED
                self._log_audit(
                    approval_id=approval_id,
                    path=record.path,
                    operation=record.operation,
                    risk_level=record.risk_level,
                    decision="consumed",
                    actor="execution_engine",
                    result="CONSUMED",
                    reason=reason or "Execution succeeded; approval consumed.",
                )
                return True, f"Approval '{approval_id}' marked as CONSUMED."
            else:
                self._statuses[approval_id] = ApprovalStatus.FAILED
                self._log_audit(
                    approval_id=approval_id,
                    path=record.path,
                    operation=record.operation,
                    risk_level=record.risk_level,
                    decision="failed",
                    actor="execution_engine",
                    result="FAILED",
                    reason=reason or "Execution failed; approval marked as FAILED.",
                )
                return True, f"Approval '{approval_id}' marked as FAILED."

    def release_claim(
        self,
        approval_id: str,
        reason: str = "Execution claim released",
    ) -> tuple[bool, str]:
        """
        Release an EXECUTION_CLAIMED state back to APPROVED if execution was aborted before any mutation.
        """
        with self._lock:
            record = self._registry.get(approval_id)
            if record is None:
                return False, f"Release claim failed: Approval ID '{approval_id}' not found."

            current_status = self._statuses.get(approval_id)
            if current_status != ApprovalStatus.EXECUTION_CLAIMED:
                return False, f"Release claim failed: Approval is in '{current_status.value if current_status else 'unknown'}' state, expected 'execution_claimed'."

            self._statuses[approval_id] = ApprovalStatus.APPROVED
            self._log_audit(
                approval_id=approval_id,
                path=record.path,
                operation=record.operation,
                risk_level=record.risk_level,
                decision="claim_released",
                actor="execution_engine",
                result="SUCCESS",
                reason=reason,
            )
            return True, f"Claim released for approval '{approval_id}'."

    def consume_approval(
        self,
        approval_id: str,
        reason: str = "Approval authorization consumed for verified future execution",
    ) -> tuple[bool, str]:
        """
        Mark an approved authorization as CONSUMED to prevent replay.
        """
        with self._lock:
            status = self._statuses.get(approval_id)
            if status != ApprovalStatus.APPROVED:
                err = f"Cannot consume approval: Request '{approval_id}' is in '{status.value if status else 'unknown'}' state."
                return False, err

            self._statuses[approval_id] = ApprovalStatus.CONSUMED
            record = self._registry[approval_id]

            self._log_audit(
                approval_id=approval_id,
                path=record.path,
                operation=record.operation,
                risk_level=record.risk_level,
                decision="consumed",
                actor="human",
                result="CONSUMED",
                reason=reason,
            )

            return True, f"Approval '{approval_id}' successfully marked as CONSUMED."

    def get_status(self, approval_id: str) -> Optional[ApprovalStatus]:
        """Retrieve the current lifecycle status for an approval request."""
        with self._lock:
            return self._statuses.get(approval_id)

    def get_record(self, approval_id: str) -> Optional[ApprovalRecord]:
        """Retrieve an approval record by ID."""
        with self._lock:
            return self._registry.get(approval_id)

    def get_decision(self, approval_id: str) -> Optional[ApprovalDecision]:
        """Retrieve an approval decision by ID."""
        with self._lock:
            return self._decisions.get(approval_id)

    def get_audit_log(self) -> list[ApprovalAuditEvent]:
        """Retrieve a copy of the immutable audit log."""
        with self._lock:
            return list(self._audit_log)

    def clear_registry(self) -> None:
        """Reset in-memory state (primarily for isolated test fixtures)."""
        with self._lock:
            self._registry.clear()
            self._statuses.clear()
            self._decisions.clear()
            self._audit_log.clear()

    def _log_audit(
        self,
        approval_id: str,
        path: str,
        operation: Operation,
        risk_level: RiskLevel,
        decision: str,
        actor: str,
        result: str,
        reason: str,
    ) -> None:
        """Internal helper to record audit events."""
        event = ApprovalAuditEvent(
            approval_id=approval_id,
            path=path,
            operation=operation,
            risk_level=risk_level,
            decision=decision,
            actor=actor,
            result=result,
            reason=reason,
        )
        self._audit_log.append(event)
