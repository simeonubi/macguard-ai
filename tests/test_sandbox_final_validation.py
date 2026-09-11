from __future__ import annotations

import hashlib
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.analysis.models import RiskLevel, StorageCandidate, StorageCategory
from app.analysis.recommendations import (
    RecommendationAction,
    RecommendationEngine,
    SafetyStatus,
    StorageRecommendation,
)
from app.analysis.storage_analyzer import StorageAnalyzer
from app.audit.models import AuditEventType
from app.audit.repository import AuditRepository
from app.execution.executor import DryRunExecutor
from app.execution.models import ExecutionAction, ExecutionStatus
from app.execution.planner import ExecutionPlanner
from app.execution.trash_executor import TrashExecutor
from app.safety.approval import (
    ApprovalRecord,
    grant_approval,
    request_approval,
    validate_approval,
)
from app.safety.approval_service import ApprovalService
from app.safety.path_validator import Operation, PathValidator
from app.safety.review import ApprovalStatus
from app.tools.storage_scanner import StorageScanner


def test_final_sandbox_validation_comprehensive():
    """
    Comprehensive Final Sandbox Validation for MacGuard AI.
    Executes the full real-filesystem controlled execution workflow against an isolated sandbox test item.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        sandbox_root = Path(temp_dir).resolve()

        # Unrelated canary file to verify no unintended filesystem mutations occur
        unrelated_canary = sandbox_root / "UNTOUCHED_CANARY.dat"
        unrelated_content = b"CANARY_SHOULD_NEVER_BE_TOUCHED_1234567890"
        unrelated_canary.write_bytes(unrelated_content)
        canary_mtime = os.lstat(unrelated_canary).st_mtime_ns

        # 1. Create isolated test sandbox item
        test_dir = sandbox_root / "Library" / "Caches" / "MacGuard_SANDBOX_TEST"
        test_dir.mkdir(parents=True, exist_ok=True)
        test_file = test_dir / "test_payload.bin"
        test_payload = b"MacGuard_AI_CONTROLLED_EXECUTION_SANDBOX_TEST_PAYLOAD_" * 64
        test_file.write_bytes(test_payload)

        # Record original metadata
        orig_stat = os.lstat(test_file)
        orig_path = str(test_file)
        orig_size = len(test_payload)
        orig_mtime = orig_stat.st_mtime
        orig_ino = orig_stat.st_ino
        orig_sha256 = hashlib.sha256(test_payload).hexdigest()

        assert test_file.exists()
        assert orig_stat.st_size == orig_size

        # Isolated sandbox Trash and Audit DB
        sandbox_trash = sandbox_root / "SandboxTrash"
        sandbox_trash.mkdir(parents=True, exist_ok=True)
        audit_db = sandbox_root / "validation_audit.db"

        # Initialize core services with custom sandbox allowlist
        validator = PathValidator(custom_allowlist_roots=[str(sandbox_root)])
        approval_service = ApprovalService(path_validator=validator)
        audit_repo = AuditRepository(db_path=str(audit_db))
        scanner = StorageScanner()
        analyzer = StorageAnalyzer()
        rec_engine = RecommendationEngine(min_cleanup_size_bytes=100)
        planner = ExecutionPlanner(approval_service=approval_service, path_validator=validator, scanner=scanner)
        dry_run_executor = DryRunExecutor(approval_service=approval_service, path_validator=validator)
        trash_executor = TrashExecutor(
            approval_service=approval_service,
            path_validator=validator,
            trash_root=sandbox_trash,
            audit_repo=audit_repo,
        )

        # 2 & 3. ANALYZE Mode Discovery & Inspection (Read-Only)
        discovered_items = scanner.get_large_files(path=str(test_dir), limit=10)
        assert len(discovered_items) >= 1
        found_item = next(it for it in discovered_items if it.path == orig_path)
        assert found_item.size_bytes == orig_size

        candidates = analyzer.analyze_items(discovered_items, deduplicate=True)
        cand = next(c for c in candidates if c.path == orig_path)
        assert cand.category == StorageCategory.CACHE
        assert cand.risk_level == RiskLevel.LOW

        recommendations = rec_engine.recommend_many(candidates)
        rec = next(r for r in recommendations if r.candidate.path == orig_path)
        assert rec.action == RecommendationAction.REVIEW_FOR_CLEANUP
        assert rec.safety_status == SafetyStatus.ELIGIBLE_FOR_REVIEW.value
        assert rec.requires_approval is True

        # Verify discovery was strictly non-mutating
        assert test_file.exists()
        assert os.lstat(test_file).st_mtime == orig_mtime
        assert os.lstat(unrelated_canary).st_mtime_ns == canary_mtime

        # 4. REVIEW Mode Presentation & Explicit Human Consent Gating
        review_items = approval_service.create_review_items(recommendations)
        rev_item = next(ri for ri in review_items if ri.candidate.path == orig_path)
        assert rev_item.is_eligible_for_approval is True
        assert rev_item.risk_level == RiskLevel.LOW

        # Human Request Approval
        pending_record, req_err = approval_service.request_approval(rec, operation=Operation.CLEAN)
        assert req_err is None
        assert pending_record is not None
        assert pending_record.approved is False
        assert approval_service.get_status(pending_record.approval_id) == ApprovalStatus.PENDING

        # Rejection when explicit consent is absent
        rej_record, rej_msg = approval_service.approve(pending_record.approval_id, explicit_consent=False)
        assert rej_record is None
        assert "consent" in rej_msg.lower()
        assert approval_service.get_status(pending_record.approval_id) == ApprovalStatus.PENDING

        # 5 & 6. Explicit Approval Grant & Verification
        approved_record, app_msg = approval_service.approve(
            pending_record.approval_id,
            explicit_consent=True,
            reason="Validated human sandbox approval",
        )
        assert approved_record is not None
        assert approved_record.approved is True
        assert approved_record.path == orig_path
        assert approved_record.risk_level == RiskLevel.LOW
        assert approved_record.token_signature is not None
        assert approval_service.get_status(approved_record.approval_id) == ApprovalStatus.APPROVED

        # Cryptographic verification
        is_valid, v_msg = validate_approval(
            record=approved_record,
            target_path=orig_path,
            expected_operation=Operation.CLEAN,
            expected_risk=RiskLevel.LOW,
            key_manager=approval_service._key_manager,
        )
        assert is_valid is True

        # 7 & 8. CONTROLLED EXECUTION: DRY RUN SIMULATION
        dry_plan, dry_plan_msg = planner.create_plan(approved_record, action=ExecutionAction.DRY_RUN)
        assert dry_plan is not None
        assert dry_plan.action == ExecutionAction.DRY_RUN
        assert dry_plan.status == ExecutionStatus.PLANNED

        dry_res = dry_run_executor.execute_dry_run(dry_plan)
        assert dry_res.status == ExecutionStatus.DRY_RUN_COMPLETED
        assert dry_res.simulated_reclaimed_bytes == orig_size
        assert "zero files were deleted" in dry_res.safety_confirmation.lower()

        # Verify Dry Run did NOT mutate source or consume approval
        assert test_file.exists()
        assert test_file.read_bytes() == test_payload
        assert hashlib.sha256(test_file.read_bytes()).hexdigest() == orig_sha256
        assert len(list(sandbox_trash.iterdir())) == 0
        assert approval_service.get_status(approved_record.approval_id) == ApprovalStatus.APPROVED

        # 9 & 10. CONTROLLED TRASH MOVE EXECUTION
        trash_plan, trash_plan_msg = planner.create_plan(approved_record, action=ExecutionAction.TRASH)
        assert trash_plan is not None
        assert trash_plan.action == ExecutionAction.TRASH
        assert trash_plan.status == ExecutionStatus.PLANNED

        exec_res = trash_executor.execute_trash(trash_plan)

        # 11 & 12. Verification of Controlled Trash Move
        assert exec_res.status == ExecutionStatus.TRASH_SUCCEEDED
        assert exec_res.verified is True
        assert exec_res.integrity_verified is True
        assert exec_res.reclaimed_bytes == orig_size
        assert not test_file.exists()  # Source is absent

        dest_path = Path(exec_res.trash_destination_path)
        assert dest_path.exists()  # Destination is present
        assert dest_path.is_relative_to(sandbox_trash)  # Contained inside sandbox Trash

        # 13. Post-Move Integrity Verification
        dest_bytes = dest_path.read_bytes()
        dest_stat = os.lstat(dest_path)
        assert len(dest_bytes) == orig_size
        assert dest_stat.st_size == orig_size
        assert hashlib.sha256(dest_bytes).hexdigest() == orig_sha256

        # 14. Lifecycle Status: CONSUMED
        assert approval_service.get_status(approved_record.approval_id) == ApprovalStatus.CONSUMED

        # 15. Replay Attack Prevention
        replay_res = trash_executor.execute_trash(trash_plan)
        assert replay_res.status in (ExecutionStatus.BLOCKED, ExecutionStatus.FAILED)
        assert not test_file.exists()
        assert "consumed" in replay_res.message.lower() or "claim" in replay_res.message.lower() or "replay" in replay_res.message.lower()

        # 16. Audit Log Forensics
        # A. Execution repository events
        events = audit_repo.get_events_by_approval_id(approved_record.approval_id)
        assert len(events) >= 5
        event_types = [e.event_type.value if hasattr(e.event_type, "value") else str(e.event_type) for e in events]
        assert AuditEventType.EXECUTION_CLAIMED.value in event_types
        assert AuditEventType.TRASH_MOVE_SUCCEEDED.value in event_types
        assert AuditEventType.TRASH_VERIFICATION_SUCCEEDED.value in event_types

        # B. Approval Service in-memory tamper-evident audit events
        approval_audit_events = approval_service.get_audit_log()
        assert len(approval_audit_events) >= 2
        app_decisions = [ev.decision for ev in approval_audit_events if ev.approval_id == approved_record.approval_id]
        assert "requested" in app_decisions
        assert "approved" in app_decisions
        assert "consumed" in app_decisions

        # Verify zero secrets or HMAC keys in audit records
        for ev in events:
            ev_str = ev.model_dump_json()
            assert "secret_key" not in ev_str.lower()
            assert approval_service._key_manager._secret_key.hex() not in ev_str

        # 17. Verify Unrelated Canary File Untouched
        assert unrelated_canary.exists()
        assert unrelated_canary.read_bytes() == unrelated_content
        assert os.lstat(unrelated_canary).st_mtime_ns == canary_mtime
