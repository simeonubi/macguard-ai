from __future__ import annotations

import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.audit.models import AuditEventType
from app.audit.repository import AuditRepository
from app.execution.models import ExecutionAction, ExecutionPlan, ExecutionStatus
from app.execution.planner import ExecutionPlanner
from app.execution.trash_executor import TrashExecutor
from app.safety.approval_service import ApprovalService
from app.safety.path_validator import Operation, PathValidator
from app.tools.storage_scanner import StorageScanner


def test_interrupted_execution_detected_in_audit_repo():
    """Simulate a process interruption/crash during execution and verify incomplete status is detected."""
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = Path(temp_dir) / "audit.db"
        repo = AuditRepository(db_path=db_path)

        exec_id = secrets.token_hex(8)
        app_id = secrets.token_hex(16)
        path = "/Users/test/Library/Caches/interrupted"

        # Record start (state becomes IN_PROGRESS)
        repo.record_execution_start(
            execution_id=exec_id,
            approval_id=app_id,
            canonical_path=path,
            action="TRASH",
            start_time=datetime.now(timezone.utc),
        )

        # Incomplete execution detected on recovery
        incomplete_list = repo.get_incomplete_executions()
        assert len(incomplete_list) == 1
        assert incomplete_list[0].execution_id == exec_id
        assert incomplete_list[0].status == "IN_PROGRESS"
        assert incomplete_list[0].verified is False


def test_incomplete_execution_fails_closed_no_automatic_retry():
    """Verify that an interrupted execution does not automatically execute without human review."""
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = Path(temp_dir) / "audit.db"
        repo = AuditRepository(db_path=db_path)

        sandbox_dir = Path(temp_dir) / "Library" / "Caches" / "sample"
        sandbox_dir.mkdir(parents=True)
        trash_dir = Path(temp_dir) / "Trash"
        trash_dir.mkdir()

        validator = PathValidator(custom_allowlist_roots=[str(sandbox_dir.parent)])
        approval_service = ApprovalService(path_validator=validator)
        planner = ExecutionPlanner(approval_service=approval_service, path_validator=validator)
        executor = TrashExecutor(
            approval_service=approval_service,
            path_validator=validator,
            audit_repo=repo,
            trash_root=trash_dir,
        )

        # Create recommendation and approve
        from app.analysis.models import StorageCandidate, StorageCategory, RiskLevel
        from app.analysis.recommendations import RecommendationEngine

        cand = StorageCandidate(
            path=str(sandbox_dir),
            size_bytes=1000,
            category=StorageCategory.CACHE,
            risk_level=RiskLevel.LOW,
            confidence=0.9,
            reason="App cache directory",
            recommendation="Review for cleanup",
        )
        rec = RecommendationEngine().recommend(cand)

        record, _ = approval_service.request_approval(rec, operation=Operation.CLEAN)
        approved_record, _ = approval_service.approve(record.approval_id, explicit_consent=True)

        plan, _ = planner.create_plan(approved_record, action=ExecutionAction.TRASH)

        # First execution run
        res = executor.execute_trash(plan, custom_trash_root=trash_dir)
        assert res.status == ExecutionStatus.TRASH_SUCCEEDED
        assert res.verified is True
        assert res.integrity_verified is True

        # Attempt to run second execution on consumed plan
        res2 = executor.execute_trash(plan, custom_trash_root=trash_dir)
        assert res2.status == ExecutionStatus.FAILED
        assert "failed to claim approval" in res2.message.lower() or "blocked" in res2.message.lower()
