from __future__ import annotations

import concurrent.futures
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Sequence

import pytest
from pydantic import ValidationError

from app.analysis.models import RiskLevel, StorageCandidate, StorageCategory
from app.analysis.recommendations import RecommendationAction, RecommendationEngine, SafetyStatus, StorageRecommendation
from app.execution.models import ExecutionAction, ExecutionPlan, ExecutionStatus, TrashExecutionResult
from app.execution.planner import ExecutionPlanner
from app.execution.trash_executor import TrashExecutor
from app.safety.approval import ApprovalKeyManager, ApprovalRecord, grant_approval, request_approval
from app.safety.approval_service import ApprovalService
from app.safety.canonicalizer import is_contained_within
from app.safety.path_validator import Operation, PathValidator
from app.safety.review import ApprovalStatus
from app.tools.storage_scanner import StorageScanner


def _make_candidate(
    path: str,
    size_bytes: int = 1024 * 1024 * 10,
    category: StorageCategory = StorageCategory.CACHE,
    risk_level: RiskLevel = RiskLevel.LOW,
) -> StorageCandidate:
    return StorageCandidate(
        path=path,
        size_bytes=size_bytes,
        category=category,
        risk_level=risk_level,
        confidence=0.95,
        reason="Test candidate fixture for trash execution",
        recommendation="Review candidate for cleanup.",
        item_type="directory",
    )


def _make_recommendation(candidate: StorageCandidate) -> StorageRecommendation:
    return StorageRecommendation(
        candidate=candidate,
        action=RecommendationAction.REVIEW_FOR_CLEANUP,
        rationale="Test recommendation rationale",
        requires_approval=True,
        safety_status=SafetyStatus.ELIGIBLE_FOR_REVIEW.value,
        confidence=candidate.confidence,
    )


# =====================================================================
# 1. Model Validation & Immutability Tests
# =====================================================================


def test_trash_execution_result_validation_and_immutability() -> None:
    res = TrashExecutionResult(
        plan_id="plan123",
        approval_id="0123456789abcdef0123456789abcdef",
        source_path="/sandbox/caches/app",
        canonical_source_path="/sandbox/caches/app",
        trash_destination_path="/sandbox/trash/MacGuard_01234567_abcd/app",
        action=ExecutionAction.TRASH,
        status=ExecutionStatus.TRASH_SUCCEEDED,
        reclaimed_bytes=1048576,
        message="Item moved to Trash.",
        verified=True,
    )
    assert res.status == ExecutionStatus.TRASH_SUCCEEDED
    assert res.verified is True
    assert "No permanent deletion" in res.safety_confirmation

    with pytest.raises(ValidationError):
        res.status = ExecutionStatus.FAILED  # type: ignore[misc]


# =====================================================================
# 2. Sandbox Trash Execution Tests (Single File and Directory)
# =====================================================================


def test_trash_executor_moves_single_file_to_sandbox_trash() -> None:
    with tempfile.TemporaryDirectory() as sandbox_dir:
        sandbox_path = Path(sandbox_dir).resolve()
        cache_dir = sandbox_path / "Caches"
        cache_dir.mkdir()
        test_file = cache_dir / "temp_cache.bin"
        test_file.write_bytes(b"A" * 1024 * 50)
        trash_root = sandbox_path / ".Trash"

        # Explicit test sandbox safety assertion
        assert str(sandbox_path) not in (str(Path.home()), "/Library", "/System", "/")

        validator = PathValidator(custom_allowlist_roots=[str(cache_dir)])
        service = ApprovalService(path_validator=validator)

        cand = _make_candidate(str(test_file), size_bytes=1024 * 50)
        rec = _make_recommendation(cand)

        record, _ = service.request_approval(rec)
        assert record is not None
        approved_record, _ = service.approve(record.approval_id, explicit_consent=True)
        assert approved_record is not None

        planner = ExecutionPlanner(approval_service=service, path_validator=validator)
        plan, _ = planner.create_plan(approval_record=approved_record, action=ExecutionAction.TRASH)
        assert plan is not None
        assert plan.status == ExecutionStatus.PLANNED
        assert plan.action == ExecutionAction.TRASH

        executor = TrashExecutor(
            approval_service=service,
            path_validator=validator,
            trash_root=trash_root,
        )
        result = executor.execute_trash(plan, custom_trash_root=trash_root)

        assert result.status == ExecutionStatus.TRASH_SUCCEEDED
        assert result.verified is True
        assert result.reclaimed_bytes == 1024 * 50
        assert not test_file.exists(), "Source file must no longer exist at original path"
        assert Path(result.trash_destination_path).exists(), "Destination file must exist in Trash"
        assert is_contained_within(Path(result.trash_destination_path), trash_root)

        # Status must transition to CONSUMED
        assert service.get_status(approved_record.approval_id) == ApprovalStatus.CONSUMED


def test_trash_executor_moves_directory_to_sandbox_trash() -> None:
    with tempfile.TemporaryDirectory() as sandbox_dir:
        sandbox_path = Path(sandbox_dir).resolve()
        cache_dir = sandbox_path / "Caches"
        cache_dir.mkdir()
        target_dir = cache_dir / "app_cache_dir"
        target_dir.mkdir()
        (target_dir / "f1.dat").write_bytes(b"1" * 1024 * 10)
        (target_dir / "f2.dat").write_bytes(b"2" * 1024 * 20)
        sub = target_dir / "nested"
        sub.mkdir()
        (sub / "f3.dat").write_bytes(b"3" * 1024 * 30)

        trash_root = sandbox_path / ".Trash"

        validator = PathValidator(custom_allowlist_roots=[str(cache_dir)])
        service = ApprovalService(path_validator=validator)

        cand = _make_candidate(str(target_dir), size_bytes=1024 * 60)
        rec = _make_recommendation(cand)

        record, _ = service.request_approval(rec)
        assert record is not None
        approved_record, _ = service.approve(record.approval_id, explicit_consent=True)
        assert approved_record is not None

        planner = ExecutionPlanner(approval_service=service, path_validator=validator)
        plan, _ = planner.create_plan(approval_record=approved_record, action=ExecutionAction.TRASH)
        assert plan is not None

        executor = TrashExecutor(
            approval_service=service,
            path_validator=validator,
            trash_root=trash_root,
        )
        result = executor.execute_trash(plan, custom_trash_root=trash_root)

        assert result.status == ExecutionStatus.TRASH_SUCCEEDED
        assert result.verified is True
        assert not target_dir.exists(), "Original directory must no longer exist"
        dest_dir = Path(result.trash_destination_path)
        assert dest_dir.exists() and dest_dir.is_dir()
        assert (dest_dir / "f1.dat").exists()
        assert (dest_dir / "nested" / "f3.dat").exists()
        assert is_contained_within(dest_dir, trash_root)
        assert service.get_status(approved_record.approval_id) == ApprovalStatus.CONSUMED


# =====================================================================
# 3. Concurrency / Atomic Execution Claim Tests
# =====================================================================


def test_concurrent_execution_claims_prevent_double_execution() -> None:
    with tempfile.TemporaryDirectory() as sandbox_dir:
        sandbox_path = Path(sandbox_dir).resolve()
        cache_dir = sandbox_path / "Caches"
        cache_dir.mkdir()
        target = cache_dir / "concurrent_item"
        target.mkdir()
        (target / "data.bin").write_bytes(b"D" * 1024)
        trash_root = sandbox_path / ".Trash"

        validator = PathValidator(custom_allowlist_roots=[str(cache_dir)])
        service = ApprovalService(path_validator=validator)

        cand = _make_candidate(str(target))
        rec = _make_recommendation(cand)

        record, _ = service.request_approval(rec)
        assert record is not None
        approved_record, _ = service.approve(record.approval_id, explicit_consent=True)
        assert approved_record is not None

        planner = ExecutionPlanner(approval_service=service, path_validator=validator)
        plan, _ = planner.create_plan(approval_record=approved_record, action=ExecutionAction.TRASH)
        assert plan is not None

        executor = TrashExecutor(
            approval_service=service,
            path_validator=validator,
            trash_root=trash_root,
        )

        results: list[TrashExecutionResult] = []

        def worker() -> TrashExecutionResult:
            return executor.execute_trash(plan, custom_trash_root=trash_root)

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as tpool:
            f1 = tpool.submit(worker)
            f2 = tpool.submit(worker)
            results.append(f1.result())
            results.append(f2.result())

        success_count = sum(1 for r in results if r.status == ExecutionStatus.TRASH_SUCCEEDED)
        failed_count = sum(1 for r in results if r.status == ExecutionStatus.FAILED)

        # EXACTLY ONE must succeed; the other must fail the claim
        assert success_count == 1
        assert failed_count == 1
        assert service.get_status(approved_record.approval_id) == ApprovalStatus.CONSUMED


# =====================================================================
# 4. Symlink Defense Tests (Pre-Mutation os.lstat Verification)
# =====================================================================


def test_trash_executor_blocks_symlink_source() -> None:
    with tempfile.TemporaryDirectory() as sandbox_dir:
        sandbox_path = Path(sandbox_dir).resolve()
        cache_dir = sandbox_path / "Caches"
        cache_dir.mkdir()
        docs_dir = sandbox_path / "Documents"
        docs_dir.mkdir()
        secret_file = docs_dir / "secret.txt"
        secret_file.write_text("sensitive data")

        # Symlink in caches pointing to secret outside allowlist
        symlink_target = cache_dir / "symlink_app"
        symlink_target.symlink_to(secret_file)

        trash_root = sandbox_path / ".Trash"

        validator = PathValidator(custom_allowlist_roots=[str(cache_dir)])
        service = ApprovalService(path_validator=validator)

        # Even if a plan somehow existed for this path
        km = service._key_manager
        rec = request_approval(str(symlink_target.resolve()), Operation.CLEAN, RiskLevel.LOW, "symlink", key_manager=km)
        rec_app = grant_approval(rec, key_manager=km)
        service._registry[rec_app.approval_id] = rec_app
        service._statuses[rec_app.approval_id] = ApprovalStatus.APPROVED

        plan = ExecutionPlan(
            approval_id=rec_app.approval_id,
            path=str(symlink_target),
            canonical_path=str(symlink_target),
            operation=Operation.CLEAN,
            risk_level=RiskLevel.LOW,
            action=ExecutionAction.TRASH,
            status=ExecutionStatus.PLANNED,
            reason="Test plan for symlink",
        )

        executor = TrashExecutor(
            approval_service=service,
            path_validator=validator,
            trash_root=trash_root,
        )
        result = executor.execute_trash(plan, custom_trash_root=trash_root)

        assert result.status == ExecutionStatus.BLOCKED
        assert "symbolic link" in result.message.lower() or "blocked" in result.message.lower()
        assert secret_file.exists() and secret_file.read_text() == "sensitive data"
        assert service.get_status(rec_app.approval_id) == ApprovalStatus.FAILED


def test_trash_executor_blocks_source_replaced_by_symlink_after_planning() -> None:
    with tempfile.TemporaryDirectory() as sandbox_dir:
        sandbox_path = Path(sandbox_dir).resolve()
        cache_dir = sandbox_path / "Caches"
        cache_dir.mkdir()
        target = cache_dir / "valid_dir"
        target.mkdir()
        (target / "data.dat").write_text("initial")

        docs_dir = sandbox_path / "Documents"
        docs_dir.mkdir()
        important_file = docs_dir / "passwords.txt"
        important_file.write_text("passwords")

        trash_root = sandbox_path / ".Trash"

        validator = PathValidator(custom_allowlist_roots=[str(cache_dir)])
        service = ApprovalService(path_validator=validator)

        cand = _make_candidate(str(target))
        rec = _make_recommendation(cand)

        record, _ = service.request_approval(rec)
        assert record is not None
        approved_record, _ = service.approve(record.approval_id, explicit_consent=True)
        assert approved_record is not None

        planner = ExecutionPlanner(approval_service=service, path_validator=validator)
        plan, _ = planner.create_plan(approval_record=approved_record, action=ExecutionAction.TRASH)
        assert plan is not None

        # ATTACK SIMULATION (TOCTOU): Replace valid_dir with symlink to passwords.txt before execution
        (target / "data.dat").unlink()
        target.rmdir()
        target.symlink_to(important_file)

        executor = TrashExecutor(
            approval_service=service,
            path_validator=validator,
            trash_root=trash_root,
        )
        result = executor.execute_trash(plan, custom_trash_root=trash_root)

        # Must fail closed immediately
        assert result.status in (ExecutionStatus.BLOCKED, ExecutionStatus.FAILED)
        assert important_file.exists() and important_file.read_text() == "passwords"
        assert service.get_status(approved_record.approval_id) == ApprovalStatus.FAILED


# =====================================================================
# 5. Protected Paths & Risk Gating Tests
# =====================================================================


def test_trash_executor_blocks_system_protected_paths() -> None:
    service = ApprovalService()
    km = service._key_manager

    rec = request_approval("/System/Library/Caches/sys", Operation.CLEAN, RiskLevel.LOW, "sys", key_manager=km)
    rec_app = grant_approval(rec, key_manager=km)
    service._registry[rec_app.approval_id] = rec_app
    service._statuses[rec_app.approval_id] = ApprovalStatus.APPROVED

    plan = ExecutionPlan(
        approval_id=rec_app.approval_id,
        path="/System/Library/Caches/sys",
        canonical_path="/System/Library/Caches/sys",
        operation=Operation.CLEAN,
        risk_level=RiskLevel.LOW,
        action=ExecutionAction.TRASH,
        status=ExecutionStatus.PLANNED,
        reason="Test plan",
    )

    executor = TrashExecutor(approval_service=service)
    result = executor.execute_trash(plan)

    assert result.status == ExecutionStatus.BLOCKED
    assert "Safety Engine" in result.message or "blocked" in result.message.lower()


def test_trash_executor_blocks_high_and_medium_and_unknown_risk() -> None:
    service = ApprovalService()
    km = service._key_manager
    home = str(Path.home())

    for risk in (RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.UNKNOWN):
        rec = request_approval(f"{home}/Library/Caches/risk_app", Operation.CLEAN, risk, "risk", key_manager=km)
        rec_app = grant_approval(rec, key_manager=km)
        service._registry[rec_app.approval_id] = rec_app
        service._statuses[rec_app.approval_id] = ApprovalStatus.APPROVED

        plan = ExecutionPlan(
            approval_id=rec_app.approval_id,
            path=f"{home}/Library/Caches/risk_app",
            canonical_path=f"{home}/Library/Caches/risk_app",
            operation=Operation.CLEAN,
            risk_level=risk,
            action=ExecutionAction.TRASH,
            status=ExecutionStatus.PLANNED,
            reason="Test plan",
        )

        executor = TrashExecutor(approval_service=service)
        result = executor.execute_trash(plan)

        assert result.status == ExecutionStatus.BLOCKED
        assert "ineligible" in result.message or "Risk level" in result.message


# =====================================================================
# 6. Cryptographic & Lifecycle Rejection Tests
# =====================================================================


def test_trash_executor_rejects_tampered_approval_hmac() -> None:
    with tempfile.TemporaryDirectory() as sandbox_dir:
        sandbox_path = Path(sandbox_dir).resolve()
        cache_dir = sandbox_path / "Caches"
        cache_dir.mkdir()
        target = cache_dir / "tampered_app"
        target.mkdir()
        trash_root = sandbox_path / ".Trash"

        validator = PathValidator(custom_allowlist_roots=[str(cache_dir)])
        service = ApprovalService(path_validator=validator)

        cand = _make_candidate(str(target))
        rec = _make_recommendation(cand)

        record, _ = service.request_approval(rec)
        assert record is not None
        approved_record, _ = service.approve(record.approval_id, explicit_consent=True)
        assert approved_record is not None

        # Tamper with signature
        tampered_record = approved_record.model_copy(update={"token_signature": "00000000000000000000000000000000"})
        service._registry[approved_record.approval_id] = tampered_record

        planner = ExecutionPlanner(approval_service=service, path_validator=validator)
        plan = ExecutionPlan(
            approval_id=approved_record.approval_id,
            path=str(target),
            canonical_path=str(target),
            operation=Operation.CLEAN,
            risk_level=RiskLevel.LOW,
            action=ExecutionAction.TRASH,
            status=ExecutionStatus.PLANNED,
            reason="Test",
        )

        executor = TrashExecutor(
            approval_service=service,
            path_validator=validator,
            trash_root=trash_root,
        )
        result = executor.execute_trash(plan, custom_trash_root=trash_root)

        assert result.status == ExecutionStatus.FAILED
        assert "Cryptographic verification failed" in result.message or "claim" in result.message.lower()
        assert target.exists()


def test_trash_executor_rejects_expired_approval() -> None:
    with tempfile.TemporaryDirectory() as sandbox_dir:
        sandbox_path = Path(sandbox_dir).resolve()
        cache_dir = sandbox_path / "Caches"
        cache_dir.mkdir()
        target = cache_dir / "expired_app"
        target.mkdir()
        trash_root = sandbox_path / ".Trash"

        validator = PathValidator(custom_allowlist_roots=[str(cache_dir)])
        service = ApprovalService(path_validator=validator)

        cand = _make_candidate(str(target))
        rec = _make_recommendation(cand)

        # Expired record
        km = service._key_manager
        rec_initial = request_approval(str(target), Operation.CLEAN, RiskLevel.LOW, "expired", validity_minutes=1, key_manager=km)
        past_time = datetime.now(timezone.utc) - timedelta(minutes=30)
        rec_obj = rec_initial.model_copy(update={"expires_at": past_time})
        approved_rec = grant_approval(rec_obj, key_manager=km)
        service._registry[approved_rec.approval_id] = approved_rec
        service._statuses[approved_rec.approval_id] = ApprovalStatus.APPROVED

        plan = ExecutionPlan(
            approval_id=approved_rec.approval_id,
            path=str(target),
            canonical_path=str(target),
            operation=Operation.CLEAN,
            risk_level=RiskLevel.LOW,
            action=ExecutionAction.TRASH,
            status=ExecutionStatus.PLANNED,
            reason="Test",
        )

        executor = TrashExecutor(
            approval_service=service,
            path_validator=validator,
            trash_root=trash_root,
        )
        result = executor.execute_trash(plan, custom_trash_root=trash_root)

        assert result.status == ExecutionStatus.FAILED
        assert "expired" in result.message.lower()
        assert target.exists()


# =====================================================================
# 7. Collision Handling & Missing Source Tests
# =====================================================================


def test_trash_executor_handles_identical_names_without_collision() -> None:
    with tempfile.TemporaryDirectory() as sandbox_dir:
        sandbox_path = Path(sandbox_dir).resolve()
        cache_dir1 = sandbox_path / "Caches1"
        cache_dir2 = sandbox_path / "Caches2"
        cache_dir1.mkdir()
        cache_dir2.mkdir()
        trash_root = sandbox_path / ".Trash"

        file1 = cache_dir1 / "cache.db"
        file1.write_text("data1")
        file2 = cache_dir2 / "cache.db"
        file2.write_text("data2")

        validator = PathValidator(custom_allowlist_roots=[str(cache_dir1), str(cache_dir2)])
        service = ApprovalService(path_validator=validator)

        # Move item 1
        cand1 = _make_candidate(str(file1), size_bytes=5)
        rec1 = _make_recommendation(cand1)
        r1, _ = service.request_approval(rec1)
        assert r1 is not None
        ar1, _ = service.approve(r1.approval_id, explicit_consent=True)
        assert ar1 is not None

        planner = ExecutionPlanner(approval_service=service, path_validator=validator)
        p1, _ = planner.create_plan(approval_record=ar1, action=ExecutionAction.TRASH)
        assert p1 is not None

        executor = TrashExecutor(approval_service=service, path_validator=validator, trash_root=trash_root)
        res1 = executor.execute_trash(p1, custom_trash_root=trash_root)
        assert res1.status == ExecutionStatus.TRASH_SUCCEEDED

        # Move item 2 with identical basename
        cand2 = _make_candidate(str(file2), size_bytes=5)
        rec2 = _make_recommendation(cand2)
        r2, _ = service.request_approval(rec2)
        assert r2 is not None
        ar2, _ = service.approve(r2.approval_id, explicit_consent=True)
        assert ar2 is not None

        p2, _ = planner.create_plan(approval_record=ar2, action=ExecutionAction.TRASH)
        assert p2 is not None

        res2 = executor.execute_trash(p2, custom_trash_root=trash_root)
        assert res2.status == ExecutionStatus.TRASH_SUCCEEDED

        # Both destinations must exist with distinct paths and preserved content
        dest1 = Path(res1.trash_destination_path)
        dest2 = Path(res2.trash_destination_path)
        assert dest1 != dest2
        assert dest1.exists() and dest1.read_text() == "data1"
        assert dest2.exists() and dest2.read_text() == "data2"


def test_trash_executor_handles_missing_source_safely() -> None:
    with tempfile.TemporaryDirectory() as sandbox_dir:
        sandbox_path = Path(sandbox_dir).resolve()
        cache_dir = sandbox_path / "Caches"
        cache_dir.mkdir()
        nonexistent = cache_dir / "never_created.bin"
        trash_root = sandbox_path / ".Trash"

        validator = PathValidator(custom_allowlist_roots=[str(cache_dir)])
        service = ApprovalService(path_validator=validator)

        cand = _make_candidate(str(nonexistent))
        rec = _make_recommendation(cand)
        r, _ = service.request_approval(rec)
        assert r is not None
        ar, _ = service.approve(r.approval_id, explicit_consent=True)
        assert ar is not None

        planner = ExecutionPlanner(approval_service=service, path_validator=validator)
        plan, _ = planner.create_plan(approval_record=ar, action=ExecutionAction.TRASH)
        assert plan is not None

        executor = TrashExecutor(approval_service=service, path_validator=validator, trash_root=trash_root)
        result = executor.execute_trash(plan, custom_trash_root=trash_root)

        assert result.status == ExecutionStatus.FAILED
        assert "does not exist" in result.message.lower()
        assert service.get_status(ar.approval_id) == ApprovalStatus.FAILED
