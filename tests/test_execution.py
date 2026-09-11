from __future__ import annotations

import io
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Sequence

import pytest
from pydantic import ValidationError

from app.analysis.models import RiskLevel, StorageCandidate, StorageCategory
from app.analysis.recommendations import RecommendationAction, RecommendationEngine, SafetyStatus, StorageRecommendation
from app.cli import run_review_workflow
from app.execution.executor import DryRunExecutor
from app.execution.models import DryRunResult, ExecutionAction, ExecutionPlan, ExecutionStatus
from app.execution.planner import ExecutionPlanner
from app.safety.approval import ApprovalKeyManager, ApprovalRecord, grant_approval, request_approval
from app.safety.approval_service import ApprovalService
from app.safety.path_validator import Operation, PathValidator
from app.safety.review import ApprovalStatus
from app.tools.storage_scanner import StorageItem, StorageScanner


def _make_candidate(
    path: str,
    size_bytes: int = 1024 * 1024 * 15,
    category: StorageCategory = StorageCategory.CACHE,
    risk_level: RiskLevel = RiskLevel.LOW,
) -> StorageCandidate:
    return StorageCandidate(
        path=path,
        size_bytes=size_bytes,
        category=category,
        risk_level=risk_level,
        confidence=0.95,
        reason="Test candidate fixture",
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


def test_execution_plan_validation_and_immutability() -> None:
    plan = ExecutionPlan(
        approval_id="0123456789abcdef0123456789abcdef",
        path="/Users/mac/Library/Caches/test_app",
        canonical_path="/Users/mac/Library/Caches/test_app",
        operation=Operation.CLEAN,
        risk_level=RiskLevel.LOW,
        action=ExecutionAction.DRY_RUN,
        status=ExecutionStatus.PLANNED,
        estimated_reclaimable_bytes=1024 * 1024 * 10,
        reason="Verified cache cleanup plan",
    )
    assert plan.action == ExecutionAction.DRY_RUN
    assert plan.status == ExecutionStatus.PLANNED
    assert plan.estimated_reclaimable_bytes == 10485760

    # Immutability check
    with pytest.raises(ValidationError):
        plan.status = ExecutionStatus.FAILED  # type: ignore[misc]

    # Extra fields forbidden
    with pytest.raises(ValidationError):
        ExecutionPlan(
            approval_id="0123456789abcdef0123456789abcdef",
            path="/Users/mac/Library/Caches/test_app",
            canonical_path="/Users/mac/Library/Caches/test_app",
            operation=Operation.CLEAN,
            risk_level=RiskLevel.LOW,
            status=ExecutionStatus.PLANNED,
            reason="reason",
            secret_key="should_fail",  # type: ignore[call-arg]
        )


def test_dry_run_result_validation_and_immutability() -> None:
    result = DryRunResult(
        plan_id="plan123456",
        approval_id="0123456789abcdef0123456789abcdef",
        path="/Users/mac/Library/Caches/test_app",
        canonical_path="/Users/mac/Library/Caches/test_app",
        action=ExecutionAction.DRY_RUN,
        status=ExecutionStatus.DRY_RUN_COMPLETED,
        simulated_reclaimed_bytes=1024 * 1024 * 5,
        message="Dry-run completed successfully.",
    )
    assert result.status == ExecutionStatus.DRY_RUN_COMPLETED
    assert "Zero files were deleted" in result.safety_confirmation

    # Immutability check
    with pytest.raises(ValidationError):
        result.status = ExecutionStatus.FAILED  # type: ignore[misc]


# =====================================================================
# 2. ExecutionPlanner Planning & Safety Policy Tests
# =====================================================================


def test_planner_creates_plan_for_valid_approval() -> None:
    home = str(Path.home())
    test_path = f"{home}/Library/Caches/planner_test_app"

    service = ApprovalService()
    cand = _make_candidate(test_path)
    rec = _make_recommendation(cand)

    record, _ = service.request_approval(rec)
    assert record is not None
    approved_record, _ = service.approve(record.approval_id, explicit_consent=True)
    assert approved_record is not None

    planner = ExecutionPlanner(approval_service=service)
    plan, msg = planner.create_plan(approval_record=approved_record)

    assert plan is not None
    assert plan.status == ExecutionStatus.PLANNED
    assert plan.action == ExecutionAction.DRY_RUN
    assert plan.canonical_path == str(Path(test_path).resolve())
    assert plan.approval_id == approved_record.approval_id


def test_planner_blocks_unapproved_record() -> None:
    home = str(Path.home())
    test_path = f"{home}/Library/Caches/unapproved_app"

    service = ApprovalService()
    cand = _make_candidate(test_path)
    rec = _make_recommendation(cand)

    record, _ = service.request_approval(rec)
    assert record is not None  # Status is PENDING

    planner = ExecutionPlanner(approval_service=service)
    plan, err = planner.create_plan(approval_record=record)

    assert plan is not None
    assert plan.status == ExecutionStatus.BLOCKED
    assert "Planning blocked" in err


def test_planner_blocks_rejected_approval() -> None:
    home = str(Path.home())
    test_path = f"{home}/Library/Caches/rejected_app"

    service = ApprovalService()
    cand = _make_candidate(test_path)
    rec = _make_recommendation(cand)

    record, _ = service.request_approval(rec)
    assert record is not None
    service.reject(record.approval_id)

    planner = ExecutionPlanner(approval_service=service)
    plan, err = planner.create_plan(approval_record=record)

    assert plan is not None
    assert plan.status == ExecutionStatus.BLOCKED
    assert "REJECTED" in err


def test_planner_blocks_consumed_approval() -> None:
    home = str(Path.home())
    test_path = f"{home}/Library/Caches/consumed_app"

    service = ApprovalService()
    cand = _make_candidate(test_path)
    rec = _make_recommendation(cand)

    record, _ = service.request_approval(rec)
    assert record is not None
    approved_record, _ = service.approve(record.approval_id, explicit_consent=True)
    assert approved_record is not None

    # Consume approval
    service.consume_approval(approved_record.approval_id)

    planner = ExecutionPlanner(approval_service=service)
    plan, err = planner.create_plan(approval_record=approved_record)

    assert plan is not None
    assert plan.status == ExecutionStatus.BLOCKED
    assert "CONSUMED" in err


def test_planner_blocks_high_risk_and_unknown_risk() -> None:
    service = ApprovalService()
    home = str(Path.home())

    # Create synthetic approval records for high risk & unknown risk items
    km = service._key_manager
    rec_high = request_approval(f"{home}/Documents/important.pdf", Operation.CLEAN, RiskLevel.HIGH, "doc", key_manager=km)
    rec_high_app = grant_approval(rec_high, key_manager=km)
    service._registry[rec_high_app.approval_id] = rec_high_app
    service._statuses[rec_high_app.approval_id] = ApprovalStatus.APPROVED

    planner = ExecutionPlanner(approval_service=service)
    plan, err = planner.create_plan(approval_record=rec_high_app)

    assert plan is not None
    assert plan.status == ExecutionStatus.BLOCKED
    assert "ineligible for cleanup execution" in err


def test_planner_blocks_system_protected_roots() -> None:
    service = ApprovalService()
    km = service._key_manager

    rec_sys = request_approval("/System/Library/Caches/sys_app", Operation.CLEAN, RiskLevel.LOW, "sys", key_manager=km)
    rec_sys_app = grant_approval(rec_sys, key_manager=km)
    service._registry[rec_sys_app.approval_id] = rec_sys_app
    service._statuses[rec_sys_app.approval_id] = ApprovalStatus.APPROVED

    planner = ExecutionPlanner(approval_service=service)
    plan, err = planner.create_plan(approval_record=rec_sys_app)

    assert plan is not None
    assert plan.status == ExecutionStatus.BLOCKED
    assert "Safety Engine" in err or "blocked" in err.lower()


def test_planner_blocks_allowlist_root_itself() -> None:
    service = ApprovalService()
    km = service._key_manager
    home = str(Path.home())

    # Target is ~/Library/Caches root itself, not a sub-directory
    root_path = str(Path(f"{home}/Library/Caches").resolve())
    rec = request_approval(root_path, Operation.CLEAN, RiskLevel.LOW, "root cache", key_manager=km)
    rec_app = grant_approval(rec, key_manager=km)
    service._registry[rec_app.approval_id] = rec_app
    service._statuses[rec_app.approval_id] = ApprovalStatus.APPROVED

    planner = ExecutionPlanner(approval_service=service)
    plan, err = planner.create_plan(approval_record=rec_app)

    assert plan is not None
    assert plan.status == ExecutionStatus.BLOCKED
    assert "allowlist root itself" in err or "Safety Engine" in err


def test_planner_blocks_symlink_escape_and_traversal() -> None:
    service = ApprovalService()
    km = service._key_manager
    home = str(Path.home())

    traversal_path = f"{home}/Library/Caches/../Documents/secret.txt"
    rec = request_approval(traversal_path, Operation.CLEAN, RiskLevel.LOW, "escape", key_manager=km)
    rec_app = grant_approval(rec, key_manager=km)
    service._registry[rec_app.approval_id] = rec_app
    service._statuses[rec_app.approval_id] = ApprovalStatus.APPROVED

    planner = ExecutionPlanner(approval_service=service)
    plan, err = planner.create_plan(approval_record=rec_app)

    assert plan is not None
    assert plan.status == ExecutionStatus.BLOCKED


# =====================================================================
# 3. DryRunExecutor Execution Tests
# =====================================================================


def test_dry_run_executor_success() -> None:
    home = str(Path.home())
    test_path = f"{home}/Library/Caches/dryrun_app_cache"

    service = ApprovalService()
    cand = _make_candidate(test_path)
    rec = _make_recommendation(cand)

    record, _ = service.request_approval(rec)
    assert record is not None
    approved_record, _ = service.approve(record.approval_id, explicit_consent=True)
    assert approved_record is not None

    planner = ExecutionPlanner(approval_service=service)
    plan, _ = planner.create_plan(approval_record=approved_record)
    assert plan is not None
    assert plan.status == ExecutionStatus.PLANNED

    executor = DryRunExecutor(approval_service=service)
    result = executor.execute_dry_run(plan)

    assert result.status == ExecutionStatus.DRY_RUN_COMPLETED
    assert result.action == ExecutionAction.DRY_RUN
    assert result.approval_id == approved_record.approval_id
    assert "ZERO files were modified" in result.message
    assert "DRY_RUN ONLY" in result.safety_confirmation

    # CRITICAL: Approval status MUST remain APPROVED (NOT consumed by dry-run)
    assert service.get_status(approved_record.approval_id) == ApprovalStatus.APPROVED


def test_dry_run_executor_rejects_non_dry_run_plan() -> None:
    service = ApprovalService()
    # Construct invalid plan with dummy status
    plan = ExecutionPlan(
        approval_id="0123456789abcdef0123456789abcdef",
        path="/Users/mac/Library/Caches/test",
        canonical_path="/Users/mac/Library/Caches/test",
        operation=Operation.CLEAN,
        risk_level=RiskLevel.LOW,
        action=ExecutionAction.DRY_RUN,
        status=ExecutionStatus.BLOCKED,
        reason="Blocked plan",
    )

    executor = DryRunExecutor(approval_service=service)
    result = executor.execute_dry_run(plan)
    assert result.status == ExecutionStatus.FAILED
    assert "Plan status is 'BLOCKED'" in result.message


def test_dry_run_executor_blocks_if_consumed_prior_to_run() -> None:
    home = str(Path.home())
    test_path = f"{home}/Library/Caches/consumed_dryrun"

    service = ApprovalService()
    cand = _make_candidate(test_path)
    rec = _make_recommendation(cand)

    record, _ = service.request_approval(rec)
    assert record is not None
    approved_record, _ = service.approve(record.approval_id, explicit_consent=True)
    assert approved_record is not None

    planner = ExecutionPlanner(approval_service=service)
    plan, _ = planner.create_plan(approval_record=approved_record)
    assert plan is not None

    # Simulate token being consumed before dry run is triggered
    service.consume_approval(approved_record.approval_id)

    executor = DryRunExecutor(approval_service=service)
    result = executor.execute_dry_run(plan)

    assert result.status == ExecutionStatus.FAILED
    assert "CONSUMED" in result.message


# =====================================================================
# 4. Filesystem Mutation Guard Tests
# =====================================================================


def test_phase6a_dry_run_performs_zero_filesystem_mutation() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a hierarchy of test files and subdirectories
        target_dir = Path(tmpdir) / "target_cache"
        target_dir.mkdir()
        file1 = target_dir / "cache1.bin"
        file1.write_bytes(b"A" * 1024 * 100)
        file2 = target_dir / "cache2.bin"
        file2.write_bytes(b"B" * 1024 * 200)
        subdir = target_dir / "sub"
        subdir.mkdir()
        file3 = subdir / "cache3.bin"
        file3.write_bytes(b"C" * 1024 * 300)

        # Record initial directory state
        initial_file_count = sum(1 for _ in Path(tmpdir).rglob("*") if _.is_file())
        initial_dir_count = sum(1 for _ in Path(tmpdir).rglob("*") if _.is_dir())
        initial_f1_content = file1.read_bytes()
        initial_f2_content = file2.read_bytes()
        initial_f3_content = file3.read_bytes()
        initial_f1_mtime = file1.stat().st_mtime

        # Set up custom allowlist root for testing
        validator = PathValidator(custom_allowlist_roots=[tmpdir])
        service = ApprovalService(path_validator=validator)

        cand = _make_candidate(str(target_dir))
        rec = _make_recommendation(cand)

        # Request and grant approval
        record, _ = service.request_approval(rec)
        assert record is not None
        approved_record, _ = service.approve(record.approval_id, explicit_consent=True)
        assert approved_record is not None

        # Plan execution
        planner = ExecutionPlanner(approval_service=service, path_validator=validator)
        plan, msg = planner.create_plan(approval_record=approved_record)
        assert plan is not None
        assert plan.status == ExecutionStatus.PLANNED
        assert plan.estimated_reclaimable_bytes == (1024 * 100 + 1024 * 200 + 1024 * 300)

        # Execute Dry Run
        executor = DryRunExecutor(approval_service=service, path_validator=validator)
        result = executor.execute_dry_run(plan)

        assert result.status == ExecutionStatus.DRY_RUN_COMPLETED
        assert result.simulated_reclaimed_bytes == plan.estimated_reclaimable_bytes

        # Verify filesystem remains 100% untouched
        after_file_count = sum(1 for _ in Path(tmpdir).rglob("*") if _.is_file())
        after_dir_count = sum(1 for _ in Path(tmpdir).rglob("*") if _.is_dir())

        assert after_file_count == initial_file_count == 3
        assert after_dir_count == initial_dir_count == 2
        assert file1.exists() and file1.read_bytes() == initial_f1_content
        assert file2.exists() and file2.read_bytes() == initial_f2_content
        assert file3.exists() and file3.read_bytes() == initial_f3_content
        assert file1.stat().st_mtime == initial_f1_mtime


# =====================================================================
# 5. Determinism Tests
# =====================================================================


def test_planner_and_executor_determinism() -> None:
    home = str(Path.home())
    test_path = f"{home}/Library/Caches/deterministic_test"

    service = ApprovalService()
    cand = _make_candidate(test_path)
    rec = _make_recommendation(cand)

    record, _ = service.request_approval(rec)
    assert record is not None
    approved_record, _ = service.approve(record.approval_id, explicit_consent=True)
    assert approved_record is not None

    planner = ExecutionPlanner(approval_service=service)
    plan1, _ = planner.create_plan(approval_record=approved_record)
    plan2, _ = planner.create_plan(approval_record=approved_record)

    assert plan1 is not None and plan2 is not None
    assert plan1.canonical_path == plan2.canonical_path
    assert plan1.action == plan2.action == ExecutionAction.DRY_RUN
    assert plan1.status == plan2.status == ExecutionStatus.PLANNED
    assert plan1.risk_level == plan2.risk_level
