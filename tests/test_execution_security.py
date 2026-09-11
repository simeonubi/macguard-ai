from __future__ import annotations

import concurrent.futures
import os
import secrets
import tempfile
from pathlib import Path

import pytest

from app.analysis.models import RiskLevel, StorageCandidate, StorageCategory
from app.analysis.recommendations import RecommendationEngine
from app.audit.repository import AuditRepository
from app.execution.models import ExecutionAction, ExecutionStatus
from app.execution.planner import ExecutionPlanner
from app.execution.trash_executor import TrashExecutor
from app.safety.approval_service import ApprovalService
from app.safety.canonicalizer import is_contained_within
from app.safety.path_validator import Operation, PathValidator


def test_security_scenario_a_file_replaced_by_symlink_blocked():
    """Scenario A: Approved regular file is replaced by a symlink before execution."""
    with tempfile.TemporaryDirectory() as temp_dir:
        home = Path(temp_dir)
        cache_dir = home / "Library" / "Caches"
        cache_file = cache_dir / "app.cache"
        cache_dir.mkdir(parents=True)
        cache_file.write_text("Regular cache data", encoding="utf-8")
        trash_dir = home / ".Trash"
        trash_dir.mkdir()

        validator = PathValidator(custom_allowlist_roots=[str(cache_dir)])
        approval_service = ApprovalService(path_validator=validator)
        planner = ExecutionPlanner(approval_service=approval_service, path_validator=validator)
        executor = TrashExecutor(
            approval_service=approval_service,
            path_validator=validator,
            trash_root=trash_dir,
        )

        cand = StorageCandidate(
            path=str(cache_file),
            size_bytes=cache_file.stat().st_size,
            category=StorageCategory.CACHE,
            risk_level=RiskLevel.LOW,
            confidence=0.9,
            reason="Cache file",
            recommendation="Review for cleanup",
        )
        rec = RecommendationEngine().recommend(cand)

        record, _ = approval_service.request_approval(rec, operation=Operation.CLEAN)
        approved_record, _ = approval_service.approve(record.approval_id, explicit_consent=True)
        plan, _ = planner.create_plan(approved_record, action=ExecutionAction.TRASH)

        # TOCTOU Attack: Replace file with symlink pointing to sensitive file
        sensitive_file = home / "secret.key"
        sensitive_file.write_text("SECRET", encoding="utf-8")
        os.remove(cache_file)
        os.symlink(sensitive_file, cache_file)

        # Execute
        res = executor.execute_trash(plan, custom_trash_root=trash_dir)

        assert res.status in (ExecutionStatus.BLOCKED, ExecutionStatus.FAILED)
        assert "symbolic link" in res.message.lower() or "symlink" in res.message.lower() or "mismatch" in res.message.lower()
        # Ensure sensitive file was untouched
        assert sensitive_file.exists()
        assert sensitive_file.read_text(encoding="utf-8") == "SECRET"


def test_security_scenario_b_directory_replaced_by_symlink_blocked():
    """Scenario B: Approved directory becomes a symlink before execution."""
    with tempfile.TemporaryDirectory() as temp_dir:
        home = Path(temp_dir)
        cache_parent = home / "Library" / "Caches"
        cache_dir = cache_parent / "dir_cache"
        cache_parent.mkdir(parents=True)
        cache_dir.mkdir()
        (cache_dir / "item.tmp").write_text("item", encoding="utf-8")
        trash_dir = home / ".Trash"
        trash_dir.mkdir()

        validator = PathValidator(custom_allowlist_roots=[str(cache_parent)])
        approval_service = ApprovalService(path_validator=validator)
        planner = ExecutionPlanner(approval_service=approval_service, path_validator=validator)
        executor = TrashExecutor(
            approval_service=approval_service,
            path_validator=validator,
            trash_root=trash_dir,
        )

        cand = StorageCandidate(
            path=str(cache_dir),
            size_bytes=1000,
            category=StorageCategory.CACHE,
            risk_level=RiskLevel.LOW,
            confidence=0.9,
            reason="Cache directory",
            recommendation="Review for cleanup",
        )
        rec = RecommendationEngine().recommend(cand)

        record, _ = approval_service.request_approval(rec, operation=Operation.CLEAN)
        approved_record, _ = approval_service.approve(record.approval_id, explicit_consent=True)
        plan, _ = planner.create_plan(approved_record, action=ExecutionAction.TRASH)

        # TOCTOU Attack: Remove directory and replace with symlink to home directory
        os.remove(cache_dir / "item.tmp")
        cache_dir.rmdir()
        os.symlink(home, cache_dir)

        res = executor.execute_trash(plan, custom_trash_root=trash_dir)
        assert res.status in (ExecutionStatus.BLOCKED, ExecutionStatus.FAILED)
        assert "symbolic link" in res.message.lower() or "symlink" in res.message.lower() or "mismatch" in res.message.lower()


def test_security_scenario_d_path_prefix_collision_not_contained():
    """Scenario D: Path prefix collision is not considered contained."""
    with tempfile.TemporaryDirectory() as temp_dir:
        base_dir = Path(temp_dir) / "Library" / "Caches" / "example"
        attacker_dir = Path(temp_dir) / "Library" / "Caches" / "example-other"
        base_dir.mkdir(parents=True)
        attacker_dir.mkdir(parents=True)

        assert is_contained_within(attacker_dir, base_dir) is False
        assert is_contained_within(base_dir, attacker_dir) is False


def test_security_scenario_e_path_traversal_blocked():
    """Scenario E: ../ traversal is blocked by validator."""
    with tempfile.TemporaryDirectory() as temp_dir:
        validator = PathValidator(home_dir=temp_dir)
        traversal_path = f"{temp_dir}/Library/Caches/../../sensitive"
        res = validator.validate_path(traversal_path, operation=Operation.CLEAN)
        assert res.allowed is False
        assert "outside" in res.reason.lower() or "allowlist" in res.reason.lower() or "protected" in res.reason.lower()


def test_security_scenario_f_protected_system_path_blocked():
    """Scenario F: Protected system paths are unconditionally blocked."""
    validator = PathValidator()
    protected_paths = ["/System", "/Library", "/usr/bin", "/etc", "/Applications"]
    for path in protected_paths:
        res = validator.validate_path(path, operation=Operation.CLEAN)
        assert res.allowed is False


def test_security_concurrency_single_execution_claim():
    """Test that concurrent execution claims result in exactly 1 success and N-1 rejections."""
    with tempfile.TemporaryDirectory() as temp_dir:
        home = Path(temp_dir)
        cache_dir = home / "Library" / "Caches"
        cache_file = cache_dir / "concurrent.cache"
        cache_dir.mkdir(parents=True)
        cache_file.write_text("Concurrent cache data", encoding="utf-8")
        trash_dir = home / ".Trash"
        trash_dir.mkdir()

        validator = PathValidator(custom_allowlist_roots=[str(cache_dir)])
        approval_service = ApprovalService(path_validator=validator)
        planner = ExecutionPlanner(approval_service=approval_service, path_validator=validator)
        executor = TrashExecutor(
            approval_service=approval_service,
            path_validator=validator,
            trash_root=trash_dir,
        )

        cand = StorageCandidate(
            path=str(cache_file),
            size_bytes=cache_file.stat().st_size,
            category=StorageCategory.CACHE,
            risk_level=RiskLevel.LOW,
            confidence=0.9,
            reason="Concurrent cache file",
            recommendation="Review for cleanup",
        )
        rec = RecommendationEngine().recommend(cand)

        record, _ = approval_service.request_approval(rec, operation=Operation.CLEAN)
        approved_record, _ = approval_service.approve(record.approval_id, explicit_consent=True)
        plan, _ = planner.create_plan(approved_record, action=ExecutionAction.TRASH)

        num_threads = 8
        results = []

        def run_attempt():
            return executor.execute_trash(plan, custom_trash_root=trash_dir)

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as pool:
            futures = [pool.submit(run_attempt) for _ in range(num_threads)]
            for f in concurrent.futures.as_completed(futures):
                results.append(f.result())

        succeeded = [r for r in results if r.status == ExecutionStatus.TRASH_SUCCEEDED]
        failed = [r for r in results if r.status in (ExecutionStatus.FAILED, ExecutionStatus.BLOCKED)]

        assert len(succeeded) == 1
        assert len(failed) == num_threads - 1
        assert succeeded[0].verified is True
        assert succeeded[0].integrity_verified is True


def test_security_audit_zero_secrets_exposure():
    """Verify audit logs and execution records never leak HMAC secret tokens or private keys."""
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = Path(temp_dir) / "audit.db"
        repo = AuditRepository(db_path=db_path)

        home = Path(temp_dir)
        cache_dir = home / "Library" / "Caches"
        cache_file = cache_dir / "audited.cache"
        cache_dir.mkdir(parents=True)
        cache_file.write_text("Audited cache data", encoding="utf-8")
        trash_dir = home / ".Trash"
        trash_dir.mkdir()

        validator = PathValidator(custom_allowlist_roots=[str(cache_dir)])
        approval_service = ApprovalService(path_validator=validator)
        planner = ExecutionPlanner(approval_service=approval_service, path_validator=validator)
        executor = TrashExecutor(
            approval_service=approval_service,
            path_validator=validator,
            audit_repo=repo,
            trash_root=trash_dir,
        )

        cand = StorageCandidate(
            path=str(cache_file),
            size_bytes=cache_file.stat().st_size,
            category=StorageCategory.CACHE,
            risk_level=RiskLevel.LOW,
            confidence=0.9,
            reason="Audited cache file",
            recommendation="Review for cleanup",
        )
        rec = RecommendationEngine().recommend(cand)

        record, _ = approval_service.request_approval(rec, operation=Operation.CLEAN)
        approved_record, _ = approval_service.approve(record.approval_id, explicit_consent=True)
        plan, _ = planner.create_plan(approved_record, action=ExecutionAction.TRASH)

        res = executor.execute_trash(plan, custom_trash_root=trash_dir)
        assert res.status == ExecutionStatus.TRASH_SUCCEEDED

        events = repo.get_events_by_approval_id(approved_record.approval_id)
        assert len(events) > 0

        secret_key_hex = approval_service._key_manager._secret_key.hex()

        for ev in events:
            # Confirm HMAC key is not logged anywhere
            assert secret_key_hex not in str(ev.metadata)
            assert secret_key_hex not in ev.reason
            assert secret_key_hex not in ev.status
            assert ev.execution_id == res.execution_id

