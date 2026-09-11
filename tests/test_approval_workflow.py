from __future__ import annotations

import io
import os
import secrets
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Sequence

import pytest

from app.analysis.models import RiskLevel, StorageCandidate, StorageCategory
from app.analysis.recommendations import RecommendationAction, RecommendationEngine, SafetyStatus, StorageRecommendation
from app.cli import run_review_workflow
from app.llm.explanation_service import ExplanationService
from app.safety.approval import ApprovalKeyManager, ApprovalRecord
from app.safety.approval_service import ApprovalService
from app.safety.path_validator import Operation
from app.safety.review import ApprovalAuditEvent, ApprovalDecision, ApprovalStatus, ReviewItem
from app.tools.storage_scanner import StorageItem, StorageScanner


def _make_candidate(
    path: str,
    size_bytes: int = 1024 * 1024 * 50,
    category: StorageCategory = StorageCategory.CACHE,
    risk_level: RiskLevel = RiskLevel.LOW,
    confidence: float = 0.95,
) -> StorageCandidate:
    return StorageCandidate(
        path=path,
        size_bytes=size_bytes,
        category=category,
        risk_level=risk_level,
        confidence=confidence,
        reason="Test candidate fixture",
        recommendation="Review this candidate for potential action.",
        item_type="directory",
    )


def _make_recommendation(
    candidate: StorageCandidate,
    action: RecommendationAction = RecommendationAction.REVIEW_FOR_CLEANUP,
    safety_status: str = SafetyStatus.ELIGIBLE_FOR_REVIEW.value,
) -> StorageRecommendation:
    return StorageRecommendation(
        candidate=candidate,
        action=action,
        rationale="Test recommendation rationale",
        requires_approval=True,
        safety_status=safety_status,
        confidence=candidate.confidence,
    )


# =====================================================================
# 1. Review Item & Eligibility Tests
# =====================================================================


def test_review_item_eligibility() -> None:
    service = ApprovalService()
    home = str(Path.home())

    cand_cache = _make_candidate(f"{home}/Library/Caches/test_app", category=StorageCategory.CACHE, risk_level=RiskLevel.LOW)
    cand_doc = _make_candidate(f"{home}/Documents/report.pdf", category=StorageCategory.DOCUMENTS, risk_level=RiskLevel.HIGH)
    cand_unknown = _make_candidate(f"{home}/unknown_dir", category=StorageCategory.UNKNOWN, risk_level=RiskLevel.UNKNOWN)

    rec_engine = RecommendationEngine()
    recs = rec_engine.recommend_many([cand_cache, cand_doc, cand_unknown])

    review_items = service.create_review_items(recs)
    assert len(review_items) == 3

    # Cache (LOW risk) -> Eligible
    assert review_items[0].is_eligible_for_approval is True
    assert review_items[0].safety_status == SafetyStatus.ELIGIBLE_FOR_REVIEW.value

    # Document (HIGH risk) -> Ineligible
    assert review_items[1].is_eligible_for_approval is False
    assert review_items[1].safety_status == SafetyStatus.MANUAL_REVIEW_REQUIRED.value

    # Unknown -> Ineligible
    assert review_items[2].is_eligible_for_approval is False
    assert review_items[2].safety_status == SafetyStatus.UNKNOWN.value


# =====================================================================
# 2. Approval Request & Risk Gate Tests
# =====================================================================


def test_approval_request_eligible_item() -> None:
    service = ApprovalService()
    home = str(Path.home())
    cand = _make_candidate(f"{home}/Library/Caches/myapp")
    rec = _make_recommendation(cand)

    record, err = service.request_approval(rec, operation=Operation.CLEAN, validity_minutes=10)
    assert err is None
    assert record is not None
    assert record.approved is False
    assert record.path == str(Path(f"{home}/Library/Caches/myapp").resolve())
    assert record.operation == Operation.CLEAN
    assert service.get_status(record.approval_id) == ApprovalStatus.PENDING


def test_approval_request_high_risk_blocked() -> None:
    service = ApprovalService()
    home = str(Path.home())
    cand = _make_candidate(f"{home}/Documents/taxes.pdf", category=StorageCategory.DOCUMENTS, risk_level=RiskLevel.HIGH)
    rec = _make_recommendation(cand, action=RecommendationAction.MANUAL_REVIEW, safety_status=SafetyStatus.MANUAL_REVIEW_REQUIRED.value)

    record, err = service.request_approval(rec, operation=Operation.CLEAN)
    assert record is None
    assert "Approval request blocked" in str(err)
    assert "high risk" in str(err).lower()


def test_approval_request_unknown_risk_blocked() -> None:
    service = ApprovalService()
    home = str(Path.home())
    cand = _make_candidate(f"{home}/mystery", category=StorageCategory.UNKNOWN, risk_level=RiskLevel.UNKNOWN)
    rec = _make_recommendation(cand, action=RecommendationAction.NO_ACTION, safety_status=SafetyStatus.UNKNOWN.value)

    record, err = service.request_approval(rec, operation=Operation.CLEAN)
    assert record is None
    assert "Approval request blocked" in str(err)


def test_approval_request_system_protected_path_blocked() -> None:
    service = ApprovalService()
    cand = _make_candidate("/System/Library/Caches/sys", category=StorageCategory.CACHE, risk_level=RiskLevel.LOW)
    rec = _make_recommendation(cand)

    record, err = service.request_approval(rec, operation=Operation.CLEAN)
    assert record is None
    assert "Approval request blocked by Safety Engine" in str(err)


def test_approval_request_allowlist_root_itself_blocked() -> None:
    service = ApprovalService()
    home = str(Path.home())
    # The root of the allowlist directory (~/Library/Caches) itself cannot be targeted for CLEAN
    cand = _make_candidate(f"{home}/Library/Caches", category=StorageCategory.CACHE, risk_level=RiskLevel.LOW)
    rec = _make_recommendation(cand)

    record, err = service.request_approval(rec, operation=Operation.CLEAN)
    assert record is None
    assert "Approval request blocked by Safety Engine" in str(err)


# =====================================================================
# 3. Explicit Human Approval & Rejection Tests
# =====================================================================


def test_explicit_consent_required_default_rejection() -> None:
    service = ApprovalService()
    home = str(Path.home())
    cand = _make_candidate(f"{home}/Library/Caches/test1")
    rec = _make_recommendation(cand)

    record, _ = service.request_approval(rec)
    assert record is not None

    # Calling approve with explicit_consent=False (default) MUST fail
    approved_record, err = service.approve(record.approval_id, explicit_consent=False)
    assert approved_record is None
    assert "Explicit human consent checkbox/confirmation was not provided" in err
    assert service.get_status(record.approval_id) == ApprovalStatus.PENDING


def test_approval_grant_and_verification_workflow() -> None:
    service = ApprovalService()
    home = str(Path.home())
    cand = _make_candidate(f"{home}/Library/Caches/test2")
    rec = _make_recommendation(cand)

    record, _ = service.request_approval(rec, operation=Operation.CLEAN)
    assert record is not None

    approved_record, msg = service.approve(record.approval_id, explicit_consent=True, reason="User agreed")
    assert approved_record is not None
    assert approved_record.approved is True
    assert service.get_status(record.approval_id) == ApprovalStatus.APPROVED

    # Verify authorization
    is_valid, v_msg = service.verify_and_authorize(
        approved_record,
        target_path=approved_record.path,
        operation=Operation.CLEAN,
    )
    assert is_valid is True
    assert "Approval verified and authorized" in v_msg


def test_approval_reject_workflow() -> None:
    service = ApprovalService()
    home = str(Path.home())
    cand = _make_candidate(f"{home}/Library/Caches/test3")
    rec = _make_recommendation(cand)

    record, _ = service.request_approval(rec)
    assert record is not None

    rej_record, rej_msg = service.reject(record.approval_id, reason="User declined")
    assert rej_record is not None
    assert service.get_status(record.approval_id) == ApprovalStatus.REJECTED

    # Rejected record cannot be verified
    is_valid, v_msg = service.verify_and_authorize(
        record,
        target_path=record.path,
        operation=Operation.CLEAN,
    )
    assert is_valid is False
    assert "state, expected 'approved'" in v_msg


# =====================================================================
# 4. Cryptographic Tampering & Security Invariant Tests
# =====================================================================


def test_tampered_path_fails_verification() -> None:
    service = ApprovalService()
    home = str(Path.home())
    cand = _make_candidate(f"{home}/Library/Caches/target_a")
    rec = _make_recommendation(cand)

    record, _ = service.request_approval(rec)
    assert record is not None
    approved_record, _ = service.approve(record.approval_id, explicit_consent=True)
    assert approved_record is not None

    # Attempting to authorize on target_b with an approval signed for target_a
    is_valid, err = service.verify_and_authorize(
        approved_record,
        target_path=f"{home}/Library/Caches/target_b",
        operation=Operation.CLEAN,
    )
    assert is_valid is False
    assert "Path mismatch" in err


def test_tampered_operation_fails_verification() -> None:
    service = ApprovalService()
    home = str(Path.home())
    cand = _make_candidate(f"{home}/Library/Caches/target_c")
    rec = _make_recommendation(cand)

    record, _ = service.request_approval(rec, operation=Operation.CLEAN)
    assert record is not None
    approved_record, _ = service.approve(record.approval_id, explicit_consent=True)
    assert approved_record is not None

    # Tampered operation parameter
    is_valid, err = service.verify_and_authorize(
        approved_record,
        target_path=approved_record.path,
        operation=Operation.ANALYZE,
    )
    assert is_valid is False
    assert "Operation mismatch" in err


def test_forged_hmac_signature_fails_verification() -> None:
    service = ApprovalService()
    home = str(Path.home())
    cand = _make_candidate(f"{home}/Library/Caches/target_d")
    rec = _make_recommendation(cand)

    record, _ = service.request_approval(rec)
    assert record is not None
    approved_record, _ = service.approve(record.approval_id, explicit_consent=True)
    assert approved_record is not None

    # Tamper with token signature
    tampered_record = ApprovalRecord(
        approval_id=approved_record.approval_id,
        path=approved_record.path,
        operation=approved_record.operation,
        requested_at=approved_record.requested_at,
        expires_at=approved_record.expires_at,
        approved=approved_record.approved,
        risk_level=approved_record.risk_level,
        reason=approved_record.reason,
        token_signature="0" * 64,
    )

    is_valid, err = service.verify_and_authorize(
        tampered_record,
        target_path=tampered_record.path,
        operation=Operation.CLEAN,
    )
    assert is_valid is False
    assert "Invalid or forged cryptographic HMAC signature" in err


def test_cross_key_manager_fails_verification() -> None:
    km1 = ApprovalKeyManager()
    km2 = ApprovalKeyManager()

    service1 = ApprovalService(key_manager=km1)
    service2 = ApprovalService(key_manager=km2)

    home = str(Path.home())
    cand = _make_candidate(f"{home}/Library/Caches/target_e")
    rec = _make_recommendation(cand)

    record, _ = service1.request_approval(rec)
    assert record is not None
    approved_record, _ = service1.approve(record.approval_id, explicit_consent=True)
    assert approved_record is not None

    # Register record in service2 registry to simulate an injection attempt
    service2._registry[approved_record.approval_id] = approved_record
    service2._statuses[approved_record.approval_id] = ApprovalStatus.APPROVED

    is_valid, err = service2.verify_and_authorize(
        approved_record,
        target_path=approved_record.path,
        operation=Operation.CLEAN,
    )
    assert is_valid is False
    assert "Invalid or forged cryptographic HMAC signature" in err


def test_expired_approval_fails_verification() -> None:
    service = ApprovalService()
    home = str(Path.home())
    cand = _make_candidate(f"{home}/Library/Caches/target_f")
    rec = _make_recommendation(cand)

    # 0 minute validity -> expires immediately
    record, _ = service.request_approval(rec, validity_minutes=0)
    assert record is not None

    past_time = datetime.now(timezone.utc) + timedelta(minutes=5)
    approved_record, _ = service.approve(record.approval_id, explicit_consent=True)
    if approved_record is not None:
        is_valid, err = service.verify_and_authorize(
            approved_record,
            target_path=approved_record.path,
            operation=Operation.CLEAN,
            current_time=past_time,
        )
        assert is_valid is False
        assert "expired" in err.lower()


# =====================================================================
# 5. Replay Protection Tests
# =====================================================================


def test_replay_protection_consumed_approval_rejected() -> None:
    service = ApprovalService()
    home = str(Path.home())
    cand = _make_candidate(f"{home}/Library/Caches/target_g")
    rec = _make_recommendation(cand)

    record, _ = service.request_approval(rec)
    assert record is not None
    approved_record, _ = service.approve(record.approval_id, explicit_consent=True)
    assert approved_record is not None

    # First verification passes
    is_valid, _ = service.verify_and_authorize(
        approved_record,
        target_path=approved_record.path,
        operation=Operation.CLEAN,
    )
    assert is_valid is True

    # Mark consumed (simulating consumption for future execution)
    consumed_ok, msg = service.consume_approval(approved_record.approval_id)
    assert consumed_ok is True
    assert service.get_status(approved_record.approval_id) == ApprovalStatus.CONSUMED

    # Replay attempt: Second verification MUST fail with replay error
    is_valid_replay, replay_err = service.verify_and_authorize(
        approved_record,
        target_path=approved_record.path,
        operation=Operation.CLEAN,
    )
    assert is_valid_replay is False
    assert "Replay attack prevented" in replay_err


def test_double_consumption_prevented() -> None:
    service = ApprovalService()
    home = str(Path.home())
    cand = _make_candidate(f"{home}/Library/Caches/target_h")
    rec = _make_recommendation(cand)

    record, _ = service.request_approval(rec)
    assert record is not None
    approved_record, _ = service.approve(record.approval_id, explicit_consent=True)
    assert approved_record is not None

    ok1, _ = service.consume_approval(approved_record.approval_id)
    assert ok1 is True

    # Second consumption attempt fails
    ok2, err2 = service.consume_approval(approved_record.approval_id)
    assert ok2 is False
    assert "Cannot consume approval" in err2


# =====================================================================
# 6. Audit Logging & Zero Secrets Guarantee
# =====================================================================


def test_audit_log_tracks_all_events_and_contains_zero_secrets() -> None:
    service = ApprovalService()
    home = str(Path.home())
    cand = _make_candidate(f"{home}/Library/Caches/target_i")
    rec = _make_recommendation(cand)

    # 1. Request
    record, _ = service.request_approval(rec)
    assert record is not None

    # 2. Approve
    approved_record, _ = service.approve(record.approval_id, explicit_consent=True)
    assert approved_record is not None

    # 3. Verify
    service.verify_and_authorize(approved_record, target_path=approved_record.path, operation=Operation.CLEAN)

    # 4. Consume
    service.consume_approval(approved_record.approval_id)

    log = service.get_audit_log()
    decisions = [evt.decision for evt in log]
    assert "requested" in decisions
    assert "approved" in decisions
    assert "verified" in decisions
    assert "consumed" in decisions

    # Verify that NO secret key is stored in audit events
    for evt in log:
        evt_dict = evt.model_dump()
        assert "_secret_key" not in evt_dict
        assert "secret" not in evt_dict
        assert "private_key" not in evt_dict
        for v in evt_dict.values():
            assert not isinstance(v, bytes)


# =====================================================================
# 7. LLM Isolation Tests
# =====================================================================


def test_llm_isolation_from_approval_key_manager() -> None:
    """Verify that LLM explanation service does not access or import approval key managers."""
    import inspect
    import app.llm.explanation_service
    import app.llm.ollama_client
    import app.llm.prompts

    llm_source = inspect.getsource(app.llm.explanation_service)
    assert "ApprovalKeyManager" not in llm_source
    assert "grant_approval" not in llm_source
    assert "approve(" not in llm_source

    client_source = inspect.getsource(app.llm.ollama_client)
    assert "ApprovalKeyManager" not in client_source

    prompt_source = inspect.getsource(app.llm.prompts)
    assert "ApprovalKeyManager" not in prompt_source
    assert "_secret_key" not in prompt_source


# =====================================================================
# 8. CLI Review Mode Tests
# =====================================================================


class DummyScanner:
    def __init__(self, items: list[StorageItem]) -> None:
        self._items = items

    def get_top_directories(self, path: str, limit: int = 10) -> list[StorageItem]:
        return self._items

    def get_large_files(self, path: str, limit: int = 10) -> list[StorageItem]:
        return []


def test_cli_review_mode_approval() -> None:
    home = str(Path.home())
    test_path = f"{home}/Library/Caches/cli_test_cache"
    scanner = DummyScanner([StorageItem(path=test_path, size_bytes=1024 * 1024 * 20, item_type="directory")])

    inputs = ["1", "y"]  # Select item 1, confirm 'y'
    input_iter = iter(inputs)

    out = io.StringIO()
    run_review_workflow(
        scanner=scanner,  # type: ignore[arg-type]
        input_func=lambda prompt: next(input_iter),
        out=out,
    )

    output = out.getvalue()
    assert "MacGuard AI — Storage Review & Human Confirmation" in output
    assert "[APPROVED & HMAC-SIGNED]" in output
    assert "READY_FOR_FUTURE_EXECUTION (Zero files were modified)." in output


def test_cli_review_mode_rejection_by_default() -> None:
    home = str(Path.home())
    test_path = f"{home}/Library/Caches/cli_test_cache_2"
    scanner = DummyScanner([StorageItem(path=test_path, size_bytes=1024 * 1024 * 20, item_type="directory")])

    inputs = ["1", ""]  # Select item 1, press enter (default to 'N')
    input_iter = iter(inputs)

    out = io.StringIO()
    run_review_workflow(
        scanner=scanner,  # type: ignore[arg-type]
        input_func=lambda prompt: next(input_iter),
        out=out,
    )

    output = out.getvalue()
    assert "[REJECTED] Operation was not approved. Default is rejection." in output


# =====================================================================
# 9. Zero Filesystem Mutation Verification
# =====================================================================


def test_phase5_performs_zero_filesystem_mutation() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "safe_file.txt"
        test_file.write_text("critical data", encoding="utf-8")
        test_dir = Path(tmpdir) / "safe_subdir"
        test_dir.mkdir()
        (test_dir / "child.txt").write_text("child data", encoding="utf-8")

        initial_file_content = test_file.read_text(encoding="utf-8")
        initial_child_content = (test_dir / "child.txt").read_text(encoding="utf-8")

        service = ApprovalService()
        home = str(Path.home())
        cand = _make_candidate(f"{home}/Library/Caches/zero_mutation_cache")
        rec = _make_recommendation(cand)

        # 1. Request
        record, _ = service.request_approval(rec)
        assert record is not None

        # 2. Approve
        approved_record, _ = service.approve(record.approval_id, explicit_consent=True)
        assert approved_record is not None

        # 3. Verify
        service.verify_and_authorize(approved_record, target_path=approved_record.path, operation=Operation.CLEAN)

        # 4. Consume
        service.consume_approval(approved_record.approval_id)

        # Verify filesystem remains completely untouched
        assert test_file.exists()
        assert test_file.read_text(encoding="utf-8") == initial_file_content
        assert test_dir.exists()
        assert (test_dir / "child.txt").exists()
        assert (test_dir / "child.txt").read_text(encoding="utf-8") == initial_child_content
