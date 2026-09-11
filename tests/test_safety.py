from __future__ import annotations

import hashlib
import os
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.analysis.models import RiskLevel
from app.analysis.recommendations import RecommendationEngine, StorageCandidate, StorageCategory
from app.safety.approval import (
    ApprovalKeyManager,
    ApprovalRecord,
    get_default_key_manager,
    grant_approval,
    request_approval,
    reset_default_key_manager,
    validate_approval,
)
from app.safety.canonicalizer import (
    canonicalize_path,
    is_contained_within,
)
from app.safety.path_validator import (
    Operation,
    PathValidator,
)


# =====================================================================
# 1. CANONICALIZATION TESTS
# =====================================================================

def test_canonicalize_empty_and_null_bytes():
    with pytest.raises(ValueError, match="Path cannot be empty"):
        canonicalize_path("")

    with pytest.raises(ValueError, match="Path cannot be empty"):
        canonicalize_path("   ")

    with pytest.raises(ValueError, match="null byte"):
        canonicalize_path("/path/with/\x00/null")


def test_canonicalize_absolute_and_relative(tmp_path: Path):
    sub = tmp_path / "sub"
    sub.mkdir()
    rel = Path(os.path.relpath(sub, Path.cwd()))

    res = canonicalize_path(rel)
    assert res.canonical_path == sub.resolve()
    assert res.exists is True
    assert res.is_dir is True


def test_canonicalize_home_expansion():
    res = canonicalize_path("~/Library/Caches")
    expected = (Path.home() / "Library/Caches").resolve()
    assert res.canonical_path == expected


def test_canonicalize_symlink_resolution(tmp_path: Path):
    target_dir = tmp_path / "target_dir"
    target_dir.mkdir()
    target_file = target_dir / "target_file.txt"
    target_file.write_text("content")

    symlink_path = tmp_path / "link_to_file"
    symlink_path.symlink_to(target_file)

    res = canonicalize_path(symlink_path)
    assert res.canonical_path == target_file.resolve()
    assert res.is_symlink is True
    assert res.is_file is True
    assert res.exists is True


def test_canonicalize_nonexistent_path(tmp_path: Path):
    nonexistent = tmp_path / "nonexistent_sub" / "file.txt"
    res = canonicalize_path(nonexistent)
    assert res.canonical_path == nonexistent.resolve()
    assert res.exists is False
    assert res.is_file is False
    assert res.is_dir is False


# =====================================================================
# 2. PATH POLICY & PROTECTED PATHS TESTS
# =====================================================================

def test_system_protected_roots_rejected_for_clean():
    validator = PathValidator()
    protected_system_paths = [
        "/",
        "/System",
        "/System/Library",
        "/usr",
        "/bin",
        "/sbin",
        "/private",
        "/private/var",
        "/Applications",
        "/Library",
        "/Volumes",
    ]

    for p in protected_system_paths:
        res = validator.validate_path(p, operation=Operation.CLEAN)
        assert res.allowed is False
        assert res.operation == Operation.CLEAN
        assert res.risk_level == RiskLevel.HIGH or res.risk_level == RiskLevel.UNKNOWN

        # Should be allowed for read-only ANALYZE
        res_analyze = validator.validate_path(p, operation=Operation.ANALYZE)
        assert res_analyze.allowed is True


def test_user_home_root_rejected_for_clean(tmp_path: Path):
    home = tmp_path / "fake_home"
    home.mkdir()
    validator = PathValidator(home_dir=home)

    res = validator.validate_path(home, operation=Operation.CLEAN)
    assert res.allowed is False
    assert res.policy_rule == "RULE_HOME_ROOT_PROTECTION"


def test_sensitive_user_subdirs_rejected_for_clean(tmp_path: Path):
    home = tmp_path / "fake_home"
    home.mkdir()
    validator = PathValidator(home_dir=home)

    sensitive_paths = [
        home / ".ssh",
        home / ".ssh" / "id_rsa",
        home / "Documents",
        home / "Documents" / "tax_returns.pdf",
        home / "Desktop" / "secret.txt",
        home / "Pictures" / "vacation.png",
        home / "Library/Preferences" / "com.apple.app.plist",
    ]

    for p in sensitive_paths:
        res = validator.validate_path(p, operation=Operation.CLEAN)
        assert res.allowed is False
        assert res.policy_rule == "RULE_SENSITIVE_USER_PATH_PROTECTION"


def test_allowlist_subpaths_allowed_for_clean(tmp_path: Path):
    home = tmp_path / "fake_home"
    home.mkdir()
    caches_dir = home / "Library" / "Caches"
    caches_dir.mkdir(parents=True)

    app_cache = caches_dir / "com.example.app"
    app_cache.mkdir()

    validator = PathValidator(
        home_dir=home,
        custom_allowlist_roots=[caches_dir],
    )

    # Subpath inside allowlist should be allowed for CLEAN
    res = validator.validate_path(app_cache, operation=Operation.CLEAN)
    assert res.allowed is True
    assert res.policy_rule == "RULE_ALLOWLIST_CONTAINED"

    # Allowlist root itself must NOT be allowed for CLEAN
    res_root = validator.validate_path(caches_dir, operation=Operation.CLEAN)
    assert res_root.allowed is False
    assert res_root.policy_rule == "RULE_ALLOWLIST_ROOT_PROTECTION"


def test_similar_prefix_path_protection(tmp_path: Path):
    home = tmp_path / "fake_home"
    home.mkdir()
    evil_home = tmp_path / "fake_home_evil"
    evil_home.mkdir()

    caches_dir = home / "Library" / "Caches"
    caches_dir.mkdir(parents=True)
    evil_caches_dir = evil_home / "Library" / "Caches" / "app"
    evil_caches_dir.mkdir(parents=True)

    validator = PathValidator(
        home_dir=home,
        custom_allowlist_roots=[caches_dir],
    )

    res = validator.validate_path(evil_caches_dir, operation=Operation.CLEAN)
    assert res.allowed is False
    assert res.policy_rule == "RULE_ALLOWLIST_REJECTED"


# =====================================================================
# 3. PATH TRAVERSAL & CONTAINMENT TESTS
# =====================================================================

def test_path_traversal_escape_rejected(tmp_path: Path):
    home = tmp_path / "fake_home"
    home.mkdir()
    caches_dir = home / "Library" / "Caches"
    caches_dir.mkdir(parents=True)

    docs_dir = home / "Documents"
    docs_dir.mkdir()
    secret_file = docs_dir / "secret.pdf"
    secret_file.write_text("confidential")

    validator = PathValidator(
        home_dir=home,
        custom_allowlist_roots=[caches_dir],
    )

    # Attempt traversal from inside cache to escape into Documents
    traversal_path = str(caches_dir) + "/../../Documents/secret.pdf"
    res = validator.validate_path(traversal_path, operation=Operation.CLEAN)

    assert res.allowed is False
    assert res.canonical_path == str(secret_file.resolve())
    assert res.policy_rule == "RULE_SENSITIVE_USER_PATH_PROTECTION"


def test_symlink_escape_rejected(tmp_path: Path):
    home = tmp_path / "fake_home"
    home.mkdir()
    caches_dir = home / "Library" / "Caches"
    caches_dir.mkdir(parents=True)

    docs_dir = home / "Documents"
    docs_dir.mkdir()
    secret_file = docs_dir / "private.txt"
    secret_file.write_text("top secret")

    # Symlink placed inside Caches pointing to Documents
    symlink_in_cache = caches_dir / "link_to_docs"
    symlink_in_cache.symlink_to(secret_file)

    validator = PathValidator(
        home_dir=home,
        custom_allowlist_roots=[caches_dir],
    )

    res = validator.validate_path(symlink_in_cache, operation=Operation.CLEAN)
    # Canonicalizer resolves link to secret_file in Documents -> Rejected!
    assert res.allowed is False
    assert res.canonical_path == str(secret_file.resolve())


def test_is_contained_within(tmp_path: Path):
    parent = tmp_path / "parent_dir"
    parent.mkdir()
    child = parent / "child_dir" / "file.txt"

    assert is_contained_within(child, parent) is True
    assert is_contained_within(parent, parent) is False
    assert is_contained_within(tmp_path, parent) is False


# =====================================================================
# 4. HMAC-SHA256 HUMAN APPROVAL TESTS
# =====================================================================

def test_approval_lifecycle_and_validation(tmp_path: Path):
    target = tmp_path / "target_cache"
    target.mkdir()

    # 1. Request approval
    req = request_approval(
        path=target,
        operation=Operation.CLEAN,
        risk_level=RiskLevel.LOW,
        reason="Cleaning stale test cache",
        validity_minutes=10,
    )
    assert req.approved is False
    assert len(req.approval_id) >= 16
    assert len(req.token_signature) == 64  # HMAC-SHA256 hex string

    # 2. Before approval, validate_approval must reject
    valid, msg = validate_approval(
        record=req,
        target_path=target,
        expected_operation=Operation.CLEAN,
        expected_risk=RiskLevel.LOW,
    )
    assert valid is False
    assert "not been explicitly approved" in msg

    # 3. Grant human approval
    granted = grant_approval(req)
    assert granted.approved is True
    assert len(granted.token_signature) == 64

    # 4. After approval, validate_approval must succeed
    valid_after, success_msg = validate_approval(
        record=granted,
        target_path=target,
        expected_operation=Operation.CLEAN,
        expected_risk=RiskLevel.LOW,
    )
    assert valid_after is True
    assert "Approval verified successfully" in success_msg


def test_approval_expired_rejected(tmp_path: Path):
    target = tmp_path / "target_cache"
    target.mkdir()

    req = request_approval(
        path=target,
        operation=Operation.CLEAN,
        risk_level=RiskLevel.LOW,
        reason="Test",
        validity_minutes=5,
    )
    granted = grant_approval(req)

    # Simulate future time 10 minutes later (beyond 5-minute validity)
    future_time = granted.requested_at + timedelta(minutes=10)

    valid, msg = validate_approval(
        record=granted,
        target_path=target,
        expected_operation=Operation.CLEAN,
        expected_risk=RiskLevel.LOW,
        current_time=future_time,
    )
    assert valid is False
    assert "expired" in msg.lower()


def test_approval_mismatched_parameters_rejected(tmp_path: Path):
    target_a = tmp_path / "target_a"
    target_b = tmp_path / "target_b"
    target_a.mkdir()
    target_b.mkdir()

    req = request_approval(
        path=target_a,
        operation=Operation.CLEAN,
        risk_level=RiskLevel.LOW,
        reason="Test",
    )
    granted = grant_approval(req)

    # Wrong path
    valid_path, msg_path = validate_approval(
        record=granted,
        target_path=target_b,
        expected_operation=Operation.CLEAN,
        expected_risk=RiskLevel.LOW,
    )
    assert valid_path is False
    assert "Path mismatch" in msg_path

    # Wrong operation
    valid_op, msg_op = validate_approval(
        record=granted,
        target_path=target_a,
        expected_operation=Operation.ANALYZE,
        expected_risk=RiskLevel.LOW,
    )
    assert valid_op is False
    assert "Operation mismatch" in msg_op

    # Wrong risk level
    valid_risk, msg_risk = validate_approval(
        record=granted,
        target_path=target_a,
        expected_operation=Operation.CLEAN,
        expected_risk=RiskLevel.HIGH,
    )
    assert valid_risk is False
    assert "Risk level mismatch" in msg_risk


def test_approval_forgery_with_unkeyed_sha256_rejected(tmp_path: Path):
    """
    Directly tests SEC-01 remediation:
    An attacker who constructs a fake approval using an unkeyed SHA-256 hash
    MUST be rejected by validate_approval() because the attacker lacks the HMAC secret.
    """
    target = tmp_path / "target_dir"
    target.mkdir()
    canonical_str = str(target.resolve())

    approval_id = "fake_attacker_id_12345"
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=15)
    expires_iso = expires.isoformat()

    # Attacker attempts to forge signature using unkeyed SHA-256
    unkeyed_payload = f"macguard-approval-v1|id={approval_id}|path={canonical_str}|op=CLEAN|exp={expires_iso}|risk=LOW|appr=true"
    fake_sha256_signature = hashlib.sha256(unkeyed_payload.encode("utf-8")).hexdigest()

    forged_record = ApprovalRecord(
        approval_id=approval_id,
        path=canonical_str,
        operation=Operation.CLEAN,
        requested_at=now,
        expires_at=expires,
        approved=True,
        risk_level=RiskLevel.LOW,
        reason="Attacker trying to authorize cleanup",
        token_signature=fake_sha256_signature,
    )

    valid, msg = validate_approval(
        record=forged_record,
        target_path=target,
        expected_operation=Operation.CLEAN,
        expected_risk=RiskLevel.LOW,
    )
    assert valid is False
    assert "Invalid or forged cryptographic HMAC signature" in msg


def test_approval_tampered_signature_rejected(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()

    req = request_approval(
        path=target,
        operation=Operation.CLEAN,
        risk_level=RiskLevel.LOW,
        reason="Test",
    )
    granted = grant_approval(req)

    # Forging via construction with invalid signature
    tampered = ApprovalRecord(
        approval_id=granted.approval_id,
        path=str((tmp_path / "other").resolve()),
        operation=granted.operation,
        requested_at=granted.requested_at,
        expires_at=granted.expires_at,
        approved=True,
        risk_level=granted.risk_level,
        reason=granted.reason,
        token_signature=granted.token_signature,  # Signature was for 'target', not 'other'
    )

    valid, msg = validate_approval(
        record=tampered,
        target_path=tmp_path / "other",
        expected_operation=Operation.CLEAN,
        expected_risk=RiskLevel.LOW,
    )
    assert valid is False
    assert "Invalid or forged cryptographic HMAC signature" in msg


def test_approval_key_isolation_and_cross_key_invalidation(tmp_path: Path):
    """
    Verifies that approvals signed with Key A fail validation under Key B (simulating app restart).
    """
    key_manager_a = ApprovalKeyManager()
    key_manager_b = ApprovalKeyManager()

    target = tmp_path / "target"
    target.mkdir()

    req = request_approval(
        path=target,
        operation=Operation.CLEAN,
        risk_level=RiskLevel.LOW,
        reason="Test",
        key_manager=key_manager_a,
    )
    granted = grant_approval(req, key_manager=key_manager_a)

    # Validate with same Key A -> Success
    valid_a, _ = validate_approval(
        record=granted,
        target_path=target,
        expected_operation=Operation.CLEAN,
        expected_risk=RiskLevel.LOW,
        key_manager=key_manager_a,
    )
    assert valid_a is True

    # Validate with different Key B -> Rejection!
    valid_b, msg_b = validate_approval(
        record=granted,
        target_path=target,
        expected_operation=Operation.CLEAN,
        expected_risk=RiskLevel.LOW,
        key_manager=key_manager_b,
    )
    assert valid_b is False
    assert "Invalid or forged cryptographic HMAC signature" in msg_b


def test_reset_default_key_manager_invalidates_past_approvals(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()

    req = request_approval(
        path=target,
        operation=Operation.CLEAN,
        risk_level=RiskLevel.LOW,
        reason="Test",
    )
    granted = grant_approval(req)

    # Valid before reset
    valid_before, _ = validate_approval(
        record=granted,
        target_path=target,
        expected_operation=Operation.CLEAN,
        expected_risk=RiskLevel.LOW,
    )
    assert valid_before is True

    # Reset default key manager (simulating application restart)
    reset_default_key_manager()

    # Invalid after reset
    valid_after, msg_after = validate_approval(
        record=granted,
        target_path=target,
        expected_operation=Operation.CLEAN,
        expected_risk=RiskLevel.LOW,
    )
    assert valid_after is False
    assert "Invalid or forged cryptographic HMAC signature" in msg_after


def test_secret_is_never_leaked_in_models(tmp_path: Path):
    """
    Verifies that the secret key is never included in serialized approval models,
    string representations, or recommendation models.
    """
    km = ApprovalKeyManager()
    secret_bytes = km._secret_key
    secret_hex = secret_bytes.hex()

    target = tmp_path / "target"
    target.mkdir()

    req = request_approval(
        path=target,
        operation=Operation.CLEAN,
        risk_level=RiskLevel.LOW,
        reason="Test",
        key_manager=km,
    )
    granted = grant_approval(req, key_manager=km)

    record_dict = granted.model_dump()
    record_json = granted.model_dump_json()
    record_str = str(granted)

    assert "_secret_key" not in record_dict
    assert "secret" not in record_dict
    assert secret_hex not in record_json
    assert secret_hex not in record_str

    # Test recommendation engine output
    candidate = StorageCandidate(
        path=str(target),
        size_bytes=100,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.9,
        reason="Test",
        recommendation="Test",
    )
    engine = RecommendationEngine()
    rec = engine.recommend(candidate)
    rec_json = rec.model_dump_json()

    assert secret_hex not in rec_json
    assert "_secret_key" not in rec.model_dump()


def test_key_manager_requires_256_bit_entropy():
    with pytest.raises(ValueError, match="at least 32 bytes"):
        ApprovalKeyManager(secret_key=b"too_short_key_123")


# =====================================================================
# 5. SAFETY INVARIANT TEST (NO FILESYSTEM MUTATION)
# =====================================================================

def test_safety_layer_performs_zero_filesystem_mutation(tmp_path: Path):
    """
    Guarantees that executing canonicalization, path validation,
    and approval workflows causes ZERO modification to files or directories.
    """
    test_file = tmp_path / "file.txt"
    test_file.write_text("initial immutable content")
    initial_stat = test_file.stat()

    # Run canonicalization
    canonicalize_path(test_file)
    canonicalize_path(tmp_path / "nonexistent")

    # Run path validation
    validator = PathValidator(home_dir=tmp_path)
    validator.validate_path(test_file, operation=Operation.CLEAN)
    validator.validate_path(test_file, operation=Operation.ANALYZE)
    validator.validate_path("/", operation=Operation.CLEAN)

    # Run approval creation & validation
    req = request_approval(test_file, Operation.CLEAN, RiskLevel.LOW, "Test invariant")
    granted = grant_approval(req)
    validate_approval(granted, test_file, Operation.CLEAN, RiskLevel.LOW)

    # Verify file contents, size, and mtime remain identical
    assert test_file.read_text() == "initial immutable content"
    current_stat = test_file.stat()
    assert current_stat.st_size == initial_stat.st_size
    assert current_stat.st_mtime == initial_stat.st_mtime
