from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, Union
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from app.analysis.models import RiskLevel
from app.safety.canonicalizer import canonicalize_path
from app.safety.path_validator import Operation


class ApprovalKeyManager:
    """
    Manages an in-memory 256-bit cryptographic secret key used for signing and
    verifying ApprovalRecords with HMAC-SHA256.

    Security Guarantees:
    - 256-bit entropy generated via secrets.token_bytes(32).
    - Secret key is never derived from user input, paths, timestamps, or LLM output.
    - Secret key is NEVER included in ApprovalRecords, recommendations, prompts, or logs.
    - Ephemeral: Restarting the application or instantiating a new KeyManager invalidates past approvals.
    """

    def __init__(self, secret_key: Optional[bytes] = None) -> None:
        if secret_key is not None:
            if not isinstance(secret_key, bytes) or len(secret_key) < 32:
                raise ValueError(
                    "Secret key must be bytes with at least 32 bytes of entropy (256 bits)."
                )
            self._secret_key = secret_key
        else:
            self._secret_key = secrets.token_bytes(32)

    def sign(self, payload: str) -> str:
        """Generate HMAC-SHA256 signature for the given payload string."""
        return hmac.new(
            self._secret_key,
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def verify(self, payload: str, signature: str) -> bool:
        """Constant-time verification of HMAC-SHA256 signature."""
        if not signature:
            return False
        expected_sig = self.sign(payload)
        return secrets.compare_digest(expected_sig, signature)


# Process-wide default ephemeral key manager
_DEFAULT_KEY_MANAGER = ApprovalKeyManager()


def get_default_key_manager() -> ApprovalKeyManager:
    """Retrieve the process-wide default key manager."""
    return _DEFAULT_KEY_MANAGER


def reset_default_key_manager() -> ApprovalKeyManager:
    """
    Reset the process-wide default key manager with a new ephemeral key.
    Invalidates all previously issued approvals under the default key manager.
    """
    global _DEFAULT_KEY_MANAGER
    _DEFAULT_KEY_MANAGER = ApprovalKeyManager()
    return _DEFAULT_KEY_MANAGER


class ApprovalRecord(BaseModel):
    """
    Structured, tamper-evident record of explicit human approval.

    This is an immutable safety primitive and performs no filesystem mutations.
    Contains no secret keys.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    approval_id: str = Field(
        ...,
        min_length=16,
        description="Cryptographically secure, unpredictable approval identifier.",
    )
    path: str = Field(
        ...,
        min_length=1,
        description="Canonical target path scoped to this approval.",
    )
    operation: Operation = Field(
        ...,
        description="Exact operation authorized by human.",
    )
    requested_at: datetime = Field(
        ...,
        description="UTC timestamp when approval was requested.",
    )
    expires_at: datetime = Field(
        ...,
        description="UTC timestamp after which approval is invalid.",
    )
    approved: bool = Field(
        ...,
        description="Whether explicit consent was granted by the human.",
    )
    risk_level: RiskLevel = Field(
        ...,
        description="Risk classification presented to human at time of approval.",
    )
    reason: str = Field(
        ...,
        min_length=1,
        description="Contextual reason provided for the proposed action.",
    )
    token_signature: str = Field(
        ...,
        min_length=32,
        description="HMAC-SHA256 signature verifying payload authenticity and integrity.",
    )


def _canonical_payload(
    approval_id: str,
    canonical_path: str,
    operation: Operation,
    expires_at_iso: str,
    risk_level: RiskLevel,
    approved: bool,
) -> str:
    """
    Produce a deterministic, unambiguous canonical payload string for HMAC computation.
    """
    return (
        f"macguard-approval-v1|"
        f"id={approval_id}|"
        f"path={canonical_path}|"
        f"op={operation.value}|"
        f"exp={expires_at_iso}|"
        f"risk={risk_level.value}|"
        f"appr={'true' if approved else 'false'}"
    )


def request_approval(
    path: Union[str, Path],
    operation: Operation,
    risk_level: RiskLevel,
    reason: str,
    validity_minutes: int = 15,
    key_manager: Optional[ApprovalKeyManager] = None,
) -> ApprovalRecord:
    """
    Create a new unapproved ApprovalRecord pending human confirmation.
    Signed with HMAC-SHA256 using the designated key manager.
    """
    km = key_manager or _DEFAULT_KEY_MANAGER
    canonical_info = canonicalize_path(path)
    canonical_str = canonical_info.path_str

    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=validity_minutes)
    expires_iso = expires.isoformat()

    approval_id = secrets.token_hex(16)
    approved = False

    payload = _canonical_payload(
        approval_id=approval_id,
        canonical_path=canonical_str,
        operation=operation,
        expires_at_iso=expires_iso,
        risk_level=risk_level,
        approved=approved,
    )
    signature = km.sign(payload)

    return ApprovalRecord(
        approval_id=approval_id,
        path=canonical_str,
        operation=operation,
        requested_at=now,
        expires_at=expires,
        approved=approved,
        risk_level=risk_level,
        reason=reason,
        token_signature=signature,
    )


def grant_approval(
    record: ApprovalRecord,
    key_manager: Optional[ApprovalKeyManager] = None,
) -> ApprovalRecord:
    """
    Explicitly grant human approval for an existing ApprovalRecord.
    Signs the approved state using HMAC-SHA256.
    """
    if record.approved:
        return record

    km = key_manager or _DEFAULT_KEY_MANAGER
    expires_iso = record.expires_at.isoformat()

    payload = _canonical_payload(
        approval_id=record.approval_id,
        canonical_path=record.path,
        operation=record.operation,
        expires_at_iso=expires_iso,
        risk_level=record.risk_level,
        approved=True,
    )
    new_signature = km.sign(payload)

    return ApprovalRecord(
        approval_id=record.approval_id,
        path=record.path,
        operation=record.operation,
        requested_at=record.requested_at,
        expires_at=record.expires_at,
        approved=True,
        risk_level=record.risk_level,
        reason=record.reason,
        token_signature=new_signature,
    )


def validate_approval(
    record: Optional[ApprovalRecord],
    target_path: Union[str, Path],
    expected_operation: Operation,
    expected_risk: RiskLevel,
    current_time: Optional[datetime] = None,
    key_manager: Optional[ApprovalKeyManager] = None,
) -> tuple[bool, str]:
    """
    Validate that an approval record authorizes the intended operation.

    Rejects:
    - Missing/None records
    - Unapproved records
    - Expired records
    - Path mismatch (after canonicalization)
    - Operation mismatch
    - Risk mismatch
    - Tampered payload fields
    - Invalid or forged HMAC signatures (requiring the 256-bit runtime secret)

    Returns:
        (is_valid, rejection_reason_or_success_message)
    """
    if record is None:
        return False, "Approval rejected: No approval record provided."

    if not record.approved:
        return False, "Approval rejected: Record has not been explicitly approved by human."

    if current_time is None:
        current_time = datetime.now(timezone.utc)
    elif current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=timezone.utc)

    if current_time > record.expires_at:
        return False, f"Approval rejected: Record expired at {record.expires_at.isoformat()}."

    # Validate target path canonical equivalence
    try:
        target_canonical = canonicalize_path(target_path).path_str
    except Exception as exc:
        return False, f"Approval rejected: Target path cannot be canonicalized ({exc})."

    if target_canonical != record.path:
        return False, f"Approval rejected: Path mismatch (approved for '{record.path}', attempted on '{target_canonical}')."

    if record.operation != expected_operation:
        return False, f"Approval rejected: Operation mismatch (approved for '{record.operation.value}', attempted '{expected_operation.value}')."

    if record.risk_level != expected_risk:
        return False, f"Approval rejected: Risk level mismatch (approved as '{record.risk_level.value}', expected '{expected_risk.value}')."

    # Verify HMAC-SHA256 signature authenticity
    km = key_manager or _DEFAULT_KEY_MANAGER
    payload = _canonical_payload(
        approval_id=record.approval_id,
        canonical_path=record.path,
        operation=record.operation,
        expires_at_iso=record.expires_at.isoformat(),
        risk_level=record.risk_level,
        approved=record.approved,
    )

    if not km.verify(payload, record.token_signature):
        return False, "Approval rejected: Invalid or forged cryptographic HMAC signature."

    return True, f"Approval verified successfully for '{record.path}'."
