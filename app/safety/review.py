from __future__ import annotations

import secrets
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.analysis.models import RiskLevel, StorageCandidate
from app.analysis.recommendations import StorageRecommendation
from app.safety.path_validator import Operation


class ApprovalStatus(str, Enum):
    """
    Lifecycle status of an approval request.
    """

    PENDING = "pending"
    APPROVED = "approved"
    EXECUTION_CLAIMED = "execution_claimed"
    REJECTED = "rejected"
    CONSUMED = "consumed"
    EXPIRED = "expired"
    FAILED = "failed"


class ReviewItem(BaseModel):
    """
    Presentation model for a recommendation submitted for human review.

    This is an immutable review model and contains no secret keys or execution capabilities.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    candidate: StorageCandidate = Field(
        ...,
        description="The underlying analyzed storage candidate.",
    )
    recommendation: StorageRecommendation = Field(
        ...,
        description="The deterministic storage recommendation.",
    )
    safety_status: str = Field(
        ...,
        min_length=1,
        description="Safety status (e.g. eligible_for_review, manual_review_required, blocked).",
    )
    risk_level: RiskLevel = Field(
        ...,
        description="Assessed risk level.",
    )
    requires_approval: bool = Field(
        default=True,
        description="Indicates that explicit human approval is mandatory.",
    )
    is_eligible_for_approval: bool = Field(
        ...,
        description="Whether this item is eligible for human cleanup approval.",
    )
    review_message: str = Field(
        ...,
        min_length=1,
        description="Human-readable guidance explaining the safety status and review expectations.",
    )


class ApprovalDecision(BaseModel):
    """
    Structured record representing a human user's explicit approval or rejection decision.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    approval_id: str = Field(
        ...,
        min_length=16,
        description="The unique approval request identifier.",
    )
    path: str = Field(
        ...,
        min_length=1,
        description="The canonical path subject to the decision.",
    )
    operation: Operation = Field(
        ...,
        description="The target filesystem operation.",
    )
    risk_level: RiskLevel = Field(
        ...,
        description="Risk level assessed at the time of decision.",
    )
    approved: bool = Field(
        ...,
        description="Whether explicit consent was granted (True) or rejected (False).",
    )
    requested_at: datetime = Field(
        ...,
        description="UTC timestamp when approval was requested.",
    )
    expires_at: datetime = Field(
        ...,
        description="UTC timestamp after which approval is invalid.",
    )
    decision_at: datetime = Field(
        ...,
        description="UTC timestamp when the human made the decision.",
    )
    reason: Optional[str] = Field(
        default=None,
        description="Optional human-provided or system contextual rationale.",
    )


class ApprovalAuditEvent(BaseModel):
    """
    Audit log event recording all approval lifecycle actions.

    Guarantees:
    - Contains zero secret keys, tokens, or private credentials.
    - Immutable for forensic review.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str = Field(
        default_factory=lambda: secrets.token_hex(8),
        description="Unique identifier for the audit event.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the event occurred.",
    )
    approval_id: str = Field(
        ...,
        description="Related approval request identifier.",
    )
    path: str = Field(
        ...,
        description="Canonical path associated with the approval.",
    )
    operation: Operation = Field(
        ...,
        description="Operation associated with the approval.",
    )
    risk_level: RiskLevel = Field(
        ...,
        description="Risk level associated with the approval.",
    )
    decision: str = Field(
        ...,
        description="Lifecycle action (e.g., requested, approved, rejected, verified, consumed, expired).",
    )
    actor: str = Field(
        default="human",
        description="Actor performing the action (strictly human or safety_engine).",
    )
    result: str = Field(
        ...,
        description="Outcome of the action (e.g. SUCCESS, REJECTED, BLOCKED, ERROR).",
    )
    reason: str = Field(
        ...,
        description="Contextual reason or error description.",
    )
