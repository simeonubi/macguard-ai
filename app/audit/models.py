from __future__ import annotations

import secrets
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.analysis.models import RiskLevel
from app.safety.path_validator import Operation


class AuditEventType(str, Enum):
    """
    Standard lifecycle audit event types for MacGuard AI.
    """

    APPROVAL_REQUESTED = "APPROVAL_REQUESTED"
    APPROVAL_APPROVED = "APPROVAL_APPROVED"
    APPROVAL_REJECTED = "APPROVAL_REJECTED"
    APPROVAL_VERIFIED = "APPROVAL_VERIFIED"
    EXECUTION_CLAIMED = "EXECUTION_CLAIMED"
    INTEGRITY_CHECK_STARTED = "INTEGRITY_CHECK_STARTED"
    INTEGRITY_CHECK_SUCCEEDED = "INTEGRITY_CHECK_SUCCEEDED"
    INTEGRITY_CHECK_FAILED = "INTEGRITY_CHECK_FAILED"
    TRASH_MOVE_STARTED = "TRASH_MOVE_STARTED"
    TRASH_MOVE_SUCCEEDED = "TRASH_MOVE_SUCCEEDED"
    TRASH_MOVE_FAILED = "TRASH_MOVE_FAILED"
    TRASH_VERIFICATION_STARTED = "TRASH_VERIFICATION_STARTED"
    TRASH_VERIFICATION_SUCCEEDED = "TRASH_VERIFICATION_SUCCEEDED"
    TRASH_VERIFICATION_FAILED = "TRASH_VERIFICATION_FAILED"
    APPROVAL_CONSUMED = "APPROVAL_CONSUMED"
    EXECUTION_IN_PROGRESS = "EXECUTION_IN_PROGRESS"
    EXECUTION_SUCCEEDED = "EXECUTION_SUCCEEDED"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    EXECUTION_BLOCKED = "EXECUTION_BLOCKED"
    AGENT_REQUEST = "AGENT_REQUEST"
    AGENT_TOOL_CALL = "AGENT_TOOL_CALL"
    AGENT_TOOL_RESULT = "AGENT_TOOL_RESULT"
    AGENT_RESPONSE = "AGENT_RESPONSE"



class AuditEvent(BaseModel):
    """
    Immutable audit event record for persistent SQLite logging.

    Guarantees:
    - Zero HMAC secrets, private keys, passwords, or file contents.
    - Captures correlated execution_id and approval_id.
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
    event_type: AuditEventType = Field(
        ...,
        description="Structured category/type of the audit event.",
    )
    approval_id: str = Field(
        ...,
        description="Associated cryptographic approval ID.",
    )
    execution_id: str = Field(
        default="",
        description="Associated unique execution run ID.",
    )
    canonical_path: str = Field(
        ...,
        description="Canonical filesystem path associated with the event.",
    )
    operation: Operation = Field(
        default=Operation.CLEAN,
        description="Filesystem operation being evaluated/executed.",
    )
    risk_level: RiskLevel = Field(
        default=RiskLevel.LOW,
        description="Risk level classification.",
    )
    status: str = Field(
        ...,
        description="Event outcome status (e.g., SUCCESS, FAILED, BLOCKED, IN_PROGRESS, CONSUMED).",
    )
    actor: str = Field(
        default="system",
        description="Actor responsible for the event (e.g. human, safety_engine, execution_engine).",
    )
    reason: str = Field(
        default="",
        description="Human-readable contextual rationale or error message.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured non-sensitive event metadata (e.g. reclaimed_bytes, destination).",
    )


class ExecutionRecord(BaseModel):
    """
    Summary record of an execution attempt stored in SQLite.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    execution_id: str = Field(
        ...,
        description="Unique execution run identifier.",
    )
    approval_id: str = Field(
        ...,
        description="Associated approval ID.",
    )
    canonical_path: str = Field(
        ...,
        description="Canonical target path.",
    )
    action: str = Field(
        default="TRASH",
        description="Action attempted (TRASH, DRY_RUN).",
    )
    status: str = Field(
        ...,
        description="Final or current execution status (e.g., IN_PROGRESS, TRASH_SUCCEEDED, FAILED, BLOCKED).",
    )
    start_time: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when execution started.",
    )
    end_time: Optional[datetime] = Field(
        default=None,
        description="UTC timestamp when execution finished.",
    )
    reclaimed_bytes: int = Field(
        default=0,
        ge=0,
        description="Actual bytes reclaimed upon verified completion.",
    )
    destination_path: str = Field(
        default="",
        description="Controlled destination path in ~/.Trash.",
    )
    verified: bool = Field(
        default=False,
        description="Whether post-execution verification confirmed success.",
    )
    message: str = Field(
        default="",
        description="Final execution summary or error description.",
    )
