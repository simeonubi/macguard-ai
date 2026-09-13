from __future__ import annotations

import secrets
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from app.analysis.models import RiskLevel
from app.safety.path_validator import Operation


class ExecutionAction(str, Enum):
    """
    Allowed execution action in Phase 6.

    Guarantees:
    - Supported actions: DRY_RUN, TRASH.
    - Permanent deletion actions (DELETE, REMOVE, PURGE, WIPE, ERASE, UNLINK) are strictly forbidden.
    """

    DRY_RUN = "DRY_RUN"
    TRASH = "TRASH"


class ExecutionStatus(str, Enum):
    """
    Lifecycle status of an execution plan or dry-run/trash execution.
    """

    PLANNED = "PLANNED"
    BLOCKED = "BLOCKED"
    DRY_RUN_COMPLETED = "DRY_RUN_COMPLETED"
    EXECUTION_CLAIMED = "EXECUTION_CLAIMED"
    TRASH_SUCCEEDED = "TRASH_SUCCEEDED"
    FAILED = "FAILED"


class ExecutionPlan(BaseModel):
    """
    Structured, immutable execution plan prepared from an approved review item.

    Guarantees:
    - Completely non-destructive.
    - Contains zero secrets or HMAC keys.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    plan_id: str = Field(
        default_factory=lambda: secrets.token_hex(8),
        description="Unique identifier for the execution plan.",
    )
    approval_id: str = Field(
        ...,
        min_length=16,
        description="ID of the cryptographic HMAC approval record authorizing this plan.",
    )
    path: str = Field(
        ...,
        min_length=1,
        description="Original target path subject to execution.",
    )
    canonical_path: str = Field(
        ...,
        min_length=1,
        description="Resolved canonical path verified by Safety Engine.",
    )
    operation: Operation = Field(
        default=Operation.CLEAN,
        description="Operation evaluated by the safety policy (default: CLEAN).",
    )
    risk_level: RiskLevel = Field(
        ...,
        description="Risk classification evaluated at planning time.",
    )
    action: ExecutionAction = Field(
        default=ExecutionAction.DRY_RUN,
        description="The planned action (strictly DRY_RUN in Phase 6A).",
    )
    status: ExecutionStatus = Field(
        ...,
        description="Current status of the plan (PLANNED or BLOCKED).",
    )
    estimated_reclaimable_bytes: int = Field(
        default=0,
        ge=0,
        description="Estimated space in bytes that would be reclaimed.",
    )
    reason: str = Field(
        ...,
        min_length=1,
        description="Contextual rationale or safety block description.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the plan was generated.",
    )


class DryRunResult(BaseModel):
    """
    Structured outcome of a non-destructive dry-run simulation.

    Guarantees:
    - Reports exact simulation details.
    - Zero filesystem mutations performed.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    plan_id: str = Field(
        ...,
        description="Associated execution plan ID.",
    )
    approval_id: str = Field(
        ...,
        description="Associated approval record ID.",
    )
    execution_id: str = Field(
        default="",
        description="Associated execution run ID.",
    )
    path: str = Field(
        ...,
        description="Original target path.",
    )
    canonical_path: str = Field(
        ...,
        description="Resolved canonical target path.",
    )
    action: ExecutionAction = Field(
        default=ExecutionAction.DRY_RUN,
        description="Action simulated (strictly DRY_RUN).",
    )
    status: ExecutionStatus = Field(
        ...,
        description="Outcome status of the dry-run simulation.",
    )
    simulated_reclaimed_bytes: int = Field(
        default=0,
        ge=0,
        description="Simulated reclaimed space in bytes.",
    )
    message: str = Field(
        ...,
        description="Human-readable simulation report.",
    )
    executed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the dry-run was simulated.",
    )
    safety_confirmation: str = Field(
        default="DRY_RUN ONLY: Zero files were deleted, moved, modified, or trashed.",
        description="Explicit safety guarantee.",
    )


class TrashExecutionResult(BaseModel):
    """
    Structured outcome of a controlled Trash move operation.

    Guarantees:
    - Verifies items moved to ~/.Trash without permanent deletion.
    - Captures exact source, destination, reclaimed bytes, execution_id, and status.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    plan_id: str = Field(
        ...,
        description="Associated execution plan ID.",
    )
    approval_id: str = Field(
        ...,
        description="Associated approval record ID.",
    )
    execution_id: str = Field(
        default="",
        description="Associated unique execution run ID.",
    )
    source_path: str = Field(
        ...,
        description="Original source path.",
    )
    canonical_source_path: str = Field(
        ...,
        description="Resolved canonical source path.",
    )
    trash_destination_path: str = Field(
        default="",
        description="Resolved controlled destination path inside ~/.Trash.",
    )
    action: ExecutionAction = Field(
        default=ExecutionAction.TRASH,
        description="Action performed (strictly TRASH).",
    )
    status: ExecutionStatus = Field(
        ...,
        description="Outcome status (TRASH_SUCCEEDED, BLOCKED, or FAILED).",
    )
    reclaimed_bytes: int = Field(
        default=0,
        ge=0,
        description="Actual bytes moved to Trash.",
    )
    message: str = Field(
        ...,
        description="Human-readable execution and verification report.",
    )
    executed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the move was executed.",
    )
    verified: bool = Field(
        default=False,
        description="Whether post-move verification confirmed source absence and destination presence.",
    )
    integrity_verified: bool = Field(
        default=False,
        description="Whether pre- and post-move integrity verification checks passed.",
    )
    safety_confirmation: str = Field(
        default="CONTROLLED TRASH EXECUTION: Item was moved to macOS Trash. No permanent deletion occurred.",
        description="Explicit safety confirmation.",
    )

    @property
    def bytes_moved_to_trash(self) -> int:
        """Exact bytes moved from active path into macOS Trash."""
        return self.reclaimed_bytes

    @property
    def bytes_moved_human(self) -> str:
        """Formatted human-readable size of bytes moved to macOS Trash."""
        from app.tools.storage_scanner import format_bytes
        return format_bytes(self.reclaimed_bytes)

    @property
    def physical_disk_reclaim_status(self) -> str:
        """Physical disk space status note."""
        return "Not yet reclaimed — Trash must be emptied"
