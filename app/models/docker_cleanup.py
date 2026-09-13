"""
MacGuard AI Phase 14A — Docker Cleanup Planning Models.

Defines typed schemas for deterministic Docker cleanup planning.
INVARIANTS:
1. PLANNING ONLY: All proposed plans have executable=False in Phase 14A.
2. ZERO AUTOMATED DELETION: All proposed plans have approval_required=True and REVIEW_REQUIRED.
3. STRICT ISOLATION: Docker.raw is always PROTECTED and never in a cleanup plan.
4. STATE DRIFT PRESERVATION: Observed Docker runtime state is captured for future pre-execution revalidation.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field

from app.models.investigation import ReclaimConfidence
from app.tools.storage_scanner import format_bytes


class DockerResourceType(str, Enum):
    """Types of Docker resources that can be inspected and planned."""

    CONTAINER = "container"
    IMAGE = "image"
    VOLUME = "volume"
    BUILD_CACHE = "build_cache"
    VIRTUAL_DISK = "virtual_disk"


class DockerCleanupPlanItem(BaseModel):
    """
    A single deterministic cleanup plan proposal for a Docker resource.
    """

    model_config = ConfigDict(frozen=True, validate_assignment=True)

    plan_id: str = Field(..., description="Unique deterministic identifier for the plan item")
    resource_type: DockerResourceType = Field(..., description="Type of Docker resource")
    resource_id: str = Field(..., description="Exact Docker resource ID (container ID, image ID, volume name, or build_cache)")
    resource_name: str = Field(..., description="Human-readable resource name or repository:tag")
    observed_size_bytes: int = Field(default=0, ge=0, description="Observed size in bytes at planning time")
    
    requested_action: str = Field(
        ...,
        description="Proposed action identifier (e.g. remove_stopped_container, remove_unused_image, prune_build_cache, remove_unused_volume)",
    )
    safety_classification: ReclaimConfidence = Field(
        default=ReclaimConfidence.REVIEW_REQUIRED,
        description="Must be REVIEW_REQUIRED in Phase 14A. Never HIGH_CONFIDENCE.",
    )
    currently_in_use: bool = Field(default=False, description="Whether resource was in use by running workload when planned")
    dependency_evidence: str = Field(default="", description="Concrete evidence regarding references, tags, or mounts")
    consequence: str = Field(default="", description="Explicit consequence if this cleanup is later approved and executed")
    evidence_ids: list[str] = Field(default_factory=list, description="Associated StorageEvidenceItem IDs from Phase 13")
    
    approval_required: bool = Field(default=True, description="Human approval is strictly required")
    executable: bool = Field(default=False, description="Always False in Phase 14A (Planning only)")
    is_high_risk: bool = Field(default=False, description="True for volumes containing persistent data")
    
    observed_state: dict[str, Any] = Field(
        default_factory=dict,
        description="Snapshot of observed Docker state for future drift revalidation before execution",
    )

    @property
    def size_human(self) -> str:
        return format_bytes(self.observed_size_bytes)


class DockerCleanupPlan(BaseModel):
    """
    Deterministic aggregated cleanup plan for Docker storage.
    """

    model_config = ConfigDict(frozen=True, validate_assignment=True)

    plan_id: str = Field(..., description="Unique plan session identifier")
    created_at: str = Field(..., description="ISO timestamp of plan creation")
    
    items: list[DockerCleanupPlanItem] = Field(default_factory=list, description="All planned cleanup candidates")
    protected_items_count: int = Field(default=0, ge=0, description="Count of protected Docker resources excluded from plan")
    
    # Explicit runtime resource inventory breakdown
    running_containers_count: int = Field(default=0, ge=0, description="Discovered running containers (strictly protected)")
    stopped_containers_count: int = Field(default=0, ge=0, description="Discovered stopped containers (review candidates)")
    active_images_count: int = Field(default=0, ge=0, description="Discovered active/in-use images (strictly protected)")
    unused_images_count: int = Field(default=0, ge=0, description="Discovered unused/dangling images (review candidates)")
    attached_volumes_count: int = Field(default=0, ge=0, description="Discovered attached volumes (strictly protected)")
    unattached_volumes_count: int = Field(default=0, ge=0, description="Discovered unattached volumes (review candidates, high-risk)")
    protected_host_targets_count: int = Field(default=0, ge=0, description="Discovered host targets (Docker.raw, ~/.docker)")

    total_proposed_bytes: int = Field(default=0, ge=0, description="Sum of proposed candidate sizes (note: images may share layers)")
    volume_warnings: list[str] = Field(default_factory=list, description="Specific safety warnings for unused volumes")
    status_message: str = Field(default="", description="Overview status of Docker cleanup planning")

    @property
    def total_proposed_human(self) -> str:
        return format_bytes(self.total_proposed_bytes)

    @property
    def review_items_count(self) -> int:
        return len(self.items)


class DockerExecutionStatus(str, Enum):
    """Execution and safety validation outcome status for Docker cleanup operations."""

    EXECUTED = "EXECUTED"
    REJECTED_INVALID_APPROVAL = "REJECTED_INVALID_APPROVAL"
    REJECTED_EXPIRED_APPROVAL = "REJECTED_EXPIRED_APPROVAL"
    REJECTED_ALREADY_CLAIMED = "REJECTED_ALREADY_CLAIMED"
    REJECTED_PROTECTED = "REJECTED_PROTECTED"
    REJECTED_NON_EXECUTABLE = "REJECTED_NON_EXECUTABLE"
    REJECTED_STATE_CHANGED = "REJECTED_STATE_CHANGED"
    REJECTED_HIGH_RISK_NOT_CONFIRMED = "REJECTED_HIGH_RISK_NOT_CONFIRMED"
    DOCKER_UNAVAILABLE = "DOCKER_UNAVAILABLE"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"


class DockerCleanupApproval(BaseModel):
    """
    Cryptographically bound, human approval record for a single Docker cleanup operation.
    """

    model_config = ConfigDict(frozen=True, validate_assignment=True)

    approval_id: str = Field(..., description="Unique approval identifier")
    plan_id: str = Field(..., description="Associated Docker cleanup plan ID")
    resource_type: DockerResourceType = Field(..., description="Target Docker resource type")
    resource_id: str = Field(..., description="Exact immutable Docker resource ID or volume name")
    resource_name: str = Field(default="", description="Human-readable resource name or repository:tag")
    planned_operation: str = Field(..., description="Exact allowlisted operation")
    planned_bytes: int = Field(default=0, ge=0, description="Planned reclaimable bytes")
    observed_state: dict[str, Any] = Field(default_factory=dict, description="Observed state snapshot at planning time")
    created_at: str = Field(..., description="ISO timestamp of approval creation")
    expires_at: str = Field(..., description="ISO timestamp of approval expiration")
    hmac_signature: str = Field(..., description="HMAC-SHA256 signature guaranteeing approval integrity")
    high_risk_confirmed: bool = Field(default=False, description="Mandatory confirmation flag for volume cleanup")


class DockerExecutionResult(BaseModel):
    """
    Deterministic execution result for a single approved Docker cleanup operation.
    """

    model_config = ConfigDict(frozen=True, validate_assignment=True)

    execution_id: str = Field(..., description="Unique execution identifier")
    approval_id: str = Field(..., description="Associated approval ID")
    resource_type: DockerResourceType = Field(..., description="Target Docker resource type")
    resource_id: str = Field(..., description="Target Docker resource ID")
    resource_name: str = Field(default="", description="Human-readable resource name")
    operation: str = Field(..., description="Executed operation identifier")
    status: DockerExecutionStatus = Field(..., description="Final execution outcome status")
    planned_bytes: int = Field(default=0, ge=0, description="Planned reclaimable bytes")
    reclaimed_bytes: int = Field(default=0, ge=0, description="Actual verified reclaimed bytes")
    verified: bool = Field(default=False, description="Whether post-execution state verification confirmed success")
    error_message: str = Field(default="", description="Error description if execution or verification failed")
    start_time: str = Field(..., description="ISO timestamp when execution started")
    end_time: Optional[str] = Field(default=None, description="ISO timestamp when execution completed")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Structured execution and verification telemetry")

    @property
    def reclaimed_human(self) -> str:
        return format_bytes(self.reclaimed_bytes)
