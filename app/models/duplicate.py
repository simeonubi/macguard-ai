"""
MacGuard AI v1.1 — Duplicate & Redundancy Intelligence Models (Phase 6).

Defines deterministic, read-only data models for duplicate file clustering,
APFS hardlink representation, and duplicate storage summaries.
"""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class DuplicateFile(BaseModel):
    """
    Representation of an individual file within a duplicate analysis candidate set.

    Advisory & Informational Only:
    - Zero execution or deletion authority.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str = Field(..., min_length=1, description="Absolute canonical file path.")
    size_bytes: int = Field(..., ge=0, description="File size in bytes.")
    inode: Optional[int] = Field(default=None, description="Filesystem inode number (st_ino).")
    dev: Optional[int] = Field(default=None, description="Filesystem device identifier (st_dev).")
    partial_hash: Optional[str] = Field(
        default=None, description="Deterministic partial hash (first 4KB + last 4KB)."
    )
    full_sha256: Optional[str] = Field(
        default=None, description="Byte-exact SHA-256 digest of entire file content."
    )
    is_hardlink: bool = Field(
        default=False,
        description="Whether this file shares physical inode allocation with another file in the cluster.",
    )
    category: Optional[str] = Field(
        default=None, description="Optional SmartCategory label from scan discovery."
    )


class DuplicateCluster(BaseModel):
    """
    A cluster of identical files sharing the exact same byte-size and SHA-256 digest.

    Advisory & Informational Only:
    - Accurately accounts for APFS hardlinks (hardlinked copies do not inflate wasted bytes).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    cluster_id: str = Field(..., min_length=1, description="Deterministic cluster identifier.")
    file_size_bytes: int = Field(..., ge=0, description="Byte size of each file in this cluster.")
    files: List[DuplicateFile] = Field(
        ..., min_length=1, description="List of duplicate file instances in this cluster."
    )
    wasted_bytes: int = Field(
        ..., ge=0, description="Potential reclaimable storage bytes: (distinct_physical_copies - 1) * size."
    )
    hardlink_count: int = Field(
        default=0, ge=0, description="Count of secondary hardlinked references in this cluster."
    )


class DuplicateGroup(BaseModel):
    """
    High-level grouping representation of duplicate clusters, e.g. by category or size tier.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    group_name: str = Field(..., min_length=1, description="Grouping label (e.g. category name or size tier).")
    clusters: List[DuplicateCluster] = Field(default_factory=list, description="Duplicate clusters in this group.")
    total_wasted_bytes: int = Field(default=0, ge=0, description="Aggregated reclaimable bytes across clusters.")


class DuplicateScanSummary(BaseModel):
    """
    Overall diagnostic summary of duplicate file analysis.

    Advisory & Read-Only:
    - Provides metrics for human review without authorization or execution power.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    total_clusters: int = Field(default=0, ge=0, description="Total number of duplicate clusters found.")
    total_duplicate_files: int = Field(
        default=0, ge=0, description="Total count of files belonging to duplicate clusters."
    )
    potential_reclaimable_bytes: int = Field(
        default=0, ge=0, description="Total wasted storage across all distinct duplicate copies."
    )
    skipped_large_files: int = Field(
        default=0, ge=0, description="Count of files exceeding 5 GiB skipped from bulk hashing."
    )
