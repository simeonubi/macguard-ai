"""
MacGuard AI v1.1 — Duplicate Recommendation Context Model (Phase 7).

Defines deterministic, read-only duplicate recommendation evidence attached
to StorageRecommendation items without altering risk classification or granting
cleanup authorization.
"""

from __future__ import annotations

from typing import List
from pydantic import BaseModel, ConfigDict, Field


class DuplicateRecommendationContext(BaseModel):
    """
    Deterministic duplicate evidence attached to an individual StorageRecommendation.

    Advisory & Informational Only:
    - Does NOT authorize cleanup or mutate safety classification.
    - Does NOT generate approval tokens or trigger execution.
    - Accurately differentiates independent physical duplicates from APFS hardlinks.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    cluster_id: str = Field(..., min_length=1, description="Cluster identifier from DuplicateDetector.")
    file_size_bytes: int = Field(..., ge=0, description="Size of each duplicate file in bytes.")
    duplicate_file_count: int = Field(..., ge=2, description="Total file entries in the duplicate cluster.")
    physical_inode_count: int = Field(
        ..., ge=1, description="Count of distinct physical inodes in the cluster."
    )
    hardlink_count: int = Field(
        default=0, ge=0, description="Count of hardlink references to existing inodes in the cluster."
    )
    wasted_bytes: int = Field(
        ..., ge=0, description="Reclaimable physical storage: (physical_inode_count - 1) * file_size_bytes."
    )
    duplicate_paths: List[str] = Field(
        ..., min_length=1, description="Other duplicate paths in the same cluster."
    )
    is_hardlink_only: bool = Field(
        default=False,
        description="True if all entries in this cluster share a single physical inode (wasted_bytes == 0).",
    )
    explanation: str = Field(
        ..., min_length=1, description="Deterministic explainable statement describing duplicate evidence."
    )
