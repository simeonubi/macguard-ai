"""
MacGuard AI v1.1 — Large File Intelligence & Ranking Models.

This module defines structured, immutable models for large storage consumer
findings, category aggregations, developer context, and attention prioritization.

DISCOVERY != CATEGORIZATION != ANALYSIS != AUTHORIZATION
These models are strictly read-only and informational, with zero cleanup or
execution authority.
"""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field

from app.models.category import ConfidenceLevel, SmartCategory
from app.models.developer import DeveloperStorageSubtype, StaleStatus


class LargeFileFinding(BaseModel):
    """
    Represents an individual large storage consumer identified during analysis.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str = Field(..., min_length=1, description="Absolute canonical or normalized path of the item.")
    size_bytes: int = Field(..., ge=0, description="Logical size in bytes.")
    category: SmartCategory = Field(..., description="Deterministic semantic category.")
    confidence: ConfidenceLevel = Field(..., description="Confidence rating for categorization.")
    rank: int = Field(..., ge=1, description="1-based rank ordered by size descending, then path ascending.")
    size_threshold_bytes: int = Field(..., ge=0, description="Size threshold in bytes applied to qualify this finding.")
    storage_percentage: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=100.0,
        description="Percentage of total scanned storage consumed by this item, if total is known.",
    )
    attention_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Deterministic attention prioritization score (0-100). Informational only, NOT a risk/safety score.",
    )
    rationale: str = Field(..., min_length=1, description="Deterministic explanation of why this item was identified.")
    developer_subtype: Optional[DeveloperStorageSubtype] = Field(
        default=None, description="Optional developer subtype if this item is developer-related."
    )
    project_name: Optional[str] = Field(
        default=None, description="Inferred project name if associated with a recognized project."
    )
    project_root: Optional[str] = Field(
        default=None, description="Inferred project root directory path."
    )
    stale_status: Optional[StaleStatus] = Field(
        default=None, description="Age/staleness classification based on modification timestamp."
    )
    parent_candidate_path: Optional[str] = Field(
        default=None, description="Path of enclosing parent candidate if nested inside another finding."
    )
    is_contained: bool = Field(
        default=False, description="Whether this item is contained within a higher-level candidate in the findings."
    )
    item_type: Optional[str] = Field(
        default=None, description="Filesystem item type ('file' or 'directory')."
    )
    mtime: Optional[float] = Field(
        default=None, description="Last modification timestamp (epoch seconds)."
    )


class LargeFileCategorySummary(BaseModel):
    """
    Aggregated summary of large storage consumption within a specific SmartCategory.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    category: SmartCategory = Field(..., description="Semantic category.")
    total_logical_bytes: int = Field(..., ge=0, description="Sum of logical bytes across findings in this category.")
    unique_physical_bytes: int = Field(..., ge=0, description="Deduplicated physical bytes for this category.")
    item_count: int = Field(..., ge=0, description="Number of large items in this category.")
    percentage_of_large_storage: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=100.0,
        description="Percentage of total large storage represented by this category.",
    )


class LargeFileDeveloperSummary(BaseModel):
    """
    Aggregated summary of large storage consumption within a specific DeveloperStorageSubtype.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    subtype: DeveloperStorageSubtype = Field(..., description="Developer storage subtype.")
    total_logical_bytes: int = Field(..., ge=0, description="Sum of logical bytes across findings for this subtype.")
    unique_physical_bytes: int = Field(..., ge=0, description="Deduplicated physical bytes for this subtype.")
    item_count: int = Field(..., ge=0, description="Number of large items for this subtype.")


class LargeFileSummary(BaseModel):
    """
    Top-level structured summary of large file intelligence.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    total_logical_bytes: int = Field(..., ge=0, description="Sum of all logical finding bytes.")
    total_unique_bytes: int = Field(..., ge=0, description="Deduplicated physical storage footprint.")
    total_findings_count: int = Field(..., ge=0, description="Total number of qualified large storage findings.")
    size_threshold_bytes: int = Field(..., ge=0, description="Default size threshold applied.")
    scanned_total_bytes: Optional[int] = Field(
        default=None, ge=0, description="Total scanned storage against which percentages are calculated."
    )
    findings: List[LargeFileFinding] = Field(
        default_factory=list, description="All qualified large storage findings, ordered by rank."
    )
    top_findings: List[LargeFileFinding] = Field(
        default_factory=list, description="Top N highest-ranking findings."
    )
    category_summaries: List[LargeFileCategorySummary] = Field(
        default_factory=list, description="Category-level breakdowns sorted by unique physical bytes descending."
    )
    developer_summaries: List[LargeFileDeveloperSummary] = Field(
        default_factory=list, description="Developer subtype breakdowns sorted by unique physical bytes descending."
    )
