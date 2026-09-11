"""
MacGuard AI v1.1 — Storage History & Trend Models.

This module defines structured, immutable models for persistent scan snapshots,
historical category and developer measurements, and deterministic storage trends.

DISCOVERY != CATEGORIZATION != ANALYSIS != AUTHORIZATION
History models are strictly informational and observational. They possess zero
cleanup or execution authority.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field

from app.models.category import ConfidenceLevel, SmartCategory
from app.models.developer import DeveloperStorageSubtype
from app.models.scan_result import ScanStatus
from app.models.scan_scope import ScopeIdentifier


class TrendDirection(str, Enum):
    """Direction of storage utilization change over time."""

    GROWING = "GROWING"
    SHRINKING = "SHRINKING"
    STABLE = "STABLE"
    UNKNOWN = "UNKNOWN"


class CategorySnapshotItem(BaseModel):
    """Aggregate storage measurement for a single SmartCategory in a snapshot."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    category: SmartCategory = Field(..., description="Semantic category.")
    total_bytes: int = Field(..., ge=0, description="Total bytes observed for this category.")
    item_count: int = Field(..., ge=0, description="Total items observed for this category.")


class DeveloperSnapshotItem(BaseModel):
    """Aggregate storage measurement for a single DeveloperStorageSubtype in a snapshot."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    subtype: DeveloperStorageSubtype = Field(..., description="Developer storage subtype.")
    total_bytes: int = Field(..., ge=0, description="Total logical bytes observed for this subtype.")
    unique_bytes: int = Field(..., ge=0, description="Deduplicated physical bytes observed for this subtype.")
    item_count: int = Field(..., ge=0, description="Total items observed for this subtype.")


class LargeConsumerSnapshotItem(BaseModel):
    """Historical record of a top storage consumer from a snapshot."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rank: int = Field(..., ge=1, description="1-based rank at the time of the scan.")
    path: str = Field(..., min_length=1, description="Path of the storage consumer.")
    size_bytes: int = Field(..., ge=0, description="Size in bytes.")
    category: SmartCategory = Field(..., description="Semantic category of the consumer.")
    confidence: ConfidenceLevel = Field(..., description="Categorization confidence rating.")


class StorageSnapshot(BaseModel):
    """
    Immutable historical snapshot representing one completed discovery scan.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    snapshot_id: str = Field(..., min_length=1, description="Unique snapshot identifier.")
    scan_id: str = Field(..., min_length=1, description="Identifier of the source discovery scan.")
    timestamp: float = Field(..., description="Epoch timestamp when the scan was recorded.")
    scope_id: ScopeIdentifier = Field(..., description="Scan scope identifier.")
    root_path: str = Field(..., min_length=1, description="Root directory path of the scope.")
    status: ScanStatus = Field(..., description="Completion status of the scan.")
    duration_seconds: float = Field(..., ge=0.0, description="Elapsed traversal time in seconds.")
    files_count: int = Field(..., ge=0, description="Count of regular files inspected.")
    directories_count: int = Field(..., ge=0, description="Count of directories inspected.")
    total_bytes: int = Field(..., ge=0, description="Aggregate logical storage observed.")
    unique_bytes: Optional[int] = Field(default=None, ge=0, description="Deduplicated physical storage if computed.")
    skipped_entries_count: int = Field(default=0, ge=0, description="Total skipped entries.")
    permission_errors_count: int = Field(default=0, ge=0, description="Total inaccessible entries.")
    categories: List[CategorySnapshotItem] = Field(
        default_factory=list, description="Category-level storage breakdown."
    )
    developer_subtypes: List[DeveloperSnapshotItem] = Field(
        default_factory=list, description="Developer subtype storage breakdown."
    )
    top_consumers: List[LargeConsumerSnapshotItem] = Field(
        default_factory=list, description="Bounded top-N largest storage consumers."
    )


class StorageTrend(BaseModel):
    """Deterministic comparison between two measurements over time."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    metric: str = Field(..., min_length=1, description="Name of the metric compared.")
    current_value: int = Field(..., ge=0, description="Current value.")
    previous_value: int = Field(..., ge=0, description="Previous value.")
    absolute_change: int = Field(..., description="Difference: current_value - previous_value.")
    percentage_change: Optional[float] = Field(
        default=None, description="Percentage change relative to previous_value, if previous_value > 0."
    )
    direction: TrendDirection = Field(..., description="Classified trend direction.")
    explanation: str = Field(..., min_length=1, description="Deterministic human-readable explanation.")


class CategoryTrend(BaseModel):
    """Deterministic storage trend for a specific SmartCategory."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    category: SmartCategory = Field(..., description="Semantic category.")
    current_bytes: int = Field(..., ge=0, description="Current total bytes in this category.")
    previous_bytes: int = Field(..., ge=0, description="Previous total bytes in this category.")
    absolute_change: int = Field(..., description="Change in bytes (current - previous).")
    percentage_change: Optional[float] = Field(
        default=None, description="Percentage change relative to previous_bytes."
    )
    direction: TrendDirection = Field(..., description="Classified trend direction.")
    current_item_count: int = Field(default=0, ge=0, description="Current item count in this category.")
    previous_item_count: int = Field(default=0, ge=0, description="Previous item count in this category.")
    explanation: str = Field(..., min_length=1, description="Deterministic human-readable explanation.")


class DeveloperTrend(BaseModel):
    """Deterministic storage trend for a specific DeveloperStorageSubtype."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    subtype: DeveloperStorageSubtype = Field(..., description="Developer storage subtype.")
    current_bytes: int = Field(..., ge=0, description="Current total bytes for this subtype.")
    previous_bytes: int = Field(..., ge=0, description="Previous total bytes for this subtype.")
    absolute_change: int = Field(..., description="Change in bytes (current - previous).")
    percentage_change: Optional[float] = Field(
        default=None, description="Percentage change relative to previous_bytes."
    )
    direction: TrendDirection = Field(..., description="Classified trend direction.")
    explanation: str = Field(..., min_length=1, description="Deterministic human-readable explanation.")


class StorageTrendReport(BaseModel):
    """
    Comprehensive, deterministic trend report comparing two historical snapshots.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    scope_id: ScopeIdentifier = Field(..., description="Scope identifier of the comparison.")
    root_path: str = Field(..., min_length=1, description="Root directory path.")
    current_snapshot_id: str = Field(..., min_length=1, description="Identifier of the current snapshot.")
    previous_snapshot_id: Optional[str] = Field(
        default=None, description="Identifier of the baseline snapshot compared against, if any."
    )
    current_timestamp: float = Field(..., description="Timestamp of the current snapshot.")
    previous_timestamp: Optional[float] = Field(
        default=None, description="Timestamp of the baseline snapshot, if any."
    )
    is_comparable: bool = Field(..., description="Whether the two snapshots represent comparable scans.")
    overall_trend: StorageTrend = Field(..., description="Aggregate volume/scope storage trend.")
    category_trends: List[CategoryTrend] = Field(
        default_factory=list, description="Per-category trends sorted by largest absolute change descending."
    )
    developer_trends: List[DeveloperTrend] = Field(
        default_factory=list, description="Per-developer subtype trends sorted by largest absolute change descending."
    )
    largest_growing_category: Optional[SmartCategory] = Field(
        default=None, description="Category with the greatest positive byte increase, if any."
    )
    largest_growing_developer_subtype: Optional[DeveloperStorageSubtype] = Field(
        default=None, description="Developer subtype with the greatest positive byte increase, if any."
    )
    notes: List[str] = Field(
        default_factory=list, description="Informational notes (e.g. partial scan warnings, first-scan note)."
    )
