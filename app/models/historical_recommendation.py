"""
MacGuard AI v1.1 — Historical Recommendation Context Model (Phase 5D).

This module defines deterministic, read-only historical context structures
that enrich current cleanup recommendations without granting or altering
cleanup authorization.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field

from app.models.storage_history import TrendDirection


class HistoricalContextLevel(str, Enum):
    """Granularity of historical evidence backing a recommendation context."""

    PATH = "PATH"
    DEVELOPER_SUBTYPE = "DEVELOPER_SUBTYPE"
    CATEGORY = "CATEGORY"
    NONE = "NONE"


class HistoricalRecommendationContext(BaseModel):
    """
    Structured historical storage intelligence context attached to a StorageRecommendation.

    Advisory & Informational Only:
    - Does NOT authorize cleanup or mutate safety classification.
    - Does NOT generate approval tokens or trigger execution.
    - Does NOT bypass human review.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    trend_direction: TrendDirection = Field(
        ..., description="Direction of storage utilization change over time."
    )
    category_name: str = Field(
        ..., description="Semantic category name associated with the historical observation."
    )
    context_type: HistoricalContextLevel = Field(
        default=HistoricalContextLevel.CATEGORY,
        description="Level of historical evidence (PATH, DEVELOPER_SUBTYPE, CATEGORY, NONE).",
    )
    absolute_change_bytes: int = Field(
        ..., description="Historical volume change in bytes since baseline."
    )
    percentage_change: Optional[float] = Field(
        default=None, description="Percentage change relative to baseline volume."
    )
    comparison_available: bool = Field(
        default=True, description="Whether a valid historical baseline was available."
    )
    is_incomplete_scan: bool = Field(
        default=False, description="Whether historical comparison involved a partial/incomplete scan."
    )
    priority_boost: bool = Field(
        default=False, description="Whether candidate has higher investigation priority due to growth."
    )
    context_summary: str = Field(
        ..., min_length=1, description="Deterministic, explainable statement describing the historical trend."
    )
    source_scope: Optional[str] = Field(
        default=None, description="Scope identifier of the historical comparison."
    )
    source_snapshot_id: Optional[str] = Field(
        default=None, description="Snapshot identifier of the comparison source."
    )
    current_path: Optional[str] = Field(
        default=None, description="Target filesystem path of the current candidate."
    )
    historical_status: Optional[str] = Field(
        default=None, description="Status of the historical trend evaluation."
    )
    comparison_type: Optional[str] = Field(
        default=None, description="Type of baseline comparison (e.g., previous scan, baseline scan)."
    )
    previous_size_bytes: Optional[int] = Field(
        default=None, description="Volume in bytes at previous historical baseline."
    )
    current_size_bytes: Optional[int] = Field(
        default=None, description="Volume in bytes observed at current scan."
    )
    change_bytes: Optional[int] = Field(
        default=None, description="Delta in bytes between current and previous scan."
    )
    change_percent: Optional[float] = Field(
        default=None, description="Percentage change relative to baseline volume."
    )
    trend_classification: Optional[str] = Field(
        default=None, description="Text classification of trend (Growing, Stable, Shrinking, Undetermined)."
    )
    observation_count: Optional[int] = Field(
        default=None, description="Number of historical snapshots included in the scope history."
    )
    contextual_priority: Optional[str] = Field(
        default=None, description="Secondary contextual presentation priority (ATTENTION, NORMAL, LOW, UNKNOWN)."
    )
    explanation: Optional[str] = Field(
        default=None, description="Deterministic textual narrative explaining historical trend."
    )
