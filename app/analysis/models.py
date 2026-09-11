from __future__ import annotations

from enum import Enum
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class StorageCategory(str, Enum):
    """Semantic category for discovered filesystem items."""

    CACHE = "CACHE"
    LOGS = "LOGS"
    DEVELOPMENT = "DEVELOPMENT"
    APPLICATION_DATA = "APPLICATION_DATA"
    MEDIA = "MEDIA"
    DOCUMENTS = "DOCUMENTS"
    UNKNOWN = "UNKNOWN"


class RiskLevel(str, Enum):
    """
    Risk rating indicating the potential impact if an item were to be modified.

    This rating does NOT imply permission to delete.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    UNKNOWN = "UNKNOWN"


class StorageCandidate(BaseModel):
    """
    Represents a categorized storage item with risk assessment and recommendations.

    Instances of this model are strictly informational and read-only.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str = Field(
        ...,
        min_length=1,
        description="Non-empty canonical or relative filesystem path of the item.",
    )
    size_bytes: int = Field(
        ...,
        ge=0,
        description="Size in bytes of the item. Must not be negative.",
    )
    category: StorageCategory = Field(
        ...,
        description="Deterministic semantic category.",
    )
    risk_level: RiskLevel = Field(
        ...,
        description="Conservative risk evaluation.",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score between 0.0 and 1.0.",
    )
    reason: str = Field(
        ...,
        min_length=1,
        description="Deterministic explanation of the classification.",
    )
    recommendation: str = Field(
        ...,
        min_length=1,
        description="Conservative, non-destructive guidance for user review.",
    )
    item_type: Optional[str] = Field(
        default=None,
        description="Optional filesystem type: 'file' or 'directory'.",
    )
