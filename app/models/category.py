"""
MacGuard AI v1.1 — Smart Category & Confidence Models.

This module defines the rich semantic taxonomy and deterministic confidence models
for storage intelligence discovery.

DISCOVERY != CATEGORIZATION != AUTHORIZATION
Categorization is strictly informational and grants zero cleanup or mutation authority.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field

from app.analysis.models import StorageCategory


class ConfidenceLevel(str, Enum):
    """
    Deterministic confidence level for semantic categorization.
    """

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class SmartCategory(str, Enum):
    """
    Rich 21-category semantic taxonomy for MacGuard AI v1.1 discovery.
    """

    CACHES = "CACHES"
    LOGS = "LOGS"
    BUILD_ARTIFACTS = "BUILD_ARTIFACTS"
    PACKAGE_MANAGERS = "PACKAGE_MANAGERS"
    VIRTUAL_ENVIRONMENTS = "VIRTUAL_ENVIRONMENTS"
    CONTAINERS = "CONTAINERS"
    DISK_IMAGES = "DISK_IMAGES"
    ML_AI_DATA = "ML_AI_DATA"
    ARCHIVES = "ARCHIVES"
    DOCUMENTS = "DOCUMENTS"
    DOWNLOADS = "DOWNLOADS"
    DESKTOP = "DESKTOP"
    PICTURES = "PICTURES"
    MOVIES = "MOVIES"
    MUSIC = "MUSIC"
    MEDIA = "MEDIA"
    DEVELOPER_DATA = "DEVELOPER_DATA"
    APPLICATIONS = "APPLICATIONS"
    TEMPORARY_DATA = "TEMPORARY_DATA"
    SYSTEM_DATA = "SYSTEM_DATA"
    USER_DATA = "USER_DATA"
    UNKNOWN = "UNKNOWN"

    def to_legacy_storage_category(self) -> StorageCategory:
        """
        Map rich v1.1 SmartCategory to v1.0 base StorageCategory for backwards compatibility.
        """
        mapping = {
            SmartCategory.CACHES: StorageCategory.CACHE,
            SmartCategory.LOGS: StorageCategory.LOGS,
            SmartCategory.BUILD_ARTIFACTS: StorageCategory.DEVELOPMENT,
            SmartCategory.PACKAGE_MANAGERS: StorageCategory.DEVELOPMENT,
            SmartCategory.VIRTUAL_ENVIRONMENTS: StorageCategory.DEVELOPMENT,
            SmartCategory.CONTAINERS: StorageCategory.DEVELOPMENT,
            SmartCategory.DEVELOPER_DATA: StorageCategory.DEVELOPMENT,
            SmartCategory.ML_AI_DATA: StorageCategory.DEVELOPMENT,
            SmartCategory.DOCUMENTS: StorageCategory.DOCUMENTS,
            SmartCategory.DOWNLOADS: StorageCategory.DOCUMENTS,
            SmartCategory.DESKTOP: StorageCategory.DOCUMENTS,
            SmartCategory.PICTURES: StorageCategory.MEDIA,
            SmartCategory.MOVIES: StorageCategory.MEDIA,
            SmartCategory.MUSIC: StorageCategory.MEDIA,
            SmartCategory.MEDIA: StorageCategory.MEDIA,
            SmartCategory.APPLICATIONS: StorageCategory.APPLICATION_DATA,
            SmartCategory.USER_DATA: StorageCategory.APPLICATION_DATA,
            SmartCategory.DISK_IMAGES: StorageCategory.UNKNOWN,
            SmartCategory.ARCHIVES: StorageCategory.UNKNOWN,
            SmartCategory.TEMPORARY_DATA: StorageCategory.CACHE,
            SmartCategory.SYSTEM_DATA: StorageCategory.UNKNOWN,
            SmartCategory.UNKNOWN: StorageCategory.UNKNOWN,
        }
        return mapping.get(self, StorageCategory.UNKNOWN)


class CategoryResult(BaseModel):
    """
    Structured outcome of deterministic categorization on a filesystem item.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    category: SmartCategory = Field(
        ...,
        description="Deterministic semantic category.",
    )
    confidence: ConfidenceLevel = Field(
        ...,
        description="Deterministic categorical confidence level.",
    )
    confidence_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence numerical value between 0.0 and 1.0.",
    )
    matched_rule: str = Field(
        ...,
        min_length=1,
        description="Identifier of the rule that produced this classification.",
    )
    rationale: str = Field(
        ...,
        min_length=1,
        description="Human-readable explanation of why this category was assigned.",
    )

    def to_legacy_category(self) -> StorageCategory:
        """Helper to get v1.0 StorageCategory representation."""
        return self.category.to_legacy_storage_category()
