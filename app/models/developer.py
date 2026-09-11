"""
MacGuard AI v1.1 — Developer Storage Analysis Models.

This module defines typed findings and aggregation models for developer storage intelligence.

DISCOVERY != CATEGORIZATION != ANALYSIS != AUTHORIZATION
Developer storage analysis is strictly informational and read-only.
It does not grant or alter cleanup eligibility.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field

from app.models.category import ConfidenceLevel, SmartCategory


class DeveloperStorageSubtype(str, Enum):
    """Specific developer storage artifact subtype."""

    PYTHON_VENV = "PYTHON_VENV"
    NODE_MODULES = "NODE_MODULES"
    PYTHON_CACHE = "PYTHON_CACHE"
    BUILD_OUTPUT = "BUILD_OUTPUT"
    PACKAGE_CACHE = "PACKAGE_CACHE"
    CONTAINER_STORAGE = "CONTAINER_STORAGE"
    ML_MODELS = "ML_MODELS"
    ML_DATASETS = "ML_DATASETS"
    IDE_CACHE = "IDE_CACHE"
    SOURCE_REPO = "SOURCE_REPO"
    OTHER_DEVELOPER = "OTHER_DEVELOPER"


class StaleStatus(str, Enum):
    """Age assessment for developer storage artifacts."""

    RECENT = "RECENT"  # <= 30 days
    MODERATE = "MODERATE"  # 31 - 90 days
    POTENTIALLY_STALE_90D = "POTENTIALLY_STALE_90D"  # 91 - 180 days
    POTENTIALLY_STALE_180D = "POTENTIALLY_STALE_180D"  # > 180 days
    UNKNOWN = "UNKNOWN"  # Missing or invalid timestamp


class DeveloperStorageFinding(BaseModel):
    """
    A single granular developer storage finding.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str = Field(..., min_length=1, description="Absolute canonical or normalized path.")
    subtype: DeveloperStorageSubtype = Field(..., description="Developer artifact subtype.")
    category: SmartCategory = Field(..., description="Parent semantic category.")
    size_bytes: int = Field(..., ge=0, description="Size in bytes.")
    item_type: str = Field(..., description="'file' or 'directory'.")
    depth: int = Field(..., ge=0, description="Recursion depth relative to scan root.")
    mtime: float = Field(..., description="Last modification timestamp (epoch seconds).")
    stale_status: StaleStatus = Field(..., description="Age evaluation based on mtime.")
    age_days: Optional[float] = Field(default=None, description="Elapsed days since last modification.")
    project_name: Optional[str] = Field(default=None, description="Associated project name if deterministically identified.")
    confidence: ConfidenceLevel = Field(..., description="Classification confidence level.")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Numerical confidence score.")
    evidence: str = Field(..., min_length=1, description="Deterministic explanation of why this finding was generated.")
    is_large: bool = Field(default=False, description="Whether item exceeds large artifact threshold.")
    parent_path: Optional[str] = Field(default=None, description="Immediate parent directory path.")


class DeveloperStorageGroup(BaseModel):
    """
    Aggregated summary of findings within a specific developer storage subtype.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    subtype: DeveloperStorageSubtype = Field(..., description="Developer storage subtype.")
    title: str = Field(..., description="Human-readable title.")
    total_logical_bytes: int = Field(..., ge=0, description="Sum of all findings' logical bytes.")
    unique_physical_bytes: int = Field(..., ge=0, description="Deduplicated physical coverage bytes.")
    item_count: int = Field(..., ge=0, description="Total findings count.")
    findings: List[DeveloperStorageFinding] = Field(default_factory=list, description="List of individual findings.")
    stale_item_count: int = Field(default=0, ge=0, description="Count of findings older than 90 days.")
    stale_bytes: int = Field(default=0, ge=0, description="Bytes in findings older than 90 days.")


class DeveloperProjectSummary(BaseModel):
    """
    Aggregated developer storage breakdown associated with a specific project.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    project_name: str = Field(..., min_length=1, description="Project identifier.")
    project_root: str = Field(..., min_length=1, description="Base directory of the project.")
    total_bytes: int = Field(..., ge=0, description="Total developer storage bytes under this project.")
    unique_physical_bytes: int = Field(..., ge=0, description="Deduplicated physical storage bytes.")
    subtypes: List[DeveloperStorageSubtype] = Field(default_factory=list, description="Distinct developer subtypes detected.")
    findings_count: int = Field(..., ge=0, description="Count of developer storage findings in this project.")


class DeveloperStorageSummary(BaseModel):
    """
    Top-level comprehensive summary of all developer storage analysis across a scan.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    total_logical_bytes: int = Field(..., ge=0, description="Total logical developer storage bytes.")
    total_unique_bytes: int = Field(..., ge=0, description="Total deduplicated physical developer storage bytes.")
    total_findings_count: int = Field(..., ge=0, description="Total developer storage items found.")
    groups: List[DeveloperStorageGroup] = Field(default_factory=list, description="Breakdown grouped by subtype.")
    projects: List[DeveloperProjectSummary] = Field(default_factory=list, description="Breakdown grouped by project.")
    large_artifacts: List[DeveloperStorageFinding] = Field(default_factory=list, description="Unusually large artifacts.")
    stale_findings: List[DeveloperStorageFinding] = Field(default_factory=list, description="Artifacts older than 90 days.")
