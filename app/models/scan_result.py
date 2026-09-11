"""
MacGuard AI v1.1 — Scan Result & Discovered Item Models.

This module defines structured models for read-only discovery results.
All models are strictly informational and grant zero mutation authority.
"""

from __future__ import annotations

import time
from enum import Enum
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field

from app.models.category import ConfidenceLevel, SmartCategory
from app.models.scan_scope import ScopeIdentifier


class ScanStatus(str, Enum):
    """Execution status of a read-only discovery traversal."""

    COMPLETED = "COMPLETED"
    ENTRY_LIMIT_REACHED = "ENTRY_LIMIT_REACHED"
    DEPTH_LIMIT_REACHED = "DEPTH_LIMIT_REACHED"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"
    ERROR = "ERROR"


class DiscoveredItem(BaseModel):
    """
    Represents a single filesystem node discovered during read-only traversal.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str = Field(..., min_length=1, description="Absolute canonical or normalized path.")
    size_bytes: int = Field(..., ge=0, description="Size in bytes.")
    item_type: str = Field(..., description="'file' or 'directory'.")
    depth: int = Field(..., ge=0, description="Recursion depth relative to the scan root.")
    mtime: float = Field(..., description="Last modification timestamp (seconds since epoch).")
    st_ino: int = Field(..., description="Filesystem inode number.")
    st_dev: int = Field(..., description="Filesystem device identifier.")
    is_symlink: bool = Field(default=False, description="Whether the item is a symbolic link.")
    parent_path: Optional[str] = Field(default=None, description="Path of parent directory.")
    category: Optional[SmartCategory] = Field(default=None, description="Optional semantic category.")
    confidence: Optional[ConfidenceLevel] = Field(default=None, description="Optional confidence rating.")
    category_rule: Optional[str] = Field(default=None, description="Optional identifier of matched category rule.")


class ScanResult(BaseModel):
    """
    Structured outcome of a read-only scan across a bounded ScanScope.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    scope_id: ScopeIdentifier = Field(..., description="Identifier of the scanned scope.")
    root_path: str = Field(..., min_length=1, description="Root directory of the scope.")
    status: ScanStatus = Field(..., description="Termination status of the traversal.")
    start_time: float = Field(..., description="Start timestamp (epoch seconds).")
    end_time: float = Field(..., description="End timestamp (epoch seconds).")
    duration_seconds: float = Field(..., ge=0.0, description="Elapsed traversal time in seconds.")
    files_count: int = Field(default=0, ge=0, description="Count of regular files inspected.")
    directories_count: int = Field(default=0, ge=0, description="Count of directories inspected.")
    total_bytes: int = Field(default=0, ge=0, description="Aggregate bytes observed.")
    items: List[DiscoveredItem] = Field(default_factory=list, description="List of discovered items.")
    skipped_entries_count: int = Field(default=0, ge=0, description="Total skipped entries.")
    permission_errors_count: int = Field(default=0, ge=0, description="Inaccessible directory count.")
    excluded_entries_count: int = Field(default=0, ge=0, description="Excluded sensitive paths count.")
    symlinks_skipped_count: int = Field(default=0, ge=0, description="Unfollowed symlinks count.")
    filesystem_boundary_skips_count: int = Field(
        default=0, ge=0, description="Entries skipped due to st_dev boundary."
    )
    error_message: Optional[str] = Field(default=None, description="Error detail if status is ERROR.")

    @property
    def total_entries(self) -> int:
        """Total entries processed (files + directories)."""
        return self.files_count + self.directories_count

    @property
    def is_complete(self) -> bool:
        """True if the scan finished without hitting limits or errors."""
        return self.status == ScanStatus.COMPLETED
