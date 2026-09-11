"""
MacGuard AI v1.1 — Scan Scope & Traversal Policy Models.

This module defines the foundational models for bounded, read-only storage discovery.
It enforces the core architectural invariant:

    DISCOVERY != AUTHORIZATION

A ScanScope defines where MacGuard MAY inspect for informational and analytical purposes.
It grants ZERO mutation or cleanup authority. Cleanup eligibility remains strictly governed
by the immutable PathValidator allowlist and ApprovalService.
"""

from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Sequence, Tuple, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ScopeIdentifier(str, Enum):
    """
    Standard scope identifiers for bounded read-only discovery.
    """

    HOME = "HOME"
    DESKTOP = "DESKTOP"
    DOCUMENTS = "DOCUMENTS"
    DOWNLOADS = "DOWNLOADS"
    PICTURES = "PICTURES"
    MOVIES = "MOVIES"
    MUSIC = "MUSIC"
    DEVELOPER = "DEVELOPER"
    USER_CACHES = "USER_CACHES"
    CUSTOM = "CUSTOM"


# Canonical subpaths excluded from broad discovery scanning to protect privacy and secrets.
# Aligned with PathValidator.SENSITIVE_USER_SUBDIRS and extended for discovery safety.
CANONICAL_SENSITIVE_EXCLUSIONS: Tuple[str, ...] = (
    ".ssh",
    ".gnupg",
    ".aws",
    ".kube",
    ".config/gcloud",
    "Library/Keychains",
    "Library/Mail",
    "Library/Messages",
    "Library/Safari",
    "Library/Preferences",
    "Library/Cookies",
    "Library/IdentityServices",
    "Library/Accounts",
    "Library/Mobile Documents",
)


class TraversalLimits(BaseModel):
    """
    Configurable safety limits and resource safeguards for read-only filesystem traversal.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    max_depth: int = Field(
        default=8,
        ge=1,
        le=64,
        description="Maximum directory recursion depth relative to the scan root.",
    )
    max_entries: int = Field(
        default=250_000,
        ge=1,
        le=10_000_000,
        description="Maximum total filesystem entries to inspect in a single scan run.",
    )
    timeout_seconds: float = Field(
        default=60.0,
        gt=0.0,
        le=3600.0,
        description="Maximum elapsed traversal duration in seconds before cooperative timeout.",
    )
    max_file_size_for_expensive_analysis: int = Field(
        default=5_368_709_120,  # 5 GiB
        ge=0,
        description="Maximum file size in bytes for deep analysis (e.g., duplicate hashing).",
    )
    follow_symlinks: bool = Field(
        default=False,
        description="Whether to recursively traverse directory symlinks. Default is False to prevent loops.",
    )
    stay_on_filesystem: bool = Field(
        default=True,
        description="Whether traversal should stay on the root path's filesystem device (st_dev).",
    )
    cancellation_event: Optional[Any] = Field(
        default=None,
        description="Optional threading.Event or cooperative cancellation token.",
    )

    @field_validator("max_depth")
    @classmethod
    def validate_max_depth(cls, v: int) -> int:
        if v < 1:
            raise ValueError("max_depth must be at least 1")
        if v > 64:
            raise ValueError("max_depth cannot exceed 64")
        return v

    @field_validator("max_entries")
    @classmethod
    def validate_max_entries(cls, v: int) -> int:
        if v < 1:
            raise ValueError("max_entries must be at least 1")
        return v

    @field_validator("timeout_seconds")
    @classmethod
    def validate_timeout_seconds(cls, v: float) -> float:
        if v <= 0.0:
            raise ValueError("timeout_seconds must be positive")
        return v

    @field_validator("max_file_size_for_expensive_analysis")
    @classmethod
    def validate_max_file_size(cls, v: int) -> int:
        if v < 0:
            raise ValueError("max_file_size_for_expensive_analysis cannot be negative")
        return v

    def is_cancelled(self) -> bool:
        """Check whether cancellation has been requested via the event token."""
        if self.cancellation_event is not None:
            if hasattr(self.cancellation_event, "is_set"):
                return bool(self.cancellation_event.is_set())
        return False


class ScanScope(BaseModel):
    """
    Defines a bounded, read-only discovery boundary.

    A ScanScope grants ZERO mutation or cleanup authority.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    scope_id: ScopeIdentifier = Field(
        ...,
        description="Standard or custom scope identifier.",
    )
    root_path: str = Field(
        ...,
        min_length=1,
        description="Root filesystem path of the discovery scope.",
    )
    description: str = Field(
        ...,
        min_length=1,
        description="Human-readable description of the scope purpose.",
    )
    enabled: bool = Field(
        default=True,
        description="Whether this scope is active for discovery.",
    )
    read_only: bool = Field(
        default=True,
        description="Strictly True for all discovery scopes. Mutation is forbidden.",
    )
    limits: TraversalLimits = Field(
        default_factory=TraversalLimits,
        description="Configurable traversal and resource limits for this scope.",
    )
    exclusions: Tuple[str, ...] = Field(
        default_factory=lambda: CANONICAL_SENSITIVE_EXCLUSIONS,
        description="Relative subpaths or patterns excluded from discovery traversal.",
    )
    stay_on_filesystem: bool = Field(
        default=True,
        description="Whether to restrict traversal to the same physical device/volume as the root.",
    )

    @field_validator("read_only")
    @classmethod
    def validate_read_only(cls, v: bool) -> bool:
        if not v:
            raise ValueError("ScanScope must always be read_only=True. Discovery grants zero mutation authority.")
        return True

    @field_validator("root_path")
    @classmethod
    def validate_root_path(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("root_path cannot be empty or whitespace.")
        expanded = os.path.expanduser(v.strip())
        if not os.path.isabs(expanded):
            raise ValueError(f"root_path must resolve to an absolute path: '{v}'")
        return os.path.abspath(expanded)

    def resolved_path(self) -> Path:
        """Return the resolved Path object for this scope root."""
        return Path(self.root_path).resolve()

    def is_path_excluded(self, path: Union[str, Path]) -> bool:
        """
        Check if a given path falls within an excluded sensitive subdirectory.
        """
        path_str = str(path)
        # Fast path: check if any exclusion segment is present in the path string
        if not any(excl.split("/")[-1] in path_str for excl in self.exclusions):
            return False

        try:
            resolved_target = Path(path).expanduser().resolve()
        except (RuntimeError, OSError):
            resolved_target = Path(path).expanduser()
        resolved_root = self.resolved_path()

        for exclusion in self.exclusions:
            # Check relative to scope root
            excl_target = (resolved_root / exclusion).resolve()
            try:
                resolved_target.relative_to(excl_target)
                return True
            except ValueError:
                pass

            # Check relative to home directory if exclusion is a home-relative subpath
            home = Path.home().resolve()
            excl_home = (home / exclusion).resolve()
            try:
                resolved_target.relative_to(excl_home)
                return True
            except ValueError:
                pass

        return False

    @classmethod
    def create_default_scopes(cls, home_dir: Optional[Union[str, Path]] = None) -> list[ScanScope]:
        """
        Factory method to generate standard v1.1 read-only discovery scopes.
        """
        home = Path(home_dir).expanduser().resolve() if home_dir else Path.home().resolve()

        return [
            cls(
                scope_id=ScopeIdentifier.HOME,
                root_path=str(home),
                description="Bounded user home directory (excluding sensitive credential and system subdirectories).",
                enabled=False,  # Home-wide scanning is disabled by default for conservative discovery
                limits=TraversalLimits(max_depth=8, max_entries=250_000, timeout_seconds=60.0),
            ),
            cls(
                scope_id=ScopeIdentifier.USER_CACHES,
                root_path=str(home / "Library" / "Caches"),
                description="User application cache directory (~/Library/Caches).",
                enabled=True,
                limits=TraversalLimits(max_depth=6, max_entries=100_000, timeout_seconds=30.0),
            ),
            cls(
                scope_id=ScopeIdentifier.DEVELOPER,
                root_path=str(home / "Projects"),
                description="User developer workspace and project directories (~/Projects).",
                enabled=False,
                limits=TraversalLimits(max_depth=10, max_entries=200_000, timeout_seconds=60.0),
            ),
            cls(
                scope_id=ScopeIdentifier.DOWNLOADS,
                root_path=str(home / "Downloads"),
                description="User Downloads directory (~/Downloads).",
                enabled=False,
                limits=TraversalLimits(max_depth=4, max_entries=50_000, timeout_seconds=30.0),
            ),
            cls(
                scope_id=ScopeIdentifier.DOCUMENTS,
                root_path=str(home / "Documents"),
                description="User Documents directory (~/Documents).",
                enabled=False,
                limits=TraversalLimits(max_depth=6, max_entries=100_000, timeout_seconds=30.0),
            ),
            cls(
                scope_id=ScopeIdentifier.DESKTOP,
                root_path=str(home / "Desktop"),
                description="User Desktop directory (~/Desktop).",
                enabled=False,
                limits=TraversalLimits(max_depth=4, max_entries=25_000, timeout_seconds=30.0),
            ),
            cls(
                scope_id=ScopeIdentifier.PICTURES,
                root_path=str(home / "Pictures"),
                description="User Pictures directory (~/Pictures).",
                enabled=False,
                limits=TraversalLimits(max_depth=6, max_entries=100_000, timeout_seconds=30.0),
            ),
            cls(
                scope_id=ScopeIdentifier.MOVIES,
                root_path=str(home / "Movies"),
                description="User Movies directory (~/Movies).",
                enabled=False,
                limits=TraversalLimits(max_depth=6, max_entries=50_000, timeout_seconds=30.0),
            ),
            cls(
                scope_id=ScopeIdentifier.MUSIC,
                root_path=str(home / "Music"),
                description="User Music directory (~/Music).",
                enabled=False,
                limits=TraversalLimits(max_depth=6, max_entries=50_000, timeout_seconds=30.0),
            ),
        ]
