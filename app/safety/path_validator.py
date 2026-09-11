from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import Optional, Sequence, Union

from pydantic import BaseModel, ConfigDict, Field

from app.analysis.models import RiskLevel
from app.safety.canonicalizer import canonicalize_path, is_contained_within


class Operation(str, Enum):
    """Operation types evaluated by the safety engine."""

    ANALYZE = "ANALYZE"
    RECOMMEND = "RECOMMEND"
    CLEAN = "CLEAN"


class PathValidationResult(BaseModel):
    """
    Structured policy evaluation result for a filesystem path.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str = Field(..., description="Original input path.")
    canonical_path: str = Field(..., description="Resolved canonical path.")
    allowed: bool = Field(..., description="Whether the operation is permitted.")
    operation: Operation = Field(..., description="The evaluated operation.")
    risk_level: RiskLevel = Field(..., description="Risk classification assigned by policy.")
    reason: str = Field(..., description="Human-readable policy explanation.")
    policy_rule: str = Field(..., description="Identifier of the governing policy rule.")


class PathValidator:
    """
    Strict deterministic safety policy validator.

    Enforces path containment, prevents path traversal/symlink escapes,
    guards protected system directories, and validates allowlisted clean locations.

    Performs zero filesystem modifications.
    """

    # System-level protected root directories (never eligible for mutation)
    SYSTEM_PROTECTED_ROOTS = frozenset({
        "/",
        "/System",
        "/System/Library",
        "/usr",
        "/bin",
        "/sbin",
        "/private",
        "/private/var",
        "/Applications",
        "/Library",
        "/Volumes",
        "/etc",
        "/var",
        "/tmp",
    })

    # Sensitive user directories that must never be targeted for cleanup
    SENSITIVE_USER_SUBDIRS = frozenset({
        ".ssh",
        ".gnupg",
        ".aws",
        ".config/gcloud",
        ".kube",
        "Documents",
        "Desktop",
        "Pictures",
        "Movies",
        "Music",
        "Library/Preferences",
        "Library/Keychains",
    })

    # Default allowlist roots for potential future clean operations
    DEFAULT_CLEAN_ALLOWLIST_ROOTS = (
        "~/Library/Caches",
        "~/Library/Logs",
        "~/.cache",
        "~/Library/Developer/Xcode/DerivedData",
    )

    def __init__(
        self,
        home_dir: Optional[Union[str, Path]] = None,
        custom_allowlist_roots: Optional[Sequence[Union[str, Path]]] = None,
    ) -> None:
        if home_dir is None:
            self._home_path = Path.home().resolve()
        else:
            self._home_path = Path(home_dir).expanduser().resolve()

        if custom_allowlist_roots is not None:
            self._allowlist_roots = [
                Path(p).expanduser().resolve() for p in custom_allowlist_roots
            ]
        else:
            self._allowlist_roots = [
                Path(os.path.expanduser(p)).resolve()
                for p in self.DEFAULT_CLEAN_ALLOWLIST_ROOTS
            ]

    @property
    def home_path(self) -> Path:
        return self._home_path

    @property
    def allowlist_roots(self) -> list[Path]:
        return list(self._allowlist_roots)

    def validate_path(
        self,
        path: Union[str, Path],
        operation: Operation = Operation.ANALYZE,
    ) -> PathValidationResult:
        """
        Validate a path against safety policies for the given operation.
        """
        try:
            canonical_info = canonicalize_path(path)
        except Exception as exc:
            return PathValidationResult(
                path=str(path),
                canonical_path=str(path),
                allowed=False,
                operation=operation,
                risk_level=RiskLevel.UNKNOWN,
                reason=f"Path rejected: Failed canonicalization ({exc}).",
                policy_rule="RULE_CANONICALIZATION_FAILED",
            )

        canonical_path = canonical_info.canonical_path
        canonical_str = str(canonical_path)

        # 1. Check System Protected Roots
        for sys_root in self.SYSTEM_PROTECTED_ROOTS:
            sys_path = Path(sys_root).resolve()
            if canonical_path == sys_path:
                return PathValidationResult(
                    path=str(path),
                    canonical_path=canonical_str,
                    allowed=operation == Operation.ANALYZE,
                    operation=operation,
                    risk_level=RiskLevel.HIGH,
                    reason=f"Path matches critical system protected root: '{sys_root}'.",
                    policy_rule="RULE_SYSTEM_ROOT_PROTECTION",
                )

        # 2. Check User Home Root (Cannot clean the entire home directory root)
        if canonical_path == self._home_path:
            return PathValidationResult(
                path=str(path),
                canonical_path=canonical_str,
                allowed=operation == Operation.ANALYZE,
                operation=operation,
                risk_level=RiskLevel.HIGH,
                reason="User home directory root itself cannot be targeted for cleanup.",
                policy_rule="RULE_HOME_ROOT_PROTECTION",
            )

        # 3. Check Sensitive User Subdirectories
        for sensitive_sub in self.SENSITIVE_USER_SUBDIRS:
            sensitive_full = (self._home_path / sensitive_sub).resolve()
            if canonical_path == sensitive_full or (
                canonical_path.is_relative_to(sensitive_full)
            ):
                return PathValidationResult(
                    path=str(path),
                    canonical_path=canonical_str,
                    allowed=operation == Operation.ANALYZE,
                    operation=operation,
                    risk_level=RiskLevel.HIGH,
                    reason=f"Path is within protected sensitive user location: '{sensitive_sub}'.",
                    policy_rule="RULE_SENSITIVE_USER_PATH_PROTECTION",
                )

        # 4. If operation is ANALYZE or RECOMMEND, allow read-only inspection
        if operation in (Operation.ANALYZE, Operation.RECOMMEND):
            return PathValidationResult(
                path=str(path),
                canonical_path=canonical_str,
                allowed=True,
                operation=operation,
                risk_level=RiskLevel.LOW,
                reason="Read-only operation permitted on non-restricted location.",
                policy_rule="RULE_READ_ONLY_ALLOWED",
            )

        # 5. Operation is CLEAN -> Strict Allowlist Verification
        # Check if the target is strictly inside one of the allowlisted roots
        matched_allowlist: Optional[Path] = None
        for allow_root in self._allowlist_roots:
            if is_contained_within(canonical_path, allow_root):
                matched_allowlist = allow_root
                break

        if matched_allowlist is None:
            # Also verify if the path was the allowlist root itself
            for allow_root in self._allowlist_roots:
                if canonical_path == allow_root:
                    return PathValidationResult(
                        path=str(path),
                        canonical_path=canonical_str,
                        allowed=False,
                        operation=Operation.CLEAN,
                        risk_level=RiskLevel.HIGH,
                        reason=f"Allowlist root directory itself ('{allow_root}') cannot be deleted.",
                        policy_rule="RULE_ALLOWLIST_ROOT_PROTECTION",
                    )

            return PathValidationResult(
                path=str(path),
                canonical_path=canonical_str,
                allowed=False,
                operation=Operation.CLEAN,
                risk_level=RiskLevel.UNKNOWN,
                reason="Path is outside all configured allowlist boundaries for cleanup.",
                policy_rule="RULE_ALLOWLIST_REJECTED",
            )

        # Path is strictly within an allowlisted root
        return PathValidationResult(
            path=str(path),
            canonical_path=canonical_str,
            allowed=True,
            operation=Operation.CLEAN,
            risk_level=RiskLevel.LOW,
            reason=f"Path is strictly contained within approved allowlist root: '{matched_allowlist}'.",
            policy_rule="RULE_ALLOWLIST_CONTAINED",
        )
