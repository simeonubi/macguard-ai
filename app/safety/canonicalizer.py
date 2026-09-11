from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Union


@dataclass(frozen=True)
class CanonicalPath:
    """
    Structured representation of a canonicalized filesystem path.

    This representation is strictly informational and guarantees zero mutation.
    """

    raw_path: str
    canonical_path: Path
    exists: bool
    is_symlink: bool
    is_dir: bool
    is_file: bool

    @property
    def path_str(self) -> str:
        return str(self.canonical_path)


def canonicalize_path(path: Union[str, Path]) -> CanonicalPath:
    """
    Safely canonicalize a filesystem path.

    - Rejects empty paths or paths with null bytes.
    - Expands user home `~`.
    - Normalizes relative components (`.`, `..`).
    - Resolves all symlinks to their true physical targets.
    - Accurately tracks existence, symlink presence, and type.
    - Never mutates, creates, deletes, or modifies filesystem objects.
    """
    if isinstance(path, Path):
        raw_str = str(path)
    else:
        raw_str = str(path).strip()

    if not raw_str:
        raise ValueError("Path cannot be empty.")

    if "\x00" in raw_str:
        raise ValueError("Path contains illegal null byte character.")

    # Expand user home tilde
    expanded_str = os.path.expanduser(raw_str)
    expanded_path = Path(expanded_str)

    # Check if the path itself or any of its ancestors is a symlink
    is_symlink = False
    try:
        if os.path.islink(expanded_str):
            is_symlink = True
        else:
            current = expanded_path
            while current != current.parent:
                if current.exists() and os.path.islink(str(current)):
                    is_symlink = True
                    break
                current = current.parent
    except (OSError, PermissionError):
        # Fail safe if stat fails
        pass

    # Resolve canonical physical path (resolves symlinks and normalizes .. and .)
    try:
        canonical_str = os.path.realpath(expanded_str)
        canonical = Path(canonical_str)
    except Exception as exc:
        raise ValueError(f"Failed to canonicalize path '{raw_str}': {exc}") from exc

    # Determine file/dir state
    exists = canonical.exists()
    is_dir = canonical.is_dir() if exists else False
    is_file = canonical.is_file() if exists else False

    return CanonicalPath(
        raw_path=raw_str,
        canonical_path=canonical,
        exists=exists,
        is_symlink=is_symlink,
        is_dir=is_dir,
        is_file=is_file,
    )


def is_contained_within(child: Union[str, Path], parent: Union[str, Path]) -> bool:
    """
    Determine if `child` is strictly located inside `parent` after canonicalization.

    Returns True ONLY if canonical `child` is a subpath of canonical `parent`
    AND `child` is not equal to `parent`.
    Prevents directory traversal, symlink escapes, and prefix collisions
    (e.g., /Users/mac-evil vs /Users/mac).
    """
    canonical_child = canonicalize_path(child).canonical_path
    canonical_parent = canonicalize_path(parent).canonical_path

    try:
        return canonical_child.is_relative_to(canonical_parent) and canonical_child != canonical_parent
    except AttributeError:
        # Fallback for older python if needed
        try:
            canonical_child.relative_to(canonical_parent)
            return canonical_child != canonical_parent
        except ValueError:
            return False
