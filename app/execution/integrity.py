from __future__ import annotations

import hashlib
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from pydantic import BaseModel, ConfigDict, Field

from app.safety.canonicalizer import canonicalize_path, is_contained_within


class PathIntegritySnapshot(BaseModel):
    """
    Immutable snapshot of a filesystem target's physical metadata recorded before execution.

    Guarantees:
    - Immutable (frozen).
    - Contains zero file contents.
    - Used solely for deterministic pre- and post-mutation integrity validation.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    canonical_path: str = Field(
        ...,
        min_length=1,
        description="Canonical absolute path of the target filesystem object.",
    )
    item_type: str = Field(
        ...,
        description="Physical type of object ('file', 'directory', 'symlink', or 'unknown').",
    )
    size_bytes: int = Field(
        default=0,
        ge=0,
        description="Size in bytes at snapshot capture time.",
    )
    mtime_ns: int = Field(
        default=0,
        description="Modification timestamp in nanoseconds.",
    )
    inode: int = Field(
        default=0,
        description="Filesystem inode number.",
    )
    device: int = Field(
        default=0,
        description="Filesystem device identifier.",
    )
    is_symlink: bool = Field(
        default=False,
        description="Whether the path was a symbolic link at snapshot time.",
    )
    approval_id: str = Field(
        ...,
        min_length=16,
        description="Associated cryptographic approval ID.",
    )
    content_sha256: Optional[str] = Field(
        default=None,
        description="Optional SHA-256 digest of regular file contents for exact verification.",
    )
    snapshot_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the snapshot was recorded.",
    )


def compute_file_sha256(
    file_path: Union[str, Path],
    max_size_bytes: int = 50 * 1024 * 1024,
) -> Optional[str]:
    """
    Compute SHA-256 digest of a regular file in streaming chunks.

    Safety:
    - Never loads entire file into memory.
    - Never uploads contents to LLMs or external networks.
    - Skips files exceeding `max_size_bytes` to prevent I/O saturation.
    - Fails safe (returns None) if file cannot be read.
    """
    path_obj = Path(file_path)
    try:
        st = os.lstat(str(path_obj))
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            return None
        if st.st_size > max_size_bytes:
            return None

        hasher = hashlib.sha256()
        with open(path_obj, "rb") as f:
            while chunk := f.read(64 * 1024):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (OSError, PermissionError):
        return None


def capture_integrity_snapshot(
    path: Union[str, Path],
    approval_id: str,
    compute_hash: bool = True,
    max_hash_size_bytes: int = 50 * 1024 * 1024,
) -> PathIntegritySnapshot:
    """
    Capture an immutable pre-execution metadata snapshot of the target filesystem object.

    Uses non-following `os.lstat()` to accurately record symlink state.
    """
    canonical_info = canonicalize_path(path)
    canonical_str = canonical_info.path_str

    try:
        st = os.lstat(canonical_str)
        is_symlink = stat.S_ISLNK(st.st_mode)
        is_dir = stat.S_ISDIR(st.st_mode)
        is_file = stat.S_ISREG(st.st_mode)

        if is_symlink:
            item_type = "symlink"
            size = 0
        elif is_dir:
            item_type = "directory"
            size = st.st_size
        elif is_file:
            item_type = "file"
            size = st.st_size
        else:
            item_type = "unknown"
            size = 0

        mtime_ns = getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))
        inode = st.st_ino
        device = st.st_dev

        content_hash = None
        if is_file and compute_hash:
            content_hash = compute_file_sha256(canonical_str, max_size_bytes=max_hash_size_bytes)

    except (OSError, FileNotFoundError):
        item_type = "nonexistent"
        size = 0
        mtime_ns = 0
        inode = 0
        device = 0
        is_symlink = False
        content_hash = None

    return PathIntegritySnapshot(
        canonical_path=canonical_str,
        item_type=item_type,
        size_bytes=size,
        mtime_ns=mtime_ns,
        inode=inode,
        device=device,
        is_symlink=is_symlink,
        approval_id=approval_id,
        content_sha256=content_hash,
        snapshot_timestamp=datetime.now(timezone.utc),
    )


def verify_pre_execution_integrity(
    snapshot: PathIntegritySnapshot,
    target_path: Union[str, Path],
    compute_hash: bool = True,
) -> tuple[bool, str]:
    """
    Verify that the target filesystem object has not changed materially between approval/planning
    and execution.

    Fails closed immediately if:
    - Path canonicalization fails or canonical path diverges.
    - Object was converted to a symlink.
    - Object type changed (e.g. file became directory).
    - Regular file size or content hash changed.
    - Inode changed on same device (indicating replacement).
    """
    try:
        canonical_info = canonicalize_path(target_path)
        canonical_str = canonical_info.path_str
    except Exception as exc:
        return False, f"Integrity check failed: Path canonicalization error ({exc})."

    if canonical_str != snapshot.canonical_path:
        return False, (
            f"Integrity check failed: Target path mismatch (snapshot: '{snapshot.canonical_path}', "
            f"current: '{canonical_str}')."
        )

    try:
        st = os.lstat(canonical_str)
    except FileNotFoundError:
        return False, f"Integrity check failed: Target path '{canonical_str}' does not exist on disk."
    except OSError as exc:
        return False, f"Integrity check failed: Unable to inspect target path '{canonical_str}' ({exc})."

    # Symlink Check
    if stat.S_ISLNK(st.st_mode) or os.path.islink(canonical_str):
        return False, f"Integrity check failed: Target '{canonical_str}' is a symbolic link. Symlinks are blocked."

    # Type Check
    is_dir = stat.S_ISDIR(st.st_mode)
    is_file = stat.S_ISREG(st.st_mode)

    if snapshot.item_type == "file" and not is_file:
        return False, f"Integrity check failed: Target '{canonical_str}' was expected to be a regular file."
    if snapshot.item_type == "directory" and not is_dir:
        return False, f"Integrity check failed: Target '{canonical_str}' was expected to be a directory."

    # Inode & Device Check (Object Replacement Detection)
    if snapshot.inode > 0 and (st.st_ino != snapshot.inode or st.st_dev != snapshot.device):
        # Inode difference indicates file was swapped or recreated
        return False, (
            f"Integrity check failed: Target '{canonical_str}' filesystem identity changed "
            f"(inode {snapshot.inode}->{st.st_ino}, dev {snapshot.device}->{st.st_dev})."
        )

    # File Size Check
    if is_file and snapshot.size_bytes > 0 and st.st_size != snapshot.size_bytes:
        return False, (
            f"Integrity check failed: Target '{canonical_str}' file size modified "
            f"(snapshot: {snapshot.size_bytes}B, current: {st.st_size}B)."
        )

    # Content Hash Verification for regular files
    if is_file and compute_hash and snapshot.content_sha256:
        current_hash = compute_file_sha256(canonical_str)
        if current_hash != snapshot.content_sha256:
            return False, (
                f"Integrity check failed: Target '{canonical_str}' content hash mismatch "
                f"(snapshot: {snapshot.content_sha256[:12]}..., current: {current_hash[:12] if current_hash else 'none'}...)."
            )

    return True, "Pre-execution integrity verification succeeded."


def verify_post_execution_integrity(
    snapshot: PathIntegritySnapshot,
    canonical_source_path: Union[str, Path],
    destination_path: Union[str, Path],
    trash_root: Union[str, Path],
) -> tuple[bool, str]:
    """
    Verify post-mutation integrity after moving an item to Trash.

    Verifies:
    1. Source path no longer exists (and is not an unlinked symlink).
    2. Destination exists and is strictly contained within canonical Trash root.
    3. Destination is not a symlink.
    4. Destination type matches original snapshot item type.
    5. Destination file size matches snapshot size for regular files.
    6. Destination content hash matches if originally computed.
    """
    source_str = str(canonical_source_path)
    dest_path = Path(destination_path)
    trash_root_path = Path(trash_root)

    # 1. Source absence verification
    if os.path.exists(source_str) or os.path.islink(source_str):
        return False, f"Post-execution verification failed: Source '{source_str}' still exists on disk."

    # 2. Destination existence & containment
    if not dest_path.exists():
        return False, f"Post-execution verification failed: Destination '{dest_path}' does not exist in Trash."

    if not is_contained_within(dest_path, trash_root_path):
        return False, f"Post-execution verification failed: Destination '{dest_path}' escapes Trash root '{trash_root_path}'."

    # 3. Destination metadata inspection
    try:
        dest_st = os.lstat(str(dest_path))
    except OSError as exc:
        return False, f"Post-execution verification failed: Unable to inspect destination '{dest_path}' ({exc})."

    if stat.S_ISLNK(dest_st.st_mode):
        return False, f"Post-execution verification failed: Destination '{dest_path}' is an unexpected symlink."

    dest_is_dir = stat.S_ISDIR(dest_st.st_mode)
    dest_is_file = stat.S_ISREG(dest_st.st_mode)

    if snapshot.item_type == "directory" and not dest_is_dir:
        return False, f"Post-execution verification failed: Destination '{dest_path}' is not a directory."
    if snapshot.item_type == "file" and not dest_is_file:
        return False, f"Post-execution verification failed: Destination '{dest_path}' is not a regular file."

    # 4. File Size & Content verification
    if snapshot.item_type == "file":
        if snapshot.size_bytes > 0 and dest_st.st_size != snapshot.size_bytes:
            return False, (
                f"Post-execution verification failed: Destination size mismatch "
                f"(expected {snapshot.size_bytes}B, found {dest_st.st_size}B)."
            )
        if snapshot.content_sha256:
            dest_hash = compute_file_sha256(str(dest_path))
            if dest_hash != snapshot.content_sha256:
                return False, (
                    f"Post-execution verification failed: Destination content hash mismatch "
                    f"(expected {snapshot.content_sha256[:12]}..., found {dest_hash[:12] if dest_hash else 'none'}...)."
                )

    return True, "Post-execution verification succeeded."
