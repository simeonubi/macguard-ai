from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import psutil

from app.models.scan_result import DiscoveredItem, ScanResult, ScanStatus
from app.models.scan_scope import ScanScope, TraversalLimits


@dataclass
class DiskUsage:
    """Represents disk usage information."""

    path: str
    total_bytes: int
    used_bytes: int
    free_bytes: int

    @property
    def usage_percent(self) -> float:
        if self.total_bytes == 0:
            return 0.0

        return (self.used_bytes / self.total_bytes) * 100


@dataclass
class StorageItem:
    """Represents a file or directory discovered during scanning."""

    path: str
    size_bytes: int
    item_type: str


class StorageScanner:
    """
    Read-only macOS storage scanner.

    This class MUST NOT modify, delete, move, or rename files.
    """

    def get_disk_usage(self, path: str = "/") -> DiskUsage:
        """
        Return filesystem disk usage statistics for the specified path.

        Uses shutil.disk_usage to read live filesystem allocation,
        validated on the current Mac/APFS environment.
        """
        import shutil

        try:
            total, used, free = shutil.disk_usage(path)
        except (OSError, ValueError):
            try:
                total, used, free = shutil.disk_usage("/")
            except Exception:
                total, used, free = 0, 0, 0

        return DiskUsage(
            path=path,
            total_bytes=total,
            used_bytes=used,
            free_bytes=free,
        )

    def get_directory_size(self, path: str) -> int:
        """
        Calculate the total size of a directory.

        Permission errors and inaccessible files are skipped.
        """

        total_size = 0

        try:
            for root, directories, files in os.walk(
                path,
                topdown=True,
                onerror=lambda _: None,
                followlinks=False,
            ):
                # Prevent traversal into symbolic links.
                directories[:] = [
                    directory
                    for directory in directories
                    if not os.path.islink(os.path.join(root, directory))
                ]

                for filename in files:
                    file_path = os.path.join(root, filename)

                    try:
                        if os.path.islink(file_path):
                            continue

                        total_size += os.path.getsize(file_path)

                    except (OSError, PermissionError):
                        continue

        except (OSError, PermissionError):
            return 0

        return total_size

    def get_top_directories(
        self,
        path: str = "/",
        limit: int = 20,
    ) -> list[StorageItem]:
        """
        Return the largest immediate directories inside path.
        """

        results: list[StorageItem] = []

        try:
            with os.scandir(path) as entries:
                for entry in entries:
                    if not entry.is_dir(follow_symlinks=False):
                        continue

                    try:
                        size = self.get_directory_size(entry.path)

                        results.append(
                            StorageItem(
                                path=entry.path,
                                size_bytes=size,
                                item_type="directory",
                            )
                        )

                    except (OSError, PermissionError):
                        continue

        except (OSError, PermissionError):
            return []

        results.sort(
            key=lambda item: item.size_bytes,
            reverse=True,
        )

        return results[:limit]

    def get_large_files(
        self,
        path: str,
        limit: int = 20,
    ) -> list[StorageItem]:
        """
        Find the largest files underneath a directory using a bounded min-heap.

        This is a read-only operation with O(limit) memory footprint.
        """
        if limit <= 0:
            return []

        import heapq

        # min-heap storing tuples of (size_bytes, counter, StorageItem)
        heap: list[tuple[int, int, StorageItem]] = []
        counter = 0

        for root, directories, files in os.walk(
            path,
            topdown=True,
            onerror=lambda _: None,
            followlinks=False,
        ):
            directories[:] = [
                directory
                for directory in directories
                if not os.path.islink(os.path.join(root, directory))
            ]

            for filename in files:
                file_path = os.path.join(root, filename)

                try:
                    if os.path.islink(file_path):
                        continue

                    size = os.path.getsize(file_path)
                    item = StorageItem(
                        path=file_path,
                        size_bytes=size,
                        item_type="file",
                    )
                    counter += 1

                    if len(heap) < limit:
                        heapq.heappush(heap, (size, counter, item))
                    elif size > heap[0][0]:
                        heapq.heappushpop(heap, (size, counter, item))

                except (OSError, PermissionError):
                    continue

        results = [entry[2] for entry in heap]
        results.sort(
            key=lambda item: item.size_bytes,
            reverse=True,
        )

        return results

    def scan_scope(
        self,
        scope: ScanScope,
        limits: Optional[TraversalLimits] = None,
    ) -> ScanResult:
        """
        Perform a bounded, read-only discovery scan across a designated ScanScope.

        Enforces:
        - max_depth traversal limit
        - max_entries traversal limit
        - timeout_seconds limit
        - cancellation_event cooperative termination
        - follow_symlinks=False (never follows symlinks by default)
        - stay_on_filesystem=True (device st_dev boundary enforcement)
        - Canonical sensitive directory exclusions

        This operation is STRICTLY READ-ONLY and grants ZERO mutation authority.
        """
        import time

        active_limits = limits if limits is not None else scope.limits
        start_time = time.time()
        root_path = scope.resolved_path()

        if not root_path.exists():
            end_time = time.time()
            return ScanResult(
                scope_id=scope.scope_id,
                root_path=str(root_path),
                status=ScanStatus.ERROR,
                start_time=start_time,
                end_time=end_time,
                duration_seconds=round(end_time - start_time, 4),
                error_message=f"Scan root path does not exist: '{root_path}'",
            )

        try:
            root_st = os.lstat(root_path)
            root_st_dev = root_st.st_dev
        except (PermissionError, OSError) as exc:
            end_time = time.time()
            return ScanResult(
                scope_id=scope.scope_id,
                root_path=str(root_path),
                status=ScanStatus.ERROR,
                start_time=start_time,
                end_time=end_time,
                duration_seconds=round(end_time - start_time, 4),
                permission_errors_count=1,
                skipped_entries_count=1,
                error_message=f"Cannot stat scan root: {exc}",
            )

        if os.path.islink(root_path) and not active_limits.follow_symlinks:
            end_time = time.time()
            return ScanResult(
                scope_id=scope.scope_id,
                root_path=str(root_path),
                status=ScanStatus.COMPLETED,
                start_time=start_time,
                end_time=end_time,
                duration_seconds=round(end_time - start_time, 4),
                symlinks_skipped_count=1,
                skipped_entries_count=1,
            )

        # Worklist: (current_directory_path, current_depth)
        worklist: list[tuple[Path, int]] = [(root_path, 0)]
        visited_dirs: set[tuple[int, int]] = {(root_st_dev, root_st.st_ino)}

        items: list[DiscoveredItem] = []
        files_count = 0
        directories_count = 0
        total_bytes = 0
        entries_count = 0
        permission_errors_count = 0
        symlinks_skipped_count = 0
        filesystem_boundary_skips_count = 0
        excluded_entries_count = 0
        skipped_entries_count = 0
        status = ScanStatus.COMPLETED

        while worklist:
            if active_limits.is_cancelled():
                status = ScanStatus.CANCELLED
                break

            if (time.time() - start_time) >= active_limits.timeout_seconds:
                status = ScanStatus.TIMEOUT
                break

            if entries_count >= active_limits.max_entries:
                status = ScanStatus.ENTRY_LIMIT_REACHED
                break

            current_dir, current_depth = worklist.pop()

            try:
                with os.scandir(current_dir) as it:
                    for entry in it:
                        if active_limits.is_cancelled():
                            status = ScanStatus.CANCELLED
                            break

                        if (time.time() - start_time) >= active_limits.timeout_seconds:
                            status = ScanStatus.TIMEOUT
                            break

                        if entries_count >= active_limits.max_entries:
                            status = ScanStatus.ENTRY_LIMIT_REACHED
                            break

                        entries_count += 1

                        # Sensitive subpath exclusion
                        if scope.is_path_excluded(entry.path):
                            excluded_entries_count += 1
                            skipped_entries_count += 1
                            continue

                        # Symlink check
                        try:
                            is_link = entry.is_symlink()
                        except (OSError, FileNotFoundError):
                            skipped_entries_count += 1
                            continue

                        if is_link and not active_limits.follow_symlinks:
                            symlinks_skipped_count += 1
                            skipped_entries_count += 1
                            continue

                        # Entry metadata stat
                        try:
                            st = entry.stat(follow_symlinks=False)
                        except PermissionError:
                            permission_errors_count += 1
                            skipped_entries_count += 1
                            continue
                        except (OSError, FileNotFoundError):
                            skipped_entries_count += 1
                            continue

                        # Filesystem boundary check
                        if active_limits.stay_on_filesystem and st.st_dev != root_st_dev:
                            filesystem_boundary_skips_count += 1
                            skipped_entries_count += 1
                            continue

                        # Directory vs regular file handling
                        try:
                            is_dir = entry.is_dir(follow_symlinks=False)
                        except (OSError, PermissionError):
                            permission_errors_count += 1
                            skipped_entries_count += 1
                            continue

                        if is_dir:
                            dir_node = (st.st_dev, st.st_ino)
                            if dir_node in visited_dirs:
                                continue
                            visited_dirs.add(dir_node)

                            directories_count += 1
                            items.append(
                                DiscoveredItem(
                                    path=entry.path,
                                    size_bytes=0,
                                    item_type="directory",
                                    depth=current_depth + 1,
                                    mtime=st.st_mtime,
                                    st_ino=st.st_ino,
                                    st_dev=st.st_dev,
                                    is_symlink=False,
                                    parent_path=str(current_dir),
                                )
                            )

                            if current_depth + 1 < active_limits.max_depth:
                                worklist.append((Path(entry.path), current_depth + 1))
                        else:
                            files_count += 1
                            size = st.st_size
                            total_bytes += size
                            items.append(
                                DiscoveredItem(
                                    path=entry.path,
                                    size_bytes=size,
                                    item_type="file",
                                    depth=current_depth + 1,
                                    mtime=st.st_mtime,
                                    st_ino=st.st_ino,
                                    st_dev=st.st_dev,
                                    is_symlink=False,
                                    parent_path=str(current_dir),
                                )
                            )

            except PermissionError:
                permission_errors_count += 1
                skipped_entries_count += 1
                continue
            except (OSError, FileNotFoundError):
                skipped_entries_count += 1
                continue

        end_time = time.time()
        return ScanResult(
            scope_id=scope.scope_id,
            root_path=str(root_path),
            status=status,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=round(end_time - start_time, 4),
            files_count=files_count,
            directories_count=directories_count,
            total_bytes=total_bytes,
            items=items,
            skipped_entries_count=skipped_entries_count,
            permission_errors_count=permission_errors_count,
            excluded_entries_count=excluded_entries_count,
            symlinks_skipped_count=symlinks_skipped_count,
            filesystem_boundary_skips_count=filesystem_boundary_skips_count,
        )

    @staticmethod
    def get_common_user_storage_targets(home_path: Optional[str] = None) -> list[str]:
        """
        Return safe, common user storage target directories for quick/focused scanning.
        """
        home = Path(home_path).resolve() if home_path else Path.home().resolve()
        candidates = [
            home / "Library" / "Caches",
            home / "Library" / "Logs",
            home / "Library" / "Developer" / "Xcode" / "DerivedData",
            home / "Library" / "Developer" / "CoreSimulator" / "Caches",
            home / ".cache",
            home / "Downloads",
        ]
        return [str(p) for p in candidates if p.exists()]



def format_bytes(size: int) -> str:
    """Convert bytes into a human-readable size (traditional base 1024)."""
    units = [
        "B",
        "KB",
        "MB",
        "GB",
        "TB",
    ]

    value = float(size)

    for unit in units:
        if abs(value) < 1024 or unit == "TB":
            return f"{value:.2f} {unit}"

        value /= 1024

    return f"{value:.2f} PB"


def format_bytes_decimal(size: int) -> str:
    """
    Convert bytes into decimal SI units (base 1000: B, KB, MB, GB, TB)
    matching macOS Finder / System Settings specifications.
    """
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size)
    for unit in units:
        if abs(value) < 1000 or unit == "TB":
            return f"{value:.2f} {unit}"
        value /= 1000
    return f"{value:.2f} PB"


def format_bytes_binary(size: int) -> str:
    """
    Convert bytes into IEC standard binary units (base 1024: B, KiB, MiB, GiB, TiB).
    """
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    value = float(size)
    for unit in units:
        if abs(value) < 1024 or unit == "TiB":
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{value:.2f} PiB"


def format_storage_dual(size: int) -> str:
    """
    Format storage showing decimal SI units alongside IEC binary units
    (e.g., '245.11 GB (228.27 GiB)').
    """
    dec = format_bytes_decimal(size)
    iec = format_bytes_binary(size)
    return f"{dec} ({iec})"