"""
MacGuard AI v1.1 — Duplicate & Redundancy Intelligence Engine (Phase 6).

Implements deterministic, read-only two-stage streaming hash comparison (partial + full SHA-256)
to detect identical files while accurately accounting for APFS hardlinks and resource bounds.

ABSOLUTE SAFETY INVARIANTS:
- ANALYSIS ONLY: Zero deletion, mutation, hardlink recreation, or moving to Trash.
- ZERO SYSTEM AUTHORITY: Possesses zero approval, execution, or HMAC capability.
- BOUNDED RESOURCE USAGE: Streaming 64KB reads, memory bounded, files > 5 GiB skipped from bulk hashing.
"""

from __future__ import annotations

import hashlib
import os
from collections import defaultdict
from typing import Dict, List, Optional, Sequence, Set, Tuple

from app.models.duplicate import (
    DuplicateCluster,
    DuplicateFile,
    DuplicateGroup,
    DuplicateScanSummary,
)
from app.models.scan_result import DiscoveredItem, ScanResult


DEFAULT_MIN_DUPLICATE_SIZE_BYTES: int = 1024 * 1024  # 1 MiB
DEFAULT_MAX_AUTO_HASH_SIZE_BYTES: int = 5 * 1024 * 1024 * 1024  # 5 GiB
PARTIAL_HASH_CHUNK_BYTES: int = 4096  # 4 KiB prefix/suffix
FULL_HASH_CHUNK_BYTES: int = 65536  # 64 KiB streaming chunk


class DuplicateDetector:
    """
    Deterministic, read-only duplicate file detection engine.

    Consumes existing scan discovery metadata (Phase 2), performs two-stage
    streaming hash analysis, and computes physical space waste accounting for APFS hardlinks.
    """

    def __init__(
        self,
        min_file_size_bytes: int = DEFAULT_MIN_DUPLICATE_SIZE_BYTES,
        max_auto_hash_size_bytes: int = DEFAULT_MAX_AUTO_HASH_SIZE_BYTES,
    ) -> None:
        """
        Initialize DuplicateDetector with configurable size thresholds.

        Args:
            min_file_size_bytes: Minimum byte size for duplicate consideration (default: 1 MiB).
            max_auto_hash_size_bytes: Maximum size for automatic bulk hashing (default: 5 GiB).
        """
        if min_file_size_bytes < 0:
            raise ValueError("min_file_size_bytes cannot be negative.")
        if max_auto_hash_size_bytes < min_file_size_bytes:
            raise ValueError("max_auto_hash_size_bytes cannot be less than min_file_size_bytes.")

        self.min_file_size_bytes = min_file_size_bytes
        self.max_auto_hash_size_bytes = max_auto_hash_size_bytes

    def find_duplicates(
        self,
        scan_result: ScanResult,
    ) -> Tuple[List[DuplicateCluster], DuplicateScanSummary]:
        """
        Analyze a completed ScanResult for duplicate file clusters.

        Args:
            scan_result: Completed scan metadata containing discovered items.

        Returns:
            Tuple of (sorted DuplicateCluster list, DuplicateScanSummary).
        """
        items = getattr(scan_result, "items", None) or getattr(scan_result, "discovered_items", [])
        return self.find_duplicates_from_items(items)

    def find_duplicates_from_items(
        self,
        items: Sequence[DiscoveredItem],
    ) -> Tuple[List[DuplicateCluster], DuplicateScanSummary]:
        """
        Analyze a sequence of DiscoveredItem metadata objects for duplicate clusters.

        Processing Pipeline:
        1. Pre-filtering: Filter regular non-symlink files >= 1 MiB and <= 5 GiB.
        2. Size Grouping: Group candidates by exact byte size; discard unique sizes.
        3. Hardlink Mapping: Map shared (st_dev, st_ino) inodes to avoid duplicate I/O.
        4. Partial Hashing: Stream first 4KB + last 4KB; discard unique partial hashes.
        5. Full SHA-256 Hashing: Stream 64KB chunks to compute byte-exact digests.
        6. Deterministic Clustering: Group identical files, calculate physical waste,
           and sort clusters stably.

        Returns:
            Tuple of (sorted DuplicateCluster list, DuplicateScanSummary).
        """
        skipped_large_files = 0
        eligible_candidates: List[DiscoveredItem] = []

        # 1. Pre-filtering
        for item in items:
            # Skip directories, symlinks, or non-regular files
            if getattr(item, "item_type", "file") != "file" or item.is_symlink:
                continue

            size = item.size_bytes
            if size > self.max_auto_hash_size_bytes:
                skipped_large_files += 1
                continue

            if size >= self.min_file_size_bytes:
                eligible_candidates.append(item)

        if not eligible_candidates:
            return [], DuplicateScanSummary(
                total_clusters=0,
                total_duplicate_files=0,
                potential_reclaimable_bytes=0,
                skipped_large_files=skipped_large_files,
            )

        # 2. Size Grouping: Group candidates by size_bytes
        size_groups: Dict[int, List[DiscoveredItem]] = defaultdict(list)
        for item in eligible_candidates:
            size_groups[item.size_bytes].append(item)

        # Eliminate unique-size files (need >= 2 items to be a duplicate candidate)
        size_candidates: List[DiscoveredItem] = []
        for size, group in size_groups.items():
            if len(group) >= 2:
                size_candidates.extend(group)

        if not size_candidates:
            return [], DuplicateScanSummary(
                total_clusters=0,
                total_duplicate_files=0,
                potential_reclaimable_bytes=0,
                skipped_large_files=skipped_large_files,
            )

        # 3. Partial Hash Stage (with hardlink-aware I/O optimization)
        # Map of (dev, ino) -> (partial_hash, full_sha256) cache
        inode_hash_cache: Dict[Tuple[int, int], Tuple[Optional[str], Optional[str]]] = {}
        partial_hash_groups: Dict[Tuple[int, str], List[Tuple[DiscoveredItem, Optional[int], Optional[int], str]]] = defaultdict(list)

        for item in size_candidates:
            dev, ino = self._get_inode_and_dev(item)
            partial_h: Optional[str] = None

            if dev is not None and ino is not None and (dev, ino) in inode_hash_cache:
                cached_partial, _ = inode_hash_cache[(dev, ino)]
                partial_h = cached_partial
            else:
                partial_h = self._compute_partial_hash(item.path, item.size_bytes)
                if dev is not None and ino is not None and partial_h is not None:
                    inode_hash_cache[(dev, ino)] = (partial_h, None)

            if partial_h is not None:
                partial_hash_groups[(item.size_bytes, partial_h)].append((item, dev, ino, partial_h))

        # Eliminate unique partial hashes
        full_hash_candidates: List[Tuple[DiscoveredItem, Optional[int], Optional[int], str]] = []
        for (size, ph), group in partial_hash_groups.items():
            if len(group) >= 2:
                full_hash_candidates.extend(group)

        if not full_hash_candidates:
            return [], DuplicateScanSummary(
                total_clusters=0,
                total_duplicate_files=0,
                potential_reclaimable_bytes=0,
                skipped_large_files=skipped_large_files,
            )

        # 4. Full SHA-256 Stage
        full_sha_groups: Dict[Tuple[int, str], List[Tuple[DiscoveredItem, Optional[int], Optional[int], str, str]]] = defaultdict(list)

        for item, dev, ino, partial_h in full_hash_candidates:
            full_sha: Optional[str] = None

            if dev is not None and ino is not None and (dev, ino) in inode_hash_cache:
                _, cached_full = inode_hash_cache[(dev, ino)]
                if cached_full is not None:
                    full_sha = cached_full

            if full_sha is None:
                full_sha = self._compute_full_sha256(item.path)
                if dev is not None and ino is not None and full_sha is not None:
                    inode_hash_cache[(dev, ino)] = (partial_h, full_sha)

            if full_sha is not None:
                full_sha_groups[(item.size_bytes, full_sha)].append((item, dev, ino, partial_h, full_sha))

        # 5. Build Clusters & Calculate APFS Hardlink Waste
        clusters: List[DuplicateCluster] = []
        total_dup_files = 0
        total_potential_reclaimable = 0

        for (file_size, full_sha), group in full_sha_groups.items():
            if len(group) < 2:
                continue

            # Sort files deterministically by canonical path
            group.sort(key=lambda entry: entry[0].path)

            seen_inodes: Set[Tuple[int, int]] = set()
            dup_files: List[DuplicateFile] = []
            distinct_physical_copies = 0
            hardlink_count = 0

            for item, dev, ino, partial_h, full_h in group:
                is_hardlink = False
                if dev is not None and ino is not None:
                    if (dev, ino) in seen_inodes:
                        is_hardlink = True
                        hardlink_count += 1
                    else:
                        seen_inodes.add((dev, ino))
                        distinct_physical_copies += 1
                else:
                    # Inode unavailable; treat as independent physical copy
                    distinct_physical_copies += 1

                cat_str = (
                    item.category.value
                    if getattr(item, "category", None)
                    else getattr(item, "smart_category", None).value
                    if getattr(item, "smart_category", None)
                    else None
                )

                dup_files.append(
                    DuplicateFile(
                        path=item.path,
                        size_bytes=item.size_bytes,
                        inode=ino,
                        dev=dev,
                        partial_hash=partial_h,
                        full_sha256=full_h,
                        is_hardlink=is_hardlink,
                        category=cat_str,
                    )
                )

            # Potential reclaimable bytes = (distinct_physical_copies - 1) * file_size
            wasted = max(0, distinct_physical_copies - 1) * file_size

            cluster_id = f"cluster-{full_sha[:16]}-{file_size}"
            cluster = DuplicateCluster(
                cluster_id=cluster_id,
                file_size_bytes=file_size,
                files=dup_files,
                wasted_bytes=wasted,
                hardlink_count=hardlink_count,
            )
            clusters.append(cluster)
            total_dup_files += len(dup_files)
            total_potential_reclaimable += wasted

        # 6. Sort clusters deterministically: wasted_bytes DESC, file_size_bytes DESC, cluster_id ASC
        clusters.sort(key=lambda c: (-c.wasted_bytes, -c.file_size_bytes, c.cluster_id))

        summary = DuplicateScanSummary(
            total_clusters=len(clusters),
            total_duplicate_files=total_dup_files,
            potential_reclaimable_bytes=total_potential_reclaimable,
            skipped_large_files=skipped_large_files,
        )

        return clusters, summary

    def _get_inode_and_dev(self, item: DiscoveredItem) -> Tuple[Optional[int], Optional[int]]:
        """
        Safely retrieve (dev, ino) metadata from item or filesystem.
        """
        if getattr(item, "st_ino", None) is not None and getattr(item, "st_dev", None) is not None:
            return item.st_dev, item.st_ino
        if getattr(item, "inode", None) is not None and getattr(item, "device_id", None) is not None:
            return item.device_id, item.inode

        try:
            st = os.lstat(item.path)
            return st.st_dev, st.st_ino
        except (OSError, PermissionError):
            return None, None

    def _compute_partial_hash(self, path: str, size_bytes: int) -> Optional[str]:
        """
        Compute deterministic partial SHA-256 over prefix (4KB) and suffix (4KB).

        Streaming strategy:
        - If size <= 8192: read the entire file once and hash.
        - If size > 8192: read first 4096 bytes, seek to size - 4096, read last 4096 bytes.

        Returns:
            Hex string digest of partial content, or None if reading fails.
        """
        try:
            with open(path, "rb") as f:
                hasher = hashlib.sha256()
                if size_bytes <= PARTIAL_HASH_CHUNK_BYTES * 2:
                    data = f.read()
                    hasher.update(data)
                else:
                    prefix = f.read(PARTIAL_HASH_CHUNK_BYTES)
                    hasher.update(prefix)
                    f.seek(size_bytes - PARTIAL_HASH_CHUNK_BYTES)
                    suffix = f.read(PARTIAL_HASH_CHUNK_BYTES)
                    hasher.update(suffix)
                return hasher.hexdigest()
        except (OSError, PermissionError):
            # Fail closed cleanly for unreadable/missing/raced files
            return None

    def _compute_full_sha256(self, path: str) -> Optional[str]:
        """
        Compute byte-exact full SHA-256 digest using streaming 64KB chunk reads.

        Never reads entire file into memory at once.

        Returns:
            Full SHA-256 hex string, or None if reading fails.
        """
        try:
            hasher = hashlib.sha256()
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(FULL_HASH_CHUNK_BYTES)
                    if not chunk:
                        break
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (OSError, PermissionError):
            # Fail closed cleanly for unreadable/missing/raced files
            return None
