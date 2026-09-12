"""
MacGuard AI Phase 12 — Base Storage Detector Interface.

Defines the contract for all modular detectors.
Every detector operates strictly read-only and emits standardized StorageEvidenceItem instances.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from app.models.investigation import StorageEvidenceItem
from app.models.scan_scope import ScanScope
from app.safety.canonicalizer import canonicalize_path
from app.safety.path_validator import Operation, PathValidator
from app.tools.storage_scanner import StorageScanner


class BaseStorageDetector(ABC):
    """
    Abstract base class for storage investigation detectors.
    """

    @property
    @abstractmethod
    def detector_id(self) -> str:
        """Unique detector identifier (e.g. 'cache_detector')."""
        pass

    @property
    @abstractmethod
    def detector_name(self) -> str:
        """Human-readable detector name."""
        pass

    @abstractmethod
    def detect(
        self,
        scope: ScanScope,
        visited_inodes: set[tuple[int, int]],
        scanner: Optional[StorageScanner] = None,
        path_validator: Optional[PathValidator] = None,
    ) -> list[StorageEvidenceItem]:
        """
        Execute read-only discovery within the allowed scope.

        Must respect:
        - visited_inodes set to avoid double counting across items
        - scope boundaries
        - non-destructive read-only constraints
        """
        pass

    def get_dir_size_and_count(
        self,
        path: str,
        visited_inodes: set[tuple[int, int]],
        max_depth: int = 10,
    ) -> tuple[int, int]:
        """
        Calculate total size and file count for a directory using inode tracking.
        """
        total_size = 0
        total_count = 0
        target_path = Path(path)
        if not target_path.exists():
            return 0, 0

        base_depth = len(target_path.parts)

        try:
            for root, dirs, files in os.walk(path, topdown=True, onerror=lambda _: None, followlinks=False):
                # Depth limit check
                cur_depth = len(Path(root).parts) - base_depth
                if cur_depth >= max_depth:
                    dirs.clear()

                for f in files:
                    fp = os.path.join(root, f)
                    try:
                        if os.path.islink(fp):
                            continue
                        st = os.lstat(fp)
                        node = (st.st_dev, st.st_ino)
                        if node in visited_inodes:
                            continue
                        visited_inodes.add(node)
                        total_size += st.st_size
                        total_count += 1
                    except (OSError, PermissionError):
                        continue
        except (OSError, PermissionError):
            return total_size, total_count

        return total_size, total_count
