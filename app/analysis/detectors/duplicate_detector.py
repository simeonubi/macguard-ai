"""
MacGuard AI Phase 12 — Duplicate Storage Detector.

Wraps and integrates DuplicateDetector to identify redundant files across user space.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from app.analysis.detectors.base import BaseStorageDetector
from app.analysis.detectors.usage_inspector import detect_associated_running_processes, is_path_recently_modified
from app.analysis.duplicate_detector import DuplicateDetector as CoreDuplicateDetector
from app.analysis.models import RiskLevel
from app.models.category import SmartCategory
from app.models.investigation import ReclaimConfidence, StorageEvidenceItem
from app.models.scan_result import DiscoveredItem
from app.models.scan_scope import ScanScope
from app.safety.canonicalizer import canonicalize_path
from app.safety.path_validator import Operation, PathValidator
from app.tools.storage_scanner import StorageScanner


class DuplicateStorageDetector(BaseStorageDetector):
    """
    Detector for identical duplicate files across user directories.
    """

    def __init__(self, core_detector: Optional[CoreDuplicateDetector] = None) -> None:
        self._detector = core_detector or CoreDuplicateDetector(min_file_size_bytes=5 * 1024 * 1024)

    @property
    def detector_id(self) -> str:
        return "duplicate_storage_detector"

    @property
    def detector_name(self) -> str:
        return "Duplicate & Redundant Files"

    def detect(
        self,
        scope: ScanScope,
        visited_inodes: set[tuple[int, int]],
        scanner: Optional[StorageScanner] = None,
        path_validator: Optional[PathValidator] = None,
    ) -> list[StorageEvidenceItem]:
        items: list[StorageEvidenceItem] = []
        validator = path_validator or PathValidator()
        user_home = Path.home()

        target_dirs = [
            user_home / "Downloads",
            user_home / "Documents",
            user_home / "Desktop",
        ]

        discovered: list[DiscoveredItem] = []
        for target_dir in target_dirs:
            if not target_dir.exists() or not scope.is_path_allowed(str(target_dir)):
                continue

            try:
                for root, _, files in os.walk(str(target_dir), topdown=True, onerror=lambda _: None, followlinks=False):
                    for f in files:
                        fp = os.path.join(root, f)
                        try:
                            if os.path.islink(fp):
                                continue
                            st = os.lstat(fp)
                            if st.st_size >= 5 * 1024 * 1024:
                                discovered.append(
                                    DiscoveredItem(
                                        path=fp,
                                        size_bytes=st.st_size,
                                        is_directory=False,
                                        is_symlink=False,
                                        modified_time=st.st_mtime,
                                    )
                                )
                                if len(discovered) > 500:  # Bounded item check for duplicates
                                    break
                        except (OSError, PermissionError):
                            continue
                    if len(discovered) > 500:
                        break
            except (OSError, PermissionError):
                continue

        if not discovered:
            return items

        summary = self._detector.analyze(discovered)
        idx = 1
        for group in summary.groups:
            # For each duplicate group, the copies (beyond 1 original) represent reclaimable duplicate storage
            if len(group.files) < 2:
                continue

            # Skip the first file (keep as original), report subsequent copies as evidence
            for dup in group.files[1:]:
                c_path = canonicalize_path(dup.path).path_str
                val_res = validator.validate_path(c_path, Operation.CLEAN)
                app_running, procs, in_use = detect_associated_running_processes(c_path)
                recently_mod = is_path_recently_modified(c_path)

                conf = ReclaimConfidence.REVIEW_REQUIRED if val_res.allowed else ReclaimConfidence.PROTECTED

                item = StorageEvidenceItem(
                    evidence_id=f"ev_dup_{idx:03d}",
                    path=dup.path,
                    canonical_path=c_path,
                    size_bytes=dup.size_bytes,
                    item_count=1,
                    category=SmartCategory.USER_DATA,
                    subcategory="duplicate_file",
                    source_app=os.path.basename(dup.path),
                    likely_owner="user",
                    is_cache=False,
                    is_generated=False,
                    is_duplicate=True,
                    risk_level=RiskLevel.LOW if val_res.allowed else RiskLevel.HIGH,
                    reclaim_confidence=conf,
                    cleanup_allowed=val_res.allowed,
                    reason_if_not_allowed=val_res.reason if not val_res.allowed else None,
                    currently_in_use=in_use if in_use is not None else (True if app_running else False),
                    associated_processes=procs,
                    associated_application_running=app_running,
                    recently_modified=recently_mod,
                    reproducible_or_redownloadable=True,
                    dependency_evidence=f"Exact binary duplicate of '{group.files[0].path}'.",
                    usage_evidence=f"Active process lock on duplicate copy: {in_use}." if in_use is not None else None,
                    cleanup_consequence="Removing this copy leaves the original identical file intact.",
                    evidence_notes=f"Identical duplicate of {group.files[0].path} ({dup.size_bytes} bytes).",
                )
                items.append(item)
                idx += 1

        return items
