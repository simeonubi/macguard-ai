"""
MacGuard AI Phase 12 — Large File Detector.

Wraps and integrates LargeFileAnalyzer to discover and report individual large file consumers.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from app.analysis.categorizer import SmartCategorizer
from app.analysis.detectors.base import BaseStorageDetector
from app.analysis.detectors.usage_inspector import detect_associated_running_processes, is_path_recently_modified
from app.analysis.large_file_analyzer import LargeFileAnalyzer
from app.analysis.models import RiskLevel
from app.models.category import SmartCategory
from app.models.investigation import ReclaimConfidence, StorageEvidenceItem
from app.models.scan_scope import ScanScope
from app.safety.canonicalizer import canonicalize_path
from app.safety.path_validator import Operation, PathValidator
from app.tools.storage_scanner import StorageScanner


class LargeFileDetector(BaseStorageDetector):
    """
    Detector for large individual files across user space (>= 100MB).
    """

    def __init__(self, analyzer: Optional[LargeFileAnalyzer] = None) -> None:
        self._analyzer = analyzer or LargeFileAnalyzer()
        self._categorizer = SmartCategorizer()

    @property
    def detector_id(self) -> str:
        return "large_file_detector"

    @property
    def detector_name(self) -> str:
        return "Large Individual Files"

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
            user_home / "Movies",
            user_home / "Music",
            user_home / "Desktop",
        ]

        idx = 1
        threshold = 100 * 1024 * 1024  # 100MB minimum for individual large file detector

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
                            if st.st_size < threshold:
                                continue
                            node = (st.st_dev, st.st_ino)
                            if node in visited_inodes:
                                continue
                            visited_inodes.add(node)

                            c_path = canonicalize_path(fp).path_str
                            val_res = validator.validate_path(c_path, Operation.CLEAN)
                            cat_res = self._categorizer.categorize(fp)

                            app_running, procs, in_use = detect_associated_running_processes(c_path)
                            recently_mod = is_path_recently_modified(c_path)

                            conf = ReclaimConfidence.REVIEW_REQUIRED if val_res.allowed else ReclaimConfidence.PROTECTED

                            item = StorageEvidenceItem(
                                evidence_id=f"ev_large_{idx:03d}",
                                path=fp,
                                canonical_path=c_path,
                                size_bytes=st.st_size,
                                item_count=1,
                                category=cat_res.category,
                                subcategory="large_file",
                                source_app=f,
                                likely_owner="user",
                                is_cache=False,
                                is_generated=False,
                                risk_level=RiskLevel.LOW if val_res.allowed else RiskLevel.HIGH,
                                reclaim_confidence=conf,
                                cleanup_allowed=val_res.allowed,
                                reason_if_not_allowed=val_res.reason if not val_res.allowed else None,
                                currently_in_use=in_use if in_use is not None else (True if app_running else False),
                                associated_processes=procs,
                                associated_application_running=app_running,
                                recently_modified=recently_mod,
                                reproducible_or_redownloadable=False,
                                dependency_evidence="Individual large user file.",
                                usage_evidence=f"Active process file lock on large file: {in_use}." if in_use is not None else None,
                                cleanup_consequence="File will be moved to macOS Trash.",
                                evidence_notes=f"Large file '{f}' ({st.st_size} bytes, category: {cat_res.category.value}).",
                            )
                            items.append(item)
                            idx += 1
                            if idx > 20:  # Bound to top 20 large individual files to prevent unbounded growth
                                break
                        except (OSError, PermissionError):
                            continue
                    if idx > 20:
                        break
            except (OSError, PermissionError):
                continue

        return items
