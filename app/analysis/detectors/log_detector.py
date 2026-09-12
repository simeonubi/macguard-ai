"""
MacGuard AI Phase 12 — Log & Diagnostic Storage Detector.

Discovers user application logs and crash reports under ~/Library/Logs.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from app.analysis.detectors.base import BaseStorageDetector
from app.analysis.detectors.usage_inspector import detect_associated_running_processes, is_path_recently_modified
from app.analysis.models import RiskLevel
from app.models.category import SmartCategory
from app.models.investigation import ReclaimConfidence, StorageEvidenceItem
from app.models.scan_scope import ScanScope
from app.safety.canonicalizer import canonicalize_path
from app.safety.path_validator import Operation, PathValidator
from app.tools.storage_scanner import StorageScanner


class LogDetector(BaseStorageDetector):
    """
    Detector for macOS application logs and crash reports.
    """

    @property
    def detector_id(self) -> str:
        return "log_detector"

    @property
    def detector_name(self) -> str:
        return "Application Logs & Diagnostic Reports"

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

        log_root = user_home / "Library" / "Logs"
        if not log_root.exists() or not scope.is_path_allowed(str(log_root)):
            return items

        try:
            entries = list(log_root.iterdir())
        except (OSError, PermissionError):
            return items

        idx = 1
        for entry in entries:
            path_str = str(entry)
            if not scope.is_path_allowed(path_str):
                continue

            if entry.is_file():
                if entry.is_symlink():
                    continue
                try:
                    st = os.lstat(path_str)
                    node = (st.st_dev, st.st_ino)
                    if node in visited_inodes:
                        continue
                    visited_inodes.add(node)
                    size = st.st_size
                    count = 1
                except (OSError, PermissionError):
                    continue
            else:
                size, count = self.get_dir_size_and_count(path_str, visited_inodes, max_depth=5)

            if size < 5 * 1024 * 1024:  # 5MB minimum
                continue

            c_path = canonicalize_path(path_str).path_str
            val_res = validator.validate_path(c_path, Operation.CLEAN)
            app_name = entry.name
            app_running, procs, in_use = detect_associated_running_processes(c_path, app_hints=[app_name])
            recently_mod = is_path_recently_modified(c_path)

            is_active = app_running or (in_use is True)
            conf = ReclaimConfidence.HIGH_CONFIDENCE if val_res.allowed and not is_active else ReclaimConfidence.REVIEW_REQUIRED

            item = StorageEvidenceItem(
                evidence_id=f"ev_log_{idx:03d}",
                path=path_str,
                canonical_path=c_path,
                size_bytes=size,
                item_count=count,
                category=SmartCategory.LOGS,
                subcategory="application_log",
                source_app=app_name,
                likely_owner="user",
                is_cache=False,
                is_generated=True,
                risk_level=RiskLevel.LOW if val_res.allowed else RiskLevel.HIGH,
                reclaim_confidence=conf,
                cleanup_allowed=val_res.allowed,
                reason_if_not_allowed=val_res.reason if not val_res.allowed else None,
                currently_in_use=in_use if in_use is not None else (True if app_running else False),
                associated_processes=procs,
                associated_application_running=app_running,
                recently_modified=recently_mod,
                reproducible_or_redownloadable=False,
                dependency_evidence="Historical diagnostic and log files. New logs are generated automatically.",
                usage_evidence=f"Associated application active: {app_running}, open log handle: {in_use}." if app_running is not None else None,
                cleanup_consequence="Past diagnostic history for this app will be cleared.",
                evidence_notes=f"Application log files for {app_name} totaling {size} bytes.",
            )
            items.append(item)
            idx += 1

        return items
