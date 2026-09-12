"""
MacGuard AI Phase 12 — Download & Installer Storage Detector.

Discovers disk images (.dmg, .iso), installer packages (.pkg), and large archives in ~/Downloads.
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

INSTALLER_EXTENSIONS = frozenset({".dmg", ".pkg", ".iso", ".appinstaller"})
ARCHIVE_EXTENSIONS = frozenset({".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar"})


class DownloadDetector(BaseStorageDetector):
    """
    Detector for disk images, installers, and large downloads.
    """

    @property
    def detector_id(self) -> str:
        return "download_detector"

    @property
    def detector_name(self) -> str:
        return "Downloads, Installers & Disk Images"

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

        dl_root = user_home / "Downloads"
        if not dl_root.exists() or not scope.is_path_allowed(str(dl_root)):
            return items

        try:
            entries = list(dl_root.iterdir())
        except (OSError, PermissionError):
            return items

        idx = 1
        for entry in entries:
            path_str = str(entry)
            if not scope.is_path_allowed(path_str):
                continue

            ext = entry.suffix.lower()
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
                size, count = self.get_dir_size_and_count(path_str, visited_inodes, max_depth=4)

            # Filter thresholds: installers >= 20MB, general items >= 50MB
            is_installer = ext in INSTALLER_EXTENSIONS
            is_archive = ext in ARCHIVE_EXTENSIONS
            min_size = 20 * 1024 * 1024 if (is_installer or is_archive) else 50 * 1024 * 1024
            if size < min_size:
                continue

            c_path = canonicalize_path(path_str).path_str
            val_res = validator.validate_path(c_path, Operation.CLEAN)

            cat = SmartCategory.DISK_IMAGES if is_installer else (SmartCategory.ARCHIVES if is_archive else SmartCategory.DOWNLOADS)
            subcat = "disk_image" if ext == ".dmg" else ("installer_package" if ext == ".pkg" else "download_item")

            app_running, procs, in_use = detect_associated_running_processes(c_path)
            recently_mod = is_path_recently_modified(c_path)

            # Installers in Downloads are often safe to remove after installation unless currently open
            is_active = app_running or (in_use is True)
            if val_res.allowed and is_installer and not is_active:
                conf = ReclaimConfidence.HIGH_CONFIDENCE
            elif val_res.allowed:
                conf = ReclaimConfidence.REVIEW_REQUIRED
            else:
                conf = ReclaimConfidence.PROTECTED

            item = StorageEvidenceItem(
                evidence_id=f"ev_dl_{idx:03d}",
                path=path_str,
                canonical_path=c_path,
                size_bytes=size,
                item_count=count,
                category=cat,
                subcategory=subcat,
                source_app=entry.name,
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
                reproducible_or_redownloadable=is_installer,
                dependency_evidence="Downloaded installer or file located in user Downloads folder.",
                usage_evidence=f"Active process lock on download file: {in_use}." if in_use is not None else None,
                cleanup_consequence="File will be moved to Trash. If needed again, installer can be re-downloaded from source vendor.",
                evidence_notes=f"Download artifact '{entry.name}' consuming {size} bytes.",
            )
            items.append(item)
            idx += 1

        return items
