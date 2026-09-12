"""
MacGuard AI Phase 12 — Cache Detector.

Discovers general user and application caches in ~/Library/Caches and ~/.cache.
Distinguishes browser caches, app caches, and general temporary cache storage.
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


class CacheDetector(BaseStorageDetector):
    """
    Modular detector for macOS application & browser caches.
    """

    @property
    def detector_id(self) -> str:
        return "cache_detector"

    @property
    def detector_name(self) -> str:
        return "Application & Browser Caches"

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

        cache_roots = [
            user_home / "Library" / "Caches",
            user_home / ".cache",
        ]

        idx = 1
        for c_root in cache_roots:
            if not c_root.exists() or not scope.is_path_allowed(str(c_root)):
                continue

            try:
                entries = list(c_root.iterdir())
            except (OSError, PermissionError):
                continue

            for entry in entries:
                if not entry.is_dir() or entry.is_symlink():
                    continue

                path_str = str(entry)
                if not scope.is_path_allowed(path_str):
                    continue

                size, count = self.get_dir_size_and_count(path_str, visited_inodes, max_depth=6)
                if size < 5 * 1024 * 1024:  # Filter out sub-5MB noise to prioritize impactful storage
                    continue

                c_path = canonicalize_path(path_str).path_str
                val_res = validator.validate_path(c_path, Operation.CLEAN)

                # Identify subcategory & source app
                app_name = entry.name
                is_browser = any(b in app_name.lower() for b in ["chrome", "safari", "firefox", "brave", "edge", "arc"])
                subcat = "browser_cache" if is_browser else "application_cache"

                # Check runtime usage / running processes
                app_running, procs, in_use = detect_associated_running_processes(c_path, app_hints=[app_name])
                recently_mod = is_path_recently_modified(c_path)

                # Determine reclaimability confidence
                is_active = app_running or (in_use is True)
                if val_res.allowed and not is_active:
                    conf = ReclaimConfidence.HIGH_CONFIDENCE
                elif val_res.allowed and is_active:
                    conf = ReclaimConfidence.REVIEW_REQUIRED
                else:
                    conf = ReclaimConfidence.PROTECTED

                item = StorageEvidenceItem(
                    evidence_id=f"ev_cache_{idx:03d}",
                    path=path_str,
                    canonical_path=c_path,
                    size_bytes=size,
                    item_count=count,
                    category=SmartCategory.CACHES,
                    subcategory=subcat,
                    source_app=app_name,
                    likely_owner="user",
                    is_cache=True,
                    is_generated=True,
                    risk_level=RiskLevel.LOW if val_res.allowed else RiskLevel.HIGH,
                    reclaim_confidence=conf,
                    cleanup_allowed=val_res.allowed,
                    reason_if_not_allowed=val_res.reason if not val_res.allowed else None,
                    currently_in_use=in_use if in_use is not None else (True if app_running else False),
                    associated_processes=procs,
                    associated_application_running=app_running,
                    recently_modified=recently_mod,
                    reproducible_or_redownloadable=True,
                    dependency_evidence="Temporary application cache. Rebuilt automatically as needed.",
                    usage_evidence=f"Associated application '{app_name}' running: {app_running}, active lock: {in_use}." if app_running is not None else None,
                    cleanup_consequence="Cache files will be recreated on next application launch. Minor first-launch delay.",
                    evidence_notes=f"Cached data for {app_name} totaling {size} bytes.",
                )
                items.append(item)
                idx += 1

        return items
