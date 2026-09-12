"""
MacGuard AI Phase 12 — Developer Storage Detector.

Discovers Xcode DerivedData, build directories, compiler caches, and developer tooling artifacts.
Wraps and reuses DeveloperStorageAnalyzer models and logic.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from app.analysis.developer_analyzer import DeveloperStorageAnalyzer
from app.analysis.detectors.base import BaseStorageDetector
from app.analysis.detectors.usage_inspector import detect_associated_running_processes, is_path_recently_modified
from app.analysis.models import RiskLevel
from app.models.category import SmartCategory
from app.models.investigation import ReclaimConfidence, StorageEvidenceItem
from app.models.scan_scope import ScanScope
from app.safety.canonicalizer import canonicalize_path
from app.safety.path_validator import Operation, PathValidator
from app.tools.storage_scanner import StorageScanner


class DeveloperStorageDetector(BaseStorageDetector):
    """
    Detector for developer tooling and build output artifacts.
    """

    def __init__(self, analyzer: Optional[DeveloperStorageAnalyzer] = None) -> None:
        self._analyzer = analyzer or DeveloperStorageAnalyzer()

    @property
    def detector_id(self) -> str:
        return "developer_storage_detector"

    @property
    def detector_name(self) -> str:
        return "Developer Tooling & Build Artifacts"

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

        targets = [
            (user_home / "Library" / "Developer" / "Xcode" / "DerivedData", "xcode_derived_data", "Xcode", True),
            (user_home / "Library" / "Developer" / "Xcode" / "Archives", "xcode_archives", "Xcode", False),
            (user_home / "Library" / "Developer" / "CoreSimulator" / "Caches", "xcode_sim_caches", "Xcode Simulator", True),
            (user_home / ".gradle" / "caches", "gradle_caches", "Gradle", True),
            (user_home / ".cargo" / "registry", "cargo_registry", "Cargo", True),
            (user_home / ".rustup" / "toolchains", "rustup_toolchains", "Rustup", False),
            (user_home / "Library" / "Caches" / "CocoaPods", "cocoapods_cache", "CocoaPods", True),
            (user_home / ".android" / "build-cache", "android_build_cache", "Android SDK", True),
        ]

        idx = 1
        for path_obj, subcat, tool_name, is_reproducible in targets:
            if not path_obj.exists() or not scope.is_path_allowed(str(path_obj)):
                continue

            path_str = str(path_obj)
            size, count = self.get_dir_size_and_count(path_str, visited_inodes, max_depth=8)
            if size < 5 * 1024 * 1024:  # 5MB minimum
                continue

            c_path = canonicalize_path(path_str).path_str
            val_res = validator.validate_path(c_path, Operation.CLEAN)

            app_running, procs, in_use = detect_associated_running_processes(c_path, app_hints=[tool_name, "xcode", "gradle", "cargo"])
            recently_mod = is_path_recently_modified(c_path)

            is_active = app_running or (in_use is True)
            if val_res.allowed and is_reproducible and not is_active:
                conf = ReclaimConfidence.HIGH_CONFIDENCE
            elif val_res.allowed:
                conf = ReclaimConfidence.REVIEW_REQUIRED
            else:
                conf = ReclaimConfidence.PROTECTED

            item = StorageEvidenceItem(
                evidence_id=f"ev_dev_{idx:03d}",
                path=path_str,
                canonical_path=c_path,
                size_bytes=size,
                item_count=count,
                category=SmartCategory.DEVELOPER_DATA,
                subcategory=subcat,
                source_app=tool_name,
                likely_owner="developer",
                is_cache=is_reproducible,
                is_generated=True,
                is_developer=True,
                risk_level=RiskLevel.LOW if val_res.allowed else RiskLevel.HIGH,
                reclaim_confidence=conf,
                cleanup_allowed=val_res.allowed,
                reason_if_not_allowed=val_res.reason if not val_res.allowed else None,
                currently_in_use=in_use if in_use is not None else (True if app_running else False),
                associated_processes=procs,
                associated_application_running=app_running,
                recently_modified=recently_mod,
                reproducible_or_redownloadable=is_reproducible,
                dependency_evidence=f"Build/artifact storage for {tool_name}. Can be rebuilt by compiling projects." if is_reproducible else f"{tool_name} storage. Review project dependencies before modification.",
                usage_evidence=f"Associated IDE/build tool running: {app_running}, active lock: {in_use}." if app_running is not None else None,
                cleanup_consequence="Cleaned builds will trigger full recompilation on next build cycle." if is_reproducible else "Requires manual review before cleanup.",
                evidence_notes=f"{tool_name} developer storage totaling {size} bytes ({count} files).",
            )
            items.append(item)
            idx += 1

        return items
