"""
MacGuard AI Phase 12 — Node & JavaScript Cache Detector.

Discovers npm, pnpm, yarn, and bun package caches and temporary directories.
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


class NodeCacheDetector(BaseStorageDetector):
    """
    Detector for Node.js ecosystem caches (npm, pnpm, yarn, bun).
    """

    @property
    def detector_id(self) -> str:
        return "node_cache_detector"

    @property
    def detector_name(self) -> str:
        return "Node & JavaScript Ecosystem Caches"

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
            (user_home / ".npm" / "_cacache", "npm_cacache", "npm"),
            (user_home / ".npm", "npm_cache", "npm"),
            (user_home / "Library" / "Caches" / "pnpm", "pnpm_cache", "pnpm"),
            (user_home / "Library" / "Caches" / "pnpm" / "store", "pnpm_store", "pnpm"),
            (user_home / "Library" / "Caches" / "Yarn", "yarn_cache", "yarn"),
            (user_home / ".yarn" / "cache", "yarn_cache", "yarn"),
            (user_home / ".bun" / "install" / "cache", "bun_cache", "bun"),
        ]

        seen_paths: set[str] = set()
        idx = 1
        for path_obj, subcat, tool_name in targets:
            if not path_obj.exists() or not scope.is_path_allowed(str(path_obj)):
                continue

            path_str = str(path_obj)
            c_path = canonicalize_path(path_str).path_str
            if c_path in seen_paths:
                continue
            seen_paths.add(c_path)

            size, count = self.get_dir_size_and_count(path_str, visited_inodes, max_depth=8)
            if size < 1024 * 1024:  # 1MB minimum
                continue

            val_res = validator.validate_path(c_path, Operation.CLEAN)
            app_running, procs, in_use = detect_associated_running_processes(c_path, app_hints=[tool_name])
            recently_mod = is_path_recently_modified(c_path)

            conf = ReclaimConfidence.HIGH_CONFIDENCE if val_res.allowed else ReclaimConfidence.REVIEW_REQUIRED

            item = StorageEvidenceItem(
                evidence_id=f"ev_nodecache_{idx:03d}",
                path=path_str,
                canonical_path=c_path,
                size_bytes=size,
                item_count=count,
                category=SmartCategory.PACKAGE_MANAGERS,
                subcategory=subcat,
                source_app=tool_name,
                likely_owner="developer",
                is_cache=True,
                is_generated=True,
                is_developer=True,
                risk_level=RiskLevel.LOW if val_res.allowed else RiskLevel.HIGH,
                reclaim_confidence=conf,
                cleanup_allowed=val_res.allowed,
                reason_if_not_allowed=val_res.reason if not val_res.allowed else None,
                currently_in_use=in_use,
                associated_processes=procs,
                associated_application_running=app_running,
                recently_modified=recently_mod,
                reproducible_or_redownloadable=True,
                dependency_evidence=f"Global package cache for {tool_name}. Tarballs/modules can be redownloaded from registry.",
                usage_evidence=f"Active process file lock on cache: {in_use}." if in_use is not None else "No active process locks detected on cache path.",
                cleanup_consequence=f"Subsequent '{tool_name} install' commands will redownload tarballs from registry.",
                evidence_notes=f"{tool_name.upper()} global cache containing {count} artifacts ({size} bytes).",
            )
            items.append(item)
            idx += 1

        return items
