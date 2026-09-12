"""
MacGuard AI Phase 12 — Read-Only Docker Storage Detector.

Discovers Docker Desktop data, virtual disks (Docker.raw/Docker.qcow2), build caches,
and container metadata.

CRITICAL INVARIANTS:
1. Docker discovery is strictly READ-ONLY.
2. Does NOT perform Docker mutations (no docker system prune, no rm).
3. Findings default to REVIEW_REQUIRED or PROTECTED.
4. Identifies associated running Docker daemon / application processes.
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


class DockerDetector(BaseStorageDetector):
    """
    Read-only detector for Docker Desktop and container runtime storage.
    """

    @property
    def detector_id(self) -> str:
        return "docker_detector"

    @property
    def detector_name(self) -> str:
        return "Docker Storage (Read-Only Inspection)"

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
            (
                user_home / "Library" / "Containers" / "com.docker.docker" / "Data" / "vms" / "0" / "data" / "Docker.raw",
                "docker_virtual_disk",
                "Docker Virtual Disk (Raw VM Image)",
            ),
            (
                user_home / ".docker",
                "docker_cli_config",
                "Docker CLI Config & Cache",
            ),
        ]

        # If Docker.raw does not exist, check container root
        if not targets[0][0].exists():
            targets.insert(
                0,
                (
                    user_home / "Library" / "Containers" / "com.docker.docker",
                    "docker_desktop_container",
                    "Docker Desktop Container Storage",
                ),
            )

        seen_paths: set[str] = set()
        idx = 1
        for path_obj, subcat, desc in targets:
            if not path_obj.exists() or not scope.is_path_allowed(str(path_obj)):
                continue

            path_str = str(path_obj)
            c_path = canonicalize_path(path_str).path_str
            if c_path in seen_paths:
                continue
            seen_paths.add(c_path)

            if path_obj.is_file():
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
                size, count = self.get_dir_size_and_count(path_str, visited_inodes, max_depth=6)

            if size < 10 * 1024 * 1024:  # 10MB minimum
                continue

            val_res = validator.validate_path(c_path, Operation.CLEAN)
            docker_running, procs, in_use = detect_associated_running_processes(c_path, app_hints=["docker", "com.docker"])
            recently_mod = is_path_recently_modified(c_path)

            # Docker storage is managed by Docker daemon; manual direct removal can corrupt VM state.
            # Classified as PROTECTED (if daemon is active) or REVIEW_REQUIRED (if stopped, as internal images/containers may be pruned via Docker CLI).
            conf = ReclaimConfidence.PROTECTED if docker_running else ReclaimConfidence.REVIEW_REQUIRED

            item = StorageEvidenceItem(
                evidence_id=f"ev_docker_{idx:03d}",
                path=path_str,
                canonical_path=c_path,
                size_bytes=size,
                item_count=count,
                category=SmartCategory.CONTAINERS,
                subcategory=subcat,
                source_app="Docker Desktop",
                likely_owner="developer",
                is_cache=False,
                is_generated=True,
                is_developer=True,
                is_docker=True,
                risk_level=RiskLevel.HIGH,
                reclaim_confidence=conf,
                cleanup_allowed=False,  # Phase 12: Docker is read-only inspection only
                reason_if_not_allowed="Docker virtual disk and container storage must be managed via 'docker system prune' or Docker Desktop settings.",
                currently_in_use=in_use if in_use is not None else (True if docker_running else False),
                associated_processes=procs,
                associated_application_running=docker_running,
                recently_modified=recently_mod,
                reproducible_or_redownloadable=False,
                dependency_evidence="Contains active Docker containers, images, volumes, and VM state.",
                usage_evidence=f"Docker daemon active: {docker_running}, process handle: {in_use}.",
                cleanup_consequence="Removing Docker files outside Docker Desktop will corrupt local container runtime state. Use 'docker system prune'.",
                evidence_notes=f"{desc} consuming {size} bytes.",
            )
            items.append(item)
            idx += 1

        return items
