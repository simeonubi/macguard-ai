"""
MacGuard AI Phase 13 — Docker-Aware Storage Detector.

Discovers Docker virtual disks (Docker.raw / Docker.qcow2) and inspects internal
Docker storage resources (images, containers, volumes, build cache) using strictly
read-only Docker CLI interfaces.

SAFETY INVARIANTS:
1. Docker.raw is ALWAYS PROTECTED, read-only, and never a cleanup candidate.
2. Read-only Docker CLI inspection only (never executes prune, rm, rmi, kill, or mutate).
3. Phase 13 is investigation-only: NO HIGH_CONFIDENCE Docker candidates.
4. Running containers & active images/volumes are PROTECTED.
5. Stopped containers & unused images/volumes/build cache are REVIEW_REQUIRED.
6. Graceful degradation when Docker daemon is stopped, unreachable, or CLI missing.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from app.analysis.detectors.base import BaseStorageDetector
from app.analysis.detectors.usage_inspector import detect_associated_running_processes, is_path_recently_modified
from app.analysis.models import RiskLevel
from app.models.category import SmartCategory
from app.models.docker_evidence import (
    DockerBuildCacheSummary,
    DockerContainerItem,
    DockerImageItem,
    DockerResourceSummary,
    DockerVolumeItem,
)
from app.models.investigation import ReclaimConfidence, StorageEvidenceItem
from app.models.scan_scope import ScanScope
from app.safety.canonicalizer import canonicalize_path
from app.safety.path_validator import Operation, PathValidator
from app.tools.docker_client import DockerClient
from app.tools.storage_scanner import StorageScanner


class DockerDetector(BaseStorageDetector):
    """
    Docker-aware storage detector combining host filesystem virtual disk discovery
    with read-only container runtime resource inspection.
    """

    def __init__(self, docker_client: Optional[DockerClient] = None) -> None:
        self._client = docker_client or DockerClient()

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

        # 1. Host Virtual Disk Discovery
        virtual_disk_targets = [
            (
                user_home / "Library" / "Containers" / "com.docker.docker" / "Data" / "vms" / "0" / "data" / "Docker.raw",
                "docker_virtual_disk",
                "Docker Virtual Disk (Raw VM Image)",
            ),
            (
                user_home / "Library" / "Containers" / "com.docker.docker" / "Data" / "vms" / "0" / "Docker.qcow2",
                "docker_virtual_disk",
                "Docker Virtual Disk (QCOW2 VM Image)",
            ),
            (
                user_home / ".docker",
                "docker_cli_config",
                "Docker CLI Config & Cache",
            ),
        ]

        # Fallback container root if virtual disk file not located directly
        if not virtual_disk_targets[0][0].exists() and not virtual_disk_targets[1][0].exists():
            virtual_disk_targets.insert(
                0,
                (
                    user_home / "Library" / "Containers" / "com.docker.docker",
                    "docker_desktop_container",
                    "Docker Desktop Container Storage",
                ),
            )

        virtual_disk_bytes = 0
        virtual_disk_path: Optional[str] = None
        seen_paths: set[str] = set()
        idx = 1

        for path_obj, subcat, desc in virtual_disk_targets:
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

            if subcat in ("docker_virtual_disk", "docker_desktop_container"):
                virtual_disk_bytes = size
                virtual_disk_path = path_str
                conf = ReclaimConfidence.PROTECTED
                item_cat = SmartCategory.CONTAINERS
                src_app = "Docker Desktop"
                dep_ev = "Contains Docker virtual machine disk image and internal container storage."
                cons = "Modifying or deleting Docker.raw directly outside Docker Desktop will corrupt container state and virtual machine disks."
                reason_not_allowed = "Docker virtual disk and container runtime storage must be managed via Docker Desktop or 'docker system prune'."
            else:
                conf = ReclaimConfidence.PROTECTED if docker_running else ReclaimConfidence.REVIEW_REQUIRED
                item_cat = SmartCategory.DEVELOPER_DATA
                src_app = "Docker CLI"
                dep_ev = "Docker CLI client configuration, context metadata, and buildx cache (~/.docker). Not part of Docker.raw."
                cons = "Contains CLI preferences and login credentials. Re-initialized when Docker CLI runs."
                reason_not_allowed = "Docker CLI configuration contains active credentials and environment settings."

            item = StorageEvidenceItem(
                evidence_id=f"ev_docker_{idx:03d}",
                path=path_str,
                canonical_path=c_path,
                size_bytes=size,
                item_count=count,
                category=item_cat,
                subcategory=subcat,
                source_app=src_app,
                likely_owner="developer",
                is_cache=False,
                is_generated=True,
                is_developer=True,
                is_docker=True,
                risk_level=RiskLevel.HIGH if subcat in ("docker_virtual_disk", "docker_desktop_container") else RiskLevel.MEDIUM,
                reclaim_confidence=conf,
                cleanup_allowed=False,  # Phase 13: Docker is read-only inspection only
                reason_if_not_allowed=reason_not_allowed,
                currently_in_use=in_use if in_use is not None else (True if docker_running else False),
                associated_processes=procs,
                associated_application_running=docker_running,
                recently_modified=recently_mod,
                reproducible_or_redownloadable=False,
                dependency_evidence=dep_ev,
                usage_evidence=f"Docker process status: {'Active / Running' if docker_running else 'Stopped / Inactive'}.",
                cleanup_consequence=cons,
                evidence_notes=f"{desc} consuming {size} bytes.",
            )
            items.append(item)
            idx += 1

        # 2. Inspect Docker Internal Resources via DockerClient
        summary, images, containers, volumes, build_cache = self._client.inspect_all(
            virtual_disk_bytes=virtual_disk_bytes,
            virtual_disk_path=virtual_disk_path,
        )

        if not summary.daemon_available:
            return items

        # 2A. Inspect Containers
        for c in containers:
            c_name = c.names[0] if c.names else c.container_id
            c_path = f"docker://containers/{c.container_id} ({c_name})"
            conf = ReclaimConfidence.PROTECTED if c.is_running else ReclaimConfidence.REVIEW_REQUIRED

            item = StorageEvidenceItem(
                evidence_id=f"ev_docker_{idx:03d}",
                path=c_path,
                canonical_path=c_path,
                size_bytes=c.size_bytes,
                item_count=1,
                category=SmartCategory.CONTAINERS,
                subcategory="docker_container",
                source_app="Docker",
                likely_owner="developer",
                is_cache=False,
                is_generated=True,
                is_developer=True,
                is_docker=True,
                risk_level=RiskLevel.LOW if not c.is_running else RiskLevel.HIGH,
                reclaim_confidence=conf,
                cleanup_allowed=False,
                reason_if_not_allowed="Container removal must be managed via Docker CLI ('docker rm').",
                currently_in_use=c.is_running,
                associated_processes=["docker", "dockerd"] if c.is_running else [],
                associated_application_running=True,
                reproducible_or_redownloadable=not c.is_running,
                dependency_evidence=f"Container based on image '{c.image}'. Mounts: {', '.join(c.mounts) if c.mounts else 'None'}.",
                usage_evidence=f"Container status: {c.status} (Running: {c.is_running}).",
                cleanup_consequence=f"Stopped container '{c_name}' can be removed via 'docker container rm {c.container_id}'.",
                evidence_notes=f"Docker container '{c_name}' ({c.status}) using image '{c.image}'.",
            )
            items.append(item)
            idx += 1

        # 2B. Inspect Images (Consolidated by unique image ID)
        grouped_images: dict[str, list[DockerImageItem]] = {}
        for img in images:
            grouped_images.setdefault(img.image_id, []).append(img)

        for img_id, img_list in grouped_images.items():
            primary_img = img_list[0]
            refs = []
            for im in img_list:
                ref = f"{im.repository}:{im.tag}" if im.repository != "<none>" else f"dangling:{im.image_id}"
                if ref not in refs:
                    refs.append(ref)
            refs_str = ", ".join(refs) if refs else f"dangling:{img_id}"

            is_active = any(im.in_use_by_running_container for im in img_list)
            is_in_use_stopped = any(im.in_use_by_stopped_container for im in img_list)
            is_dangling = all(im.is_dangling for im in img_list)
            conf = ReclaimConfidence.PROTECTED if is_active else ReclaimConfidence.REVIEW_REQUIRED

            img_path = f"docker://images/{img_id} ({refs_str})"

            item = StorageEvidenceItem(
                evidence_id=f"ev_docker_{idx:03d}",
                path=img_path,
                canonical_path=img_path,
                size_bytes=primary_img.size_bytes,
                item_count=1,
                category=SmartCategory.CONTAINERS,
                subcategory="docker_image",
                source_app="Docker",
                likely_owner="developer",
                is_cache=False,
                is_generated=True,
                is_developer=True,
                is_docker=True,
                risk_level=RiskLevel.LOW if not is_active else RiskLevel.HIGH,
                reclaim_confidence=conf,
                cleanup_allowed=False,
                reason_if_not_allowed="Image removal must be managed via Docker CLI ('docker rmi').",
                currently_in_use=is_active,
                associated_processes=["docker", "dockerd"] if is_active else [],
                associated_application_running=True,
                reproducible_or_redownloadable=True,
                dependency_evidence=(
                    "Referenced by running container(s)." if is_active
                    else ("Referenced by stopped container(s)." if is_in_use_stopped else "Unreferenced / unused image.")
                ),
                usage_evidence=f"Image in use by running containers: {is_active}, dangling: {is_dangling}.",
                cleanup_consequence=f"Image '{refs_str}' can be removed via 'docker image rm {img_id}' if no longer needed.",
                evidence_notes=f"Docker image '{refs_str}' ({primary_img.size_bytes} bytes). Dangling: {is_dangling}.",
            )
            items.append(item)
            idx += 1

        # 2C. Inspect Volumes
        for vol in volumes:
            vol_path = f"docker://volumes/{vol.name}"
            is_active = vol.is_attached_to_running
            conf = ReclaimConfidence.PROTECTED if is_active else ReclaimConfidence.REVIEW_REQUIRED

            item = StorageEvidenceItem(
                evidence_id=f"ev_docker_{idx:03d}",
                path=vol_path,
                canonical_path=vol_path,
                size_bytes=vol.size_bytes,
                item_count=1,
                category=SmartCategory.CONTAINERS,
                subcategory="docker_volume",
                source_app="Docker",
                likely_owner="developer",
                is_cache=False,
                is_generated=False,
                is_developer=True,
                is_docker=True,
                risk_level=RiskLevel.MEDIUM if not is_active else RiskLevel.HIGH,
                reclaim_confidence=conf,
                cleanup_allowed=False,
                reason_if_not_allowed="Volume removal must be managed via Docker CLI ('docker volume rm').",
                currently_in_use=is_active,
                associated_processes=["docker", "dockerd"] if is_active else [],
                associated_application_running=True,
                reproducible_or_redownloadable=False,
                dependency_evidence=f"Attached to running containers: {is_active}, stopped containers: {vol.is_attached_to_stopped}.",
                usage_evidence=f"Volume attachment status: {'Attached to running container' if is_active else 'Unattached / idle'}.",
                cleanup_consequence=f"Volume '{vol.name}' contains persistent data. Removal requires 'docker volume rm {vol.name}'.",
                evidence_notes=f"Docker local volume '{vol.name}' ({vol.size_bytes} bytes).",
            )
            items.append(item)
            idx += 1

        # 2D. Inspect Build Cache
        if build_cache.total_bytes > 0:
            bc_path = "docker://build_cache"
            item = StorageEvidenceItem(
                evidence_id=f"ev_docker_{idx:03d}",
                path=bc_path,
                canonical_path=bc_path,
                size_bytes=build_cache.total_bytes,
                item_count=build_cache.total_records,
                category=SmartCategory.CONTAINERS,
                subcategory="docker_build_cache",
                source_app="Docker BuildKit",
                likely_owner="developer",
                is_cache=True,
                is_generated=True,
                is_developer=True,
                is_docker=True,
                risk_level=RiskLevel.LOW,
                reclaim_confidence=ReclaimConfidence.REVIEW_REQUIRED,
                cleanup_allowed=False,
                reason_if_not_allowed="Build cache must be reclaimed via Docker CLI ('docker builder prune').",
                currently_in_use=False,
                associated_processes=[],
                associated_application_running=True,
                reproducible_or_redownloadable=True,
                dependency_evidence=f"{build_cache.total_records} BuildKit cache records ({build_cache.in_use_records} in active build graphs).",
                usage_evidence=f"Reclaimable build cache: {build_cache.reclaimable_bytes} bytes.",
                cleanup_consequence="Rebuilding Docker images may take longer as cached intermediate layers will be re-executed.",
                evidence_notes=f"Docker BuildKit cache consuming {build_cache.total_bytes} bytes ({build_cache.total_records} records).",
            )
            items.append(item)
            idx += 1

        return items
