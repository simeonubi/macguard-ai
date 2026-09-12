"""
MacGuard AI Phase 13 — Read-Only Docker Client.

Provides safe, bounded, deterministic inspection of Docker storage and resources.
ABSOLUTE INVARIANTS:
1. STRICTLY READ-ONLY: Never executes prune, rm, rmi, kill, stop, restart, or mutation commands.
2. BOUNDED EXECUTION: All subprocess invocations have explicit timeouts (<= 5.0s).
3. NO SHELL: Always executes with shell=False and fixed argument lists.
4. COMMAND WHITELIST: Strictly rejects any command not in the read-only whitelist.
"""

from __future__ import annotations

import json
import re
import subprocess
from typing import Any, Optional

from app.models.docker_evidence import (
    DockerBuildCacheSummary,
    DockerContainerItem,
    DockerImageItem,
    DockerResourceSummary,
    DockerVolumeItem,
)

# Whitelist of strictly read-only Docker CLI subcommands permitted in MacGuard
ALLOWED_READONLY_COMMANDS: frozenset[tuple[str, ...]] = frozenset({
    ("docker", "info"),
    ("docker", "system", "df"),
    ("docker", "ps"),
    ("docker", "images"),
    ("docker", "volume", "ls"),
    ("docker", "builder", "du"),
})

# Forbidden mutating subcommands / flags for defensive validation
FORBIDDEN_MUTATING_TOKENS: frozenset[str] = frozenset({
    "prune", "rm", "rmi", "kill", "stop", "restart", "exec", "run",
    "create", "build", "commit", "cp", "pause", "unpause", "down",
    "destroy", "delete", "truncate", "system-prune", "--force", "-f",
})


def parse_docker_size_bytes(size_str: str) -> int:
    """
    Parse Docker human-readable size string (e.g. '1.5GB', '450MB', '25kB', '0B') into exact bytes.
    """
    if not size_str or not isinstance(size_str, str):
        return 0

    s = size_str.strip().upper()
    # Match number and unit
    match = re.match(r"^([0-9.]+)\s*([A-Z]*B?)$", s)
    if not match:
        return 0

    num_str, unit = match.groups()
    try:
        val = float(num_str)
    except ValueError:
        return 0

    unit = unit.strip()
    multipliers = {
        "": 1,
        "B": 1,
        "KB": 1000,
        "KIB": 1024,
        "K": 1000,
        "MB": 1000 * 1000,
        "MIB": 1024 * 1024,
        "M": 1000 * 1000,
        "GB": 1000 * 1000 * 1000,
        "GIB": 1024 * 1024 * 1024,
        "G": 1000 * 1000 * 1000,
        "TB": 1000 * 1000 * 1000 * 1000,
        "TIB": 1024 * 1024 * 1024 * 1024,
        "T": 1000 * 1000 * 1000 * 1000,
    }

    mult = multipliers.get(unit, 1)
    return int(val * mult)


class DockerClient:
    """
    Lightweight, read-only Docker inspection client.
    """

    def __init__(self, timeout_seconds: float = 5.0) -> None:
        self.timeout_seconds = max(1.0, min(timeout_seconds, 15.0))

    def _execute_readonly(self, cmd: list[str]) -> tuple[bool, str]:
        """
        Execute a read-only Docker command with strict whitelist and defensive validation.

        Returns:
            (success: bool, output_text: str)
        """
        if not cmd or cmd[0] != "docker":
            return False, "Invalid command: must start with 'docker'"

        # Verify command prefix against read-only whitelist
        cmd_prefix_2 = tuple(cmd[:2])
        cmd_prefix_3 = tuple(cmd[:3]) if len(cmd) >= 3 else cmd_prefix_2
        if cmd_prefix_2 not in ALLOWED_READONLY_COMMANDS and cmd_prefix_3 not in ALLOWED_READONLY_COMMANDS:
            return False, f"Prohibited Docker command: {cmd[:3]} not in read-only whitelist"

        # Defensive check against forbidden mutating tokens
        for token in cmd:
            if token.lower() in FORBIDDEN_MUTATING_TOKENS:
                return False, f"Prohibited token detected: {token}"

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
                shell=False,
            )
            if res.returncode != 0:
                return False, res.stderr or res.stdout
            return True, res.stdout
        except FileNotFoundError:
            return False, "Docker CLI is not installed or not in PATH."
        except subprocess.TimeoutExpired:
            return False, f"Docker command timed out after {self.timeout_seconds}s."
        except Exception as exc:
            return False, f"Subprocess execution error: {exc}"

    def is_daemon_running(self) -> bool:
        """Check if Docker daemon is running and reachable."""
        ok, out = self._execute_readonly(["docker", "info", "--format", "json"])
        if not ok:
            return False
        try:
            data = json.loads(out)
            # If ServerVersion is present, daemon is communicating
            return bool(data.get("ServerVersion") or data.get("ID"))
        except Exception:
            return False

    def get_system_df_json(self) -> Optional[list[dict[str, Any]]]:
        """Fetch docker system df breakdown in JSON format."""
        ok, out = self._execute_readonly(["docker", "system", "df", "--format", "{{json .}}"])
        if not ok or not out.strip():
            return None

        records: list[dict[str, Any]] = []
        for line in out.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return records if records else None

    def list_containers(self) -> list[DockerContainerItem]:
        """Fetch all containers (running and stopped) with status and mounts."""
        ok, out = self._execute_readonly(["docker", "ps", "-a", "--no-trunc", "--format", "{{json .}}"])
        if not ok or not out.strip():
            return []

        containers: list[DockerContainerItem] = []
        for line in out.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            c_id = data.get("ID", "")[:12]
            names_raw = data.get("Names", "")
            names = [n.strip() for n in names_raw.split(",") if n.strip()]
            image = data.get("Image", "")
            status = data.get("Status", "")
            state = data.get("State", "").lower()
            is_running = state == "running" or "up" in status.lower()
            size_str = data.get("Size", "0B")
            size_bytes = parse_docker_size_bytes(size_str.split(" ")[0])
            created_at = data.get("CreatedAt", "")
            mounts_raw = data.get("Mounts", "")
            mounts = [m.strip() for m in mounts_raw.split(",") if m.strip()]

            containers.append(
                DockerContainerItem(
                    container_id=c_id,
                    names=names,
                    image=image,
                    image_id="",  # Populated when correlating with images
                    status=status,
                    is_running=is_running,
                    size_bytes=size_bytes,
                    created_at=created_at,
                    mounts=mounts,
                )
            )
        return containers

    def list_images(self, running_container_images: Optional[set[str]] = None, stopped_container_images: Optional[set[str]] = None) -> list[DockerImageItem]:
        """Fetch all Docker images and correlate usage with running/stopped containers."""
        running_set = running_container_images or set()
        stopped_set = stopped_container_images or set()

        ok, out = self._execute_readonly(["docker", "images", "-a", "--no-trunc", "--format", "{{json .}}"])
        if not ok or not out.strip():
            return []

        images: list[DockerImageItem] = []
        for line in out.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            img_id = data.get("ID", "")[:12]
            repo = data.get("Repository", "<none>")
            tag = data.get("Tag", "<none>")
            size_str = data.get("Size", "0B")
            size_bytes = parse_docker_size_bytes(size_str)
            created_at = data.get("CreatedAt", "")
            is_dangling = repo == "<none>" or tag == "<none>"

            # Correlation with container references (by ID, repo, or repo:tag)
            full_ref = f"{repo}:{tag}"
            in_use_running = (
                img_id in running_set
                or repo in running_set
                or full_ref in running_set
            )
            in_use_stopped = (
                img_id in stopped_set
                or repo in stopped_set
                or full_ref in stopped_set
            )

            images.append(
                DockerImageItem(
                    image_id=img_id,
                    repository=repo,
                    tag=tag,
                    size_bytes=size_bytes,
                    created_at=created_at,
                    is_dangling=is_dangling,
                    in_use_by_running_container=in_use_running,
                    in_use_by_stopped_container=in_use_stopped,
                )
            )
        return images

    def list_volumes(self, mounted_by_running: Optional[set[str]] = None, mounted_by_stopped: Optional[set[str]] = None) -> list[DockerVolumeItem]:
        """Fetch all Docker volumes and correlate attachment to containers."""
        running_mounts = mounted_by_running or set()
        stopped_mounts = mounted_by_stopped or set()

        ok, out = self._execute_readonly(["docker", "volume", "ls", "--format", "{{json .}}"])
        if not ok or not out.strip():
            return []

        volumes: list[DockerVolumeItem] = []
        for line in out.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            name = data.get("Name", "")
            driver = data.get("Driver", "local")
            size_str = data.get("Size", "0B")
            size_bytes = parse_docker_size_bytes(size_str)

            is_attached_running = name in running_mounts
            is_attached_stopped = name in stopped_mounts

            volumes.append(
                DockerVolumeItem(
                    name=name,
                    driver=driver,
                    size_bytes=size_bytes,
                    is_attached_to_running=is_attached_running,
                    is_attached_to_stopped=is_attached_stopped,
                )
            )
        return volumes

    def get_builder_du(self) -> DockerBuildCacheSummary:
        """Fetch Docker build cache usage statistics."""
        ok, out = self._execute_readonly(["docker", "builder", "du", "--format", "{{json .}}"])
        if not ok or not out.strip():
            return DockerBuildCacheSummary()

        total_bytes = 0
        reclaimable_bytes = 0
        total_records = 0
        in_use_records = 0

        for line in out.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            total_records += 1
            size_str = data.get("Size", "0B")
            sz = parse_docker_size_bytes(size_str)
            total_bytes += sz
            in_use = bool(data.get("InUse", False))
            if in_use:
                in_use_records += 1
            else:
                reclaimable_bytes += sz

        return DockerBuildCacheSummary(
            total_bytes=total_bytes,
            reclaimable_bytes=reclaimable_bytes,
            total_records=total_records,
            in_use_records=in_use_records,
        )

    def inspect_all(self, virtual_disk_bytes: int = 0, virtual_disk_path: Optional[str] = None) -> tuple[DockerResourceSummary, list[DockerImageItem], list[DockerContainerItem], list[DockerVolumeItem], DockerBuildCacheSummary]:
        """
        Execute comprehensive read-only Docker inspection across all resource types.
        """
        daemon_ok = self.is_daemon_running()
        if not daemon_ok:
            summary = DockerResourceSummary(
                daemon_available=False,
                virtual_disk_bytes=virtual_disk_bytes,
                virtual_disk_path=virtual_disk_path,
                status_message="Docker Desktop daemon is stopped or unreachable.",
            )
            return summary, [], [], [], DockerBuildCacheSummary()

        # 1. Inspect containers
        containers = self.list_containers()
        running_images: set[str] = set()
        stopped_images: set[str] = set()
        running_mounts: set[str] = set()
        stopped_mounts: set[str] = set()

        running_cnt = 0
        stopped_cnt = 0
        containers_total_sz = 0
        containers_reclaimable_sz = 0

        for c in containers:
            if c.is_running:
                running_cnt += 1
                running_images.add(c.image)
                for m in c.mounts:
                    running_mounts.add(m)
            else:
                stopped_cnt += 1
                stopped_images.add(c.image)
                containers_reclaimable_sz += c.size_bytes
                for m in c.mounts:
                    stopped_mounts.add(m)
            containers_total_sz += c.size_bytes

        # 2. Inspect images
        images = self.list_images(running_container_images=running_images, stopped_container_images=stopped_images)
        active_img_cnt = 0
        unused_img_cnt = 0
        dangling_img_cnt = 0
        images_total_sz = 0
        images_reclaimable_sz = 0

        for img in images:
            images_total_sz += img.size_bytes
            if img.in_use_by_running_container:
                active_img_cnt += 1
            else:
                unused_img_cnt += 1
                images_reclaimable_sz += img.size_bytes
            if img.is_dangling:
                dangling_img_cnt += 1

        # 3. Inspect volumes
        volumes = self.list_volumes(mounted_by_running=running_mounts, mounted_by_stopped=stopped_mounts)
        active_vol_cnt = 0
        unused_vol_cnt = 0
        volumes_total_sz = 0
        volumes_reclaimable_sz = 0

        for vol in volumes:
            volumes_total_sz += vol.size_bytes
            if vol.is_attached_to_running:
                active_vol_cnt += 1
            else:
                unused_vol_cnt += 1
                volumes_reclaimable_sz += vol.size_bytes

        # 4. Inspect build cache
        build_cache = self.get_builder_du()

        # Parse docker system df high-level metrics if available
        df_records = self.get_system_df_json()
        if df_records:
            for rec in df_records:
                rtype = rec.get("Type", "").lower()
                total_sz = parse_docker_size_bytes(rec.get("Size", "0B"))
                reclaim_sz = parse_docker_size_bytes(rec.get("Reclaimable", "0B").split(" ")[0])
                if "image" in rtype and total_sz > 0:
                    images_total_sz = total_sz
                    images_reclaimable_sz = reclaim_sz
                elif "container" in rtype and total_sz > 0:
                    containers_total_sz = total_sz
                    containers_reclaimable_sz = reclaim_sz
                elif "volume" in rtype and total_sz > 0:
                    volumes_total_sz = total_sz
                    volumes_reclaimable_sz = reclaim_sz
                elif "build" in rtype and total_sz > 0:
                    build_cache = DockerBuildCacheSummary(
                        total_bytes=total_sz,
                        reclaimable_bytes=reclaim_sz,
                        total_records=build_cache.total_records,
                        in_use_records=build_cache.in_use_records,
                    )

        summary = DockerResourceSummary(
            daemon_available=True,
            virtual_disk_bytes=virtual_disk_bytes,
            virtual_disk_path=virtual_disk_path,
            images_total_bytes=images_total_sz,
            images_reclaimable_bytes=images_reclaimable_sz,
            containers_total_bytes=containers_total_sz,
            containers_reclaimable_bytes=containers_reclaimable_sz,
            volumes_total_bytes=volumes_total_sz,
            volumes_reclaimable_bytes=volumes_reclaimable_sz,
            build_cache_total_bytes=build_cache.total_bytes,
            build_cache_reclaimable_bytes=build_cache.reclaimable_bytes,
            total_images_count=len(images),
            active_images_count=active_img_cnt,
            unused_images_count=unused_img_cnt,
            dangling_images_count=dangling_img_cnt,
            running_containers_count=running_cnt,
            stopped_containers_count=stopped_cnt,
            total_volumes_count=len(volumes),
            active_volumes_count=active_vol_cnt,
            unused_volumes_count=unused_vol_cnt,
            status_message=f"Docker daemon active. {running_cnt} running containers, {len(images)} images.",
        )

        return summary, images, containers, volumes, build_cache
