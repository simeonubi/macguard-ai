"""
MacGuard AI Phase 13 — Docker Structured Evidence Models.

Defines typed schemas for Docker storage inspection, resource inventory,
and aggregated Docker metrics.
"""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class DockerResourceSummary(BaseModel):
    """Aggregated summary of Docker Desktop and container runtime storage."""

    model_config = ConfigDict(frozen=True)

    daemon_available: bool = Field(default=False, description="Whether Docker daemon is running and responsive")
    virtual_disk_bytes: int = Field(default=0, ge=0, description="Physical size of Docker.raw / Docker.qcow2 on host")
    virtual_disk_path: Optional[str] = Field(default=None, description="Path to Docker virtual disk file")

    # Docker internal reported breakdown (from docker system df). None when daemon is offline.
    images_total_bytes: Optional[int] = Field(default=None, ge=0, description="Total size of Docker images")
    images_reclaimable_bytes: Optional[int] = Field(default=None, ge=0, description="Reclaimable size of unused images")
    containers_total_bytes: Optional[int] = Field(default=None, ge=0, description="Total size of Docker containers")
    containers_reclaimable_bytes: Optional[int] = Field(default=None, ge=0, description="Reclaimable size of stopped containers")
    volumes_total_bytes: Optional[int] = Field(default=None, ge=0, description="Total size of Docker local volumes")
    volumes_reclaimable_bytes: Optional[int] = Field(default=None, ge=0, description="Reclaimable size of unused volumes")
    build_cache_total_bytes: Optional[int] = Field(default=None, ge=0, description="Total size of Docker build cache")
    build_cache_reclaimable_bytes: Optional[int] = Field(default=None, ge=0, description="Reclaimable size of build cache")

    # Counts. None when daemon is offline.
    total_images_count: Optional[int] = Field(default=None, ge=0)
    active_images_count: Optional[int] = Field(default=None, ge=0)
    unused_images_count: Optional[int] = Field(default=None, ge=0)
    dangling_images_count: Optional[int] = Field(default=None, ge=0)

    running_containers_count: Optional[int] = Field(default=None, ge=0)
    stopped_containers_count: Optional[int] = Field(default=None, ge=0)

    total_volumes_count: Optional[int] = Field(default=None, ge=0)
    active_volumes_count: Optional[int] = Field(default=None, ge=0)
    unused_volumes_count: Optional[int] = Field(default=None, ge=0)

    status_message: str = Field(default="", description="Diagnostic message regarding Docker daemon status")


class DockerImageItem(BaseModel):
    """Metadata for a single Docker image."""

    model_config = ConfigDict(frozen=True)

    image_id: str
    repository: str
    tag: str
    size_bytes: int
    created_at: str
    is_dangling: bool = False
    in_use_by_running_container: bool = False
    in_use_by_stopped_container: bool = False
    associated_container_ids: list[str] = Field(default_factory=list)


class DockerContainerItem(BaseModel):
    """Metadata for a single Docker container."""

    model_config = ConfigDict(frozen=True)

    container_id: str
    names: list[str]
    image: str
    image_id: str
    status: str
    is_running: bool
    size_bytes: int = 0
    created_at: str
    mounts: list[str] = Field(default_factory=list)


class DockerVolumeItem(BaseModel):
    """Metadata for a single Docker volume."""

    model_config = ConfigDict(frozen=True)

    name: str
    driver: str
    size_bytes: int = 0
    is_attached_to_running: bool = False
    is_attached_to_stopped: bool = False
    attached_container_names: list[str] = Field(default_factory=list)


class DockerBuildCacheSummary(BaseModel):
    """Metadata for Docker builder cache."""

    model_config = ConfigDict(frozen=True)

    total_bytes: int = 0
    reclaimable_bytes: int = 0
    total_records: int = 0
    in_use_records: int = 0
