"""
MacGuard AI Phase 14A — Docker Cleanup Planner.

Produces deterministic, structured cleanup plans for review from Phase 13 Docker evidence.
SAFETY INVARIANTS:
1. PLANNING ONLY: Every plan item has executable=False.
2. ZERO AUTOMATED DELETION: Every candidate requires explicit human approval (approval_required=True).
3. NO HIGH CONFIDENCE: All Docker cleanup plans are classified as REVIEW_REQUIRED.
4. STRICT PROTECTION: Docker.raw, running containers, active images, and mounted volumes are NEVER planned.
5. STATE DRIFT GROUNDING: Captures observed state metadata for pre-execution revalidation.
"""

from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone
from typing import Optional

from app.models.docker_cleanup import (
    DockerCleanupPlan,
    DockerCleanupPlanItem,
    DockerResourceType,
)
from app.models.investigation import ReclaimConfidence, StorageEvidenceItem, StorageInvestigationEvidence


class DockerCleanupPlanner:
    """
    Deterministic planning engine that transforms Phase 13 Docker storage evidence
    into human-reviewable Docker cleanup proposals.
    """

    @staticmethod
    def _parse_container_info(path: str) -> tuple[str, str]:
        """Extract container ID and name from path: 'docker://containers/<id> (<name>)'."""
        match = re.search(r"docker://containers/([^\s()]+)\s*\((.*?)\)", path)
        if match:
            return match.group(1), match.group(2)
        match_id = re.search(r"docker://containers/([^\s()]+)", path)
        if match_id:
            return match_id.group(1), match_id.group(1)
        return path, path

    @staticmethod
    def _parse_image_info(path: str) -> tuple[str, str]:
        """Extract image ID and repo:tag from path: 'docker://images/<id> (<ref>)'."""
        match = re.search(r"docker://images/([^\s()]+)\s*\((.*?)\)", path)
        if match:
            return match.group(1), match.group(2)
        match_id = re.search(r"docker://images/([^\s()]+)", path)
        if match_id:
            return match_id.group(1), match_id.group(1)
        return path, path

    @staticmethod
    def _parse_volume_name(path: str) -> str:
        """Extract volume name from path: 'docker://volumes/<name>'."""
        match = re.search(r"docker://volumes/(.*)", path)
        if match:
            return match.group(1).strip()
        return path

    def create_plan(
        self,
        evidence: StorageInvestigationEvidence,
        plan_id: Optional[str] = None,
    ) -> DockerCleanupPlan:
        """
        Create a deterministic Docker cleanup plan from structured investigation evidence.
        Guarantees strict 1:1 uniqueness per immutable Docker resource ID.
        """
        pid = plan_id or f"dplan_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(3)}"
        now_iso = datetime.now(timezone.utc).isoformat()

        plan_items: list[DockerCleanupPlanItem] = []
        total_proposed = 0
        volume_warnings: list[str] = []

        seen_containers: dict[str, DockerCleanupPlanItem] = {}
        seen_images: dict[str, DockerCleanupPlanItem] = {}
        seen_volumes: dict[str, DockerCleanupPlanItem] = {}
        seen_build_cache: bool = False

        seen_running_containers: set[str] = set()
        seen_stopped_containers: set[str] = set()
        seen_active_images: set[str] = set()
        seen_unused_images: set[str] = set()
        seen_attached_volumes: set[str] = set()
        seen_unattached_volumes: set[str] = set()
        seen_host_targets: set[str] = set()

        docker_items = [it for it in evidence.items if it.is_docker]

        for it in docker_items:
            subcat = it.subcategory

            # 1. Docker Virtual Disk & Desktop Root: ALWAYS PROTECTED, NEVER PLANNED
            if subcat in ("docker_virtual_disk", "docker_desktop_container", "docker_cli_config"):
                seen_host_targets.add(it.path)
                continue

            # 2. Containers
            if subcat == "docker_container":
                c_id, c_name = self._parse_container_info(it.path)
                if it.currently_in_use or it.reclaim_confidence == ReclaimConfidence.PROTECTED:
                    seen_running_containers.add(c_id)
                    continue

                seen_stopped_containers.add(c_id)
                if c_id in seen_containers:
                    existing = seen_containers[c_id]
                    if it.evidence_id not in existing.evidence_ids:
                        idx = plan_items.index(existing)
                        updated = existing.model_copy(update={"evidence_ids": [*existing.evidence_ids, it.evidence_id]})
                        plan_items[idx] = updated
                        seen_containers[c_id] = updated
                    continue

                item = DockerCleanupPlanItem(
                    plan_id=f"item_cnt_{c_id[:12]}",
                    resource_type=DockerResourceType.CONTAINER,
                    resource_id=c_id,
                    resource_name=c_name,
                    observed_size_bytes=it.size_bytes,
                    requested_action="remove_stopped_container",
                    safety_classification=ReclaimConfidence.REVIEW_REQUIRED,
                    currently_in_use=False,
                    dependency_evidence=it.dependency_evidence or "Stopped container",
                    consequence=f"Stopped container '{c_name}' will be removed. Attached volumes and image layers remain intact.",
                    evidence_ids=[it.evidence_id],
                    approval_required=True,
                    executable=False,
                    is_high_risk=False,
                    observed_state={
                        "container_id": c_id,
                        "name": c_name,
                        "status": it.usage_evidence,
                        "mounts_or_image": it.dependency_evidence,
                    },
                )
                seen_containers[c_id] = item
                plan_items.append(item)
                total_proposed += it.size_bytes

            # 3. Images
            elif subcat == "docker_image":
                img_id, img_ref = self._parse_image_info(it.path)
                if it.currently_in_use or it.reclaim_confidence == ReclaimConfidence.PROTECTED:
                    seen_active_images.add(img_id)
                    continue

                seen_unused_images.add(img_id)
                if img_id in seen_images:
                    existing = seen_images[img_id]
                    updated_ev_ids = existing.evidence_ids
                    if it.evidence_id not in updated_ev_ids:
                        updated_ev_ids = [*updated_ev_ids, it.evidence_id]

                    # Merge new tag alias into resource_name if not already included
                    updated_name = existing.resource_name
                    if img_ref and img_ref not in updated_name:
                        updated_name = f"{existing.resource_name}, {img_ref}"

                    idx = plan_items.index(existing)
                    updated = existing.model_copy(update={
                        "evidence_ids": updated_ev_ids,
                        "resource_name": updated_name,
                    })
                    plan_items[idx] = updated
                    seen_images[img_id] = updated
                    continue

                item = DockerCleanupPlanItem(
                    plan_id=f"item_img_{img_id[:12]}",
                    resource_type=DockerResourceType.IMAGE,
                    resource_id=img_id,
                    resource_name=img_ref,
                    observed_size_bytes=it.size_bytes,
                    requested_action="remove_unused_image",
                    safety_classification=ReclaimConfidence.REVIEW_REQUIRED,
                    currently_in_use=False,
                    dependency_evidence=it.dependency_evidence or "Unused image layer",
                    consequence=f"Image '{img_ref}' will be removed from local Docker cache. Can be pulled again if needed.",
                    evidence_ids=[it.evidence_id],
                    approval_required=True,
                    executable=False,
                    is_high_risk=False,
                    observed_state={
                        "image_id": img_id,
                        "ref": img_ref,
                        "is_dangling": "dangling" in it.path.lower(),
                    },
                )
                seen_images[img_id] = item
                plan_items.append(item)
                total_proposed += it.size_bytes

            # 4. Volumes
            elif subcat == "docker_volume":
                vol_name = self._parse_volume_name(it.path)
                if it.currently_in_use or it.reclaim_confidence == ReclaimConfidence.PROTECTED:
                    seen_attached_volumes.add(vol_name)
                    continue

                seen_unattached_volumes.add(vol_name)
                if vol_name in seen_volumes:
                    existing = seen_volumes[vol_name]
                    if it.evidence_id not in existing.evidence_ids:
                        idx = plan_items.index(existing)
                        updated = existing.model_copy(update={"evidence_ids": [*existing.evidence_ids, it.evidence_id]})
                        plan_items[idx] = updated
                        seen_volumes[vol_name] = updated
                    continue

                warn_msg = f"HIGH RISK: Volume '{vol_name}' is unattached but may contain persistent database or application data."
                volume_warnings.append(warn_msg)

                item = DockerCleanupPlanItem(
                    plan_id=f"item_vol_{vol_name[:16]}",
                    resource_type=DockerResourceType.VOLUME,
                    resource_id=vol_name,
                    resource_name=vol_name,
                    observed_size_bytes=it.size_bytes,
                    requested_action="remove_unused_volume",
                    safety_classification=ReclaimConfidence.REVIEW_REQUIRED,
                    currently_in_use=False,
                    dependency_evidence=it.dependency_evidence or "Unattached volume",
                    consequence=f"HIGH RISK: Volume '{vol_name}' contains persistent data. Removing it permanently erases all contained files.",
                    evidence_ids=[it.evidence_id],
                    approval_required=True,
                    executable=False,
                    is_high_risk=True,
                    observed_state={
                        "volume_name": vol_name,
                        "attachment_status": it.usage_evidence,
                    },
                )
                seen_volumes[vol_name] = item
                plan_items.append(item)
                total_proposed += it.size_bytes

            # 5. Build Cache
            elif subcat == "docker_build_cache":
                if seen_build_cache:
                    continue
                seen_build_cache = True

                item = DockerCleanupPlanItem(
                    plan_id="item_bc_buildkit",
                    resource_type=DockerResourceType.BUILD_CACHE,
                    resource_id="build_cache",
                    resource_name="Docker BuildKit Cache",
                    observed_size_bytes=it.size_bytes,
                    requested_action="prune_build_cache",
                    safety_classification=ReclaimConfidence.REVIEW_REQUIRED,
                    currently_in_use=False,
                    dependency_evidence=it.dependency_evidence or "BuildKit build graph cache",
                    consequence="Reclaims cached intermediate build steps. Subsequent container builds will re-download and re-execute uncached layers.",
                    evidence_ids=[it.evidence_id],
                    approval_required=True,
                    executable=False,
                    is_high_risk=False,
                    observed_state={
                        "records_count": it.item_count,
                    },
                )
                plan_items.append(item)
                total_proposed += it.size_bytes

        running_cnt = len(seen_running_containers)
        stopped_cnt = len(seen_stopped_containers)
        active_img = len(seen_active_images)
        unused_img = len(seen_unused_images)
        attached_vol = len(seen_attached_volumes)
        unattached_vol = len(seen_unattached_volumes)
        host_targets = len(seen_host_targets)

        protected_total = host_targets + running_cnt + active_img + attached_vol

        status_msg = (
            f"Generated Docker cleanup plan with {len(plan_items)} review candidates "
            f"({len(volume_warnings)} high-risk volumes). {protected_total} protected resources excluded "
            f"({running_cnt} running containers, {active_img} active images, {attached_vol} attached volumes, {host_targets} host targets)."
        )

        return DockerCleanupPlan(
            plan_id=pid,
            created_at=now_iso,
            items=plan_items,
            protected_items_count=protected_total,
            running_containers_count=running_cnt,
            stopped_containers_count=stopped_cnt,
            active_images_count=active_img,
            unused_images_count=unused_img,
            attached_volumes_count=attached_vol,
            unattached_volumes_count=unattached_vol,
            protected_host_targets_count=host_targets,
            total_proposed_bytes=total_proposed,
            volume_warnings=volume_warnings,
            status_message=status_msg,
        )
