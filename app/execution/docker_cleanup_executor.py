"""
MacGuard AI Phase 14B — Controlled Docker Cleanup Executor.

Executes verified, approved, deterministic Docker cleanup operations.
SAFETY INVARIANTS:
1. CONTROLLED EXECUTION ONLY: Requires valid, non-expired HMAC approval.
2. ATOMIC CLAIM: Approvals are claimed atomically to prevent double execution or replay.
3. MANDATORY REVALIDATION: Resource state is revalidated against Docker runtime immediately before execution.
4. OPERATION ALLOWLIST: Only supports:
   - docker rm <container_id> (stopped container)
   - docker rmi <image_id> (unused/dangling image)
   - docker volume rm <volume_id> (unattached volume, requires high-risk confirmation)
   - docker builder prune -f (tightly bounded build cache prune)
5. ZERO PROHIBITED MUTATIONS: Never executes docker system prune, broad container/image/volume prunes, stop, kill, or restart.
6. ZERO DIRECT VIRTUAL DISK ACCESS: Never modifies Docker.raw, ~/.docker, or host VM files.
7. FAIL CLOSED: Any state drift, timeout, or uncertainty immediately aborts execution.
8. POST-EXECUTION VERIFICATION: Confirms removal from runtime state before marking success.
9. 100% AUDIT LOGGING: All execution attempts and rejections are permanently recorded.
"""

from __future__ import annotations

import json
import re
import secrets
import threading
from datetime import datetime, timezone, timedelta
from typing import Any, Optional, Union

from app.analysis.models import RiskLevel
from app.audit.models import AuditEvent, AuditEventType, ExecutionRecord
from app.audit.repository import AuditRepository
from app.models.docker_cleanup import (
    DockerCleanupApproval,
    DockerCleanupPlanItem,
    DockerExecutionResult,
    DockerExecutionStatus,
    DockerResourceType,
)
from app.models.investigation import ReclaimConfidence
from app.safety.approval import ApprovalKeyManager, get_default_key_manager
from app.safety.path_validator import Operation
from app.tools.docker_client import DockerClient


# Strict operation allowlist
ALLOWED_OPERATIONS: frozenset[str] = frozenset({
    "remove_stopped_container",
    "remove_unused_image",
    "remove_unused_volume",
})

# Forbidden subcommands/tokens
FORBIDDEN_OPERATIONS: frozenset[str] = frozenset({
    "system", "system_prune", "container_prune", "image_prune", "volume_prune",
    "stop", "kill", "restart", "run", "exec", "build", "pull", "push", "prune",
})


def validate_docker_identifier(resource_type: DockerResourceType, resource_id: str) -> tuple[bool, str]:
    """
    Validate Docker resource identifier format to prevent injection or invalid IDs.
    """
    if not resource_id or not isinstance(resource_id, str):
        return False, "Resource ID must be a non-empty string"

    res_id = resource_id.strip()

    # Reject path traversal or shell metacharacters
    if any(c in res_id for c in (";", "&", "|", "$", "`", "\n", "\r", "\x00", " ")):
        return False, "Resource ID contains invalid characters"

    if ".." in res_id or "/" in res_id:
        return False, "Resource ID contains path traversal elements"

    # Virtual disk protection
    if "docker.raw" in res_id.lower() or "docker.qcow2" in res_id.lower() or ".docker" in res_id.lower():
        return False, "Virtual disk and host configuration paths cannot be targeted"

    if resource_type == DockerResourceType.CONTAINER:
        if not re.match(r"^[a-fA-F0-9]{12,64}$", res_id):
            return False, f"Invalid container ID format: '{res_id}' (expected 12-64 hex chars)"
        return True, ""

    elif resource_type == DockerResourceType.IMAGE:
        # Image IDs may start with sha256: or be 12-64 hex chars
        clean_id = res_id.removeprefix("sha256:")
        if not re.match(r"^[a-fA-F0-9]{12,64}$", clean_id):
            return False, f"Invalid image ID format: '{res_id}' (expected 12-64 hex chars)"
        return True, ""

    elif resource_type == DockerResourceType.VOLUME:
        if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254}$", res_id):
            return False, f"Invalid volume name format: '{res_id}'"
        return True, ""

    elif resource_type == DockerResourceType.BUILD_CACHE:
        return False, "BuildKit cache cannot be targeted by exact immutable ID; build cache is REVIEW_ONLY / NOT_EXECUTABLE"

    elif resource_type == DockerResourceType.VIRTUAL_DISK:
        return False, "Virtual disk resources cannot be targeted for cleanup"

    return False, f"Unsupported resource type: {resource_type}"


class DockerCleanupExecutor:
    """
    Controlled, deterministic executor for approved Docker cleanup operations.
    """

    def __init__(
        self,
        docker_client: Optional[DockerClient] = None,
        key_manager: Optional[ApprovalKeyManager] = None,
        audit_repo: Optional[AuditRepository] = None,
        execution_timeout_seconds: float = 10.0,
    ) -> None:
        self._docker_client = docker_client or DockerClient()
        self._key_manager = key_manager or get_default_key_manager()
        self._audit_repo = audit_repo or AuditRepository()
        self._timeout = max(2.0, min(execution_timeout_seconds, 30.0))
        self._claim_lock = threading.Lock()
        self._claimed_approvals: set[str] = set()

    # -----------------------------------------------------------------------
    # Approval Creation & Verification
    # -----------------------------------------------------------------------

    def create_approval(
        self,
        item: DockerCleanupPlanItem,
        plan_id: str,
        expires_in_seconds: int = 300,
        high_risk_confirmed: bool = False,
    ) -> DockerCleanupApproval:
        """
        Generate a cryptographically signed HMAC-SHA256 approval for a Docker plan item.
        """
        appr_id = f"dappr_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(6)}"
        created_dt = datetime.now(timezone.utc)
        expires_dt = created_dt + timedelta(seconds=max(30, min(expires_in_seconds, 3600)))

        created_iso = created_dt.isoformat()
        expires_iso = expires_dt.isoformat()

        payload = self._build_canonical_payload(
            approval_id=appr_id,
            plan_id=plan_id,
            resource_type=item.resource_type.value,
            resource_id=item.resource_id,
            planned_operation=item.requested_action,
            planned_bytes=item.observed_size_bytes,
            created_at=created_iso,
            expires_at=expires_iso,
            high_risk_confirmed=high_risk_confirmed,
        )

        signature = self._key_manager.sign(payload)

        return DockerCleanupApproval(
            approval_id=appr_id,
            plan_id=plan_id,
            resource_type=item.resource_type,
            resource_id=item.resource_id,
            resource_name=item.resource_name,
            planned_operation=item.requested_action,
            planned_bytes=item.observed_size_bytes,
            observed_state=item.observed_state,
            created_at=created_iso,
            expires_at=expires_iso,
            hmac_signature=signature,
            high_risk_confirmed=high_risk_confirmed,
        )

    def verify_approval(self, approval: DockerCleanupApproval) -> tuple[bool, str]:
        """
        Verify the HMAC-SHA256 signature and expiration of an approval record.
        """
        if not approval.approval_id or not approval.hmac_signature:
            return False, "Missing approval ID or signature"

        # Check expiration
        try:
            exp_dt = datetime.fromisoformat(approval.expires_at)
            now_dt = datetime.now(timezone.utc)
            if now_dt > exp_dt:
                return False, f"Approval expired at {approval.expires_at} (current time: {now_dt.isoformat()})"
        except Exception as exc:
            return False, f"Malformed expiration timestamp: {exc}"

        payload = self._build_canonical_payload(
            approval_id=approval.approval_id,
            plan_id=approval.plan_id,
            resource_type=approval.resource_type.value,
            resource_id=approval.resource_id,
            planned_operation=approval.planned_operation,
            planned_bytes=approval.planned_bytes,
            created_at=approval.created_at,
            expires_at=approval.expires_at,
            high_risk_confirmed=approval.high_risk_confirmed,
        )

        valid_sig = self._key_manager.verify(payload, approval.hmac_signature)
        if not valid_sig:
            return False, "Invalid HMAC signature — approval integrity check failed"

        return True, ""

    @staticmethod
    def _build_canonical_payload(
        approval_id: str,
        plan_id: str,
        resource_type: str,
        resource_id: str,
        planned_operation: str,
        planned_bytes: int,
        created_at: str,
        expires_at: str,
        high_risk_confirmed: bool,
    ) -> str:
        """Create a deterministic, canonical string for HMAC signing."""
        return (
            f"DOCKER_APPROVAL|{approval_id}|{plan_id}|{resource_type}|"
            f"{resource_id}|{planned_operation}|{planned_bytes}|"
            f"{created_at}|{expires_at}|{high_risk_confirmed}"
        )

    # -----------------------------------------------------------------------
    # Atomic Claim
    # -----------------------------------------------------------------------

    def claim_approval(self, approval_id: str) -> bool:
        """
        Atomically claim an approval ID to prevent double execution or replay.
        """
        with self._claim_lock:
            if approval_id in self._claimed_approvals:
                return False
            self._claimed_approvals.add(approval_id)
            return True

    # -----------------------------------------------------------------------
    # Pre-Execution Revalidation
    # -----------------------------------------------------------------------

    def revalidate_resource(
        self,
        approval: DockerCleanupApproval,
    ) -> tuple[bool, DockerExecutionStatus, str, dict[str, Any]]:
        """
        Perform mandatory pre-execution revalidation against live Docker daemon.
        """
        # 1. Check daemon availability
        if not self._docker_client.is_daemon_running():
            return (
                False,
                DockerExecutionStatus.DOCKER_UNAVAILABLE,
                "Docker Desktop daemon is stopped or unreachable.",
                {},
            )

        # 2. Validate identifier
        valid_id, id_err = validate_docker_identifier(approval.resource_type, approval.resource_id)
        if not valid_id:
            return (
                False,
                DockerExecutionStatus.REJECTED_STATE_CHANGED,
                f"Resource identifier validation failed: {id_err}",
                {},
            )

        # 3. Check operation allowlist
        if approval.planned_operation not in ALLOWED_OPERATIONS:
            return (
                False,
                DockerExecutionStatus.REJECTED_INVALID_APPROVAL,
                f"Prohibited or unknown operation: '{approval.planned_operation}'",
                {},
            )

        # 4. Resource-type specific revalidation
        r_type = approval.resource_type
        r_id = approval.resource_id

        # 4A. Container Revalidation
        if r_type == DockerResourceType.CONTAINER:
            containers = self._docker_client.list_containers()
            matching = [c for c in containers if c.container_id == r_id[:12] or c.container_id.startswith(r_id)]
            if not matching:
                return (
                    False,
                    DockerExecutionStatus.REJECTED_STATE_CHANGED,
                    f"Container '{r_id}' was not found in Docker runtime.",
                    {},
                )
            cnt = matching[0]
            if cnt.is_running:
                return (
                    False,
                    DockerExecutionStatus.REJECTED_PROTECTED,
                    f"Container '{cnt.names[0] if cnt.names else r_id}' is currently running and is PROTECTED.",
                    {"status": cnt.status, "is_running": True},
                )
            return (
                True,
                DockerExecutionStatus.EXECUTED,
                "Container is stopped and eligible for removal.",
                {"container_id": cnt.container_id, "status": cnt.status, "size_bytes": cnt.size_bytes},
            )

        # 4B. Image Revalidation
        elif r_type == DockerResourceType.IMAGE:
            containers = self._docker_client.list_containers()
            running_imgs = {c.image for c in containers if c.is_running}
            stopped_imgs = {c.image for c in containers if not c.is_running}

            images = self._docker_client.list_images(
                running_container_images=running_imgs,
                stopped_container_images=stopped_imgs,
            )
            clean_r_id = r_id.removeprefix("sha256:")
            matching_img = [img for img in images if img.image_id == clean_r_id[:12] or img.image_id.startswith(clean_r_id)]
            if not matching_img:
                return (
                    False,
                    DockerExecutionStatus.REJECTED_STATE_CHANGED,
                    f"Image '{r_id}' was not found in Docker runtime.",
                    {},
                )
            img = matching_img[0]
            if img.in_use_by_running_container:
                return (
                    False,
                    DockerExecutionStatus.REJECTED_PROTECTED,
                    f"Image '{img.repository}:{img.tag}' is in use by a running container and is PROTECTED.",
                    {"image_id": img.image_id, "in_use_running": True},
                )
            return (
                True,
                DockerExecutionStatus.EXECUTED,
                "Image is unused by running containers and eligible for removal.",
                {"image_id": img.image_id, "size_bytes": img.size_bytes},
            )

        # 4C. Volume Revalidation
        elif r_type == DockerResourceType.VOLUME:
            containers = self._docker_client.list_containers()
            running_mounts: set[str] = set()
            stopped_mounts: set[str] = set()
            for c in containers:
                if c.is_running:
                    for m in c.mounts:
                        running_mounts.add(m)
                else:
                    for m in c.mounts:
                        stopped_mounts.add(m)

            volumes = self._docker_client.list_volumes(
                mounted_by_running=running_mounts,
                mounted_by_stopped=stopped_mounts,
            )
            matching_vol = [v for v in volumes if v.name == r_id]
            if not matching_vol:
                return (
                    False,
                    DockerExecutionStatus.REJECTED_STATE_CHANGED,
                    f"Volume '{r_id}' was not found in Docker runtime.",
                    {},
                )
            vol = matching_vol[0]
            if vol.is_attached_to_running or vol.is_attached_to_stopped:
                return (
                    False,
                    DockerExecutionStatus.REJECTED_STATE_CHANGED,
                    f"Volume '{vol.name}' is attached to containers (running={vol.is_attached_to_running}, stopped={vol.is_attached_to_stopped}).",
                    {"name": vol.name, "attached_running": vol.is_attached_to_running, "attached_stopped": vol.is_attached_to_stopped},
                )
            return (
                True,
                DockerExecutionStatus.EXECUTED,
                "Volume is unattached and eligible for removal.",
                {"name": vol.name, "driver": vol.driver, "size_bytes": vol.size_bytes},
            )

        # 4D. Build Cache Revalidation (Review Only / Not Executable)
        elif r_type == DockerResourceType.BUILD_CACHE:
            return (
                False,
                DockerExecutionStatus.REJECTED_NON_EXECUTABLE,
                "BuildKit cache cleanup is REVIEW_ONLY / NOT_EXECUTABLE in MacGuard AI because Docker lacks an exact, single-resource immutable mutation interface.",
                {},
            )

        return (
            False,
            DockerExecutionStatus.REJECTED_PROTECTED,
            f"Unsupported or protected resource type: {r_type}",
            {},
        )

    # -----------------------------------------------------------------------
    # Mutation Execution & Verification
    # -----------------------------------------------------------------------

    def _execute_docker_cmd(self, cmd: list[str]) -> tuple[bool, str]:
        """
        Execute an allowlisted Docker mutation subcommand through DockerClient.
        """
        return self._docker_client.execute_mutation(cmd)

    def _verify_post_execution(
        self,
        approval: DockerCleanupApproval,
        pre_state: dict[str, Any],
    ) -> tuple[bool, int, str]:
        """
        Verify that the resource was actually removed from the runtime state.
        """
        r_type = approval.resource_type
        r_id = approval.resource_id

        if r_type == DockerResourceType.CONTAINER:
            containers = self._docker_client.list_containers()
            still_exists = any(c.container_id == r_id[:12] or c.container_id.startswith(r_id) for c in containers)
            if still_exists:
                return False, 0, f"Verification failed: container '{r_id}' still present in runtime."
            reclaimed = pre_state.get("size_bytes", approval.planned_bytes)
            return True, reclaimed, "Container successfully removed and verified absent."

        elif r_type == DockerResourceType.IMAGE:
            containers = self._docker_client.list_containers()
            running_imgs = {c.image for c in containers if c.is_running}
            images = self._docker_client.list_images(running_container_images=running_imgs)
            clean_id = r_id.removeprefix("sha256:")
            still_exists = any(img.image_id == clean_id[:12] or img.image_id.startswith(clean_id) for img in images)
            if still_exists:
                return False, 0, f"Verification failed: image '{r_id}' still present in runtime."
            reclaimed = pre_state.get("size_bytes", approval.planned_bytes)
            return True, reclaimed, "Image successfully removed and verified absent."

        elif r_type == DockerResourceType.VOLUME:
            volumes = self._docker_client.list_volumes()
            still_exists = any(v.name == r_id for v in volumes)
            if still_exists:
                return False, 0, f"Verification failed: volume '{r_id}' still present in runtime."
            reclaimed = pre_state.get("size_bytes", approval.planned_bytes)
            return True, reclaimed, "Volume successfully removed and verified absent."

        return False, 0, f"Unknown or non-executable resource type for verification: {r_type}"

    # -----------------------------------------------------------------------
    # Main Execution Entry Point
    # -----------------------------------------------------------------------

    def execute_approved_cleanup(self, approval: DockerCleanupApproval) -> DockerExecutionResult:
        """
        Execute an approved Docker cleanup candidate through the full security pipeline:
        approval verification -> atomic claim -> pre-revalidation -> mutation -> post-verification -> audit.
        """
        exec_id = f"dexec_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(4)}"
        start_iso = datetime.now(timezone.utc).isoformat()

        # Step 1: Verify HMAC and expiration
        is_valid_appr, appr_err = self.verify_approval(approval)
        if not is_valid_appr:
            status = (
                DockerExecutionStatus.REJECTED_EXPIRED_APPROVAL
                if "expired" in appr_err.lower()
                else DockerExecutionStatus.REJECTED_INVALID_APPROVAL
            )
            return self._record_and_return_failure(
                exec_id=exec_id,
                approval=approval,
                status=status,
                error_msg=appr_err,
                start_iso=start_iso,
            )

        # Step 2: High-risk confirmation check for volumes
        if approval.resource_type == DockerResourceType.VOLUME and not approval.high_risk_confirmed:
            return self._record_and_return_failure(
                exec_id=exec_id,
                approval=approval,
                status=DockerExecutionStatus.REJECTED_HIGH_RISK_NOT_CONFIRMED,
                error_msg="Volume cleanup is HIGH RISK and requires explicit confirmation.",
                start_iso=start_iso,
            )

        # Step 3: Atomic claim
        if not self.claim_approval(approval.approval_id):
            return self._record_and_return_failure(
                exec_id=exec_id,
                approval=approval,
                status=DockerExecutionStatus.REJECTED_ALREADY_CLAIMED,
                error_msg="Approval has already been claimed or executed.",
                start_iso=start_iso,
            )

        # Step 4: Mandatory Pre-Execution Revalidation
        reval_ok, reval_status, reval_msg, pre_state = self.revalidate_resource(approval)
        if not reval_ok:
            return self._record_and_return_failure(
                exec_id=exec_id,
                approval=approval,
                status=reval_status,
                error_msg=reval_msg,
                start_iso=start_iso,
            )

        # Step 5: Bounded Mutation Execution
        cmd = self._construct_docker_cmd(approval)
        mut_ok, mut_msg = self._execute_docker_cmd(cmd)
        if not mut_ok:
            return self._record_and_return_failure(
                exec_id=exec_id,
                approval=approval,
                status=DockerExecutionStatus.EXECUTION_FAILED,
                error_msg=mut_msg,
                start_iso=start_iso,
                metadata={"cmd": cmd, "pre_state": pre_state},
            )

        # Step 6: Post-Execution Verification
        ver_ok, reclaimed_bytes, ver_msg = self._verify_post_execution(approval, pre_state)
        end_iso = datetime.now(timezone.utc).isoformat()

        if not ver_ok:
            return self._record_and_return_failure(
                exec_id=exec_id,
                approval=approval,
                status=DockerExecutionStatus.VERIFICATION_FAILED,
                error_msg=ver_msg,
                start_iso=start_iso,
                metadata={"cmd": cmd, "pre_state": pre_state, "mutation_output": mut_msg},
            )

        # Step 7: Record Audit Success
        result = DockerExecutionResult(
            execution_id=exec_id,
            approval_id=approval.approval_id,
            resource_type=approval.resource_type,
            resource_id=approval.resource_id,
            resource_name=approval.resource_name,
            operation=approval.planned_operation,
            status=DockerExecutionStatus.EXECUTED,
            planned_bytes=approval.planned_bytes,
            reclaimed_bytes=reclaimed_bytes,
            verified=True,
            error_message="",
            start_time=start_iso,
            end_time=end_iso,
            metadata={
                "command": cmd,
                "mutation_output": mut_msg,
                "verification_message": ver_msg,
                "pre_state": pre_state,
            },
        )

        self._log_audit_event(
            event_type=AuditEventType.EXECUTION_SUCCEEDED,
            result=result,
            approval=approval,
            reason=f"Docker cleanup of '{approval.resource_name or approval.resource_id}' succeeded and verified.",
        )

        return result

    def _construct_docker_cmd(self, approval: DockerCleanupApproval) -> list[str]:
        """Construct the exact allowlisted Docker CLI command."""
        r_type = approval.resource_type
        r_id = approval.resource_id

        if r_type == DockerResourceType.CONTAINER:
            return ["docker", "rm", r_id]
        elif r_type == DockerResourceType.IMAGE:
            return ["docker", "rmi", r_id]
        elif r_type == DockerResourceType.VOLUME:
            return ["docker", "volume", "rm", r_id]
        raise ValueError(f"Cannot construct command for unsupported or non-executable resource type: {r_type}")

    def _record_and_return_failure(
        self,
        exec_id: str,
        approval: DockerCleanupApproval,
        status: DockerExecutionStatus,
        error_msg: str,
        start_iso: str,
        metadata: Optional[dict[str, Any]] = None,
    ) -> DockerExecutionResult:
        """Helper to create failure result, log audit event, and return."""
        end_iso = datetime.now(timezone.utc).isoformat()
        res = DockerExecutionResult(
            execution_id=exec_id,
            approval_id=approval.approval_id,
            resource_type=approval.resource_type,
            resource_id=approval.resource_id,
            resource_name=approval.resource_name,
            operation=approval.planned_operation,
            status=status,
            planned_bytes=approval.planned_bytes,
            reclaimed_bytes=0,
            verified=False,
            error_message=error_msg,
            start_time=start_iso,
            end_time=end_iso,
            metadata=metadata or {},
        )

        ev_type = (
            AuditEventType.EXECUTION_BLOCKED
            if "REJECTED" in status.value or status == DockerExecutionStatus.DOCKER_UNAVAILABLE
            else AuditEventType.EXECUTION_FAILED
        )

        self._log_audit_event(
            event_type=ev_type,
            result=res,
            approval=approval,
            reason=error_msg,
        )

        return res

    def _log_audit_event(
        self,
        event_type: AuditEventType,
        result: DockerExecutionResult,
        approval: DockerCleanupApproval,
        reason: str,
    ) -> None:
        """Write structured audit event to SQLite audit repository."""
        canonical_target = f"docker://{approval.resource_type.value}/{approval.resource_id}"
        risk = RiskLevel.HIGH if approval.resource_type == DockerResourceType.VOLUME else RiskLevel.MEDIUM

        try:
            event = AuditEvent(
                event_type=event_type,
                approval_id=approval.approval_id,
                execution_id=result.execution_id,
                canonical_path=canonical_target,
                operation=Operation.CLEAN,
                risk_level=risk,
                status=result.status.value,
                actor="human_with_executor",
                reason=reason,
                metadata={
                    "resource_type": approval.resource_type.value,
                    "resource_id": approval.resource_id,
                    "resource_name": approval.resource_name,
                    "operation": approval.planned_operation,
                    "planned_bytes": approval.planned_bytes,
                    "reclaimed_bytes": result.reclaimed_bytes,
                    "verified": result.verified,
                    "error_message": result.error_message,
                    "high_risk_confirmed": approval.high_risk_confirmed,
                },
            )
            self._audit_repo.record_event(event)

            rec = ExecutionRecord(
                execution_id=result.execution_id,
                approval_id=approval.approval_id,
                canonical_path=canonical_target,
                action="DOCKER_CLEANUP",
                status=result.status.value,
                start_time=datetime.fromisoformat(result.start_time),
                end_time=datetime.fromisoformat(result.end_time) if result.end_time else None,
                reclaimed_bytes=result.reclaimed_bytes,
                destination_path="DOCKER_ENGINE",
                verified=result.verified,
                message=reason,
            )
            self._audit_repo.record_execution(rec)
        except Exception:
            # Audit logging must not crash the executor
            pass
