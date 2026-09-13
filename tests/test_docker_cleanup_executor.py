"""
MacGuard AI Phase 14B — Comprehensive Test Suite for Controlled Docker Cleanup Execution.

Explicit 1:1 Mapping of All 25 Phase 14B Safety Invariants & Requirements:
1. Valid stopped-container approval executes (docker rm <id>)
2. Valid unused-image approval executes (docker rmi <id>)
3. Valid unattached-volume approval requires high-risk confirmation
4. Build-cache cleanup is REVIEW_ONLY / NOT_EXECUTABLE (fails closed, no broad builder prune)
5. Invalid HMAC rejected (REJECTED_INVALID_APPROVAL)
6. Expired approval rejected (REJECTED_EXPIRED_APPROVAL)
7. Replayed approval rejected (REJECTED_ALREADY_CLAIMED)
8. Already-claimed approval rejected (REJECTED_ALREADY_CLAIMED)
9. Running container protected (REJECTED_PROTECTED)
10. Active image protected (REJECTED_PROTECTED)
11. Attached volume protected (REJECTED_STATE_CHANGED)
12. Docker.raw cannot be targeted (REJECTED_PROTECTED)
13. ~/.docker cannot be targeted (REJECTED_PROTECTED)
14. Fabricated resource ID rejected
15. Resource state changed after approval -> rejected (REJECTED_STATE_CHANGED)
16. Image becomes active after approval -> rejected (REJECTED_PROTECTED)
17. Volume becomes attached after approval -> rejected (REJECTED_STATE_CHANGED)
18. Docker daemon unavailable -> no execution (DOCKER_UNAVAILABLE)
19. Docker mutation failure audited (EXECUTION_FAILED)
20. Verification failure audited (VERIFICATION_FAILED)
21. No broad prune commands allowed
22. AST check: no shell=True
23. AST check: no sudo
24. AST check: no arbitrary command execution
25. Concurrent/replayed execution cannot execute twice
"""

from __future__ import annotations

import ast
import concurrent.futures
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.audit.models import AuditEventType
from app.audit.repository import AuditRepository
from app.execution.docker_cleanup_executor import (
    ALLOWED_OPERATIONS,
    DockerCleanupExecutor,
    validate_docker_identifier,
)
from app.models.docker_cleanup import (
    DockerCleanupApproval,
    DockerCleanupPlanItem,
    DockerExecutionResult,
    DockerExecutionStatus,
    DockerResourceType,
)
from app.models.docker_evidence import (
    DockerBuildCacheSummary,
    DockerContainerItem,
    DockerImageItem,
    DockerVolumeItem,
)
from app.models.investigation import ReclaimConfidence
from app.safety.approval import ApprovalKeyManager


@pytest.fixture
def mock_audit_repo(tmp_path) -> AuditRepository:
    db_file = tmp_path / "test_audit.db"
    return AuditRepository(db_path=db_file)


@pytest.fixture
def key_manager() -> ApprovalKeyManager:
    return ApprovalKeyManager()


@pytest.fixture
def mock_docker_client() -> MagicMock:
    client = MagicMock()
    client.is_daemon_running.return_value = True

    # Sample stopped container
    c_stopped = DockerContainerItem(
        container_id="c1234567890a",
        names=["test-worker"],
        image="worker:latest",
        image_id="img123456789",
        status="Exited (0) 2 hours ago",
        is_running=False,
        size_bytes=50_000_000,
        created_at="2026-09-12T10:00:00Z",
    )
    # Sample running container
    c_running = DockerContainerItem(
        container_id="c99988877766",
        names=["active-web"],
        image="web:latest",
        image_id="img999888777",
        status="Up 4 hours",
        is_running=True,
        size_bytes=100_000_000,
        created_at="2026-09-12T08:00:00Z",
        mounts=["live_volume"],
    )
    client.list_containers.return_value = [c_stopped, c_running]

    # Sample unused image
    img_unused = DockerImageItem(
        image_id="a1b2c3d4e5f6",
        repository="old-app",
        tag="1.0.0",
        size_bytes=200_000_000,
        created_at="2026-09-01T00:00:00Z",
        is_dangling=False,
        in_use_by_running_container=False,
        in_use_by_stopped_container=False,
    )
    # Sample active image
    img_active = DockerImageItem(
        image_id="999888777666",
        repository="web",
        tag="latest",
        size_bytes=400_000_000,
        created_at="2026-09-01T00:00:00Z",
        is_dangling=False,
        in_use_by_running_container=True,
        in_use_by_stopped_container=False,
    )
    client.list_images.return_value = [img_unused, img_active]

    # Sample unattached volume
    vol_unattached = DockerVolumeItem(
        name="unused_db_vol",
        driver="local",
        size_bytes=500_000_000,
        is_attached_to_running=False,
        is_attached_to_stopped=False,
    )
    # Sample attached volume
    vol_attached = DockerVolumeItem(
        name="live_volume",
        driver="local",
        size_bytes=800_000_000,
        is_attached_to_running=True,
        is_attached_to_stopped=False,
    )
    client.list_volumes.return_value = [vol_unattached, vol_attached]

    # Sample build cache
    client.get_builder_du.return_value = DockerBuildCacheSummary(
        total_bytes=1_500_000_000,
        reclaimable_bytes=1_200_000_000,
        total_records=45,
        in_use_records=5,
    )

    return client


# ---------------------------------------------------------------------------
# Invariant 1: Valid stopped container approval executes
# ---------------------------------------------------------------------------

def test_req01_valid_stopped_container_approval_executes(mock_docker_client, key_manager, mock_audit_repo):
    executor = DockerCleanupExecutor(
        docker_client=mock_docker_client,
        key_manager=key_manager,
        audit_repo=mock_audit_repo,
    )

    plan_item = DockerCleanupPlanItem(
        plan_id="item_cnt_c1234567890a",
        resource_type=DockerResourceType.CONTAINER,
        resource_id="c1234567890a",
        resource_name="test-worker",
        observed_size_bytes=50_000_000,
        requested_action="remove_stopped_container",
        safety_classification=ReclaimConfidence.REVIEW_REQUIRED,
        currently_in_use=False,
    )

    approval = executor.create_approval(item=plan_item, plan_id="dplan_001")

    with patch.object(mock_docker_client, "execute_mutation", return_value=(True, "c1234567890a")) as mock_mut:
        mock_docker_client.list_containers.side_effect = [
            mock_docker_client.list_containers.return_value,
            [c for c in mock_docker_client.list_containers.return_value if c.container_id != "c1234567890a"],
        ]

        result = executor.execute_approved_cleanup(approval)

        assert result.status == DockerExecutionStatus.EXECUTED
        assert result.verified is True
        assert result.reclaimed_bytes == 50_000_000
        mock_mut.assert_called_once_with(["docker", "rm", "c1234567890a"])

    events = mock_audit_repo.get_events_by_approval_id(approval.approval_id)
    assert len(events) >= 1
    assert events[0].event_type == AuditEventType.EXECUTION_SUCCEEDED


# ---------------------------------------------------------------------------
# Invariant 2: Valid unused image approval executes
# ---------------------------------------------------------------------------

def test_req02_valid_unused_image_approval_executes(mock_docker_client, key_manager, mock_audit_repo):
    executor = DockerCleanupExecutor(
        docker_client=mock_docker_client,
        key_manager=key_manager,
        audit_repo=mock_audit_repo,
    )

    plan_item = DockerCleanupPlanItem(
        plan_id="item_img_a1b2c3d4e5f6",
        resource_type=DockerResourceType.IMAGE,
        resource_id="a1b2c3d4e5f6",
        resource_name="old-app:1.0.0",
        observed_size_bytes=200_000_000,
        requested_action="remove_unused_image",
        safety_classification=ReclaimConfidence.REVIEW_REQUIRED,
        currently_in_use=False,
    )

    approval = executor.create_approval(item=plan_item, plan_id="dplan_001")

    with patch.object(mock_docker_client, "execute_mutation", return_value=(True, "Untagged: old-app:1.0.0")) as mock_mut:
        mock_docker_client.list_images.side_effect = [
            mock_docker_client.list_images.return_value,
            [img for img in mock_docker_client.list_images.return_value if img.image_id != "a1b2c3d4e5f6"],
        ]

        result = executor.execute_approved_cleanup(approval)

        assert result.status == DockerExecutionStatus.EXECUTED
        assert result.verified is True
        assert result.reclaimed_bytes == 200_000_000
        mock_mut.assert_called_once_with(["docker", "rmi", "a1b2c3d4e5f6"])


# ---------------------------------------------------------------------------
# Invariant 3: Unattached volume requires high-risk confirmation
# ---------------------------------------------------------------------------

def test_req03_valid_unattached_volume_approval_requires_high_risk_confirmation(mock_docker_client, key_manager, mock_audit_repo):
    executor = DockerCleanupExecutor(
        docker_client=mock_docker_client,
        key_manager=key_manager,
        audit_repo=mock_audit_repo,
    )

    plan_item = DockerCleanupPlanItem(
        plan_id="item_vol_unused_db_vol",
        resource_type=DockerResourceType.VOLUME,
        resource_id="unused_db_vol",
        resource_name="unused_db_vol",
        observed_size_bytes=500_000_000,
        requested_action="remove_unused_volume",
        safety_classification=ReclaimConfidence.REVIEW_REQUIRED,
        currently_in_use=False,
        is_high_risk=True,
    )

    # 3A. Without high_risk_confirmed -> REJECTED
    approval_unconfirmed = executor.create_approval(
        item=plan_item,
        plan_id="dplan_001",
        high_risk_confirmed=False,
    )

    result_unconfirmed = executor.execute_approved_cleanup(approval_unconfirmed)
    assert result_unconfirmed.status == DockerExecutionStatus.REJECTED_HIGH_RISK_NOT_CONFIRMED
    assert result_unconfirmed.verified is False

    # 3B. With high_risk_confirmed=True -> EXECUTES
    approval_confirmed = executor.create_approval(
        item=plan_item,
        plan_id="dplan_001",
        high_risk_confirmed=True,
    )

    with patch.object(mock_docker_client, "execute_mutation", return_value=(True, "unused_db_vol")) as mock_mut:
        mock_docker_client.list_volumes.side_effect = [
            mock_docker_client.list_volumes.return_value,
            [v for v in mock_docker_client.list_volumes.return_value if v.name != "unused_db_vol"],
        ]

        result_confirmed = executor.execute_approved_cleanup(approval_confirmed)
        assert result_confirmed.status == DockerExecutionStatus.EXECUTED
        assert result_confirmed.verified is True
        mock_mut.assert_called_once_with(["docker", "volume", "rm", "unused_db_vol"])


# ---------------------------------------------------------------------------
# Invariant 4: Build cache is REVIEW_ONLY / NOT_EXECUTABLE (fails closed)
# ---------------------------------------------------------------------------

def test_req04_build_cache_is_review_only_and_rejected_from_execution(mock_docker_client, key_manager, mock_audit_repo):
    executor = DockerCleanupExecutor(
        docker_client=mock_docker_client,
        key_manager=key_manager,
        audit_repo=mock_audit_repo,
    )

    plan_item = DockerCleanupPlanItem(
        plan_id="item_bc_buildkit",
        resource_type=DockerResourceType.BUILD_CACHE,
        resource_id="build_cache",
        resource_name="Docker BuildKit Cache",
        observed_size_bytes=1_200_000_000,
        requested_action="prune_build_cache",
        safety_classification=ReclaimConfidence.REVIEW_REQUIRED,
        currently_in_use=False,
    )

    approval = executor.create_approval(item=plan_item, plan_id="dplan_001")

    # Attempted execution must fail closed (REJECTED_PROTECTED / REVIEW_ONLY)
    result = executor.execute_approved_cleanup(approval)
    assert result.status in (DockerExecutionStatus.REJECTED_PROTECTED, DockerExecutionStatus.REJECTED_INVALID_APPROVAL, DockerExecutionStatus.REJECTED_STATE_CHANGED)
    assert result.verified is False
    assert "review_only" in result.error_message.lower() or "not_executable" in result.error_message.lower() or "prohibited" in result.error_message.lower()


# ---------------------------------------------------------------------------
# Invariant 5: Invalid HMAC rejected
# ---------------------------------------------------------------------------

def test_req05_invalid_hmac_rejected(mock_docker_client, key_manager, mock_audit_repo):
    executor = DockerCleanupExecutor(
        docker_client=mock_docker_client,
        key_manager=key_manager,
        audit_repo=mock_audit_repo,
    )

    plan_item = DockerCleanupPlanItem(
        plan_id="item_cnt_c1234567890a",
        resource_type=DockerResourceType.CONTAINER,
        resource_id="c1234567890a",
        resource_name="test-worker",
        observed_size_bytes=50_000_000,
        requested_action="remove_stopped_container",
    )
    approval = executor.create_approval(item=plan_item, plan_id="dplan_001")

    # Tamper with signature
    tampered = DockerCleanupApproval(
        approval_id=approval.approval_id,
        plan_id=approval.plan_id,
        resource_type=approval.resource_type,
        resource_id=approval.resource_id,
        resource_name=approval.resource_name,
        planned_operation=approval.planned_operation,
        planned_bytes=approval.planned_bytes,
        observed_state=approval.observed_state,
        created_at=approval.created_at,
        expires_at=approval.expires_at,
        hmac_signature="bad_signature_00000000000000000000000000000000",
        high_risk_confirmed=approval.high_risk_confirmed,
    )

    result = executor.execute_approved_cleanup(tampered)
    assert result.status == DockerExecutionStatus.REJECTED_INVALID_APPROVAL
    assert result.verified is False


# ---------------------------------------------------------------------------
# Invariant 6: Expired approval rejected
# ---------------------------------------------------------------------------

def test_req06_expired_approval_rejected(mock_docker_client, key_manager, mock_audit_repo):
    executor = DockerCleanupExecutor(
        docker_client=mock_docker_client,
        key_manager=key_manager,
        audit_repo=mock_audit_repo,
    )

    plan_item = DockerCleanupPlanItem(
        plan_id="item_cnt_c1234567890a",
        resource_type=DockerResourceType.CONTAINER,
        resource_id="c1234567890a",
        resource_name="test-worker",
        observed_size_bytes=50_000_000,
        requested_action="remove_stopped_container",
    )

    past_created = (datetime.now(timezone.utc) - timedelta(minutes=20)).isoformat()
    past_expires = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()

    payload = executor._build_canonical_payload(
        approval_id="dappr_expired_001",
        plan_id="dplan_001",
        resource_type=plan_item.resource_type.value,
        resource_id=plan_item.resource_id,
        planned_operation=plan_item.requested_action,
        planned_bytes=plan_item.observed_size_bytes,
        created_at=past_created,
        expires_at=past_expires,
        high_risk_confirmed=False,
    )
    sig = key_manager.sign(payload)

    approval = DockerCleanupApproval(
        approval_id="dappr_expired_001",
        plan_id="dplan_001",
        resource_type=plan_item.resource_type,
        resource_id=plan_item.resource_id,
        resource_name=plan_item.resource_name,
        planned_operation=plan_item.requested_action,
        planned_bytes=plan_item.observed_size_bytes,
        created_at=past_created,
        expires_at=past_expires,
        hmac_signature=sig,
    )

    result = executor.execute_approved_cleanup(approval)
    assert result.status == DockerExecutionStatus.REJECTED_EXPIRED_APPROVAL


# ---------------------------------------------------------------------------
# Invariant 7: Replayed approval rejected
# ---------------------------------------------------------------------------

def test_req07_replayed_approval_rejected(mock_docker_client, key_manager, mock_audit_repo):
    executor = DockerCleanupExecutor(
        docker_client=mock_docker_client,
        key_manager=key_manager,
        audit_repo=mock_audit_repo,
    )

    plan_item = DockerCleanupPlanItem(
        plan_id="item_cnt_c1234567890a",
        resource_type=DockerResourceType.CONTAINER,
        resource_id="c1234567890a",
        resource_name="test-worker",
        observed_size_bytes=50_000_000,
        requested_action="remove_stopped_container",
    )
    approval = executor.create_approval(item=plan_item, plan_id="dplan_001")

    with patch.object(mock_docker_client, "execute_mutation", return_value=(True, "c1234567890a")):
        mock_docker_client.list_containers.side_effect = [
            mock_docker_client.list_containers.return_value,
            [c for c in mock_docker_client.list_containers.return_value if c.container_id != "c1234567890a"],
        ]

        # 1st execution succeeds
        res1 = executor.execute_approved_cleanup(approval)
        assert res1.status == DockerExecutionStatus.EXECUTED

        # 2nd execution (replay) fails
        res2 = executor.execute_approved_cleanup(approval)
        assert res2.status == DockerExecutionStatus.REJECTED_ALREADY_CLAIMED


# ---------------------------------------------------------------------------
# Invariant 8: Already-claimed approval rejected
# ---------------------------------------------------------------------------

def test_req08_already_claimed_approval_rejected(mock_docker_client, key_manager, mock_audit_repo):
    executor = DockerCleanupExecutor(
        docker_client=mock_docker_client,
        key_manager=key_manager,
        audit_repo=mock_audit_repo,
    )

    plan_item = DockerCleanupPlanItem(
        plan_id="item_cnt_c1234567890a",
        resource_type=DockerResourceType.CONTAINER,
        resource_id="c1234567890a",
        resource_name="test-worker",
        observed_size_bytes=50_000_000,
        requested_action="remove_stopped_container",
    )
    approval = executor.create_approval(item=plan_item, plan_id="dplan_001")

    # Manually pre-claim the approval ID
    assert executor.claim_approval(approval.approval_id) is True

    # Execution attempt must be rejected
    result = executor.execute_approved_cleanup(approval)
    assert result.status == DockerExecutionStatus.REJECTED_ALREADY_CLAIMED


# ---------------------------------------------------------------------------
# Invariant 9: Running container protected
# ---------------------------------------------------------------------------

def test_req09_running_container_protected(mock_docker_client, key_manager, mock_audit_repo):
    executor = DockerCleanupExecutor(
        docker_client=mock_docker_client,
        key_manager=key_manager,
        audit_repo=mock_audit_repo,
    )

    plan_item = DockerCleanupPlanItem(
        plan_id="item_cnt_c99988877766",
        resource_type=DockerResourceType.CONTAINER,
        resource_id="c99988877766",
        resource_name="active-web",
        observed_size_bytes=100_000_000,
        requested_action="remove_stopped_container",
    )
    approval = executor.create_approval(item=plan_item, plan_id="dplan_001")

    result = executor.execute_approved_cleanup(approval)
    assert result.status == DockerExecutionStatus.REJECTED_PROTECTED
    assert "running" in result.error_message.lower()


# ---------------------------------------------------------------------------
# Invariant 10: Active image protected
# ---------------------------------------------------------------------------

def test_req10_active_image_protected(mock_docker_client, key_manager, mock_audit_repo):
    executor = DockerCleanupExecutor(
        docker_client=mock_docker_client,
        key_manager=key_manager,
        audit_repo=mock_audit_repo,
    )

    plan_item = DockerCleanupPlanItem(
        plan_id="item_img_999888777666",
        resource_type=DockerResourceType.IMAGE,
        resource_id="999888777666",
        resource_name="web:latest",
        observed_size_bytes=400_000_000,
        requested_action="remove_unused_image",
    )
    approval = executor.create_approval(item=plan_item, plan_id="dplan_001")

    result = executor.execute_approved_cleanup(approval)
    assert result.status == DockerExecutionStatus.REJECTED_PROTECTED
    assert "in use" in result.error_message.lower()


# ---------------------------------------------------------------------------
# Invariant 11: Attached volume protected
# ---------------------------------------------------------------------------

def test_req11_attached_volume_protected(mock_docker_client, key_manager, mock_audit_repo):
    executor = DockerCleanupExecutor(
        docker_client=mock_docker_client,
        key_manager=key_manager,
        audit_repo=mock_audit_repo,
    )

    plan_item = DockerCleanupPlanItem(
        plan_id="item_vol_live_volume",
        resource_type=DockerResourceType.VOLUME,
        resource_id="live_volume",
        resource_name="live_volume",
        observed_size_bytes=800_000_000,
        requested_action="remove_unused_volume",
        is_high_risk=True,
    )
    approval = executor.create_approval(item=plan_item, plan_id="dplan_001", high_risk_confirmed=True)

    result = executor.execute_approved_cleanup(approval)
    assert result.status == DockerExecutionStatus.REJECTED_STATE_CHANGED
    assert "attached" in result.error_message.lower()


# ---------------------------------------------------------------------------
# Invariant 12: Docker.raw cannot be targeted
# ---------------------------------------------------------------------------

def test_req12_docker_raw_cannot_be_targeted():
    ok_raw, err_raw = validate_docker_identifier(DockerResourceType.CONTAINER, "Docker.raw")
    assert ok_raw is False
    assert "virtual disk" in err_raw.lower()

    ok_vdisk, err_vdisk = validate_docker_identifier(DockerResourceType.VIRTUAL_DISK, "vms/0/Docker.raw")
    assert ok_vdisk is False


# ---------------------------------------------------------------------------
# Invariant 13: ~/.docker cannot be targeted
# ---------------------------------------------------------------------------

def test_req13_docker_config_cannot_be_targeted():
    ok_cfg, err_cfg = validate_docker_identifier(DockerResourceType.CONTAINER, ".docker")
    assert ok_cfg is False


# ---------------------------------------------------------------------------
# Invariant 14: Fabricated resource ID rejected
# ---------------------------------------------------------------------------

def test_req14_fabricated_resource_id_rejected():
    ok_traversal, _ = validate_docker_identifier(DockerResourceType.CONTAINER, "../../../etc/passwd")
    assert ok_traversal is False

    ok_injection, _ = validate_docker_identifier(DockerResourceType.CONTAINER, "c12345;rm -rf /")
    assert ok_injection is False

    ok_nonhex, _ = validate_docker_identifier(DockerResourceType.CONTAINER, "invalid_id_not_hex!")
    assert ok_nonhex is False


# ---------------------------------------------------------------------------
# Invariant 15: Resource state changed after approval -> rejected
# ---------------------------------------------------------------------------

def test_req15_resource_state_changed_after_approval_rejected(mock_docker_client, key_manager, mock_audit_repo):
    executor = DockerCleanupExecutor(
        docker_client=mock_docker_client,
        key_manager=key_manager,
        audit_repo=mock_audit_repo,
    )

    plan_item = DockerCleanupPlanItem(
        plan_id="item_cnt_c1234567890a",
        resource_type=DockerResourceType.CONTAINER,
        resource_id="c1234567890a",
        resource_name="test-worker",
        observed_size_bytes=50_000_000,
        requested_action="remove_stopped_container",
    )
    approval = executor.create_approval(item=plan_item, plan_id="dplan_001")

    # Container disappears from runtime before execution
    mock_docker_client.list_containers.return_value = []

    result = executor.execute_approved_cleanup(approval)
    assert result.status == DockerExecutionStatus.REJECTED_STATE_CHANGED
    assert "not found" in result.error_message.lower()


# ---------------------------------------------------------------------------
# Invariant 16: Image becomes active after approval -> rejected
# ---------------------------------------------------------------------------

def test_req16_image_becomes_active_after_approval_rejected(mock_docker_client, key_manager, mock_audit_repo):
    executor = DockerCleanupExecutor(
        docker_client=mock_docker_client,
        key_manager=key_manager,
        audit_repo=mock_audit_repo,
    )

    plan_item = DockerCleanupPlanItem(
        plan_id="item_img_a1b2c3d4e5f6",
        resource_type=DockerResourceType.IMAGE,
        resource_id="a1b2c3d4e5f6",
        resource_name="old-app:1.0.0",
        observed_size_bytes=200_000_000,
        requested_action="remove_unused_image",
    )
    approval = executor.create_approval(item=plan_item, plan_id="dplan_001")

    mock_docker_client.list_images.return_value = [
        DockerImageItem(
            image_id="a1b2c3d4e5f6",
            repository="old-app",
            tag="1.0.0",
            size_bytes=200_000_000,
            created_at="2026-09-01T00:00:00Z",
            in_use_by_running_container=True,
        )
    ]

    result = executor.execute_approved_cleanup(approval)
    assert result.status == DockerExecutionStatus.REJECTED_PROTECTED


# ---------------------------------------------------------------------------
# Invariant 17: Volume becomes attached after approval -> rejected
# ---------------------------------------------------------------------------

def test_req17_volume_becomes_attached_after_approval_rejected(mock_docker_client, key_manager, mock_audit_repo):
    executor = DockerCleanupExecutor(
        docker_client=mock_docker_client,
        key_manager=key_manager,
        audit_repo=mock_audit_repo,
    )

    plan_item = DockerCleanupPlanItem(
        plan_id="item_vol_unused_db_vol",
        resource_type=DockerResourceType.VOLUME,
        resource_id="unused_db_vol",
        resource_name="unused_db_vol",
        observed_size_bytes=500_000_000,
        requested_action="remove_unused_volume",
        is_high_risk=True,
    )
    approval = executor.create_approval(item=plan_item, plan_id="dplan_001", high_risk_confirmed=True)

    mock_docker_client.list_volumes.return_value = [
        DockerVolumeItem(
            name="unused_db_vol",
            driver="local",
            size_bytes=500_000_000,
            is_attached_to_running=True,
        )
    ]

    result = executor.execute_approved_cleanup(approval)
    assert result.status == DockerExecutionStatus.REJECTED_STATE_CHANGED


# ---------------------------------------------------------------------------
# Invariant 18: Docker daemon unavailable -> no execution
# ---------------------------------------------------------------------------

def test_req18_docker_daemon_unavailable_no_execution(mock_docker_client, key_manager, mock_audit_repo):
    mock_docker_client.is_daemon_running.return_value = False

    executor = DockerCleanupExecutor(
        docker_client=mock_docker_client,
        key_manager=key_manager,
        audit_repo=mock_audit_repo,
    )

    plan_item = DockerCleanupPlanItem(
        plan_id="item_cnt_c1234567890a",
        resource_type=DockerResourceType.CONTAINER,
        resource_id="c1234567890a",
        resource_name="test-worker",
        observed_size_bytes=50_000_000,
        requested_action="remove_stopped_container",
    )
    approval = executor.create_approval(item=plan_item, plan_id="dplan_001")

    result = executor.execute_approved_cleanup(approval)
    assert result.status == DockerExecutionStatus.DOCKER_UNAVAILABLE


# ---------------------------------------------------------------------------
# Invariant 19: Docker mutation failure audited
# ---------------------------------------------------------------------------

def test_req19_docker_mutation_failure_audited(mock_docker_client, key_manager, mock_audit_repo):
    executor = DockerCleanupExecutor(
        docker_client=mock_docker_client,
        key_manager=key_manager,
        audit_repo=mock_audit_repo,
    )

    plan_item = DockerCleanupPlanItem(
        plan_id="item_cnt_c1234567890a",
        resource_type=DockerResourceType.CONTAINER,
        resource_id="c1234567890a",
        resource_name="test-worker",
        observed_size_bytes=50_000_000,
        requested_action="remove_stopped_container",
    )
    approval = executor.create_approval(item=plan_item, plan_id="dplan_001")

    with patch.object(mock_docker_client, "execute_mutation", return_value=(False, "Docker error: device or resource busy")):
        result = executor.execute_approved_cleanup(approval)
        assert result.status == DockerExecutionStatus.EXECUTION_FAILED
        assert result.verified is False

    events = mock_audit_repo.get_events_by_approval_id(approval.approval_id)
    assert len(events) >= 1
    assert events[0].event_type == AuditEventType.EXECUTION_FAILED


# ---------------------------------------------------------------------------
# Invariant 20: Verification failure audited
# ---------------------------------------------------------------------------

def test_req20_verification_failure_audited(mock_docker_client, key_manager, mock_audit_repo):
    executor = DockerCleanupExecutor(
        docker_client=mock_docker_client,
        key_manager=key_manager,
        audit_repo=mock_audit_repo,
    )

    plan_item = DockerCleanupPlanItem(
        plan_id="item_cnt_c1234567890a",
        resource_type=DockerResourceType.CONTAINER,
        resource_id="c1234567890a",
        resource_name="test-worker",
        observed_size_bytes=50_000_000,
        requested_action="remove_stopped_container",
    )
    approval = executor.create_approval(item=plan_item, plan_id="dplan_001")

    with patch.object(mock_docker_client, "execute_mutation", return_value=(True, "c1234567890a")):
        result = executor.execute_approved_cleanup(approval)
        assert result.status == DockerExecutionStatus.VERIFICATION_FAILED
        assert result.verified is False

    events = mock_audit_repo.get_events_by_approval_id(approval.approval_id)
    assert len(events) >= 1
    assert events[0].event_type == AuditEventType.EXECUTION_FAILED


# ---------------------------------------------------------------------------
# Invariant 21: No broad prune commands allowed
# ---------------------------------------------------------------------------

def test_req21_no_broad_prune_commands():
    assert ALLOWED_OPERATIONS == {
        "remove_stopped_container",
        "remove_unused_image",
        "remove_unused_volume",
    }
    assert "system_prune" not in ALLOWED_OPERATIONS
    assert "container_prune" not in ALLOWED_OPERATIONS
    assert "image_prune" not in ALLOWED_OPERATIONS
    assert "volume_prune" not in ALLOWED_OPERATIONS
    assert "prune_build_cache" not in ALLOWED_OPERATIONS


# ---------------------------------------------------------------------------
# Invariant 22: AST Check: No shell=True
# ---------------------------------------------------------------------------

def test_req22_ast_check_no_shell_true():
    executor_file = Path("app/execution/docker_cleanup_executor.py")
    assert executor_file.exists()
    tree = ast.parse(executor_file.read_text(encoding="utf-8"))

    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "shell":
            if isinstance(node.value, ast.Constant) and node.value.value is True:
                pytest.fail("Found shell=True in docker_cleanup_executor.py")


# ---------------------------------------------------------------------------
# Invariant 23: AST Check: No sudo
# ---------------------------------------------------------------------------

def test_req23_ast_check_no_sudo():
    executor_file = Path("app/execution/docker_cleanup_executor.py")
    assert executor_file.exists()
    tree = ast.parse(executor_file.read_text(encoding="utf-8"))

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            assert "sudo" not in node.value.lower().split(), f"Found sudo string in code: {node.value}"


# ---------------------------------------------------------------------------
# Invariant 24: AST Check: No arbitrary command execution
# ---------------------------------------------------------------------------

def test_req24_ast_check_no_arbitrary_command_execution():
    executor_file = Path("app/execution/docker_cleanup_executor.py")
    assert executor_file.exists()
    tree = ast.parse(executor_file.read_text(encoding="utf-8"))

    forbidden_calls = {"eval", "exec", "compile", "__import__", "os.system"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in forbidden_calls:
                pytest.fail(f"Found forbidden call: {node.func.id}")


# ---------------------------------------------------------------------------
# Invariant 25: Concurrent execution cannot execute twice
# ---------------------------------------------------------------------------

def test_req25_concurrent_execution_cannot_execute_twice(mock_docker_client, key_manager, mock_audit_repo):
    executor = DockerCleanupExecutor(
        docker_client=mock_docker_client,
        key_manager=key_manager,
        audit_repo=mock_audit_repo,
    )

    plan_item = DockerCleanupPlanItem(
        plan_id="item_cnt_c1234567890a",
        resource_type=DockerResourceType.CONTAINER,
        resource_id="c1234567890a",
        resource_name="test-worker",
        observed_size_bytes=50_000_000,
        requested_action="remove_stopped_container",
    )
    approval = executor.create_approval(item=plan_item, plan_id="dplan_001")

    with patch.object(mock_docker_client, "execute_mutation", return_value=(True, "c1234567890a")):
        mock_docker_client.list_containers.side_effect = [
            mock_docker_client.list_containers.return_value,
            [c for c in mock_docker_client.list_containers.return_value if c.container_id != "c1234567890a"],
        ] * 10

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            futures = [pool.submit(executor.execute_approved_cleanup, approval) for _ in range(5)]
            results = [f.result() for f in futures]

        statuses = [r.status for r in results]
        assert statuses.count(DockerExecutionStatus.EXECUTED) == 1
        assert statuses.count(DockerExecutionStatus.REJECTED_ALREADY_CLAIMED) == 4
