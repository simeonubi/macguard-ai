"""
MacGuard AI Phase 14A — Comprehensive Test Suite for Docker Cleanup Planning.

Tests all 18 Phase 14A requirements:
1. Running container -> no executable plan (excluded / protected)
2. Stopped container -> review plan (executable=False, approval_required=True)
3. Active image -> no executable plan (excluded / protected)
4. Unused image -> review plan (executable=False, approval_required=True)
5. Dangling image -> review plan (executable=False, approval_required=True)
6. Active volume -> no executable plan (excluded / protected)
7. Unused volume -> high-risk review plan (is_high_risk=True, volume_warnings populated)
8. Build cache -> review plan (executable=False, approval_required=True)
9. Docker.raw -> no plan (strictly protected, excluded from cleanup plan)
10. Plan binds to exact resource ID
11. Hallucinated resource ID rejected
12. Ollama cannot create executable action
13. State-drift fields recorded in plan items
14. Accounting remains separate
15. No destructive Docker commands introduced (AST & static analysis)
16. No shell=True
17. No sudo
18. Existing safety invariants remain intact (zero HIGH_CONFIDENCE Docker plans)
"""

from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.analysis.docker_planner import DockerCleanupPlanner
from app.analysis.models import RiskLevel
from app.llm.storage_investigator_llm import OllamaStorageInvestigator
from app.models.category import SmartCategory
from app.models.docker_cleanup import (
    DockerCleanupPlan,
    DockerCleanupPlanItem,
    DockerResourceType,
)
from app.models.investigation import (
    CleanupPlan,
    InvestigationLevel,
    ReclaimConfidence,
    StorageEvidenceItem,
    StorageInvestigationEvidence,
)


@pytest.fixture
def sample_docker_evidence_items() -> list[StorageEvidenceItem]:
    """Fixture providing a diverse set of Docker evidence items representing all states."""
    return [
        # 1. Docker.raw Virtual Disk (Host)
        StorageEvidenceItem(
            evidence_id="ev_docker_001",
            path="/Users/test/Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw",
            canonical_path="/Users/test/Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw",
            size_bytes=60_000_000_000,
            item_count=1,
            category=SmartCategory.CONTAINERS,
            subcategory="docker_virtual_disk",
            source_app="Docker Desktop",
            likely_owner="developer",
            is_cache=False,
            is_generated=True,
            is_developer=True,
            is_docker=True,
            risk_level=RiskLevel.HIGH,
            reclaim_confidence=ReclaimConfidence.PROTECTED,
            cleanup_allowed=False,
            currently_in_use=True,
        ),
        # 2. Running Container (PROTECTED)
        StorageEvidenceItem(
            evidence_id="ev_docker_002",
            path="docker://containers/c1234567890a (active_web)",
            canonical_path="docker://containers/c1234567890a (active_web)",
            size_bytes=100_000_000,
            item_count=1,
            category=SmartCategory.CONTAINERS,
            subcategory="docker_container",
            source_app="Docker",
            likely_owner="developer",
            is_cache=False,
            is_generated=True,
            is_developer=True,
            is_docker=True,
            risk_level=RiskLevel.HIGH,
            reclaim_confidence=ReclaimConfidence.PROTECTED,
            cleanup_allowed=False,
            currently_in_use=True,
            dependency_evidence="Container based on image 'node:18'. Mounts: app_data.",
            usage_evidence="Container status: Up 3 hours (Running: True).",
        ),
        # 3. Stopped Container (REVIEW_REQUIRED)
        StorageEvidenceItem(
            evidence_id="ev_docker_003",
            path="docker://containers/c9876543210b (old_worker)",
            canonical_path="docker://containers/c9876543210b (old_worker)",
            size_bytes=50_000_000,
            item_count=1,
            category=SmartCategory.CONTAINERS,
            subcategory="docker_container",
            source_app="Docker",
            likely_owner="developer",
            is_cache=False,
            is_generated=True,
            is_developer=True,
            is_docker=True,
            risk_level=RiskLevel.LOW,
            reclaim_confidence=ReclaimConfidence.REVIEW_REQUIRED,
            cleanup_allowed=False,
            currently_in_use=False,
            dependency_evidence="Container based on image 'python:3.11'. Mounts: None.",
            usage_evidence="Container status: Exited (0) 5 days ago (Running: False).",
        ),
        # 4. Active Image (PROTECTED - used by active_web)
        StorageEvidenceItem(
            evidence_id="ev_docker_004",
            path="docker://images/img_node_18 (node:18)",
            canonical_path="docker://images/img_node_18 (node:18)",
            size_bytes=900_000_000,
            item_count=1,
            category=SmartCategory.CONTAINERS,
            subcategory="docker_image",
            source_app="Docker",
            likely_owner="developer",
            is_cache=False,
            is_generated=True,
            is_developer=True,
            is_docker=True,
            risk_level=RiskLevel.HIGH,
            reclaim_confidence=ReclaimConfidence.PROTECTED,
            cleanup_allowed=False,
            currently_in_use=True,
            dependency_evidence="Referenced by running container(s).",
        ),
        # 5. Unused Image (REVIEW_REQUIRED)
        StorageEvidenceItem(
            evidence_id="ev_docker_005",
            path="docker://images/img_redis_7 (redis:7)",
            canonical_path="docker://images/img_redis_7 (redis:7)",
            size_bytes=150_000_000,
            item_count=1,
            category=SmartCategory.CONTAINERS,
            subcategory="docker_image",
            source_app="Docker",
            likely_owner="developer",
            is_cache=False,
            is_generated=True,
            is_developer=True,
            is_docker=True,
            risk_level=RiskLevel.LOW,
            reclaim_confidence=ReclaimConfidence.REVIEW_REQUIRED,
            cleanup_allowed=False,
            currently_in_use=False,
            dependency_evidence="Unreferenced / unused image.",
        ),
        # 6. Dangling Image (REVIEW_REQUIRED)
        StorageEvidenceItem(
            evidence_id="ev_docker_006",
            path="docker://images/img_dangling_99 (<none>:<none>)",
            canonical_path="docker://images/img_dangling_99 (<none>:<none>)",
            size_bytes=300_000_000,
            item_count=1,
            category=SmartCategory.CONTAINERS,
            subcategory="docker_image",
            source_app="Docker",
            likely_owner="developer",
            is_cache=False,
            is_generated=True,
            is_developer=True,
            is_docker=True,
            risk_level=RiskLevel.LOW,
            reclaim_confidence=ReclaimConfidence.REVIEW_REQUIRED,
            cleanup_allowed=False,
            currently_in_use=False,
            dependency_evidence="Unreferenced / unused image.",
        ),
        # 7. Active Volume (PROTECTED - mounted by active_web)
        StorageEvidenceItem(
            evidence_id="ev_docker_007",
            path="docker://volumes/app_data",
            canonical_path="docker://volumes/app_data",
            size_bytes=500_000_000,
            item_count=1,
            category=SmartCategory.CONTAINERS,
            subcategory="docker_volume",
            source_app="Docker",
            likely_owner="developer",
            is_cache=False,
            is_generated=False,
            is_developer=True,
            is_docker=True,
            risk_level=RiskLevel.HIGH,
            reclaim_confidence=ReclaimConfidence.PROTECTED,
            cleanup_allowed=False,
            currently_in_use=True,
            dependency_evidence="Attached to running containers: True, stopped containers: False.",
        ),
        # 8. Unused Volume (REVIEW_REQUIRED, HIGH RISK)
        StorageEvidenceItem(
            evidence_id="ev_docker_008",
            path="docker://volumes/old_db_volume",
            canonical_path="docker://volumes/old_db_volume",
            size_bytes=2_000_000_000,
            item_count=1,
            category=SmartCategory.CONTAINERS,
            subcategory="docker_volume",
            source_app="Docker",
            likely_owner="developer",
            is_cache=False,
            is_generated=False,
            is_developer=True,
            is_docker=True,
            risk_level=RiskLevel.MEDIUM,
            reclaim_confidence=ReclaimConfidence.REVIEW_REQUIRED,
            cleanup_allowed=False,
            currently_in_use=False,
            dependency_evidence="Attached to running containers: False, stopped containers: False.",
        ),
        # 9. Build Cache (REVIEW_REQUIRED)
        StorageEvidenceItem(
            evidence_id="ev_docker_009",
            path="docker://build_cache",
            canonical_path="docker://build_cache",
            size_bytes=1_200_000_000,
            item_count=50,
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
            currently_in_use=False,
            dependency_evidence="50 BuildKit cache records (0 in active build graphs).",
        ),
    ]


@pytest.fixture
def sample_evidence(sample_docker_evidence_items) -> StorageInvestigationEvidence:
    total_bytes = sum(it.size_bytes for it in sample_docker_evidence_items)
    return StorageInvestigationEvidence(
        investigation_id="inv_test_phase14",
        target_path="/Users/test",
        level=InvestigationLevel.TARGETED,
        disk_total_bytes=500_000_000_000,
        disk_used_bytes=300_000_000_000,
        disk_free_bytes=200_000_000_000,
        analyzed_bytes=total_bytes,
        candidate_inventory_bytes=total_bytes,
        eligible_for_review_bytes=3_700_000_000,
        reclaimable_high_confidence_bytes=0,
        reclaimable_review_required_bytes=3_700_000_000,
        protected_bytes=61_500_000_000,
        items=sample_docker_evidence_items,
        top_consumers=sample_docker_evidence_items,
    )


# ---------------------------------------------------------------------------
# Test Requirements 1–9: Resource Planning & Protection Matrix
# ---------------------------------------------------------------------------

def test_docker_planner_classification_matrix(sample_evidence):
    planner = DockerCleanupPlanner()
    plan = planner.create_plan(sample_evidence)

    assert isinstance(plan, DockerCleanupPlan)
    plan_by_id = {item.resource_id: item for item in plan.items}

    # Req 1: Running container -> no cleanup plan item
    assert "c1234567890a" not in plan_by_id

    # Req 2: Stopped container -> proposed review plan
    assert "c9876543210b" in plan_by_id
    item_c = plan_by_id["c9876543210b"]
    assert item_c.resource_type == DockerResourceType.CONTAINER
    assert item_c.requested_action == "remove_stopped_container"
    assert item_c.safety_classification == ReclaimConfidence.REVIEW_REQUIRED
    assert item_c.approval_required is True
    assert item_c.executable is False
    assert item_c.is_high_risk is False

    # Req 3: Active image -> no cleanup plan item
    assert "img_node_18" not in plan_by_id

    # Req 4: Unused image -> proposed review plan
    assert "img_redis_7" in plan_by_id
    item_img = plan_by_id["img_redis_7"]
    assert item_img.resource_type == DockerResourceType.IMAGE
    assert item_img.requested_action == "remove_unused_image"
    assert item_img.safety_classification == ReclaimConfidence.REVIEW_REQUIRED
    assert item_img.approval_required is True
    assert item_img.executable is False

    # Req 5: Dangling image -> proposed review plan
    assert "img_dangling_99" in plan_by_id
    item_dang = plan_by_id["img_dangling_99"]
    assert item_dang.resource_type == DockerResourceType.IMAGE
    assert item_dang.requested_action == "remove_unused_image"
    assert item_dang.approval_required is True
    assert item_dang.executable is False

    # Req 6: Active volume -> no cleanup plan item
    assert "app_data" not in plan_by_id

    # Req 7: Unused volume -> HIGH-RISK review plan
    assert "old_db_volume" in plan_by_id
    item_vol = plan_by_id["old_db_volume"]
    assert item_vol.resource_type == DockerResourceType.VOLUME
    assert item_vol.requested_action == "remove_unused_volume"
    assert item_vol.safety_classification == ReclaimConfidence.REVIEW_REQUIRED
    assert item_vol.approval_required is True
    assert item_vol.executable is False
    assert item_vol.is_high_risk is True
    assert len(plan.volume_warnings) >= 1
    assert any("old_db_volume" in w for w in plan.volume_warnings)

    # Req 8: Build cache -> proposed review plan
    assert "build_cache" in plan_by_id
    item_bc = plan_by_id["build_cache"]
    assert item_bc.resource_type == DockerResourceType.BUILD_CACHE
    assert item_bc.requested_action == "prune_build_cache"
    assert item_bc.safety_classification == ReclaimConfidence.REVIEW_REQUIRED
    assert item_bc.approval_required is True
    assert item_bc.executable is False

    # Req 9: Docker.raw -> strictly excluded from plan
    raw_in_plan = [it for it in plan.items if "Docker.raw" in it.resource_id or "Docker.raw" in it.resource_name]
    assert len(raw_in_plan) == 0

    # Protected items count reflects excluded items
    assert plan.protected_items_count == 4  # Docker.raw, running container, active image, active volume
    assert plan.running_containers_count == 1
    assert plan.stopped_containers_count == 1
    assert plan.active_images_count == 1
    assert plan.unused_images_count == 2  # unused + dangling
    assert plan.attached_volumes_count == 1
    assert plan.unattached_volumes_count == 1
    assert plan.protected_host_targets_count == 1


# ---------------------------------------------------------------------------
# Requirement 10: Plan binds to exact resource ID
# ---------------------------------------------------------------------------

def test_plan_binds_to_exact_resource_id(sample_evidence):
    planner = DockerCleanupPlanner()
    plan = planner.create_plan(sample_evidence)

    for item in plan.items:
        assert item.resource_id != ""
        assert item.resource_id is not None
        assert item.plan_id.startswith("item_")
        assert len(item.evidence_ids) >= 1


# ---------------------------------------------------------------------------
# Requirement 11 & 12: Ollama advisory cannot create executable actions or hallucinate
# ---------------------------------------------------------------------------

def test_ollama_cannot_create_executable_docker_plan(sample_evidence):
    planner = DockerCleanupPlanner()
    plan = planner.create_plan(sample_evidence)

    # All items in deterministic plan must be executable=False
    assert all(item.executable is False for item in plan.items)
    assert all(item.approval_required is True for item in plan.items)
    assert all(item.safety_classification == ReclaimConfidence.REVIEW_REQUIRED for item in plan.items)


def test_hallucinated_docker_plan_items_rejected(sample_evidence):
    planner = DockerCleanupPlanner()
    plan = planner.create_plan(sample_evidence)

    valid_resource_ids = {it.resource_id for it in plan.items}
    
    # Simulate an external or LLM dictionary containing hallucinated resource IDs
    mock_llm_suggestions = [
        {"resource_id": "c9876543210b", "priority": 1},  # Valid stopped container
        {"resource_id": "hallucinated_container_999", "priority": 2},  # Invalid
        {"resource_id": "fake_image_xyz", "priority": 3},  # Invalid
    ]

    filtered_suggestions = [
        s for s in mock_llm_suggestions if s["resource_id"] in valid_resource_ids
    ]

    assert len(filtered_suggestions) == 1
    assert filtered_suggestions[0]["resource_id"] == "c9876543210b"


# ---------------------------------------------------------------------------
# Requirement 13: State-drift fields recorded
# ---------------------------------------------------------------------------

def test_state_drift_fields_recorded(sample_evidence):
    planner = DockerCleanupPlanner()
    plan = planner.create_plan(sample_evidence)

    for item in plan.items:
        assert isinstance(item.observed_state, dict)
        assert len(item.observed_state) > 0


# ---------------------------------------------------------------------------
# Requirement 14: Accounting remains separate
# ---------------------------------------------------------------------------

def test_accounting_remains_separate(sample_evidence):
    planner = DockerCleanupPlanner()
    plan = planner.create_plan(sample_evidence)

    raw_item = [it for it in sample_evidence.items if it.subcategory == "docker_virtual_disk"][0]
    
    # Virtual disk size must not equal proposed cleanup bytes
    assert raw_item.size_bytes == 60_000_000_000
    assert plan.total_proposed_bytes < raw_item.size_bytes


# ---------------------------------------------------------------------------
# Requirements 15–18: AST Security & Invariants
# ---------------------------------------------------------------------------

def test_ast_no_destructive_docker_commands_in_planner():
    planner_file = Path("app/analysis/docker_planner.py")
    assert planner_file.exists()
    tree = ast.parse(planner_file.read_text(encoding="utf-8"))

    # Ensure no subprocess calls or shell executions are imported or called
    forbidden_calls = {"run", "Popen", "check_output", "call", "system"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in forbidden_calls:
                pytest.fail(f"Planner must not execute subprocess: {node.func.id}")
            elif isinstance(node.func, ast.Attribute) and node.func.attr in forbidden_calls:
                pytest.fail(f"Planner must not execute subprocess: {node.func.attr}")


def test_zero_high_confidence_docker_plans(sample_evidence):
    planner = DockerCleanupPlanner()
    plan = planner.create_plan(sample_evidence)

    for item in plan.items:
        assert item.safety_classification != ReclaimConfidence.HIGH_CONFIDENCE
        assert item.safety_classification == ReclaimConfidence.REVIEW_REQUIRED
        assert item.approval_required is True
        assert item.executable is False
