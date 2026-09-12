"""
MacGuard AI Phase 13 — Comprehensive Test Suite for Docker-Aware Storage Investigation.

Validates all 20 Phase 13 requirements:
1. Docker daemon available (test_docker_daemon_available)
2. Docker unavailable (test_docker_unavailable_scenario)
3. Docker command timeout (test_docker_client_timeout_handling)
4. Malformed Docker output (test_docker_client_malformed_json_handling)
5. Running container (PROTECTED) (test_docker_running_and_stopped_resources)
6. Stopped container (REVIEW_REQUIRED) (test_docker_running_and_stopped_resources)
7. Image referenced by running container (PROTECTED) (test_docker_running_and_stopped_resources)
8. Unused image (REVIEW_REQUIRED) (test_docker_running_and_stopped_resources)
9. Dangling image (REVIEW_REQUIRED) (test_docker_running_and_stopped_resources)
10. Active volume (PROTECTED) (test_docker_running_and_stopped_resources)
11. Unused volume (REVIEW_REQUIRED) (test_docker_running_and_stopped_resources)
12. Build cache (REVIEW_REQUIRED) (test_docker_running_and_stopped_resources)
13. Docker.raw protected (PROTECTED, cleanup_allowed=False) (test_docker_raw_always_protected)
14. Correct safety classification (test_docker_safety_classification_matrix)
15. currently_in_use semantics (test_currently_in_use_concrete_evidence_only)
16. Accounting/non-overlap behavior (test_docker_accounting_invariants_and_non_overlap)
17. Ollama cannot introduce executable Docker actions (test_ollama_cannot_introduce_executable_docker_actions)
18. Ollama hallucinated resources are rejected (test_ollama_hallucinated_docker_resources_rejected)
19. No destructive Docker command can be invoked (test_ast_no_mutating_docker_commands_in_app)
20. Overall investigation still works when Docker is unavailable (test_overall_investigation_docker_unavailable)
"""

from __future__ import annotations

import ast
import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.analysis.detectors.docker_detector import DockerDetector
from app.analysis.models import RiskLevel
from app.analysis.storage_investigator import StorageInvestigator
from app.llm.storage_investigator_llm import OllamaStorageInvestigator
from app.models.category import SmartCategory
from app.models.docker_evidence import (
    DockerBuildCacheSummary,
    DockerContainerItem,
    DockerImageItem,
    DockerResourceSummary,
    DockerVolumeItem,
)
from app.models.investigation import (
    CleanupPlan,
    CleanupPlanItem,
    InvestigationLevel,
    ReclaimConfidence,
    StorageEvidenceItem,
    StorageInvestigationEvidence,
)
from app.models.scan_scope import ScanScope, ScopeIdentifier
from app.tools.docker_client import (
    ALLOWED_READONLY_COMMANDS,
    FORBIDDEN_MUTATING_TOKENS,
    DockerClient,
    parse_docker_size_bytes,
)
from app.tools.storage_scanner import DiskUsage, StorageScanner


# ---------------------------------------------------------------------------
# Unit Tests: parse_docker_size_bytes
# ---------------------------------------------------------------------------

def test_parse_docker_size_bytes():
    assert parse_docker_size_bytes("0B") == 0
    assert parse_docker_size_bytes("500B") == 500
    assert parse_docker_size_bytes("1.5KB") == 1500
    assert parse_docker_size_bytes("10MB") == 10_000_000
    assert parse_docker_size_bytes("2.5GB") == 2_500_000_000
    assert parse_docker_size_bytes("1.2GiB") == int(1.2 * 1024 * 1024 * 1024)
    assert parse_docker_size_bytes("invalid") == 0
    assert parse_docker_size_bytes("") == 0


# ---------------------------------------------------------------------------
# Requirement 1: Docker daemon available
# ---------------------------------------------------------------------------

def test_docker_daemon_available():
    client = DockerClient()
    with patch.object(client, "_execute_readonly", return_value=(True, '{"ServerVersion": "24.0.5", "ID": "daemon123"}')):
        assert client.is_daemon_running() is True


# ---------------------------------------------------------------------------
# Requirement 2: Docker unavailable (reports runtime uninspected, not "0 unused")
# ---------------------------------------------------------------------------

def test_docker_unavailable_scenario(tmp_path):
    mock_client = MagicMock(spec=DockerClient)
    mock_client.is_daemon_running.return_value = False
    
    summary = DockerResourceSummary(
        daemon_available=False,
        virtual_disk_bytes=10_000_000_000,
        virtual_disk_path="/fake/Docker.raw",
        status_message="Docker Desktop daemon is stopped or unreachable.",
    )
    mock_client.inspect_all.return_value = (summary, [], [], [], DockerBuildCacheSummary())

    # Ensure runtime counts are None, not 0
    assert summary.total_images_count is None
    assert summary.unused_images_count is None
    assert summary.running_containers_count is None
    assert summary.stopped_containers_count is None

    detector = DockerDetector(docker_client=mock_client)
    scope = ScanScope(scope_id=ScopeIdentifier.HOME, root_path=str(tmp_path), description="Home")
    visited = set()
    
    items = detector.detect(scope, visited)
    assert isinstance(items, list)
    # When daemon is offline, no runtime items (images, containers, volumes, build_cache) are emitted
    runtime_items = [it for it in items if it.subcategory in ("docker_image", "docker_container", "docker_volume", "docker_build_cache")]
    assert len(runtime_items) == 0


# ---------------------------------------------------------------------------
# Requirement 3: Docker command timeout
# ---------------------------------------------------------------------------

def test_docker_client_timeout_handling():
    client = DockerClient(timeout_seconds=0.1)
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["docker", "info"], timeout=0.1)):
        ok, msg = client._execute_readonly(["docker", "info", "--format", "json"])
        assert not ok
        assert "timed out" in msg


# ---------------------------------------------------------------------------
# Requirement 4: Malformed Docker output
# ---------------------------------------------------------------------------

def test_docker_client_malformed_json_handling():
    client = DockerClient()
    
    # Malformed daemon info
    with patch.object(client, "_execute_readonly", return_value=(True, "{corrupt json")):
        assert not client.is_daemon_running()
        
    # Malformed container list
    with patch.object(client, "_execute_readonly", return_value=(True, "{corrupt\nnot json")):
        containers = client.list_containers()
        assert containers == []

    # Malformed image list
    with patch.object(client, "_execute_readonly", return_value=(True, "bad json")):
        images = client.list_images()
        assert images == []


# ---------------------------------------------------------------------------
# Requirements 5–12: Mocked Deterministic Runtime Fixture
# (running & stopped container, active & unused & dangling image, active & unused volume, build cache)
# ---------------------------------------------------------------------------

def test_docker_mocked_runtime_fixture(tmp_path):
    mock_client = MagicMock(spec=DockerClient)
    mock_client.is_daemon_running.return_value = True

    # 1 running container, 1 stopped container
    containers = [
        DockerContainerItem(
            container_id="c_run_123",
            names=["web_app"],
            image="node:18",
            image_id="img_node",
            status="Up 2 hours",
            is_running=True,
            size_bytes=50_000_000,
            created_at="2026-09-01",
            mounts=["db_data"],
        ),
        DockerContainerItem(
            container_id="c_stop_456",
            names=["old_test"],
            image="python:3.11",
            image_id="img_py",
            status="Exited (0) 5 days ago",
            is_running=False,
            size_bytes=20_000_000,
            created_at="2026-08-15",
            mounts=["temp_vol"],
        ),
    ]

    # Images: node:18 (running ref), python:3.11 (stopped ref), unused_img, dangling_img
    images = [
        DockerImageItem(
            image_id="img_node",
            repository="node",
            tag="18",
            size_bytes=900_000_000,
            created_at="2026-08-01",
            is_dangling=False,
            in_use_by_running_container=True,
            in_use_by_stopped_container=False,
        ),
        DockerImageItem(
            image_id="img_py",
            repository="python",
            tag="3.11",
            size_bytes=850_000_000,
            created_at="2026-07-20",
            is_dangling=False,
            in_use_by_running_container=False,
            in_use_by_stopped_container=True,
        ),
        DockerImageItem(
            image_id="img_unused",
            repository="redis",
            tag="7",
            size_bytes=120_000_000,
            created_at="2026-06-10",
            is_dangling=False,
            in_use_by_running_container=False,
            in_use_by_stopped_container=False,
        ),
        DockerImageItem(
            image_id="img_dangling",
            repository="<none>",
            tag="<none>",
            size_bytes=300_000_000,
            created_at="2026-08-10",
            is_dangling=True,
            in_use_by_running_container=False,
            in_use_by_stopped_container=False,
        ),
    ]

    # Volumes: db_data (attached to running), unused_vol (unused)
    volumes = [
        DockerVolumeItem(
            name="db_data",
            driver="local",
            size_bytes=500_000_000,
            is_attached_to_running=True,
            is_attached_to_stopped=False,
        ),
        DockerVolumeItem(
            name="unused_vol",
            driver="local",
            size_bytes=100_000_000,
            is_attached_to_running=False,
            is_attached_to_stopped=False,
        ),
    ]

    # Build cache
    build_cache = DockerBuildCacheSummary(
        total_bytes=1_500_000_000,
        reclaimable_bytes=1_200_000_000,
        total_records=45,
        in_use_records=5,
    )

    summary = DockerResourceSummary(
        daemon_available=True,
        virtual_disk_bytes=10_000_000_000,
        virtual_disk_path="/fake/Docker.raw",
        images_total_bytes=2_170_000_000,
        containers_total_bytes=70_000_000,
        volumes_total_bytes=600_000_000,
        build_cache_total_bytes=1_500_000_000,
        running_containers_count=1,
        stopped_containers_count=1,
        total_images_count=4,
        active_images_count=1,
        unused_images_count=3,
        dangling_images_count=1,
    )

    mock_client.inspect_all.return_value = (summary, images, containers, volumes, build_cache)

    detector = DockerDetector(docker_client=mock_client)
    scope = ScanScope(scope_id=ScopeIdentifier.HOME, root_path=str(tmp_path), description="Home")
    visited = set()

    items = detector.detect(scope, visited)
    items_by_path = {it.path: it for it in items}

    # Req 5: Running container -> PROTECTED & in_use=True
    run_c = items_by_path.get("docker://containers/c_run_123 (web_app)")
    assert run_c is not None
    assert run_c.reclaim_confidence == ReclaimConfidence.PROTECTED
    assert run_c.currently_in_use is True

    # Req 6: Stopped container -> REVIEW_REQUIRED & in_use=False
    stop_c = items_by_path.get("docker://containers/c_stop_456 (old_test)")
    assert stop_c is not None
    assert stop_c.reclaim_confidence == ReclaimConfidence.REVIEW_REQUIRED
    assert stop_c.currently_in_use is False

    # Req 7: Image referenced by running container -> PROTECTED & in_use=True
    img_node = items_by_path.get("docker://images/img_node (node:18)")
    assert img_node is not None
    assert img_node.reclaim_confidence == ReclaimConfidence.PROTECTED
    assert img_node.currently_in_use is True

    # Req 8: Unused image -> REVIEW_REQUIRED & in_use=False
    img_redis = items_by_path.get("docker://images/img_unused (redis:7)")
    assert img_redis is not None
    assert img_redis.reclaim_confidence == ReclaimConfidence.REVIEW_REQUIRED
    assert img_redis.currently_in_use is False

    # Req 9: Dangling image -> REVIEW_REQUIRED
    img_dang = items_by_path.get("docker://images/img_dangling (dangling:img_dangling)")
    assert img_dang is not None
    assert img_dang.reclaim_confidence == ReclaimConfidence.REVIEW_REQUIRED

    # Req 10: Active volume attached to running container -> PROTECTED & in_use=True
    vol_db = items_by_path.get("docker://volumes/db_data")
    assert vol_db is not None
    assert vol_db.reclaim_confidence == ReclaimConfidence.PROTECTED
    assert vol_db.currently_in_use is True

    # Req 11: Unused volume -> REVIEW_REQUIRED & in_use=False
    vol_un = items_by_path.get("docker://volumes/unused_vol")
    assert vol_un is not None
    assert vol_un.reclaim_confidence == ReclaimConfidence.REVIEW_REQUIRED
    assert vol_un.currently_in_use is False

    # Req 12: Build cache -> REVIEW_REQUIRED
    bc = items_by_path.get("docker://build_cache")
    assert bc is not None
    assert bc.reclaim_confidence == ReclaimConfidence.REVIEW_REQUIRED


# ---------------------------------------------------------------------------
# Requirement 13: Docker.raw is ALWAYS protected
# ---------------------------------------------------------------------------

def test_docker_raw_always_protected(tmp_path):
    fake_docker_dir = tmp_path / "Library" / "Containers" / "com.docker.docker" / "Data" / "vms" / "0" / "data"
    fake_docker_dir.mkdir(parents=True)
    fake_raw = fake_docker_dir / "Docker.raw"
    fake_raw.write_bytes(b"0" * (15 * 1024 * 1024))  # 15MB

    with patch("pathlib.Path.home", return_value=tmp_path):
        mock_client = MagicMock(spec=DockerClient)
        mock_client.inspect_all.return_value = (
            DockerResourceSummary(daemon_available=False),
            [],
            [],
            [],
            DockerBuildCacheSummary(),
        )

        detector = DockerDetector(docker_client=mock_client)
        scope = ScanScope(scope_id=ScopeIdentifier.HOME, root_path=str(tmp_path), description="Home")
        visited = set()

        items = detector.detect(scope, visited)
        raw_items = [it for it in items if "Docker.raw" in it.path]
        assert len(raw_items) == 1
        raw_item = raw_items[0]
        assert raw_item.reclaim_confidence == ReclaimConfidence.PROTECTED
        assert raw_item.cleanup_allowed is False
        assert "outside Docker Desktop" in raw_item.cleanup_consequence


# ---------------------------------------------------------------------------
# Requirement 14: Correct safety classification matrix
# ---------------------------------------------------------------------------

def test_docker_safety_classification_matrix(tmp_path):
    mock_client = MagicMock(spec=DockerClient)
    mock_client.is_daemon_running.return_value = True

    containers = [
        DockerContainerItem(container_id="c1", names=["run1"], image="img1", image_id="img1", status="Up", is_running=True, size_bytes=100, created_at="", mounts=[]),
        DockerContainerItem(container_id="c2", names=["stop1"], image="img2", image_id="img2", status="Exited", is_running=False, size_bytes=100, created_at="", mounts=[]),
    ]
    images = [
        DockerImageItem(image_id="img1", repository="img1", tag="latest", size_bytes=1000, created_at="", is_dangling=False, in_use_by_running_container=True),
        DockerImageItem(image_id="img2", repository="img2", tag="latest", size_bytes=1000, created_at="", is_dangling=False, in_use_by_running_container=False, in_use_by_stopped_container=True),
        DockerImageItem(image_id="img3", repository="<none>", tag="<none>", size_bytes=500, created_at="", is_dangling=True, in_use_by_running_container=False),
    ]
    volumes = [
        DockerVolumeItem(name="v_run", driver="local", size_bytes=200, is_attached_to_running=True),
        DockerVolumeItem(name="v_stop", driver="local", size_bytes=200, is_attached_to_running=False, is_attached_to_stopped=True),
    ]
    bc = DockerBuildCacheSummary(total_bytes=300, reclaimable_bytes=300, total_records=1, in_use_records=0)
    summary = DockerResourceSummary(daemon_available=True)

    mock_client.inspect_all.return_value = (summary, images, containers, volumes, bc)

    detector = DockerDetector(docker_client=mock_client)
    scope = ScanScope(scope_id=ScopeIdentifier.HOME, root_path=str(tmp_path), description="Home")
    items = detector.detect(scope, set())

    for it in items:
        # Phase 13 Invariant: No HIGH_CONFIDENCE for any Docker items
        assert it.reclaim_confidence != ReclaimConfidence.HIGH_CONFIDENCE
        assert it.cleanup_allowed is False
        assert it.reclaim_confidence in (ReclaimConfidence.PROTECTED, ReclaimConfidence.REVIEW_REQUIRED)


# ---------------------------------------------------------------------------
# Requirement 15: currently_in_use semantics (concrete evidence only)
# ---------------------------------------------------------------------------

def test_currently_in_use_concrete_evidence_only(tmp_path):
    mock_client = MagicMock(spec=DockerClient)
    mock_client.is_daemon_running.return_value = True

    # Stopped container, unused image, unattached volume
    containers = [DockerContainerItem(container_id="c_stop", names=["stopped_c"], image="img_unused", image_id="img_unused", status="Exited", is_running=False, size_bytes=100, created_at="", mounts=[])]
    images = [DockerImageItem(image_id="img_unused", repository="test", tag="1.0", size_bytes=100, created_at="", in_use_by_running_container=False)]
    volumes = [DockerVolumeItem(name="vol_unused", driver="local", size_bytes=100, is_attached_to_running=False)]
    summary = DockerResourceSummary(daemon_available=True)

    mock_client.inspect_all.return_value = (summary, images, containers, volumes, DockerBuildCacheSummary())

    detector = DockerDetector(docker_client=mock_client)
    scope = ScanScope(scope_id=ScopeIdentifier.HOME, root_path=str(tmp_path), description="Home")
    items = detector.detect(scope, set())

    for it in items:
        # Unused / stopped items must NOT be inferred as currently_in_use
        assert it.currently_in_use is False


# ---------------------------------------------------------------------------
# Requirement 16: Accounting / Non-overlap behavior (separating virtual disk, cli config, runtime)
# ---------------------------------------------------------------------------

def test_docker_accounting_invariants_and_non_overlap(tmp_path):
    fake_docker_dir = tmp_path / "Library" / "Containers" / "com.docker.docker" / "Data" / "vms" / "0" / "data"
    fake_docker_dir.mkdir(parents=True)
    fake_raw = fake_docker_dir / "Docker.raw"
    fake_raw.write_bytes(b"0" * (20 * 1024 * 1024))  # 20MB

    fake_cli_dir = tmp_path / ".docker"
    fake_cli_dir.mkdir(parents=True)
    (fake_cli_dir / "config.json").write_bytes(b"0" * (11 * 1024 * 1024))  # 11MB

    mock_client = MagicMock(spec=DockerClient)
    mock_client.is_daemon_running.return_value = True

    containers = [
        DockerContainerItem(container_id="c1", names=["stopped_web"], image="img1", image_id="img1", status="Exited", is_running=False, size_bytes=5 * 1024 * 1024, created_at="", mounts=[]),
    ]
    images = [
        DockerImageItem(image_id="img1", repository="myrepo", tag="v1", size_bytes=10 * 1024 * 1024, created_at="", in_use_by_running_container=False),
    ]
    summary = DockerResourceSummary(
        daemon_available=True,
        virtual_disk_bytes=20 * 1024 * 1024,
        images_total_bytes=10 * 1024 * 1024,
        containers_total_bytes=5 * 1024 * 1024,
    )
    mock_client.inspect_all.return_value = (summary, images, containers, [], DockerBuildCacheSummary())

    with patch("pathlib.Path.home", return_value=tmp_path):
        detector = DockerDetector(docker_client=mock_client)
        scope = ScanScope(scope_id=ScopeIdentifier.HOME, root_path=str(tmp_path), description="Home")
        items = detector.detect(scope, set())

        # Check subcategories
        subcats = [it.subcategory for it in items]
        assert "docker_virtual_disk" in subcats
        assert "docker_cli_config" in subcats
        assert "docker_container" in subcats
        assert "docker_image" in subcats

        # Verify separation of categories:
        # docker_virtual_disk -> CONTAINERS
        # docker_cli_config -> DEVELOPER
        vdisk_items = [it for it in items if it.subcategory == "docker_virtual_disk"]
        cli_items = [it for it in items if it.subcategory == "docker_cli_config"]
        assert len(vdisk_items) == 1
        assert vdisk_items[0].category == SmartCategory.CONTAINERS
        assert len(cli_items) == 1
        assert cli_items[0].category == SmartCategory.DEVELOPER_DATA


# ---------------------------------------------------------------------------
# Requirement 17: Ollama cannot introduce executable Docker actions
# ---------------------------------------------------------------------------

def test_ollama_cannot_introduce_executable_docker_actions():
    inv_llm = OllamaStorageInvestigator()
    
    docker_item = StorageEvidenceItem(
        evidence_id="ev_docker_001",
        path="docker://images/img123 (node:18)",
        canonical_path="docker://images/img123 (node:18)",
        size_bytes=500_000_000,
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
    )

    evidence = StorageInvestigationEvidence(
        investigation_id="inv_test_001",
        target_path="/Users/test",
        level=InvestigationLevel.TARGETED,
        disk_total_bytes=500_000_000_000,
        disk_used_bytes=300_000_000_000,
        disk_free_bytes=200_000_000_000,
        analyzed_bytes=500_000_000,
        candidate_inventory_bytes=500_000_000,
        eligible_for_review_bytes=500_000_000,
        reclaimable_high_confidence_bytes=0,
        reclaimable_review_required_bytes=500_000_000,
        protected_bytes=0,
        top_consumers=[docker_item],
        items=[docker_item],
    )
    cleanup_plan = CleanupPlan(
        high_confidence_items=[],
        review_required_items=[
            CleanupPlanItem(
                evidence_id=docker_item.evidence_id,
                path=docker_item.path,
                canonical_path=docker_item.canonical_path,
                size_bytes=docker_item.size_bytes,
                category=docker_item.category,
                subcategory=docker_item.subcategory,
                tier=docker_item.reclaim_confidence,
                requires_review=True,
            )
        ],
        total_reclaimable_bytes=0,
        high_confidence_bytes=0,
        review_required_bytes=500_000_000,
    )

    res = inv_llm.investigate_deterministic(evidence, cleanup_plan)
    assert res.cleanup_plan.total_reclaimable_bytes == 0
    assert all(it.requires_review for it in res.cleanup_plan.review_required_items)


# ---------------------------------------------------------------------------
# Requirement 18: Ollama hallucinated resources are rejected
# ---------------------------------------------------------------------------

def test_ollama_hallucinated_docker_resources_rejected():
    inv_llm = OllamaStorageInvestigator()
    
    mock_llm_json = {
        "summary_text": "Docker storage is large.",
        "severity": "WARNING",
        "reasoning_notes": ["Docker data found."],
        "findings": [
            {
                "evidence_id": "ev_nonexistent_999",
                "why_it_exists": "Hallucinated item",
                "why_safe_or_unsafe": "Safe",
                "consequence": "None",
                "recommended_priority": 1,
            }
        ],
    }

    evidence = StorageInvestigationEvidence(
        investigation_id="inv_test_002",
        target_path="/Users/test",
        level=InvestigationLevel.TARGETED,
        disk_total_bytes=500_000_000_000,
        disk_used_bytes=300_000_000_000,
        disk_free_bytes=200_000_000_000,
        analyzed_bytes=0,
        candidate_inventory_bytes=0,
        eligible_for_review_bytes=0,
        reclaimable_high_confidence_bytes=0,
        reclaimable_review_required_bytes=0,
        protected_bytes=0,
        top_consumers=[],
        items=[],
    )
    cleanup_plan = CleanupPlan(
        high_confidence_items=[],
        review_required_items=[],
        total_reclaimable_bytes=0,
        high_confidence_bytes=0,
        review_required_bytes=0,
    )

    with patch.object(inv_llm.client, "generate", return_value=json.dumps(mock_llm_json)):
        res = inv_llm.investigate(evidence, cleanup_plan, fallback_to_deterministic=False)
        assert res.evidence.total_reclaimable_bytes == 0
        assert len(res.cleanup_plan.high_confidence_items) == 0
        assert len(res.cleanup_plan.review_required_items) == 0
        assert len(res.llm_findings) == 0


# ---------------------------------------------------------------------------
# Requirement 19: No destructive Docker commands can be invoked (AST & Whitelist)
# ---------------------------------------------------------------------------

def test_docker_client_rejects_mutating_commands():
    client = DockerClient()
    mutating_cmds = [
        ["docker", "system", "prune"],
        ["docker", "image", "prune", "-a"],
        ["docker", "rm", "c123"],
        ["docker", "rmi", "img123"],
        ["docker", "volume", "rm", "vol1"],
        ["docker", "builder", "prune"],
        ["docker", "kill", "c123"],
        ["docker", "stop", "c123"],
        ["docker", "run", "ubuntu"],
        ["docker", "exec", "c123", "sh"],
    ]
    for cmd in mutating_cmds:
        ok, msg = client._execute_readonly(cmd)
        assert not ok
        assert "Prohibited" in msg or "not in read-only whitelist" in msg


def test_ast_no_shell_true_in_docker_client():
    client_file = Path("app/tools/docker_client.py")
    assert client_file.exists()
    tree = ast.parse(client_file.read_text(encoding="utf-8"))

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "shell":
                    if isinstance(kw.value, ast.Constant):
                        assert kw.value.value is False, "shell=True is strictly forbidden in DockerClient"


def test_ast_no_mutating_docker_commands_in_app():
    app_dir = Path("app")
    mutating_words = {"prune", "rmi", "rm", "kill", "system-prune"}
    
    for py_file in app_dir.rglob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                elif isinstance(node.func, ast.Name):
                    func_name = node.func.id
                
                if func_name in ("run", "Popen", "check_output", "call"):
                    for arg in node.args:
                        if isinstance(arg, ast.List):
                            str_elts = [elt.value for elt in arg.elts if isinstance(elt, ast.Constant) and isinstance(elt.value, str)]
                            if str_elts and str_elts[0] == "docker":
                                for token in str_elts[1:]:
                                    assert token not in mutating_words, f"Found forbidden mutating command {token} in {py_file}"


# ---------------------------------------------------------------------------
# Requirement 20: Overall investigation still works when Docker is unavailable
# ---------------------------------------------------------------------------

def test_overall_investigation_docker_unavailable(tmp_path):
    mock_scanner = MagicMock(spec=StorageScanner)
    mock_scanner.get_disk_usage.return_value = DiskUsage(
        path=str(tmp_path),
        total_bytes=500_000_000_000,
        used_bytes=300_000_000_000,
        free_bytes=200_000_000_000,
    )

    investigator = StorageInvestigator(scanner=mock_scanner)
    scope = ScanScope(scope_id=ScopeIdentifier.HOME, root_path=str(tmp_path), description="Home")

    with patch("app.tools.docker_client.DockerClient.is_daemon_running", return_value=False):
        evidence, plan = investigator.investigate(scope=scope, level=InvestigationLevel.TARGETED)
        assert evidence.level == InvestigationLevel.TARGETED
        assert evidence.disk_free_bytes == 200_000_000_000
        assert isinstance(evidence.items, list)
        assert isinstance(plan.high_confidence_items, list)
