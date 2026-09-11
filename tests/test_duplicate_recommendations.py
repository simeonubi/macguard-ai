"""
MacGuard AI v1.1 — Phase 7 Duplicate Recommendation Integration Tests.

Comprehensive test suite verifying:
- Deterministic duplicate evidence integration with RecommendationEngine
- Strict preservation of safety invariants, risk ratings, and human review boundaries
- Precise APFS hardlink vs independent physical duplicate storage accounting
- Zero mutation, zero approval bypass, zero execution capabilities
"""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
from typing import List, Optional
import pytest

from app.agent.tools import AgentToolRegistry
from app.analysis.models import RiskLevel, StorageCandidate, StorageCategory
from app.analysis.recommendations import (
    RecommendationAction,
    RecommendationEngine,
    SafetyStatus,
    StorageRecommendation,
)
from app.models.duplicate import DuplicateCluster, DuplicateFile
from app.models.duplicate_recommendation import DuplicateRecommendationContext


def _make_candidate(
    path: str = "/Users/test/Library/Caches/sample.cache",
    size_bytes: int = 10 * 1024 * 1024,  # 10 MB
    category: StorageCategory = StorageCategory.CACHE,
    risk_level: RiskLevel = RiskLevel.LOW,
    confidence: float = 0.95,
) -> StorageCandidate:
    return StorageCandidate(
        path=path,
        size_bytes=size_bytes,
        category=category,
        risk_level=risk_level,
        confidence=confidence,
        reason="Cache item for test",
        recommendation="Eligible for review",
        item_type="file",
    )


def _make_cluster(
    cluster_id: str,
    file_paths: List[str],
    size_bytes: int = 10 * 1024 * 1024,
    inodes: Optional[List[int]] = None,
    sha256: str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
) -> DuplicateCluster:
    files = []
    if inodes is None:
        # Default to distinct inodes (independent physical copies)
        inodes = [1000 + i for i in range(len(file_paths))]

    for p, ino in zip(file_paths, inodes):
        files.append(
            DuplicateFile(
                path=p,
                size_bytes=size_bytes,
                dev=16777220,
                inode=ino,
                full_sha256=sha256,
            )
        )

    # Compute wasted bytes based on distinct inodes
    distinct_inodes = len(set(inodes))
    wasted = (distinct_inodes - 1) * size_bytes if distinct_inodes > 1 else 0
    hardlinks = len(file_paths) - distinct_inodes

    return DuplicateCluster(
        cluster_id=cluster_id,
        file_size_bytes=size_bytes,
        files=files,
        wasted_bytes=wasted,
        hardlink_count=hardlinks,
    )


class TestDuplicateRecommendationBasics:
    """Test fundamental duplicate recommendation context generation."""

    def test_genuine_duplicate_produces_contextual_evidence(self):
        cand = _make_candidate("/Users/test/Library/Caches/copy1.cache", size_bytes=10_000_000)
        cluster = _make_cluster(
            "cluster_1",
            ["/Users/test/Library/Caches/copy1.cache", "/Users/test/Downloads/copy2.cache"],
            size_bytes=10_000_000,
            inodes=[1001, 1002],
        )

        engine = RecommendationEngine()
        rec = engine.recommend(cand, duplicate_clusters=[cluster])

        assert rec.duplicate_context is not None
        assert rec.duplicate_context.cluster_id == "cluster_1"
        assert rec.duplicate_context.file_size_bytes == 10_000_000
        assert rec.duplicate_context.duplicate_file_count == 2
        assert rec.duplicate_context.physical_inode_count == 2
        assert rec.duplicate_context.hardlink_count == 0
        assert rec.duplicate_context.wasted_bytes == 10_000_000
        assert rec.duplicate_context.is_hardlink_only is False
        assert rec.duplicate_context.duplicate_paths == ["/Users/test/Downloads/copy2.cache"]
        assert "potential reclaimable space" in rec.duplicate_context.explanation

    def test_hardlinks_produce_zero_reclaimable_bytes(self):
        cand = _make_candidate("/Users/test/Library/Caches/link1.cache", size_bytes=5_000_000)
        cluster = _make_cluster(
            "cluster_hl",
            ["/Users/test/Library/Caches/link1.cache", "/Users/test/Library/Caches/link2.cache"],
            size_bytes=5_000_000,
            inodes=[2001, 2001],  # Same inode -> hardlinks
        )

        engine = RecommendationEngine()
        rec = engine.recommend(cand, duplicate_clusters=[cluster])

        assert rec.duplicate_context is not None
        assert rec.duplicate_context.wasted_bytes == 0
        assert rec.duplicate_context.is_hardlink_only is True
        assert rec.duplicate_context.physical_inode_count == 1
        assert rec.duplicate_context.hardlink_count == 1
        assert "No additional physical storage is reclaimable" in rec.duplicate_context.explanation

    def test_three_independent_copies_accounting(self):
        cand = _make_candidate("/Users/test/Library/Caches/fileA", size_bytes=100_000_000)
        cluster = _make_cluster(
            "cluster_3copies",
            ["/Users/test/Library/Caches/fileA", "/Users/test/Downloads/fileB", "/Users/test/Tmp/fileC"],
            size_bytes=100_000_000,
            inodes=[3001, 3002, 3003],  # 3 distinct inodes
        )

        engine = RecommendationEngine()
        rec = engine.recommend(cand, duplicate_clusters=[cluster])

        assert rec.duplicate_context is not None
        assert rec.duplicate_context.duplicate_file_count == 3
        assert rec.duplicate_context.physical_inode_count == 3
        # Wasted bytes for 3 copies of 100MB is 200MB (since 1 must remain)
        assert rec.duplicate_context.wasted_bytes == 200_000_000
        assert rec.duplicate_context.is_hardlink_only is False

    def test_mixed_hardlink_and_independent_inode_accounting(self):
        cand = _make_candidate("/Users/test/Library/Caches/file1", size_bytes=10_000_000)
        cluster = _make_cluster(
            "cluster_mixed",
            [
                "/Users/test/Library/Caches/file1",
                "/Users/test/Library/Caches/file1_link",
                "/Users/test/Downloads/file2",
            ],
            size_bytes=10_000_000,
            inodes=[4001, 4001, 4002],  # 3 paths, 2 physical inodes
        )

        engine = RecommendationEngine()
        rec = engine.recommend(cand, duplicate_clusters=[cluster])

        assert rec.duplicate_context is not None
        assert rec.duplicate_context.duplicate_file_count == 3
        assert rec.duplicate_context.physical_inode_count == 2
        assert rec.duplicate_context.hardlink_count == 1
        assert rec.duplicate_context.wasted_bytes == 10_000_000
        assert rec.duplicate_context.is_hardlink_only is False


class TestDuplicateSafetyAndRiskPreservation:
    """Verify that duplicate context never bypasses or alters safety/risk policies."""

    def test_high_risk_remains_blocked_despite_duplicate_evidence(self):
        cand = _make_candidate(
            path="/Users/test/Documents/important.docx",
            category=StorageCategory.DOCUMENTS,
            risk_level=RiskLevel.HIGH,
            size_bytes=20_000_000,
        )
        cluster = _make_cluster(
            "cluster_docs",
            ["/Users/test/Documents/important.docx", "/Users/test/Downloads/important_copy.docx"],
            size_bytes=20_000_000,
        )

        engine = RecommendationEngine()
        rec = engine.recommend(cand, duplicate_clusters=[cluster])

        # Risk and action must remain strictly MANUAL_REVIEW
        assert rec.action == RecommendationAction.MANUAL_REVIEW
        assert rec.safety_status == SafetyStatus.MANUAL_REVIEW_REQUIRED.value
        assert rec.requires_approval is True
        assert rec.duplicate_context is not None
        assert rec.duplicate_context.wasted_bytes == 20_000_000

    def test_unknown_risk_remains_blocked_no_action(self):
        cand = _make_candidate(
            path="/Users/test/unknown_payload.bin",
            category=StorageCategory.UNKNOWN,
            risk_level=RiskLevel.UNKNOWN,
            size_bytes=15_000_000,
        )
        cluster = _make_cluster(
            "cluster_unknown",
            ["/Users/test/unknown_payload.bin", "/Users/test/copy_unknown.bin"],
            size_bytes=15_000_000,
        )

        engine = RecommendationEngine()
        rec = engine.recommend(cand, duplicate_clusters=[cluster])

        assert rec.action == RecommendationAction.NO_ACTION
        assert rec.safety_status == SafetyStatus.UNKNOWN.value
        assert rec.requires_approval is True
        assert rec.duplicate_context is not None

    def test_low_risk_cache_retains_review_for_cleanup(self):
        cand = _make_candidate(
            path="/Users/test/Library/Caches/app.cache",
            category=StorageCategory.CACHE,
            risk_level=RiskLevel.LOW,
            size_bytes=50_000_000,
        )
        cluster = _make_cluster(
            "cluster_cache",
            ["/Users/test/Library/Caches/app.cache", "/Users/test/Downloads/app_old.cache"],
            size_bytes=50_000_000,
        )

        engine = RecommendationEngine()
        rec = engine.recommend(cand, duplicate_clusters=[cluster])

        assert rec.action == RecommendationAction.REVIEW_FOR_CLEANUP
        assert rec.safety_status == SafetyStatus.ELIGIBLE_FOR_REVIEW.value
        assert rec.requires_approval is True
        assert rec.duplicate_context is not None

    def test_medium_risk_development_remains_manual_review(self):
        cand = _make_candidate(
            path="/Users/test/Projects/myrepo/node_modules/pkg.tgz",
            category=StorageCategory.DEVELOPMENT,
            risk_level=RiskLevel.MEDIUM,
            size_bytes=30_000_000,
        )
        cluster = _make_cluster(
            "cluster_dev",
            [
                "/Users/test/Projects/myrepo/node_modules/pkg.tgz",
                "/Users/test/Projects/other/node_modules/pkg.tgz",
            ],
            size_bytes=30_000_000,
        )

        engine = RecommendationEngine()
        rec = engine.recommend(cand, duplicate_clusters=[cluster])

        assert rec.action == RecommendationAction.MANUAL_REVIEW
        assert rec.safety_status == SafetyStatus.MANUAL_REVIEW_REQUIRED.value
        assert rec.requires_approval is True

    def test_zero_byte_items_remain_no_action(self):
        cand = _make_candidate(
            path="/Users/test/Library/Caches/empty.cache",
            size_bytes=0,
            category=StorageCategory.CACHE,
            risk_level=RiskLevel.LOW,
        )
        cluster = _make_cluster(
            "cluster_zero",
            ["/Users/test/Library/Caches/empty.cache", "/Users/test/Downloads/empty2.cache"],
            size_bytes=0,
        )

        engine = RecommendationEngine()
        rec = engine.recommend(cand, duplicate_clusters=[cluster])

        assert rec.action == RecommendationAction.NO_ACTION
        assert rec.safety_status == SafetyStatus.MANUAL_REVIEW_REQUIRED.value

    def test_sub_threshold_items_remain_no_action(self):
        cand = _make_candidate(
            path="/Users/test/Library/Caches/tiny.cache",
            size_bytes=500,
            category=StorageCategory.CACHE,
            risk_level=RiskLevel.LOW,
        )
        cluster = _make_cluster(
            "cluster_tiny",
            ["/Users/test/Library/Caches/tiny.cache", "/Users/test/Downloads/tiny2.cache"],
            size_bytes=500,
        )

        engine = RecommendationEngine(min_cleanup_size_bytes=1024)
        rec = engine.recommend(cand, duplicate_clusters=[cluster])

        assert rec.action == RecommendationAction.NO_ACTION
        assert rec.duplicate_context is not None


class TestDuplicateIntegrityAndAuthority:
    """Verify authority boundaries, candidate integrity, and deterministic matching."""

    def test_duplicate_cannot_create_arbitrary_candidates(self):
        # Only existing candidate path is evaluated
        cand = _make_candidate("/Users/test/Library/Caches/file1.cache")
        cluster = _make_cluster(
            "cluster_extra",
            [
                "/Users/test/Library/Caches/file1.cache",
                "/Users/test/System/Library/forbidden_file.cache",
            ],
            size_bytes=10_000_000,
        )

        engine = RecommendationEngine()
        recs = engine.recommend_many([cand], duplicate_clusters=[cluster])

        assert len(recs) == 1
        assert recs[0].candidate.path == "/Users/test/Library/Caches/file1.cache"
        # The un-scanned forbidden path does not become a recommendation
        assert all(r.candidate.path != "/Users/test/System/Library/forbidden_file.cache" for r in recs)

    def test_duplicate_path_outside_candidate_set_is_contextual_only(self):
        cand = _make_candidate("/Users/test/Library/Caches/active.cache")
        cluster = _make_cluster(
            "cluster_outside",
            [
                "/Users/test/Library/Caches/active.cache",
                "/Users/test/External/unscanned_copy.cache",
            ],
            size_bytes=10_000_000,
        )

        engine = RecommendationEngine()
        rec = engine.recommend(cand, duplicate_clusters=[cluster])

        assert rec.duplicate_context is not None
        assert rec.duplicate_context.duplicate_paths == ["/Users/test/External/unscanned_copy.cache"]
        # Candidate path remains the authoritative target
        assert rec.candidate.path == "/Users/test/Library/Caches/active.cache"

    def test_candidate_path_remains_authoritative(self):
        cand = _make_candidate("/Users/test/Library/Caches/item.cache")
        cluster = _make_cluster(
            "cluster_auth",
            ["/Users/test/Library/Caches/item.cache", "/Users/test/Downloads/dup.cache"],
            size_bytes=10_000_000,
        )

        engine = RecommendationEngine()
        rec = engine.recommend(cand, duplicate_clusters=[cluster])
        assert rec.candidate.path == "/Users/test/Library/Caches/item.cache"

    def test_missing_duplicate_clusters_handled_safely(self):
        cand = _make_candidate("/Users/test/Library/Caches/sample.cache")
        engine = RecommendationEngine()

        rec_none = engine.recommend(cand, duplicate_clusters=None)
        assert rec_none.duplicate_context is None

        rec_empty = engine.recommend(cand, duplicate_clusters=[])
        assert rec_empty.duplicate_context is None

    def test_unmatched_candidate_receives_none_context(self):
        cand = _make_candidate("/Users/test/Library/Caches/unmatched.cache")
        cluster = _make_cluster(
            "cluster_other",
            ["/Users/test/Library/Caches/other1.cache", "/Users/test/Library/Caches/other2.cache"],
            size_bytes=10_000_000,
        )

        engine = RecommendationEngine()
        rec = engine.recommend(cand, duplicate_clusters=[cluster])
        assert rec.duplicate_context is None

    def test_multiple_clusters_match_correctly(self):
        cand1 = _make_candidate("/Users/test/Library/Caches/c1_file.cache")
        cand2 = _make_candidate("/Users/test/Library/Caches/c2_file.cache")

        cl1 = _make_cluster("cl1", ["/Users/test/Library/Caches/c1_file.cache", "/Users/test/Downloads/c1_copy.cache"])
        cl2 = _make_cluster("cl2", ["/Users/test/Library/Caches/c2_file.cache", "/Users/test/Downloads/c2_copy.cache"])

        engine = RecommendationEngine()
        recs = engine.recommend_many([cand1, cand2], duplicate_clusters=[cl1, cl2])

        assert len(recs) == 2
        assert recs[0].duplicate_context.cluster_id == "cl1"
        assert recs[1].duplicate_context.cluster_id == "cl2"

    def test_deterministic_recommendation_ordering(self):
        cand1 = _make_candidate("/Users/test/Library/Caches/fileA.cache")
        cand2 = _make_candidate("/Users/test/Library/Caches/fileB.cache")
        cl = _make_cluster("cl", ["/Users/test/Library/Caches/fileA.cache", "/Users/test/Library/Caches/fileB.cache"])

        engine = RecommendationEngine()
        recs1 = engine.recommend_many([cand1, cand2], duplicate_clusters=[cl])
        recs2 = engine.recommend_many([cand1, cand2], duplicate_clusters=[cl])

        assert [r.candidate.path for r in recs1] == [r.candidate.path for r in recs2]
        assert [r.duplicate_context.cluster_id for r in recs1] == [r.duplicate_context.cluster_id for r in recs2]


class TestAgentAndToolIntegration:
    """Verify agent tools expose duplicate context in read-only format."""

    def test_agent_tool_get_recommendations_includes_duplicate_context(self):
        cand = _make_candidate("/Users/test/Library/Caches/sample.cache")
        cluster = _make_cluster(
            "cl_agent",
            ["/Users/test/Library/Caches/sample.cache", "/Users/test/Downloads/sample2.cache"],
            size_bytes=10_000_000,
        )

        engine = RecommendationEngine()
        rec = engine.recommend(cand, duplicate_clusters=[cluster])

        registry = AgentToolRegistry()
        obs = registry.execute_tool("get_recommendations", recommendations=[rec])

        assert obs.success is True
        assert len(obs.data) == 1
        rec_data = obs.data[0]
        assert "duplicate_context" in rec_data
        assert rec_data["duplicate_context"]["cluster_id"] == "cl_agent"
        assert rec_data["duplicate_context"]["wasted_bytes"] == 10_000_000
        assert rec_data["duplicate_context"]["physical_inode_count"] == 2

    def test_agent_registry_remains_strictly_read_only(self):
        registry = AgentToolRegistry()
        for forbidden in ["delete_duplicate", "approve_recommendation", "trash_execute", "cleanup"]:
            obs = registry.execute_tool(forbidden)
            assert obs.success is False
            assert "forbidden" in obs.error_message


class TestDuplicateModelImmutability:
    """Verify frozen and strict validation rules of DuplicateRecommendationContext."""

    def test_duplicate_recommendation_context_is_frozen(self):
        ctx = DuplicateRecommendationContext(
            cluster_id="cl_frozen",
            file_size_bytes=1000,
            duplicate_file_count=2,
            physical_inode_count=2,
            hardlink_count=0,
            wasted_bytes=1000,
            duplicate_paths=["/path/b"],
            is_hardlink_only=False,
            explanation="Test explanation",
        )

        with pytest.raises(Exception):
            ctx.wasted_bytes = 2000  # type: ignore

    def test_duplicate_recommendation_context_forbids_extra_fields(self):
        with pytest.raises(Exception):
            DuplicateRecommendationContext(
                cluster_id="cl_extra",
                file_size_bytes=1000,
                duplicate_file_count=2,
                physical_inode_count=2,
                hardlink_count=0,
                wasted_bytes=1000,
                duplicate_paths=["/path/b"],
                is_hardlink_only=False,
                explanation="Test explanation",
                extra_field="disallowed",  # type: ignore
            )

    def test_duplicate_recommendation_context_field_bounds(self):
        with pytest.raises(Exception):
            DuplicateRecommendationContext(
                cluster_id="cl_bad",
                file_size_bytes=1000,
                duplicate_file_count=1,  # Must be >= 2
                physical_inode_count=1,
                hardlink_count=0,
                wasted_bytes=0,
                duplicate_paths=["/path/a"],
                is_hardlink_only=True,
                explanation="Test explanation",
            )


class TestDuplicateAdvancedIntegrations:
    """Verify cross-component interactions: Approval, ReviewItem, and Historical context."""

    def test_duplicate_and_historical_context_coexist(self):
        from app.models.storage_history import CategoryTrend, StorageTrend, StorageTrendReport, TrendDirection
        from app.models.category import SmartCategory
        from app.models.scan_scope import ScopeIdentifier

        cand = _make_candidate(
            path="/Users/test/Library/Caches/growth_copy1.cache",
            category=StorageCategory.CACHE,
            risk_level=RiskLevel.LOW,
            size_bytes=20_000_000,
        )

        trend_report = StorageTrendReport(
            scope_id=ScopeIdentifier.HOME,
            root_path="/Users/test",
            current_snapshot_id="snap_curr",
            previous_snapshot_id="snap_prev",
            current_timestamp=1700000000.0,
            previous_timestamp=1699900000.0,
            is_comparable=True,
            overall_trend=StorageTrend(
                metric="Total Storage",
                current_value=30_000_000,
                previous_value=10_000_000,
                absolute_change=20_000_000,
                percentage_change=200.0,
                direction=TrendDirection.GROWING,
                explanation="Total storage increased by 20 MB",
            ),
            category_trends=[
                CategoryTrend(
                    category=SmartCategory.CACHES,
                    previous_bytes=10_000_000,
                    current_bytes=30_000_000,
                    absolute_change=20_000_000,
                    percentage_change=200.0,
                    direction=TrendDirection.GROWING,
                    explanation="Caches grew by 20 MB",
                )
            ],
            developer_trends=[],
            notes=[],
        )

        cluster = _make_cluster(
            "cl_coexist",
            [
                "/Users/test/Library/Caches/growth_copy1.cache",
                "/Users/test/Downloads/growth_copy2.cache",
            ],
            size_bytes=20_000_000,
        )

        engine = RecommendationEngine()
        rec = engine.recommend(cand, trend_report=trend_report, duplicate_clusters=[cluster])

        assert rec.historical_context is not None
        assert rec.historical_context.trend_direction == TrendDirection.GROWING
        assert rec.duplicate_context is not None
        assert rec.duplicate_context.cluster_id == "cl_coexist"
        assert rec.action == RecommendationAction.REVIEW_FOR_CLEANUP

    def test_four_copies_three_physical_inodes_accounting(self):
        cand = _make_candidate("/Users/test/Library/Caches/file1", size_bytes=10_000_000)
        cluster = _make_cluster(
            "cluster_4copies_3inodes",
            [
                "/Users/test/Library/Caches/file1",
                "/Users/test/Library/Caches/file1_link",
                "/Users/test/Downloads/file2",
                "/Users/test/Tmp/file3",
            ],
            size_bytes=10_000_000,
            inodes=[5001, 5001, 5002, 5003],  # 4 paths, 3 distinct inodes
        )

        engine = RecommendationEngine()
        rec = engine.recommend(cand, duplicate_clusters=[cluster])

        assert rec.duplicate_context is not None
        assert rec.duplicate_context.duplicate_file_count == 4
        assert rec.duplicate_context.physical_inode_count == 3
        assert rec.duplicate_context.hardlink_count == 1
        assert rec.duplicate_context.wasted_bytes == 20_000_000
        assert rec.duplicate_context.is_hardlink_only is False

    def test_three_paths_single_inode_hardlink_accounting(self):
        cand = _make_candidate("/Users/test/Library/Caches/hl1", size_bytes=50_000_000)
        cluster = _make_cluster(
            "cluster_3hl_1ino",
            [
                "/Users/test/Library/Caches/hl1",
                "/Users/test/Library/Caches/hl2",
                "/Users/test/Library/Caches/hl3",
            ],
            size_bytes=50_000_000,
            inodes=[6001, 6001, 6001],  # All 3 paths share 1 physical inode
        )

        engine = RecommendationEngine()
        rec = engine.recommend(cand, duplicate_clusters=[cluster])

        assert rec.duplicate_context is not None
        assert rec.duplicate_context.duplicate_file_count == 3
        assert rec.duplicate_context.physical_inode_count == 1
        assert rec.duplicate_context.hardlink_count == 2
        assert rec.duplicate_context.wasted_bytes == 0
        assert rec.duplicate_context.is_hardlink_only is True

    def test_duplicate_cluster_with_gigabyte_scale_wasted_bytes(self):
        gib = 1024 * 1024 * 1024
        cand = _make_candidate("/Users/test/Library/Caches/big1.iso", size_bytes=4 * gib)
        cluster = _make_cluster(
            "cluster_big",
            [
                "/Users/test/Library/Caches/big1.iso",
                "/Users/test/Downloads/big2.iso",
                "/Users/test/Backup/big3.iso",
            ],
            size_bytes=4 * gib,
            inodes=[7001, 7002, 7003],
        )

        engine = RecommendationEngine()
        rec = engine.recommend(cand, duplicate_clusters=[cluster])

        assert rec.duplicate_context is not None
        assert rec.duplicate_context.wasted_bytes == 8 * gib
        assert rec.duplicate_context.duplicate_file_count == 3
        assert rec.duplicate_context.physical_inode_count == 3

    def test_approval_service_integration_preserves_duplicate_context(self):
        from app.safety.approval_service import ApprovalService
        from app.safety.path_validator import Operation, PathValidator

        home_cache = str(Path.home() / "Library/Caches/test_app/cache.bin")
        cand = _make_candidate(home_cache)
        cluster = _make_cluster(
            "cluster_appr",
            [home_cache, str(Path.home() / "Downloads/cache_copy.bin")],
            size_bytes=10_000_000,
        )

        engine = RecommendationEngine()
        rec = engine.recommend(cand, duplicate_clusters=[cluster])

        assert rec.duplicate_context is not None
        assert rec.duplicate_context.cluster_id == "cluster_appr"

        approval_service = ApprovalService(path_validator=PathValidator(custom_allowlist_roots=[str(Path.home() / "Library/Caches")]))
        record, err = approval_service.request_approval(rec, operation=Operation.CLEAN)

        assert err is None
        assert record is not None
        assert record.path == str(Path(home_cache).resolve())
        assert record.risk_level == RiskLevel.LOW
        assert record.approved is False

    def test_review_item_preserves_duplicate_context(self):
        from app.safety.review import ReviewItem

        cand = _make_candidate("/Users/test/Library/Caches/review_dup.cache")
        cluster = _make_cluster(
            "cluster_rev",
            ["/Users/test/Library/Caches/review_dup.cache", "/Users/test/Downloads/review_dup2.cache"],
            size_bytes=10_000_000,
        )

        engine = RecommendationEngine()
        rec = engine.recommend(cand, duplicate_clusters=[cluster])

        item = ReviewItem(
            candidate=cand,
            recommendation=rec,
            risk_level=cand.risk_level,
            safety_status=SafetyStatus.ELIGIBLE_FOR_REVIEW.value,
            requires_approval=True,
            is_eligible_for_approval=True,
            review_message="Eligible for cleanup review",
        )

        assert item.recommendation.duplicate_context is not None
        assert item.recommendation.duplicate_context.cluster_id == "cluster_rev"
        assert item.recommendation.duplicate_context.wasted_bytes == 10_000_000

    def test_duplicate_cluster_empty_files_raises_validation_error(self):
        with pytest.raises(Exception):
            DuplicateCluster(
                cluster_id="cl_empty",
                file_size_bytes=1000,
                files=[],  # min_length=1
                wasted_bytes=0,
                hardlink_count=0,
            )


class TestStaticSafetyGuarantees:
    """Static AST safety scan ensuring zero prohibited execution/mutation primitives."""

    def test_static_ast_safety_on_duplicate_recommendations(self):
        files_to_check = [
            Path("app/models/duplicate_recommendation.py"),
            Path("app/analysis/recommendations.py"),
        ]

        prohibited_functions = {
            "remove",
            "unlink",
            "rmdir",
            "rmtree",
            "move",
            "rename",
            "popen",
            "system",
            "exec",
            "eval",
        }

        prohibited_modules = {
            "subprocess",
            "shutil",
        }

        for path in files_to_check:
            assert path.exists(), f"File {path} must exist"
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        assert (
                            alias.name not in prohibited_modules
                        ), f"Prohibited import '{alias.name}' found in {path}"
                elif isinstance(node, ast.ImportFrom):
                    assert (
                        node.module not in prohibited_modules
                    ), f"Prohibited from-import '{node.module}' found in {path}"
                    assert (
                        node.module is None or not node.module.startswith("app.safety")
                    ), f"Prohibited safety internal import found in {path}"
                    assert (
                        node.module is None or not node.module.startswith("app.execution")
                    ), f"Prohibited execution internal import found in {path}"
                elif isinstance(node, ast.Call):
                    func = node.func
                    if isinstance(func, ast.Name):
                        assert (
                            func.id not in prohibited_functions
                        ), f"Prohibited function call '{func.id}' found in {path}"
                    elif isinstance(func, ast.Attribute):
                        assert (
                            func.attr not in prohibited_functions
                        ), f"Prohibited method call '{func.attr}' found in {path}"
