from __future__ import annotations

import tempfile
from pathlib import Path

from app.agent.tools import ALLOWED_AGENT_TOOLS, AgentToolRegistry
from app.analysis.models import RiskLevel, StorageCandidate, StorageCategory
from app.analysis.recommendations import RecommendationEngine, SafetyStatus, StorageRecommendation


def test_tool_registry_allowlist() -> None:
    registry = AgentToolRegistry()

    for tool in ALLOWED_AGENT_TOOLS:
        assert registry.is_tool_allowed(tool) is True

    for forbidden in ["delete", "remove", "move", "execute", "shell", "python", "approve"]:
        assert registry.is_tool_allowed(forbidden) is False


def test_tool_registry_forbidden_tool_fails_closed() -> None:
    registry = AgentToolRegistry()
    obs = registry.execute_tool("delete_file", {"path": "/tmp/test"})
    assert obs.success is False
    assert "forbidden" in obs.error_message.lower()


def test_tool_registry_read_only_execution() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "test.cache"
        test_file.write_bytes(b"A" * 1024)

        cand = StorageCandidate(
            path=str(test_file),
            size_bytes=1024,
            category=StorageCategory.CACHE,
            risk_level=RiskLevel.LOW,
            confidence=0.9,
            reason="Test cache",
            recommendation="Review test cache",
        )
        rec = RecommendationEngine().recommend(cand)

        registry = AgentToolRegistry()

        # 1. get_storage_overview
        obs_overview = registry.execute_tool("get_storage_overview", {"path": tmpdir})
        assert obs_overview.success is True
        assert obs_overview.data["total_bytes"] > 0

        # 2. get_storage_candidates
        obs_cands = registry.execute_tool("get_storage_candidates", candidates=[cand])
        assert obs_cands.success is True
        assert len(obs_cands.data) == 1

        # 3. get_candidate_details
        obs_details = registry.execute_tool("get_candidate_details", {"path": str(test_file)}, candidates=[cand])
        assert obs_details.success is True
        assert obs_details.data["path"] == str(test_file)

        # 4. get_category_summary
        obs_cat = registry.execute_tool("get_category_summary", candidates=[cand])
        assert obs_cat.success is True
        assert obs_cat.data["CACHE"]["count"] == 1

        # 5. get_recommendations
        obs_recs = registry.execute_tool("get_recommendations", recommendations=[rec])
        assert obs_recs.success is True
        assert len(obs_recs.data) == 1

        # 6. get_safety_policies
        obs_safety = registry.execute_tool("get_safety_policies")
        assert obs_safety.success is True
        assert obs_safety.data["permanent_deletion_enabled"] is False
