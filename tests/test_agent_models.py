from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.agent.models import (
    AgentAction,
    AgentIntent,
    AgentObservation,
    AgentPriorityItem,
    AgentResponse,
    AgentToolCall,
)
from app.analysis.models import RiskLevel, StorageCategory


def test_agent_action_allowed_values() -> None:
    """Verify AgentAction only allows non-destructive, observational actions."""
    assert AgentAction.EXPLAIN == "EXPLAIN"
    assert AgentAction.SUMMARIZE == "SUMMARIZE"
    assert AgentAction.PRIORITIZE == "PRIORITIZE"
    assert AgentAction.INSPECT == "INSPECT"
    assert AgentAction.RECOMMEND_REVIEW == "RECOMMEND_REVIEW"
    assert AgentAction.ASK_USER == "ASK_USER"
    assert AgentAction.NO_ACTION == "NO_ACTION"

    # Ensure destructive actions are NOT members
    for forbidden in ["DELETE", "REMOVE", "MOVE", "PURGE", "WIPE", "EXECUTE", "AUTHORIZE", "APPROVE"]:
        assert forbidden not in AgentAction.__members__


def test_agent_tool_call_immutability() -> None:
    """Verify AgentToolCall is frozen and validates fields."""
    tool_call = AgentToolCall(tool_name="get_storage_overview", arguments={"path": "/"})
    assert tool_call.tool_name == "get_storage_overview"
    assert tool_call.arguments == {"path": "/"}

    with pytest.raises(ValidationError):
        tool_call.tool_name = "other"  # type: ignore


def test_agent_observation_structure() -> None:
    """Verify AgentObservation structure and serialization."""
    obs = AgentObservation(tool_name="get_category_summary", success=True, data={"cache_bytes": 1024})
    assert obs.success is True
    assert obs.data["cache_bytes"] == 1024
    assert obs.error_message is None


def test_agent_priority_item() -> None:
    """Verify AgentPriorityItem correctly captures ranked candidate information."""
    item = AgentPriorityItem(
        priority_rank=1,
        path="/Users/test/Library/Caches/com.apple.test",
        size_bytes=1048576,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        safety_status="ELIGIBLE_FOR_REVIEW",
        reasoning="Low risk cache eligible for review.",
    )
    assert item.priority_rank == 1
    assert item.risk_level == RiskLevel.LOW
    assert item.safety_status == "ELIGIBLE_FOR_REVIEW"


def test_agent_response_separation_of_facts() -> None:
    """Verify AgentResponse cleanly separates deterministic facts from explanation."""
    resp = AgentResponse(
        session_id="session-123",
        intent=AgentIntent.STORAGE_OVERVIEW,
        action=AgentAction.SUMMARIZE,
        summary="Found 1.2 GB in caches.",
        explanation="Caches are temporary files created by applications.",
        deterministic_facts={"total_bytes": 1288490188, "eligible_count": 2},
        requires_human_review=True,
    )
    assert resp.deterministic_facts["eligible_count"] == 2
    assert resp.action == AgentAction.SUMMARIZE
    assert resp.requires_human_review is True
