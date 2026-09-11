from __future__ import annotations

from app.agent.models import AgentIntent
from app.agent.planner import AgentPlanner
from app.agent.tools import ALLOWED_AGENT_TOOLS


def test_planner_intent_classification() -> None:
    planner = AgentPlanner()

    assert planner.classify_intent("What is using my storage?") == AgentIntent.STORAGE_OVERVIEW
    assert planner.classify_intent("Show me the biggest files") == AgentIntent.FIND_LARGE_FILES
    assert planner.classify_intent("What can I clean safely?") == AgentIntent.RECOMMENDATIONS_QUERY
    assert planner.classify_intent("Show breakdown by category") == AgentIntent.CATEGORY_BREAKDOWN
    assert planner.classify_intent("Explain /Users/mac/Library/Caches/test") == AgentIntent.EXPLAIN_CANDIDATE
    assert planner.classify_intent("Show recent audit log history") == AgentIntent.AUDIT_QUERY
    assert planner.classify_intent("What are the safety rules?") == AgentIntent.SAFETY_INQUIRY


def test_planner_creates_only_allowlisted_tools() -> None:
    planner = AgentPlanner(max_tools_per_plan=5)
    queries = [
        "What is taking up space?",
        "Find the largest files",
        "What can I delete?",
        "Explain /Users/test/Library/Developer/Xcode/DerivedData",
        "Show audit logs",
    ]

    for q in queries:
        intent, tool_calls = planner.create_plan(q)
        assert len(tool_calls) <= 5
        for tc in tool_calls:
            assert tc.tool_name in ALLOWED_AGENT_TOOLS
            assert tc.tool_name not in ["delete", "remove", "move", "execute", "shell", "approve"]


def test_planner_bounding_limits() -> None:
    planner = AgentPlanner(max_tools_per_plan=2)
    intent, tool_calls = planner.create_plan("What is taking up space?")
    assert len(tool_calls) <= 2
