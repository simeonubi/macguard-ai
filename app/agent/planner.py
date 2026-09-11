from __future__ import annotations

import re
from typing import Optional

from app.agent.models import AgentIntent, AgentToolCall
from app.agent.tools import ALLOWED_AGENT_TOOLS

# Intent keywords mapping
_INTENT_KEYWORD_MAP: list[tuple[AgentIntent, list[str]]] = [
    (
        AgentIntent.FIND_LARGE_FILES,
        ["large", "biggest", "huge", "top files", "largest", "gigantic", "heavy", "space hog"],
    ),
    (
        AgentIntent.RECOMMENDATIONS_QUERY,
        ["clean", "delete", "remove", "recommend", "safe to", "what can i", "free up", "purge", "trash"],
    ),
    (
        AgentIntent.CATEGORY_BREAKDOWN,
        ["category", "categories", "breakdown", "cache", "caches", "developer", "deriveddata", "logs", "types"],
    ),
    (
        AgentIntent.STORAGE_TRENDS,
        ["trend", "trends", "growth", "grew", "velocity", "compare", "past scan", "previous scan", "change over time", "changed since"],
    ),
    (
        AgentIntent.DUPLICATE_QUERY,
        ["duplicate", "duplicates", "redundant", "redundancy", "same file", "copies", "hardlink", "hardlinks"],
    ),
    (
        AgentIntent.DEVELOPER_STORAGE_QUERY,
        ["docker", "xcode", "node_modules", "npm", "pip", "venv", "virtualenv", "cargo", "huggingface", "model cache", "developer tool"],
    ),
    (
        AgentIntent.AUDIT_QUERY,
        ["history", "audit", "past", "previous", "log", "logs", "what happened", "records"],
    ),
    (
        AgentIntent.SAFETY_INQUIRY,
        ["safe", "safety", "policy", "policies", "rules", "risk", "how it works", "validator", "hmac"],
    ),
    (
        AgentIntent.STORAGE_OVERVIEW,
        ["overview", "disk", "storage", "space", "usage", "free space", "total", "drive", "capacity"],
    ),
]


class AgentPlanner:
    """
    Translates user requests into safe, bounded, informational tool execution plans.

    Guarantees:
    - Never produces mutation or execution tool calls.
    - All planned tool calls are strictly within ALLOWED_AGENT_TOOLS.
    - Enforces a maximum tool limit per plan.
    """

    def __init__(self, max_tools_per_plan: int = 5) -> None:
        self._max_tools_per_plan = max_tools_per_plan

    def classify_intent(self, user_query: str) -> AgentIntent:
        """Deterministically classify user intent from the query text."""
        query_lower = user_query.lower()

        # Check for candidate path explanation inquiry (e.g. paths starting with / or ~)
        if re.search(r"(?:/|~/)[a-zA-Z0-9_\-./]+", user_query):
            return AgentIntent.EXPLAIN_CANDIDATE

        for intent, keywords in _INTENT_KEYWORD_MAP:
            if any(kw in query_lower for kw in keywords):
                return intent

        return AgentIntent.GENERAL_QUESTION

    def create_plan(
        self,
        user_query: str,
        scan_path: str = "/",
        target_path: Optional[str] = None,
    ) -> tuple[AgentIntent, list[AgentToolCall]]:
        """
        Create a safe sequence of informational tool calls for the given user inquiry.

        Returns:
            (intent, list_of_tool_calls)
        """
        intent = self.classify_intent(user_query)
        tool_calls: list[AgentToolCall] = []

        # Extract explicit path if query has one and target_path wasn't supplied
        if not target_path:
            path_match = re.search(r"((?:/|~/)[a-zA-Z0-9_\-./]+)", user_query)
            if path_match:
                target_path = path_match.group(1)

        if intent == AgentIntent.STORAGE_OVERVIEW:
            tool_calls.append(AgentToolCall(tool_name="get_storage_overview", arguments={"path": scan_path}))
            tool_calls.append(AgentToolCall(tool_name="get_category_summary", arguments={}))
            tool_calls.append(AgentToolCall(tool_name="get_large_files", arguments={"limit": 5}))

        elif intent == AgentIntent.CATEGORY_BREAKDOWN:
            tool_calls.append(AgentToolCall(tool_name="get_category_summary", arguments={}))
            tool_calls.append(AgentToolCall(tool_name="get_storage_candidates", arguments={}))

        elif intent == AgentIntent.FIND_LARGE_FILES:
            tool_calls.append(AgentToolCall(tool_name="get_large_files", arguments={"limit": 10}))
            tool_calls.append(AgentToolCall(tool_name="get_storage_candidates", arguments={}))

        elif intent == AgentIntent.RECOMMENDATIONS_QUERY:
            tool_calls.append(AgentToolCall(tool_name="get_recommendations", arguments={"only_eligible": False}))
            tool_calls.append(AgentToolCall(tool_name="get_category_summary", arguments={}))
            tool_calls.append(AgentToolCall(tool_name="get_storage_overview", arguments={"path": scan_path}))

        elif intent == AgentIntent.EXPLAIN_CANDIDATE:
            if target_path:
                tool_calls.append(AgentToolCall(tool_name="get_candidate_details", arguments={"path": target_path}))
            tool_calls.append(AgentToolCall(tool_name="get_recommendations", arguments={}))
            tool_calls.append(AgentToolCall(tool_name="get_safety_policies", arguments={}))

        elif intent == AgentIntent.STORAGE_TRENDS:
            tool_calls.append(AgentToolCall(tool_name="get_storage_trends", arguments={}))
            tool_calls.append(AgentToolCall(tool_name="get_category_summary", arguments={}))

        elif intent == AgentIntent.DUPLICATE_QUERY:
            tool_calls.append(AgentToolCall(tool_name="get_duplicate_summary", arguments={}))
            tool_calls.append(AgentToolCall(tool_name="get_recommendations", arguments={}))

        elif intent == AgentIntent.DEVELOPER_STORAGE_QUERY:
            tool_calls.append(AgentToolCall(tool_name="get_developer_storage_summary", arguments={}))
            tool_calls.append(AgentToolCall(tool_name="get_category_summary", arguments={}))

        elif intent == AgentIntent.AUDIT_QUERY:
            tool_calls.append(AgentToolCall(tool_name="get_audit_summary", arguments={"limit": 10}))

        elif intent == AgentIntent.SAFETY_INQUIRY:
            tool_calls.append(AgentToolCall(tool_name="get_safety_policies", arguments={}))
            tool_calls.append(AgentToolCall(tool_name="get_recommendations", arguments={}))

        else:  # GENERAL_QUESTION
            tool_calls.append(AgentToolCall(tool_name="get_storage_overview", arguments={"path": scan_path}))
            tool_calls.append(AgentToolCall(tool_name="get_category_summary", arguments={}))

        # Validate that all generated tool calls are allowlisted and bounded
        validated_calls: list[AgentToolCall] = []
        for call in tool_calls[: self._max_tools_per_plan]:
            if call.tool_name in ALLOWED_AGENT_TOOLS:
                validated_calls.append(call)

        return intent, validated_calls
