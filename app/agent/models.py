from __future__ import annotations

import secrets
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.analysis.models import RiskLevel, StorageCategory
from app.analysis.recommendations import SafetyStatus


class AgentAction(str, Enum):
    """
    Allowed non-destructive agent informational actions.

    Guarantees:
    - Supported actions are strictly observational, explanatory, and advisory.
    - Destructive or mutating actions (DELETE, MOVE, PURGE, WIPE, EXECUTE, APPROVE) are strictly forbidden.
    """

    EXPLAIN = "EXPLAIN"
    SUMMARIZE = "SUMMARIZE"
    PRIORITIZE = "PRIORITIZE"
    INSPECT = "INSPECT"
    RECOMMEND_REVIEW = "RECOMMEND_REVIEW"
    ASK_USER = "ASK_USER"
    NO_ACTION = "NO_ACTION"


class AgentIntent(str, Enum):
    """Classified high-level user inquiry intent."""

    STORAGE_OVERVIEW = "STORAGE_OVERVIEW"
    CATEGORY_BREAKDOWN = "CATEGORY_BREAKDOWN"
    FIND_LARGE_FILES = "FIND_LARGE_FILES"
    RECOMMENDATIONS_QUERY = "RECOMMENDATIONS_QUERY"
    EXPLAIN_CANDIDATE = "EXPLAIN_CANDIDATE"
    AUDIT_QUERY = "AUDIT_QUERY"
    SAFETY_INQUIRY = "SAFETY_INQUIRY"
    STORAGE_TRENDS = "STORAGE_TRENDS"
    DUPLICATE_QUERY = "DUPLICATE_QUERY"
    DEVELOPER_STORAGE_QUERY = "DEVELOPER_STORAGE_QUERY"
    GENERAL_QUESTION = "GENERAL_QUESTION"


class AgentToolCall(BaseModel):
    """Represents a planned or executed read-only agent tool invocation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool_call_id: str = Field(
        default_factory=lambda: secrets.token_hex(6),
        description="Unique identifier for the tool call.",
    )
    tool_name: str = Field(
        ...,
        description="Name of the allowlisted tool.",
    )
    arguments: dict[str, Any] = Field(
        default_factory=dict,
        description="Arguments passed to the tool.",
    )


class AgentObservation(BaseModel):
    """Deterministic result observed from an allowlisted tool execution."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool_name: str = Field(
        ...,
        description="Name of the executed tool.",
    )
    success: bool = Field(
        ...,
        description="Whether the tool execution succeeded.",
    )
    data: Any = Field(
        default=None,
        description="Structured deterministic data returned by the tool.",
    )
    error_message: Optional[str] = Field(
        default=None,
        description="Error explanation if the tool failed.",
    )


class AgentPriorityItem(BaseModel):
    """Ranked storage candidate prioritized by deterministic criteria."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    priority_rank: int = Field(
        ...,
        ge=1,
        description="1-based priority rank.",
    )
    path: str = Field(
        ...,
        description="Canonical target path.",
    )
    size_bytes: int = Field(
        ...,
        ge=0,
        description="Size in bytes.",
    )
    category: StorageCategory = Field(
        ...,
        description="Semantic storage category.",
    )
    risk_level: RiskLevel = Field(
        ...,
        description="Assessed risk level.",
    )
    safety_status: str = Field(
        ...,
        description="Safety status of the recommendation.",
    )
    reasoning: str = Field(
        ...,
        description="Explanation for why this item received its priority rank.",
    )


class AgentResponse(BaseModel):
    """
    Structured, validated output from the MacGuard AI Agent.

    Guarantees:
    - Strictly separates deterministic facts from AI explanations.
    - Contains zero authority to delete, move, approve, or execute filesystem changes.
    - Directs users to the Human Review workflow when action is recommended.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    response_id: str = Field(
        default_factory=lambda: secrets.token_hex(8),
        description="Unique identifier for the agent response.",
    )
    session_id: str = Field(
        ...,
        description="Associated conversation/session identifier.",
    )
    intent: AgentIntent = Field(
        ...,
        description="Classified user intent.",
    )
    action: AgentAction = Field(
        ...,
        description="Primary non-destructive agent action performed.",
    )
    summary: str = Field(
        ...,
        description="Concise, high-level summary of findings.",
    )
    explanation: str = Field(
        ...,
        description="Natural-language reasoning and contextual insights.",
    )
    deterministic_facts: dict[str, Any] = Field(
        default_factory=dict,
        description="Verified, unalterable facts produced by MacGuard backend engines.",
    )
    priorities: list[AgentPriorityItem] = Field(
        default_factory=list,
        description="Ranked candidate items if applicable.",
    )
    recommended_next_step: str = Field(
        default="Review findings before taking any action.",
        description="Human-centric next step (e.g. 'Open Human Review tab to inspect eligible items').",
    )
    requires_human_review: bool = Field(
        default=False,
        description="Indicates whether the user must perform explicit review.",
    )
    fallback_used: bool = Field(
        default=False,
        description="Indicates whether deterministic fallback was used due to LLM unavailability.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the response was generated.",
    )
