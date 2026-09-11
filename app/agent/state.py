from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.agent.models import AgentObservation, AgentToolCall
from app.analysis.models import StorageCandidate
from app.analysis.recommendations import StorageRecommendation


class AgentState(BaseModel):
    """
    State container for an agent session.

    Guarantees:
    - Zero secrets: NEVER holds HMAC signing keys, credentials, or encryption secrets.
    - Zero mutation authority: Holds purely observational data and conversation context.
    """

    model_config = ConfigDict(frozen=False, extra="forbid")

    session_id: str = Field(
        default_factory=lambda: secrets.token_hex(8),
        description="Unique session identifier.",
    )
    user_mode: str = Field(
        default="AGENT",
        description="Current user operating mode.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Session creation timestamp.",
    )
    conversation_history: list[dict[str, str]] = Field(
        default_factory=list,
        description="List of messages exchanged in this session [{'role': 'user'|'agent', 'content': str}].",
    )
    last_scan_id: Optional[str] = Field(
        default=None,
        description="ID of the most recently referenced storage scan.",
    )
    tool_history: list[AgentToolCall] = Field(
        default_factory=list,
        description="Audit list of tool calls requested during this session.",
    )
    observation_history: list[AgentObservation] = Field(
        default_factory=list,
        description="Audit list of tool observations received during this session.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Non-sensitive conversational metadata.",
    )

    def add_user_message(self, content: str) -> None:
        """Add a user message to history."""
        self.conversation_history.append({"role": "user", "content": content})

    def add_agent_message(self, content: str) -> None:
        """Add an agent response to history."""
        self.conversation_history.append({"role": "agent", "content": content})

    def record_tool_call(self, tool_call: AgentToolCall) -> None:
        """Log a tool invocation."""
        self.tool_history.append(tool_call)

    def record_observation(self, observation: AgentObservation) -> None:
        """Log a tool observation."""
        self.observation_history.append(observation)

    def add_tool_call(self, tool_call: AgentToolCall, observation: AgentObservation) -> None:
        """Record both tool call and its resulting observation."""
        self.tool_history.append(tool_call)
        self.observation_history.append(observation)
