"""
MacGuard AI Agentic Intelligence & Orchestration Layer.

Guarantees:
- The agent has intelligence, but zero execution or approval authority.
- Strictly read-only, allowlisted tools.
- Human review remains mandatory for all cleanup operations.
"""

from app.agent.models import (
    AgentAction,
    AgentIntent,
    AgentObservation,
    AgentPriorityItem,
    AgentResponse,
    AgentToolCall,
)
from app.agent.orchestrator import MacGuardAgent
from app.agent.planner import AgentPlanner
from app.agent.policies import (
    check_prompt_injection,
    prioritize_candidates,
    validate_agent_output,
)
from app.agent.state import AgentState
from app.agent.tools import ALLOWED_AGENT_TOOLS, AgentToolRegistry

__all__ = [
    "AgentAction",
    "AgentIntent",
    "AgentObservation",
    "AgentPriorityItem",
    "AgentResponse",
    "AgentToolCall",
    "AgentPlanner",
    "AgentState",
    "AgentToolRegistry",
    "ALLOWED_AGENT_TOOLS",
    "MacGuardAgent",
    "check_prompt_injection",
    "prioritize_candidates",
    "validate_agent_output",
]
