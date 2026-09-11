from __future__ import annotations

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field


class EvaluationCategory(str, Enum):
    """Category of evaluation scenarios."""

    LEGITIMATE_INQUIRY = "LEGITIMATE_INQUIRY"
    UNSAFE_REQUEST = "UNSAFE_REQUEST"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    BOUNDARY_ATTACK = "BOUNDARY_ATTACK"
    SECRET_EXTRACTION = "SECRET_EXTRACTION"
    TOOL_ABUSE = "TOOL_ABUSE"


class EvaluationScenario(BaseModel):
    """Defines a deterministic test scenario for evaluating agent safety and correctness."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scenario_id: str = Field(..., description="Unique scenario identifier.")
    name: str = Field(..., description="Short human-readable name.")
    category: EvaluationCategory = Field(..., description="Evaluation scenario category.")
    user_prompt: str = Field(..., description="The query input to the agent.")
    should_reject: bool = Field(..., description="Whether the agent must reject the request.")
    expected_action: Optional[str] = Field(default=None, description="Expected AgentAction string.")
    forbidden_tokens: list[str] = Field(
        default_factory=list,
        description="Tokens that must never appear in the agent response.",
    )


class ScenarioResult(BaseModel):
    """Result of running a single evaluation scenario."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scenario_id: str = Field(..., description="ID of the evaluated scenario.")
    name: str = Field(..., description="Name of the scenario.")
    category: EvaluationCategory = Field(..., description="Category of the scenario.")
    passed: bool = Field(..., description="Whether the scenario met all safety criteria.")
    latency_ms: float = Field(..., ge=0.0, description="Execution time in milliseconds.")
    action_taken: str = Field(..., description="The actual AgentAction taken.")
    requires_human_review: bool = Field(..., description="Whether human review was mandated.")
    violations: list[str] = Field(default_factory=list, description="List of observed safety or policy violations.")


class EvaluationReport(BaseModel):
    """Aggregate evaluation report computed across all scenarios."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    total_scenarios: int = Field(..., ge=0)
    passed_scenarios: int = Field(..., ge=0)
    failed_scenarios: int = Field(..., ge=0)
    safety_pass_rate: float = Field(..., ge=0.0, le=100.0)
    prompt_injection_resistance_rate: float = Field(..., ge=0.0, le=100.0)
    tool_boundary_violation_count: int = Field(..., ge=0)
    secret_leakage_count: int = Field(..., ge=0)
    approval_bypass_count: int = Field(..., ge=0)
    unauthorized_mutation_count: int = Field(..., ge=0)
    fallback_success_rate: float = Field(..., ge=0.0, le=100.0)
    average_latency_ms: float = Field(..., ge=0.0)
    results: list[ScenarioResult] = Field(default_factory=list)
