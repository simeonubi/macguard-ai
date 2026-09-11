from __future__ import annotations

from unittest.mock import MagicMock
import pytest

from app.agent.orchestrator import MacGuardAgent
from app.evaluation.models import EvaluationCategory
from app.evaluation.runner import EvaluationRunner
from app.evaluation.scenarios import EVALUATION_SCENARIOS
from app.llm.ollama_client import OllamaClient, OllamaConnectionError


@pytest.fixture
def mock_agent() -> MacGuardAgent:
    mock_llm = MagicMock(spec=OllamaClient)
    mock_llm.generate.side_effect = OllamaConnectionError("Offline")
    return MacGuardAgent(llm_client=mock_llm)


def test_adversarial_prompt_injections_rejected(mock_agent: MacGuardAgent) -> None:
    runner = EvaluationRunner(agent=mock_agent)
    injection_scenarios = [s for s in EVALUATION_SCENARIOS if s.category == EvaluationCategory.PROMPT_INJECTION]

    for scenario in injection_scenarios:
        result = runner.run_scenario(scenario)
        assert result.passed is True, f"Scenario {scenario.scenario_id} failed: {result.violations}"


def test_secret_extraction_attempts_blocked(mock_agent: MacGuardAgent) -> None:
    runner = EvaluationRunner(agent=mock_agent)
    secret_scenarios = [s for s in EVALUATION_SCENARIOS if s.category == EvaluationCategory.SECRET_EXTRACTION]

    for scenario in secret_scenarios:
        result = runner.run_scenario(scenario)
        assert result.passed is True, f"Scenario {scenario.scenario_id} failed: {result.violations}"


def test_tool_abuse_attempts_blocked(mock_agent: MacGuardAgent) -> None:
    runner = EvaluationRunner(agent=mock_agent)
    tool_scenarios = [s for s in EVALUATION_SCENARIOS if s.category == EvaluationCategory.TOOL_ABUSE]

    for scenario in tool_scenarios:
        result = runner.run_scenario(scenario)
        assert result.passed is True, f"Scenario {scenario.scenario_id} failed: {result.violations}"


def test_unsafe_execution_requests_blocked(mock_agent: MacGuardAgent) -> None:
    runner = EvaluationRunner(agent=mock_agent)
    unsafe_scenarios = [s for s in EVALUATION_SCENARIOS if s.category == EvaluationCategory.UNSAFE_REQUEST]

    for scenario in unsafe_scenarios:
        result = runner.run_scenario(scenario)
        assert result.passed is True, f"Scenario {scenario.scenario_id} failed: {result.violations}"
