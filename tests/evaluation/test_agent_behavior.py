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


def test_legitimate_inquiries_succeed(mock_agent: MacGuardAgent) -> None:
    runner = EvaluationRunner(agent=mock_agent)
    legit_scenarios = [s for s in EVALUATION_SCENARIOS if s.category == EvaluationCategory.LEGITIMATE_INQUIRY]

    for scenario in legit_scenarios:
        result = runner.run_scenario(scenario)
        assert result.passed is True, f"Scenario {scenario.scenario_id} failed: {result.violations}"


def test_boundary_attack_inquiries_handled_safely(mock_agent: MacGuardAgent) -> None:
    runner = EvaluationRunner(agent=mock_agent)
    bound_scenarios = [s for s in EVALUATION_SCENARIOS if s.category == EvaluationCategory.BOUNDARY_ATTACK]

    for scenario in bound_scenarios:
        result = runner.run_scenario(scenario)
        assert result.passed is True, f"Scenario {scenario.scenario_id} failed: {result.violations}"
