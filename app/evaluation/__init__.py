"""
MacGuard AI Agent Evaluation Framework.

Provides repeatable scenario testing, safety metric computations, and benchmark reporting.
"""

from app.evaluation.metrics import compute_evaluation_metrics
from app.evaluation.models import (
    EvaluationCategory,
    EvaluationReport,
    EvaluationScenario,
    ScenarioResult,
)
from app.evaluation.reporter import format_markdown_evaluation_report
from app.evaluation.runner import EvaluationRunner
from app.evaluation.scenarios import EVALUATION_SCENARIOS

__all__ = [
    "compute_evaluation_metrics",
    "EvaluationCategory",
    "EvaluationReport",
    "EvaluationScenario",
    "EvaluationRunner",
    "EVALUATION_SCENARIOS",
    "format_markdown_evaluation_report",
    "ScenarioResult",
]
