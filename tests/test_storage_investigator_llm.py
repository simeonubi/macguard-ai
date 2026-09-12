"""
Unit and adversarial security tests for Phase 12 Ollama Storage Reasoner.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from app.analysis.models import RiskLevel
from app.llm.ollama_client import OllamaClient, OllamaConnectionError, OllamaTimeoutError
from app.llm.storage_investigator_llm import OllamaStorageInvestigator
from app.models.category import SmartCategory
from app.models.investigation import (
    CleanupPlan,
    CleanupPlanItem,
    InvestigationLevel,
    ReclaimConfidence,
    StorageEvidenceItem,
    StorageInvestigationEvidence,
)


@pytest.fixture
def sample_evidence_and_plan() -> tuple[StorageInvestigationEvidence, CleanupPlan]:
    item1 = StorageEvidenceItem(
        evidence_id="ev_cache_001",
        path="/Users/test/Library/Caches/com.apple.Safari",
        canonical_path="/Users/test/Library/Caches/com.apple.Safari",
        size_bytes=100_000_000,
        category=SmartCategory.CACHES,
        risk_level=RiskLevel.LOW,
        reclaim_confidence=ReclaimConfidence.HIGH_CONFIDENCE,
        cleanup_allowed=True,
    )
    item2 = StorageEvidenceItem(
        evidence_id="ev_docker_002",
        path="/Users/test/Library/Containers/com.docker.docker",
        canonical_path="/Users/test/Library/Containers/com.docker.docker",
        size_bytes=500_000_000,
        category=SmartCategory.CONTAINERS,
        risk_level=RiskLevel.HIGH,
        reclaim_confidence=ReclaimConfidence.PROTECTED,
        cleanup_allowed=False,
    )

    evidence = StorageInvestigationEvidence(
        investigation_id="inv_test_llm",
        level=InvestigationLevel.TARGETED,
        target_path="/Users/test",
        disk_total_bytes=500_000_000_000,
        disk_used_bytes=400_000_000_000,
        disk_free_bytes=100_000_000_000,
        analyzed_bytes=600_000_000,
        candidate_inventory_bytes=600_000_000,
        eligible_for_review_bytes=100_000_000,
        reclaimable_high_confidence_bytes=100_000_000,
        reclaimable_review_required_bytes=0,
        protected_bytes=500_000_000,
        items=[item1, item2],
        top_consumers=[item2, item1],
    )

    plan = CleanupPlan(
        high_confidence_items=[
            CleanupPlanItem(
                evidence_id=item1.evidence_id,
                path=item1.path,
                canonical_path=item1.canonical_path,
                size_bytes=item1.size_bytes,
                category=item1.category,
                subcategory=item1.subcategory,
                tier=ReclaimConfidence.HIGH_CONFIDENCE,
                requires_review=False,
            )
        ],
        total_reclaimable_bytes=100_000_000,
        high_confidence_bytes=100_000_000,
    )

    return evidence, plan


def test_ollama_investigator_successful_reasoning(sample_evidence_and_plan) -> None:
    evidence, plan = sample_evidence_and_plan
    mock_client = MagicMock(spec=OllamaClient)
    mock_client.generate.return_value = json.dumps({
        "summary_text": "Your Mac has 100 MB of safe cache that can be reclaimed.",
        "severity": "HEALTHY",
        "reasoning_notes": ["Safari cache is the primary safe recovery target."],
        "findings": [
            {
                "evidence_id": "ev_cache_001",
                "why_it_exists": "Safari browser temporary cache.",
                "why_safe_or_unsafe": "Safe to remove; will be recreated automatically.",
                "consequence": "None; pages reload slightly slower on first visit.",
                "recommended_priority": 1,
            }
        ],
    })

    investigator = OllamaStorageInvestigator(client=mock_client)
    result = investigator.investigate(evidence, plan)

    assert result.is_ai_reasoned is True
    assert len(result.llm_findings) == 1
    assert result.llm_findings[0].evidence_id == "ev_cache_001"
    assert result.evidence.total_reclaimable_bytes == 100_000_000  # Deterministic number preserved


def test_ollama_investigator_hallucinated_id_rejection(sample_evidence_and_plan) -> None:
    """Ensure recommendations with hallucinated or non-existent evidence IDs are rejected."""
    evidence, plan = sample_evidence_and_plan
    mock_client = MagicMock(spec=OllamaClient)
    mock_client.generate.return_value = json.dumps({
        "summary_text": "Hallucinated recommendations.",
        "severity": "WARNING",
        "reasoning_notes": [],
        "findings": [
            {
                "evidence_id": "ev_fake_999",  # Does NOT exist in evidence
                "why_it_exists": "Fake data",
                "why_safe_or_unsafe": "Fake safety",
                "consequence": "Fake",
                "recommended_priority": 1,
            }
        ],
    })

    investigator = OllamaStorageInvestigator(client=mock_client)
    result = investigator.investigate(evidence, plan)

    # The hallucinated finding must be rejected
    assert len(result.llm_findings) == 0


def test_ollama_investigator_destructive_command_rejection(sample_evidence_and_plan) -> None:
    """Ensure LLM outputs containing destructive patterns (e.g. rm -rf, sudo) are rejected and fall back."""
    evidence, plan = sample_evidence_and_plan
    mock_client = MagicMock(spec=OllamaClient)
    mock_client.generate.return_value = json.dumps({
        "summary_text": "Run sudo rm -rf /System to free space",
        "severity": "CRITICAL",
        "reasoning_notes": [],
        "findings": [],
    })

    investigator = OllamaStorageInvestigator(client=mock_client)
    result = investigator.investigate(evidence, plan, fallback_to_deterministic=True)

    assert result.is_ai_reasoned is False  # Fell back to deterministic
    assert "sudo rm -rf" not in result.summary_text


def test_ollama_investigator_offline_fallback(sample_evidence_and_plan) -> None:
    evidence, plan = sample_evidence_and_plan
    mock_client = MagicMock(spec=OllamaClient)
    mock_client.generate.side_effect = OllamaConnectionError("Connection refused")

    investigator = OllamaStorageInvestigator(client=mock_client)
    result = investigator.investigate(evidence, plan, fallback_to_deterministic=True)

    assert result.is_ai_reasoned is False
    assert "Local AI unavailable" in (result.ai_status_message or "")
    assert result.evidence.total_reclaimable_bytes == 100_000_000
    assert len(result.llm_findings) >= 1  # Deterministic findings populated
