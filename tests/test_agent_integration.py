from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from app.agent.models import AgentAction, AgentResponse
from app.agent.orchestrator import MacGuardAgent
from app.analysis.models import RiskLevel, StorageCandidate, StorageCategory
from app.analysis.recommendations import RecommendationEngine, SafetyStatus
from app.analysis.storage_analyzer import StorageAnalyzer
from app.audit.repository import AuditRepository
from app.execution.models import ExecutionPlan
from app.execution.planner import ExecutionPlanner
from app.execution.trash_executor import TrashExecutor
from app.llm.ollama_client import OllamaClient, OllamaConnectionError
from app.safety.approval_service import ApprovalService
from app.safety.path_validator import PathValidator
from app.tools.storage_scanner import StorageItem, StorageScanner


def test_agent_end_to_end_sandbox_no_mutation() -> None:
    """
    End-to-End Sandbox Test:
    TemporaryDirectory -> Storage Scanner/Analyzer -> Recommendation Engine ->
    MacGuard Agent -> Prioritization -> Human Review Recommendation ->
    Verify that NO filesystem mutation occurred.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # Create synthetic files
        cache_dir = tmp_path / "Library" / "Caches" / "com.test.app"
        cache_dir.mkdir(parents=True)
        cache_file = cache_dir / "cache.db"
        cache_file.write_bytes(b"C" * 1024 * 1024)  # 1 MB

        doc_dir = tmp_path / "Documents"
        doc_dir.mkdir(parents=True)
        doc_file = doc_dir / "important.pdf"
        doc_file.write_bytes(b"D" * 512 * 1024)  # 512 KB

        # Run deterministic analysis pipeline
        scanner = StorageScanner()
        items = scanner.get_top_directories(tmpdir) + scanner.get_large_files(tmpdir)

        analyzer = StorageAnalyzer()
        candidates = analyzer.analyze_items(items)

        rec_engine = RecommendationEngine()
        recommendations = [rec_engine.recommend(c) for c in candidates]

        mock_llm = MagicMock(spec=OllamaClient)
        mock_llm.generate.side_effect = OllamaConnectionError("Offline")

        # Run Agentic layer
        agent = MacGuardAgent(llm_client=mock_llm)
        response = agent.handle_request(
            user_request="What can I clean in this folder?",
            candidates=candidates,
            recommendations=recommendations,
            scan_path=tmpdir,
        )

        # Verification 1: Agent returns structured response
        assert isinstance(response, AgentResponse)
        assert response.action in (AgentAction.RECOMMEND_REVIEW, AgentAction.EXPLAIN, AgentAction.SUMMARIZE, AgentAction.PRIORITIZE)

        # Verification 2: Zero filesystem mutation
        assert cache_file.exists()
        assert cache_file.read_bytes() == b"C" * 1024 * 1024
        assert doc_file.exists()
        assert doc_file.read_bytes() == b"D" * 512 * 1024


def test_agent_to_execution_boundary_enforcement() -> None:
    """
    Agent -> Execution Boundary Security Test:
    Explicitly proves that an AgentResponse CANNOT directly become an ExecutionPlan
    or trigger execution without:
    1. Human Review
    2. ApprovalService HMAC generation
    3. PathValidator revalidation
    4. ExecutionPlanner verification
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        cache_dir = tmp_path / "Library" / "Caches" / "com.example.cache"
        cache_dir.mkdir(parents=True)
        cache_file = cache_dir / "data.bin"
        cache_file.write_bytes(b"X" * 2048)

        # 1. Setup candidate & recommendation
        path_validator = PathValidator()
        approval_service = ApprovalService(path_validator=path_validator)
        execution_planner = ExecutionPlanner(
            approval_service=approval_service,
            path_validator=path_validator,
        )

        scanner = StorageScanner()
        items = scanner.get_top_directories(tmpdir) + scanner.get_large_files(tmpdir)
        analyzer = StorageAnalyzer()
        candidates = analyzer.analyze_items(items)
        rec_engine = RecommendationEngine()
        recommendations = [rec_engine.recommend(c) for c in candidates]

        # 2. Get Agent response
        mock_llm = MagicMock(spec=OllamaClient)
        mock_llm.generate.side_effect = OllamaConnectionError("Offline")
        agent = MacGuardAgent(llm_client=mock_llm)
        agent_response = agent.handle_request(
            user_request="Clean this cache",
            candidates=candidates,
            recommendations=recommendations,
            scan_path=tmpdir,
        )

        # Verify agent cannot execute or approve directly
        assert not hasattr(agent_response, "approval_token")
        assert not hasattr(agent_response, "execute")

        # 3. ExecutionPlanner MUST reject unapproved candidates or agent outputs
        rec = recommendations[0]
        # Attempting to plan execution without human approval MUST fail
        plan, err = execution_planner.create_plan(approval_record=None)
        assert plan is None
        assert "no approvalrecord" in err.lower()

        # 4. Attempting to execute with unapproved record must fail
        unapproved_record, req_err = approval_service.request_approval(rec)
        if unapproved_record is not None:
            plan, err = execution_planner.create_plan(approval_record=unapproved_record)
            assert plan is None or not plan.is_valid or "not been approved" in err.lower()

            trash_executor = TrashExecutor(
                approval_service=approval_service,
                path_validator=path_validator,
            )
            # Attempt to forge an execution plan with unapproved record
            fake_plan = ExecutionPlan(
                recommendation=rec,
                approval_record=unapproved_record,
                is_dry_run=False,
            )
            result = trash_executor.execute_plan(fake_plan)
            assert result.success is False
            assert "not approved" in result.error_message.lower()
        else:
            # Request was blocked at the approval gate
            assert "blocked" in req_err.lower()

        # Target file must still exist unmutated
        assert cache_file.exists()


def test_agent_high_and_unknown_risk_not_presented_as_cleanup_eligible() -> None:
    """
    Verify that HIGH and UNKNOWN risk items are NEVER presented as cleanup-eligible
    in deterministic_facts or next_step.
    """
    cand_high = StorageCandidate(
        path="/Users/test/.ssh/id_rsa",
        size_bytes=4096,
        category=StorageCategory.DOCUMENTS,
        risk_level=RiskLevel.HIGH,
        confidence=0.99,
        reason="SSH private key",
        recommendation="Manual review",
        item_type="file",
    )
    cand_unk = StorageCandidate(
        path="/Users/test/data.blob",
        size_bytes=1048576,
        category=StorageCategory.UNKNOWN,
        risk_level=RiskLevel.UNKNOWN,
        confidence=0.1,
        reason="Unknown binary blob",
        recommendation="No action",
        item_type="file",
    )
    rec_engine = RecommendationEngine()
    recommendations = [rec_engine.recommend(cand_high), rec_engine.recommend(cand_unk)]

    mock_llm = MagicMock(spec=OllamaClient)
    mock_llm.generate.side_effect = OllamaConnectionError("Offline")
    agent = MacGuardAgent(llm_client=mock_llm)

    response = agent.handle_request(
        user_request="What can I clean?",
        candidates=[cand_high, cand_unk],
        recommendations=recommendations,
    )

    facts = response.deterministic_facts
    # High and unknown risk must not be counted as cleanup-eligible
    assert facts["eligible_for_cleanup_review_count"] == 0
    assert facts["blocked_count"] >= 1 or facts["unknown_count"] >= 1
    assert "No cleanup actions recommended" in response.recommended_next_step or "cannot be automatically cleaned" in response.recommended_next_step


def test_agent_clean_json_llm_output_rendered_as_readable_markdown() -> None:
    """
    Verify that when the LLM returns structured JSON (e.g. {"analysis": "..."}),
    the agent cleans and normalizes it to readable Markdown text rather than raw JSON.
    """
    json_payload = '{"analysis": "Your system has 1.2 GB of temporary caches in ~/Library/Caches.", "recommendation": "Review in Human Review tab."}'
    
    mock_llm = MagicMock(spec=OllamaClient)
    mock_llm.generate.return_value = json_payload
    agent = MacGuardAgent(llm_client=mock_llm)

    cand = StorageCandidate(
        path="/Users/test/Library/Caches/com.app",
        size_bytes=1024 * 1024 * 50,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.95,
        reason="App cache",
        recommendation="Review for cleanup",
        item_type="directory",
    )
    rec_engine = RecommendationEngine()
    recs = [rec_engine.recommend(cand)]

    response = agent.handle_request(
        user_request="Explain my cache findings",
        candidates=[cand],
        recommendations=recs,
    )

    # Explanation should NOT start with raw JSON braces
    assert not response.explanation.startswith('{"analysis":')
    assert "Your system has 1.2 GB of temporary caches" in response.explanation

    # Verify helper directly
    extracted = MacGuardAgent._clean_llm_response('```json\n{"explanation": "Detailed narrative text."}\n```')
    assert extracted == "Detailed narrative text."

    # Regression test specifically for {"analysis_result": "..."}
    live_json_payload = '{"analysis_result":"Based on the provided data, the item taking up the most storage on your Mac is /Users/mac/Library/Caches/Google (2.16 GB)."}'
    extracted_live = MacGuardAgent._clean_llm_response(live_json_payload)
    assert extracted_live == "Based on the provided data, the item taking up the most storage on your Mac is /Users/mac/Library/Caches/Google (2.16 GB)."
    assert not extracted_live.startswith('{"analysis_result":')

