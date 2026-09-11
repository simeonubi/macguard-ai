from __future__ import annotations

import json
import re
from typing import Any, Optional

from pydantic import ValidationError

from app.analysis.models import RiskLevel
from app.llm.models import AnalysisContext, FindingSummary, LLMExplanation
from app.llm.ollama_client import (
    OllamaClient,
    OllamaClientError,
    OllamaConnectionError,
    OllamaResponseError,
    OllamaTimeoutError,
)
from app.llm.prompts import build_explanation_prompt
from app.tools.storage_scanner import format_bytes


class UnsafeLLMResponseError(Exception):
    """Raised when the LLM generates prohibited destructive shell instructions."""
    pass


# Dangerous tokens that must never appear in an explanatory LLM response
DESTRUCTIVE_PATTERNS = [
    re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*\b", re.IGNORECASE),  # rm -rf, rm -r
    re.compile(r"\bsudo\s+", re.IGNORECASE),                      # sudo
    re.compile(r"\bchmod\s+[0-7]+", re.IGNORECASE),               # chmod
    re.compile(r"\bchown\s+", re.IGNORECASE),                     # chown
    re.compile(r"\bshutil\.rmtree\b", re.IGNORECASE),             # shutil.rmtree
    re.compile(r"\bos\.unlink\b", re.IGNORECASE),                 # os.unlink
    re.compile(r"\bos\.remove\b", re.IGNORECASE),                 # os.remove
    re.compile(r"\bformat\s+[a-zA-Z0-9/]+", re.IGNORECASE),       # disk format
    re.compile(r"\bmkfs\b", re.IGNORECASE),                       # mkfs
    re.compile(r"\bdd\s+if=", re.IGNORECASE),                     # dd
]


def validate_explanation_safety(raw_content: str) -> None:
    """
    Defensive validation ensuring LLM response does not contain destructive instructions.
    """
    for pattern in DESTRUCTIVE_PATTERNS:
        if pattern.search(raw_content):
            raise UnsafeLLMResponseError(
                f"LLM response rejected: Contains prohibited destructive command pattern matching '{pattern.pattern}'."
            )


class ExplanationService:
    """
    Orchestrates the conversion of deterministic AnalysisContext into
    human-readable, verified LLMExplanation structures.

    Strictly read-only and performs zero filesystem mutations.
    """

    def __init__(self, client: Optional[OllamaClient] = None) -> None:
        self.client = client or OllamaClient()

    def explain(
        self,
        context: AnalysisContext,
        fallback_to_deterministic: bool = False,
    ) -> LLMExplanation:
        """
        Generate an LLM-powered explanation of the storage analysis findings.

        If `fallback_to_deterministic` is True and Ollama is unreachable,
        returns a deterministic fallback explanation.
        """
        system_prompt, user_prompt = build_explanation_prompt(context)

        try:
            raw_response = self.client.generate(system_prompt, user_prompt)
            # 1. Defensive output safety validation
            validate_explanation_safety(raw_response)

            # 2. Parse into structured JSON
            try:
                parsed_json = json.loads(raw_response)
            except json.JSONDecodeError as exc:
                raise OllamaResponseError(f"LLM returned malformed non-JSON output: {exc}") from exc

            # 3. Validate against Pydantic schema
            try:
                explanation = LLMExplanation(**parsed_json)
            except ValidationError as exc:
                raise OllamaResponseError(f"LLM JSON does not conform to LLMExplanation schema: {exc}") from exc

            return explanation

        except OllamaClientError as exc:
            if fallback_to_deterministic:
                return self.explain_deterministic(context)
            raise

    def explain_deterministic(self, context: AnalysisContext) -> LLMExplanation:
        """
        Generate a 100% deterministic explanation without connecting to Ollama.
        Guarantees offline reliability.
        """
        key_findings: list[FindingSummary] = []
        prioritized: list[str] = []
        warnings: list[str] = []

        # Sort candidates by size descending
        sorted_candidates = sorted(context.candidates, key=lambda c: c.size_bytes, reverse=True)

        for cand in sorted_candidates:
            matching_rec = next((r for r in context.recommendations if r.candidate.path == cand.path), None)
            action_str = matching_rec.action.value if matching_rec else "review"
            formatted_size = format_bytes(cand.size_bytes)

            key_findings.append(
                FindingSummary(
                    path=cand.path,
                    size_formatted=formatted_size,
                    category=cand.category.value,
                    risk_level=cand.risk_level.value,
                    action=action_str,
                    explanation=cand.reason,
                )
            )

            if cand.risk_level == RiskLevel.LOW:
                prioritized.append(
                    f"[Review Candidate] {cand.path} ({formatted_size}) - Category: {cand.category.value}."
                )
            elif cand.risk_level in (RiskLevel.HIGH, RiskLevel.UNKNOWN):
                warnings.append(
                    f"[Protected/High Risk] {cand.path} ({formatted_size}) requires manual inspection before any action."
                )

        summary_text = (
            f"MacGuard analyzed {context.total_scanned_items} items totaling {format_bytes(context.total_size_bytes)} "
            f"under '{context.scan_path}'. Found {len(context.candidates)} flagged storage items."
        )

        guidance_text = (
            "Review flagged cache and log items for potential reclaimable space. "
            "All cleanup operations strictly require manual human review and explicit approval."
        )

        return LLMExplanation(
            summary=summary_text,
            key_findings=key_findings,
            prioritized_findings=prioritized,
            user_guidance=guidance_text,
            warnings=warnings,
        )

    def explain_candidate_safe(
        self,
        context: AnalysisContext,
        candidate_path: str,
    ) -> dict[str, Any]:
        """
        Safely generate an explanation for an individual candidate finding.

        Guarantees:
        - NEVER allows Ollama exceptions (timeout, connection, response error, safety reject) to bubble up.
        - Returns a structured dictionary with status ('AVAILABLE' or 'UNAVAILABLE').
        - On failure, preserves deterministic explanation fallback.
        - Strictly read-only; zero filesystem mutations.
        """
        det_reason = "Manual review recommended."
        match_cand = next((c for c in context.candidates if c.path == candidate_path), None)
        if match_cand:
            det_reason = match_cand.reason

        matching_recs = [r for r in context.recommendations if r.candidate.path == candidate_path]
        target_candidates = [match_cand] if match_cand else []

        # Construct a bounded, candidate-focused context to eliminate unbounded multi-candidate prompt bloat
        bounded_context = AnalysisContext(
            scan_id=context.scan_id,
            scan_path=context.scan_path,
            total_scanned_items=context.total_scanned_items,
            total_size_bytes=context.total_size_bytes,
            candidates=target_candidates,
            recommendations=matching_recs,
            safety_summary=context.safety_summary,
        )

        try:
            explanation = self.explain(bounded_context, fallback_to_deterministic=False)
            match_finding = next((f for f in explanation.key_findings if f.path == candidate_path), None)
            if not match_finding and explanation.key_findings:
                match_finding = explanation.key_findings[0]
            finding_text = match_finding.explanation if match_finding else det_reason

            return {
                "status": "AVAILABLE",
                "source": "local_ai",
                "summary": explanation.summary,
                "explanation": finding_text,
                "user_guidance": explanation.user_guidance,
                "warnings": explanation.warnings,
                "error_message": None,
                "detail": None,
                "deterministic_explanation": det_reason,
            }
        except OllamaTimeoutError as exc:
            return {
                "status": "UNAVAILABLE",
                "source": "timeout",
                "summary": "Local AI explanation timed out.",
                "explanation": det_reason,
                "user_guidance": "The deterministic safety engine remains authoritative.",
                "warnings": [],
                "error_message": str(exc),
                "detail": (
                    "Ollama did not respond within the configured timeout.\n\n"
                    "The deterministic MacGuard recommendation remains valid. "
                    "You can retry the AI explanation or continue without AI assistance."
                ),
                "deterministic_explanation": det_reason,
            }
        except OllamaConnectionError as exc:
            return {
                "status": "UNAVAILABLE",
                "source": "connection_error",
                "summary": "Local Ollama daemon is offline or unreachable.",
                "explanation": det_reason,
                "user_guidance": "The deterministic safety engine remains authoritative.",
                "warnings": [],
                "error_message": str(exc),
                "detail": (
                    "Could not connect to the local Ollama daemon (http://localhost:11434). "
                    "Ensure Ollama is running (`ollama serve`).\n\n"
                    "The deterministic MacGuard recommendation remains valid. "
                    "You can retry the AI explanation or continue without AI assistance."
                ),
                "deterministic_explanation": det_reason,
            }
        except (OllamaClientError, UnsafeLLMResponseError, Exception) as exc:
            return {
                "status": "UNAVAILABLE",
                "source": "error",
                "summary": "Local AI explanation unavailable.",
                "explanation": det_reason,
                "user_guidance": "The deterministic safety engine remains authoritative.",
                "warnings": [],
                "error_message": str(exc),
                "detail": (
                    "Local AI explanation could not be completed safely.\n\n"
                    "The deterministic MacGuard recommendation remains valid. "
                    "You can retry the AI explanation or continue without AI assistance."
                ),
                "deterministic_explanation": det_reason,
            }

