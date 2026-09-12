"""
MacGuard AI Phase 12 — Ollama Storage Investigation Reasoning Engine.

Enables local Ollama LLM to reason over deterministic StorageInvestigationEvidence,
explain "Why is my Mac full?", identify dependencies, and recommend investigation priorities.

ABSOLUTE SAFETY & GROUNDING INVARIANTS:
1. READ-ONLY ADVISORY: Ollama has ZERO filesystem mutation authority.
2. EVIDENCE ID GROUNDING: Ollama MUST reference evidence strictly by evidence_id.
   Any recommendation referencing an invalid/hallucinated evidence_id or inventing arbitrary paths is rejected.
3. DETERMINISTIC TOTALS: All storage totals, free space, and reclaimable bytes are computed
   deterministically by MacGuard. Ollama cannot alter or define numbers.
4. DEFENSIVE VALIDATION: Rejects destructive commands (rm -rf, sudo, dd) and malformed schemas.
5. DETERMINISTIC FALLBACK: Generates 100% deterministic investigation reports if Ollama is unavailable.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from pydantic import BaseModel, Field, ValidationError

from app.llm.explanation_service import DESTRUCTIVE_PATTERNS, UnsafeLLMResponseError, validate_explanation_safety
from app.llm.ollama_client import (
    OllamaClient,
    OllamaClientError,
    OllamaConnectionError,
    OllamaResponseError,
    OllamaTimeoutError,
)
from app.models.investigation import (
    CleanupPlan,
    LLMReasonedFinding,
    ReclaimConfidence,
    StorageEvidenceItem,
    StorageInvestigationEvidence,
    StorageInvestigationResult,
)
from app.tools.storage_scanner import format_bytes


class RawLLMInvestigationOutput(BaseModel):
    """Schema expected from Ollama for storage investigation reasoning."""

    summary_text: str = Field(default="")
    severity: str = Field(default="INFO")  # HEALTHY, WARNING, CRITICAL
    reasoning_notes: list[str] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)


SYSTEM_INVESTIGATION_PROMPT = """You are a storage investigation assistant for MacGuard AI.
Reason ONLY from the supplied structured evidence.
Do not invent paths, sizes, applications, dependencies, or cleanup actions.
You have no filesystem authority. You cannot delete, move, modify, approve, or execute anything.
Your role is to analyze evidence, explain why data exists, and recommend review priority.

CRITICAL RULES:
1. Every finding in your response MUST include an 'evidence_id' exactly matching one from the evidence list.
2. Never invent arbitrary file paths or shell commands.
3. Never output destructive instructions such as rm, sudo, or deletion scripts.
4. Output valid JSON matching the following schema:
{
  "summary_text": "Executive summary explaining why storage is full and key findings",
  "severity": "CRITICAL" | "WARNING" | "HEALTHY",
  "reasoning_notes": ["Key observation 1", "Key observation 2"],
  "findings": [
    {
      "evidence_id": "ev_cache_001",
      "why_it_exists": "Cached data created by browser",
      "why_safe_or_unsafe": "Safe to remove; will be recreated on launch",
      "consequence": "Minor initial load time increase on next launch",
      "recommended_priority": 1
    }
  ]
}
"""


class OllamaStorageInvestigator:
    """
    Orchestrates Ollama reasoning over deterministic storage evidence.
    """

    def __init__(self, client: Optional[OllamaClient] = None) -> None:
        self.client = client or OllamaClient()

    def build_evidence_payload(self, evidence: StorageInvestigationEvidence) -> str:
        """
        Build a compact, bounded JSON payload of evidence items for the LLM.
        """
        items_summary = []
        # Sort by size descending and bound to top 15 items to eliminate unbounded prompt bloat
        sorted_items = sorted(evidence.items, key=lambda x: x.size_bytes, reverse=True)[:15]
        for it in sorted_items:
            items_summary.append({
                "evidence_id": it.evidence_id,
                "category": it.category.value,
                "subcategory": it.subcategory,
                "path": it.path,
                "size_formatted": it.size_human,
                "size_bytes": it.size_bytes,
                "is_cache": it.is_cache,
                "is_developer": it.is_developer,
                "is_docker": it.is_docker,
                "is_ai_ml": it.is_ai_ml,
                "risk_level": it.risk_level.value,
                "reclaim_confidence": it.reclaim_confidence.value,
                "currently_in_use": it.currently_in_use,
                "associated_processes": it.associated_processes,
                "associated_app_running": it.associated_application_running,
                "recently_modified": it.recently_modified,
                "dependency_evidence": it.dependency_evidence,
                "evidence_notes": it.evidence_notes,
            })

        payload = {
            "physical_disk_total": evidence.disk_total_human,
            "physical_disk_used": evidence.disk_used_human,
            "physical_disk_free": evidence.disk_free_human,
            "macguard_analyzed_bytes": evidence.analyzed_human,
            "reclaimable_high_confidence": format_bytes(evidence.reclaimable_high_confidence_bytes),
            "reclaimable_review_required": format_bytes(evidence.reclaimable_review_required_bytes),
            "protected_storage": format_bytes(evidence.protected_bytes),
            "evidence_items": items_summary,
        }
        return json.dumps(payload, indent=2)

    def investigate(
        self,
        evidence: StorageInvestigationEvidence,
        cleanup_plan: CleanupPlan,
        fallback_to_deterministic: bool = True,
    ) -> StorageInvestigationResult:
        """
        Execute Ollama reasoning over storage evidence with defensive validation and deterministic fallback.
        """
        user_prompt = f"Analyze this MacGuard storage investigation evidence:\n\n{self.build_evidence_payload(evidence)}"

        try:
            raw_response = self.client.generate(SYSTEM_INVESTIGATION_PROMPT, user_prompt)

            # 1. Prohibited destructive pattern validation
            validate_explanation_safety(raw_response)

            # 2. JSON parsing
            try:
                parsed_json = json.loads(raw_response)
            except json.JSONDecodeError as exc:
                raise OllamaResponseError(f"LLM returned non-JSON output: {exc}") from exc

            # 3. Schema validation
            try:
                raw_out = RawLLMInvestigationOutput(**parsed_json)
            except ValidationError as exc:
                raise OllamaResponseError(f"LLM output failed schema validation: {exc}") from exc

            # 4. Strict Evidence ID Grounding & Hallucination Rejection
            valid_ids = {it.evidence_id: it for it in evidence.items}
            validated_findings: list[LLMReasonedFinding] = []

            for f_dict in raw_out.findings:
                ev_id = f_dict.get("evidence_id")
                if not ev_id or ev_id not in valid_ids:
                    # REJECT hallucinated or invalid evidence IDs
                    continue

                # Ensure no injected shell commands in explanation text
                why_exists = str(f_dict.get("why_it_exists", ""))
                why_safe = str(f_dict.get("why_safe_or_unsafe", ""))
                consequence = str(f_dict.get("consequence", ""))
                validate_explanation_safety(f"{why_exists} {why_safe} {consequence}")

                prio = int(f_dict.get("recommended_priority", 999))
                validated_findings.append(
                    LLMReasonedFinding(
                        evidence_id=ev_id,
                        why_it_exists=why_exists,
                        why_safe_or_unsafe=why_safe,
                        consequence=consequence,
                        recommended_priority=max(1, prio),
                    )
                )

            # Sort validated findings by recommended priority
            validated_findings.sort(key=lambda f: f.recommended_priority)

            severity = raw_out.severity.upper()
            if severity not in ("CRITICAL", "WARNING", "HEALTHY"):
                severity = "INFO"

            return StorageInvestigationResult(
                evidence=evidence,
                cleanup_plan=cleanup_plan,
                summary_text=raw_out.summary_text or f"Storage investigation completed. {evidence.total_reclaimable_human} potentially reclaimable.",
                severity=severity,
                reasoning_notes=raw_out.reasoning_notes,
                llm_findings=validated_findings,
                is_ai_reasoned=True,
                ai_status_message="Reasoned with local AI (Ollama).",
            )

        except (OllamaClientError, UnsafeLLMResponseError, Exception) as exc:
            if fallback_to_deterministic:
                return self.investigate_deterministic(evidence, cleanup_plan, status_message=str(exc))
            raise

    def investigate_deterministic(
        self,
        evidence: StorageInvestigationEvidence,
        cleanup_plan: CleanupPlan,
        status_message: Optional[str] = None,
    ) -> StorageInvestigationResult:
        """
        Generate a 100% deterministic investigation report without Ollama.
        Guarantees complete functionality when Ollama is offline or unavailable.
        """
        severity = "HEALTHY"
        if evidence.disk_free_bytes < 10 * 1024 * 1024 * 1024:  # Under 10GB free
            severity = "CRITICAL"
        elif evidence.disk_free_bytes < 30 * 1024 * 1024 * 1024:  # Under 30GB free
            severity = "WARNING"

        notes: list[str] = [
            f"Physical disk usage: {evidence.disk_used_human} used / {evidence.disk_free_human} free of {evidence.disk_total_human}.",
            f"MacGuard analyzed {evidence.analyzed_human} across user-accessible storage locations.",
            f"High confidence reclaimable storage: {format_bytes(evidence.reclaimable_high_confidence_bytes)}.",
            f"Review recommended storage: {format_bytes(evidence.reclaimable_review_required_bytes)}.",
            f"Protected storage: {format_bytes(evidence.protected_bytes)}.",
        ]

        if evidence.macos_system_data_reported_bytes:
            notes.append(
                f"macOS reports {format_bytes(evidence.macos_system_data_reported_bytes)} as System Data. "
                f"MacGuard identified {evidence.analyzed_human} of user-accessible storage that may contribute to storage pressure."
            )

        findings: list[LLMReasonedFinding] = []
        for idx, item in enumerate(evidence.top_consumers[:15], start=1):
            findings.append(
                LLMReasonedFinding(
                    evidence_id=item.evidence_id,
                    why_it_exists=item.evidence_notes or f"Generated {item.category.value} storage.",
                    why_safe_or_unsafe=item.dependency_evidence or ("Eligible for review" if item.cleanup_allowed else "Protected by safety rules"),
                    consequence=item.cleanup_consequence or "Item will be moved to macOS Trash upon explicit human approval.",
                    recommended_priority=idx,
                )
            )

        summary = (
            f"MacGuard Storage Health: {evidence.disk_free_human} free on physical disk. "
            f"Found {len(evidence.items)} storage consumer items. "
            f"Potentially reclaimable: {evidence.total_reclaimable_human} "
            f"({format_bytes(evidence.reclaimable_high_confidence_bytes)} safe, "
            f"{format_bytes(evidence.reclaimable_review_required_bytes)} review required)."
        )

        msg = "Local AI unavailable — showing deterministic storage investigation."
        if status_message:
            msg = f"Local AI unavailable ({status_message}) — showing deterministic storage investigation."

        return StorageInvestigationResult(
            evidence=evidence,
            cleanup_plan=cleanup_plan,
            summary_text=summary,
            severity=severity,
            reasoning_notes=notes,
            llm_findings=findings,
            is_ai_reasoned=False,
            ai_status_message=msg,
        )
