from __future__ import annotations

import json
import logging
import re
import secrets
from datetime import datetime, timezone
from typing import Any, Optional, Sequence

from app.agent.context import build_agent_llm_context
from app.agent.models import (
    AgentAction,
    AgentIntent,
    AgentObservation,
    AgentPriorityItem,
    AgentResponse,
)
from app.agent.planner import AgentPlanner
from app.agent.policies import (
    check_prompt_injection,
    prioritize_candidates,
    validate_agent_output,
)
from app.agent.prompts import AGENT_SYSTEM_PROMPT
from app.agent.state import AgentState
from app.agent.tools import AgentToolRegistry
from app.analysis.models import RiskLevel, StorageCandidate
from app.analysis.recommendations import SafetyStatus, StorageRecommendation
from app.audit.models import AuditEvent, AuditEventType
from app.audit.repository import AuditRepository
from app.llm.ollama_client import OllamaClient, OllamaClientError
from app.models.developer import DeveloperStorageSummary
from app.models.duplicate import DuplicateCluster, DuplicateScanSummary
from app.models.scan_result import ScanResult
from app.models.storage_history import StorageTrendReport
from app.tools.storage_scanner import format_bytes

logger = logging.getLogger(__name__)


class MacGuardAgent:
    """
    Intelligent Storage Orchestration Agent for MacGuard AI.

    Guarantees:
    - Advisory Only: Possesses intelligence, but zero execution or approval authority.
    - Deterministic Safety: Strictly separates verified facts from AI reasoning.
    - Defense-in-Depth: Enforces prompt injection defense, output validation, and tool allowlisting.
    - Zero Secrets: Never accesses or processes cryptographic signing keys or HMAC secrets.
    """

    def __init__(
        self,
        planner: Optional[AgentPlanner] = None,
        tool_registry: Optional[AgentToolRegistry] = None,
        llm_client: Optional[OllamaClient] = None,
        audit_repo: Optional[AuditRepository] = None,
        max_iterations: int = 5,
        max_tool_calls: int = 10,
        max_context_bytes: int = 65536,
    ) -> None:
        self._planner = planner or AgentPlanner()
        self._tool_registry = tool_registry or AgentToolRegistry()
        self._llm_client = llm_client or OllamaClient()
        self._audit_repo = audit_repo or AuditRepository()
        self._max_iterations = max_iterations
        self._max_tool_calls = max_tool_calls
        self._max_context_bytes = max_context_bytes
        self._sessions: dict[str, AgentState] = {}

    def get_or_create_state(self, session_id: Optional[str] = None) -> AgentState:
        """Retrieve or initialize state for a conversational session."""
        sid = session_id or secrets.token_hex(8)
        if sid not in self._sessions:
            self._sessions[sid] = AgentState(session_id=sid)
        return self._sessions[sid]

    def handle_request(
        self,
        user_request: str,
        candidates: Optional[Sequence[StorageCandidate]] = None,
        recommendations: Optional[Sequence[StorageRecommendation]] = None,
        scan_path: str = "/",
        session_id: Optional[str] = None,
        scan_result: Optional[ScanResult] = None,
        duplicate_clusters: Optional[Sequence[DuplicateCluster]] = None,
        duplicate_summary: Optional[DuplicateScanSummary] = None,
        developer_summary: Optional[DeveloperStorageSummary] = None,
        trend_report: Optional[StorageTrendReport] = None,
    ) -> AgentResponse:
        """
        Process a user inquiry safely through planning, allowlisted tool execution,
        deterministic prioritization, and LLM reasoning.
        """
        cands = list(candidates or [])
        recs = list(recommendations or [])
        state = self.get_or_create_state(session_id)
        sid = state.session_id

        # 1. Prompt Injection Defense
        is_injection, injection_reason = check_prompt_injection(user_request)
        if is_injection:
            self._record_audit(
                AuditEventType.AGENT_REQUEST,
                sid,
                details={"query": user_request, "status": "BLOCKED_INJECTION", "reason": injection_reason},
            )
            resp = AgentResponse(
                session_id=sid,
                intent=AgentIntent.GENERAL_QUESTION,
                action=AgentAction.NO_ACTION,
                summary="Security Policy Alert: Prohibited instruction detected.",
                explanation=(
                    f"Your request was rejected by MacGuard AI's safety guardrails. "
                    f"Reason: {injection_reason} "
                    "MacGuard AI does not allow overriding safety checks, accessing cryptographic secrets, "
                    "or executing unauthorized operations."
                ),
                deterministic_facts={"security_alert": True, "reason": injection_reason},
                requires_human_review=False,
            )
            self._record_audit(
                AuditEventType.AGENT_RESPONSE,
                sid,
                details={"response_id": resp.response_id, "action": resp.action.value, "status": "REJECTED"},
            )
            return resp

        # 2. Plan informational tool calls
        intent, planned_tool_calls = self._planner.create_plan(
            user_query=user_request,
            scan_path=scan_path,
        )

        self._record_audit(
            AuditEventType.AGENT_REQUEST,
            sid,
            details={
                "query": user_request,
                "intent": intent.value,
                "planned_tools": [tc.tool_name for tc in planned_tool_calls],
            },
        )

        # 3. Execute allowlisted tools with bounding limits
        executed_observations: list[AgentObservation] = []
        iteration_count = 0

        for tool_call in planned_tool_calls[: self._max_tool_calls]:
            if iteration_count >= self._max_iterations:
                logger.warning("Max agent iterations reached (%d). Halting tool execution.", self._max_iterations)
                break

            iteration_count += 1
            self._record_audit(
                AuditEventType.AGENT_TOOL_CALL,
                sid,
                details={"tool_name": tool_call.tool_name, "arguments": tool_call.arguments},
            )

            obs = self._tool_registry.execute_tool(
                tool_name=tool_call.tool_name,
                arguments=tool_call.arguments,
                candidates=cands,
                recommendations=recs,
                scan_result=scan_result,
                duplicate_clusters=duplicate_clusters,
                duplicate_summary=duplicate_summary,
                developer_summary=developer_summary,
                trend_report=trend_report,
            )

            self._record_audit(
                AuditEventType.AGENT_TOOL_RESULT,
                sid,
                details={"tool_name": obs.tool_name, "success": obs.success},
            )

            executed_observations.append(obs)
            state.add_tool_call(tool_call, obs)

        # 4. Deterministic Prioritization
        priorities = prioritize_candidates(cands, recs, limit=5)

        # 5. Build Granular Deterministic Facts
        total_candidate_bytes = sum(c.size_bytes for c in cands)
        eligible_recs = [r for r in recs if r.safety_status == SafetyStatus.ELIGIBLE_FOR_REVIEW.value]
        eligible_bytes = sum(r.candidate.size_bytes for r in eligible_recs)
        manual_recs = [r for r in recs if r.safety_status == SafetyStatus.MANUAL_REVIEW_REQUIRED.value]
        manual_bytes = sum(r.candidate.size_bytes for r in manual_recs)
        blocked_recs = [r for r in recs if r.safety_status == SafetyStatus.BLOCKED.value or r.candidate.risk_level == RiskLevel.HIGH]
        blocked_bytes = sum(r.candidate.size_bytes for r in blocked_recs)
        unknown_recs = [r for r in recs if r.safety_status == SafetyStatus.UNKNOWN.value or r.candidate.risk_level == RiskLevel.UNKNOWN]
        unknown_bytes = sum(r.candidate.size_bytes for r in unknown_recs)

        facts: dict[str, Any] = {
            "total_candidates_found": len(cands),
            "total_candidate_size": format_bytes(total_candidate_bytes),
            "eligible_for_cleanup_review_count": len(eligible_recs),
            "eligible_for_cleanup_review_size": format_bytes(eligible_bytes),
            "manual_review_required_count": len(manual_recs),
            "manual_review_required_size": format_bytes(manual_bytes),
            "blocked_count": len(blocked_recs),
            "blocked_size": format_bytes(blocked_bytes),
            "unknown_count": len(unknown_recs),
            "unknown_size": format_bytes(unknown_bytes),
            # Backwards-compatible aliases
            "eligible_for_review_count": len(eligible_recs),
            "eligible_for_review_size": format_bytes(eligible_bytes),
            "low_risk_count": sum(1 for c in cands if c.risk_level == RiskLevel.LOW),
            "medium_risk_count": sum(1 for c in cands if c.risk_level == RiskLevel.MEDIUM),
            "high_risk_count": sum(1 for c in cands if c.risk_level == RiskLevel.HIGH),
            "unknown_risk_count": sum(1 for c in cands if c.risk_level == RiskLevel.UNKNOWN),
        }

        # 6. Build Context for LLM Reasoner
        llm_context = build_agent_llm_context(
            user_query=user_request,
            observations=executed_observations,
            priorities=priorities,
            scan_path=scan_path,
        )

        # Truncate context if exceeding limit
        if len(llm_context.encode("utf-8")) > self._max_context_bytes:
            llm_context = llm_context[: self._max_context_bytes] + "\n[CONTEXT TRUNCATED FOR SAFETY]"

        # 7. LLM Reasoning or Fallback
        explanation_text = ""
        summary_text = ""
        fallback_used = False

        try:
            raw_llm_output = self._llm_client.generate(AGENT_SYSTEM_PROMPT, llm_context)
            is_safe, validated_or_reason = validate_agent_output(raw_llm_output)
            if is_safe:
                clean_text = self._clean_llm_response(validated_or_reason)
                explanation_text = clean_text.strip()
                summary_text = self._build_deterministic_summary(intent, facts, priorities)
            else:
                logger.warning("LLM output failed safety validation: %s", validated_or_reason)
                fallback_used = True
                summary_text, explanation_text = self._generate_deterministic_explanation(
                    intent, facts, priorities, executed_observations
                )
        except (OllamaClientError, Exception) as exc:
            logger.info("Ollama unavailable or error (%s); using deterministic analysis.", exc)
            fallback_used = True
            summary_text, explanation_text = self._generate_deterministic_explanation(
                intent, facts, priorities, executed_observations
            )

        # 8. Determine Action and Recommendations
        action = self._determine_action(intent, eligible_recs)
        requires_review = len(eligible_recs) > 0

        if len(eligible_recs) > 0:
            if len(manual_recs) > 0:
                next_step = (
                    f"Open the Human Review tab to inspect {len(eligible_recs)} low-risk item(s) "
                    f"eligible for cleanup review ({format_bytes(eligible_bytes)}), and manually inspect "
                    f"{len(manual_recs)} item(s) requiring manual review. Explicit human approval is mandatory."
                )
            else:
                next_step = (
                    f"Open the Human Review tab to inspect {len(eligible_recs)} low-risk item(s) "
                    f"eligible for cleanup review ({format_bytes(eligible_bytes)}). Explicit human approval is mandatory."
                )
        elif len(manual_recs) > 0:
            next_step = (
                f"Inspect {len(manual_recs)} item(s) ({format_bytes(manual_bytes)}) requiring manual inspection "
                "in the Findings tab. These items cannot be automatically cleaned."
            )
        else:
            next_step = "No cleanup actions recommended. All discovered items are protected or informational."

        response = AgentResponse(
            session_id=sid,
            intent=intent,
            action=action,
            summary=summary_text,
            explanation=explanation_text,
            deterministic_facts=facts,
            priorities=priorities,
            recommended_next_step=next_step,
            requires_human_review=requires_review,
            fallback_used=fallback_used,
        )

        self._record_audit(
            AuditEventType.AGENT_RESPONSE,
            sid,
            details={
                "response_id": response.response_id,
                "intent": response.intent.value,
                "action": response.action.value,
                "fallback_used": fallback_used,
            },
        )

        return response

    @staticmethod
    def _clean_llm_response(raw: str) -> str:
        """
        Normalize and clean LLM responses.
        If the model returned a JSON object or JSON code block (e.g. {"analysis_result": "..."}, {"explanation": "..."}),
        extract human-readable text so raw JSON is not rendered in the UI.
        """
        text = raw.strip()

        # Strip markdown json block if wrapped in ```json ... ``` or ``` ... ```
        json_block_match = re.match(r"^```(?:json)?\s*([\s\S]*?)\s*```$", text, re.IGNORECASE)
        if json_block_match:
            text = json_block_match.group(1).strip()

        if text.startswith("{") and text.endswith("}"):
            try:
                data = json.loads(text)
                if isinstance(data, dict):
                    # Canonical priority narrative keys
                    primary_keys = (
                        "analysis_result",
                        "analysis",
                        "result",
                        "explanation",
                        "summary",
                        "narrative",
                        "insights",
                        "response",
                        "message",
                        "answer",
                        "content",
                        "findings",
                        "description",
                        "recommendation",
                    )

                    # Direct check for primary keys
                    for key in primary_keys:
                        if key in data and isinstance(data[key], str) and data[key].strip():
                            return data[key].strip()

                    # Case-insensitive / normalized key check
                    lower_map = {k.lower().replace(" ", "_"): v for k, v in data.items()}
                    for key in primary_keys:
                        if key in lower_map and isinstance(lower_map[key], str) and lower_map[key].strip():
                            return lower_map[key].strip()

                    # If dict has a single key with a string value, return that string value
                    if len(data) == 1:
                        val = next(iter(data.values()))
                        if isinstance(val, str) and val.strip():
                            return val.strip()

                    # If multiple keys, format as readable Markdown sections
                    formatted_sections: list[str] = []
                    for k, v in data.items():
                        title = k.replace("_", " ").title()
                        if isinstance(v, (str, int, float, bool)):
                            formatted_sections.append(f"**{title}:** {v}")
                        elif isinstance(v, list):
                            items_str = "\n".join(f"- {item}" for item in v)
                            formatted_sections.append(f"**{title}:**\n{items_str}")
                    if formatted_sections:
                        return "\n\n".join(formatted_sections)
            except Exception:
                pass

        return text

    def _determine_action(
        self,
        intent: AgentIntent,
        eligible_recs: list[StorageRecommendation],
    ) -> AgentAction:
        if intent == AgentIntent.RECOMMENDATIONS_QUERY:
            return AgentAction.RECOMMEND_REVIEW if eligible_recs else AgentAction.EXPLAIN
        elif intent == AgentIntent.FIND_LARGE_FILES:
            return AgentAction.PRIORITIZE
        elif intent == AgentIntent.EXPLAIN_CANDIDATE:
            return AgentAction.EXPLAIN
        elif intent in (
            AgentIntent.STORAGE_OVERVIEW,
            AgentIntent.CATEGORY_BREAKDOWN,
            AgentIntent.STORAGE_TRENDS,
            AgentIntent.DUPLICATE_QUERY,
            AgentIntent.DEVELOPER_STORAGE_QUERY,
        ):
            return AgentAction.SUMMARIZE
        elif intent == AgentIntent.SAFETY_INQUIRY:
            return AgentAction.EXPLAIN
        return AgentAction.EXPLAIN

    def _build_deterministic_summary(
        self,
        intent: AgentIntent,
        facts: dict[str, Any],
        priorities: list[AgentPriorityItem],
    ) -> str:
        total_cands = facts.get("total_candidates_found", 0)
        total_size = facts.get("total_candidate_size", "0 B")
        eligible_count = facts.get("eligible_for_cleanup_review_count", facts.get("eligible_for_review_count", 0))
        eligible_size = facts.get("eligible_for_cleanup_review_size", facts.get("eligible_for_review_size", "0 B"))
        manual_count = facts.get("manual_review_required_count", 0)

        if total_cands == 0:
            return "No storage candidates identified in current scan."

        parts = [f"Found {total_cands} storage item(s) occupying {total_size}."]
        if eligible_count > 0:
            parts.append(f"{eligible_count} item(s) ({eligible_size}) are low-risk and eligible for cleanup review.")
        if manual_count > 0:
            parts.append(f"{manual_count} item(s) require manual user inspection.")
        if eligible_count == 0 and manual_count == 0:
            parts.append("All discovered items are protected or informational.")

        return " ".join(parts)

    def _generate_deterministic_explanation(
        self,
        intent: AgentIntent,
        facts: dict[str, Any],
        priorities: list[AgentPriorityItem],
        observations: list[AgentObservation],
    ) -> tuple[str, str]:
        """Generate a structured deterministic summary and explanation when LLM is offline."""
        summary = self._build_deterministic_summary(intent, facts, priorities)

        lines: list[str] = [
            "### MacGuard Deterministic Analysis",
            "",
            f"- **Total Storage Findings:** {facts.get('total_candidates_found', 0)} ({facts.get('total_candidate_size', '0 B')})",
            f"- **Eligible for Cleanup Review (Low Risk):** {facts.get('eligible_for_cleanup_review_count', 0)} ({facts.get('eligible_for_cleanup_review_size', '0 B')})",
            f"- **Manual Review Required (Medium Risk):** {facts.get('manual_review_required_count', 0)} ({facts.get('manual_review_required_size', '0 B')})",
            f"- **Blocked / Protected (High Risk):** {facts.get('blocked_count', 0)} ({facts.get('blocked_size', '0 B')})",
            f"- **Unclassified / Unknown Risk:** {facts.get('unknown_count', 0)} ({facts.get('unknown_size', '0 B')})",
            "",
        ]

        if priorities:
            lines.append("### Top Prioritized Candidates:")
            for p in priorities:
                lines.append(
                    f"1. **{p.path}** ({format_bytes(p.size_bytes)}) — *{p.category.value}* (Risk: {p.risk_level.value})\n"
                    f"   _{p.reasoning}_"
                )
            lines.append("")

        lines.append(
            "> **Safety Note:** MacGuard AI never deletes or moves files automatically. "
            "All cleanups require explicit human approval and verified cryptographic authorization."
        )

        return summary, "\n".join(lines)

    def _record_audit(
        self,
        event_type: AuditEventType,
        session_id: str,
        details: dict[str, Any],
    ) -> None:
        """Safely record an audit event without secrets."""
        try:
            event = AuditEvent(
                event_type=event_type,
                target_path=session_id,
                details=details,
            )
            self._audit_repo.record_event(event)
        except Exception as exc:
            logger.debug("Failed to record agent audit event: %s", exc)
