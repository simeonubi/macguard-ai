from __future__ import annotations

import re
from typing import Sequence

from app.agent.models import AgentPriorityItem
from app.analysis.models import RiskLevel, StorageCandidate, StorageCategory
from app.analysis.recommendations import SafetyStatus, StorageRecommendation

# Patterns that indicate prompt injection or attempts to subvert safety controls
_PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(previous|all|safety|policy|policies|restrictions)", re.IGNORECASE),
    re.compile(r"disable\s+(safety|validator|protection|engine)", re.IGNORECASE),
    re.compile(r"give\s+me\s+(the\s+)?(hmac|secret|key|signing)", re.IGNORECASE),
    re.compile(r"approve\s+(this\s+)?(automatically|all|without\s+review)", re.IGNORECASE),
    re.compile(r"call\s+(the\s+)?(executor|trash_executor|planner)\s+directly", re.IGNORECASE),
    re.compile(r"\b(delete|clean|remove|erase|wipe|purge)\s+(this|all|everything|my|the)\b", re.IGNORECASE),
    re.compile(r"\b(execute|run)\s+(the\s+)?(cleanup|purge|wipe|deletion|shell)\b", re.IGNORECASE),
    re.compile(r"\b(pretend\s+i\s+already\s+approved|bypass\s+(the\s+)?human\s+approval|override\s+safety)\b", re.IGNORECASE),
    re.compile(r"\b(environment\s+variables|internal\s+secrets|show.*secret|generate.*approval\s+token)\b", re.IGNORECASE),
    re.compile(r"system\s+administrator\s+says", re.IGNORECASE),
    re.compile(r"rm\s+-rf", re.IGNORECASE),
    re.compile(r"os\.(remove|unlink|system)", re.IGNORECASE),
    re.compile(r"subprocess\.", re.IGNORECASE),
    re.compile(r"\b(grew|increased|jumped|growth)\b.*?\b(delete|clean|remove|purge|wipe|approve)\b", re.IGNORECASE),
    re.compile(r"\b(trend|duplicate\s+detector|historical\s+growth|scan\s+history)\b.*?\b(authoriz|approv|permi|justif)\b", re.IGNORECASE),
    re.compile(r"\b(user\s+already\s+approved|already\s+(been\s+)?granted\s+approval|approval\s+has\s+already\s+been\s+granted|i\s+am\s+the\s+administrator|bypass\s+approval)\b", re.IGNORECASE),
    re.compile(r"\b(print|show|give|display|extract|dump|reveal)\b.*?\b(hmac|secret|key|token|signing)\b", re.IGNORECASE),
    re.compile(r"\b(use\s+(the\s+)?trend\s+report\s+as\s+authorization|trend\s+proves\s+safe)\b", re.IGNORECASE),
    re.compile(r"\b(duplicate\s+detector\s+says\s+these\s+files\s+should\s+be\s+deleted|delete\s+duplicates\s+automatically)\b", re.IGNORECASE),
]

# Patterns in generated LLM text that falsely claim execution authority or bypass safety
_UNSAFE_OUTPUT_PATTERNS = [
    re.compile(r"\b(i\s+have\s+deleted|i\s+deleted|i\s+have\s+moved|i\s+moved|i\s+cleaned)\b", re.IGNORECASE),
    re.compile(r"\b(i\s+have\s+approved|i\s+authorized|i\s+signed)\b", re.IGNORECASE),
    re.compile(r"\b(executing\s+deletion|performing\s+purge|wiping\s+disk)\b", re.IGNORECASE),
    re.compile(r"\b(sudo\s+rm|rm\s+-rf|rmdir)\b", re.IGNORECASE),
]


def check_prompt_injection(user_input: str) -> tuple[bool, str]:
    """
    Check if a user prompt contains injection attempts or safety circumvention requests.

    Returns:
        (is_injection, reason)
    """
    for pattern in _PROMPT_INJECTION_PATTERNS:
        if pattern.search(user_input):
            return True, "User prompt contains prohibited instructions attempting to override safety policies or access secrets."
    return False, ""


def validate_agent_output(output_text: str) -> tuple[bool, str]:
    """
    Verify that an AI agent response does not falsely claim execution authority
    or provide destructive command instructions.

    Returns:
        (is_safe, sanitized_or_rejection_reason)
    """
    for pattern in _UNSAFE_OUTPUT_PATTERNS:
        if pattern.search(output_text):
            return False, "Agent output was rejected because it attempted to claim execution authority or output destructive instructions."
    return True, output_text


def prioritize_candidates(
    candidates: Sequence[StorageCandidate],
    recommendations: Sequence[StorageRecommendation],
    limit: int = 10,
) -> list[AgentPriorityItem]:
    """
    Deterministically prioritize storage candidates based on:
    1. Risk level (LOW risk eligible items first for review)
    2. Size (largest first)
    3. Category (Caches and Logs before App Data)
    4. Confidence

    Invariant: HIGH and UNKNOWN risk items are never promoted to automated cleanup status.
    """
    rec_map = {r.candidate.path: r for r in recommendations}
    priorities: list[AgentPriorityItem] = []

    # Helper scoring function (higher score = higher priority for review)
    def calculate_priority_score(c: StorageCandidate) -> tuple[int, int, int]:
        rec = rec_map.get(c.path)
        # Priority tier:
        # Tier 3: LOW risk Cache / Logs (Eligible for Review)
        # Tier 2: MEDIUM risk Developer / App Data (Manual Review)
        # Tier 1: HIGH risk / UNKNOWN (Protected / Conservative)
        if c.risk_level == RiskLevel.LOW and rec and rec.safety_status == SafetyStatus.ELIGIBLE_FOR_REVIEW.value:
            tier = 3
        elif c.risk_level == RiskLevel.MEDIUM:
            tier = 2
        else:
            tier = 1

        return (tier, c.size_bytes, int(c.confidence * 100))

    sorted_cands = sorted(candidates, key=calculate_priority_score, reverse=True)[:limit]

    for rank, c in enumerate(sorted_cands, start=1):
        rec = rec_map.get(c.path)
        safety_status = rec.safety_status if rec else SafetyStatus.UNKNOWN.value

        if c.risk_level == RiskLevel.LOW:
            reason = f"Ranked #{rank} due to significant size ({c.size_bytes} B) and LOW risk ({c.category.value}). Eligible for human review."
        elif c.risk_level == RiskLevel.MEDIUM:
            reason = f"Ranked #{rank} for manual inspection. Medium risk {c.category.value} requiring developer/user review."
        else:
            reason = f"Ranked #{rank} for awareness only. Protected or unclassified data (Risk: {c.risk_level.value}). Automated cleanup is blocked."

        priorities.append(
            AgentPriorityItem(
                priority_rank=rank,
                path=c.path,
                size_bytes=c.size_bytes,
                category=c.category,
                risk_level=c.risk_level,
                safety_status=safety_status,
                reasoning=reason,
            )
        )

    return priorities
