from __future__ import annotations

from typing import Optional
import streamlit as st

from app.analysis.models import RiskLevel, StorageCategory
from app.analysis.recommendations import SafetyStatus
from app.tools.storage_scanner import format_bytes


def alias_and_redact_path(path_str: str) -> str:
    """Home-alias and sanitize/redact sensitive directories for safe UI display."""
    if not path_str:
        return ""
    try:
        home_str = str(Path.home().resolve())
        if path_str.startswith(home_str):
            path_str = "~" + path_str[len(home_str):]
    except Exception:
        pass

    for sensitive in [".ssh", ".aws", ".gnupg", "Keychains", "Cookies", "Messages", "Mail", "IdentityServices"]:
        if sensitive in path_str:
            parts = path_str.split(sensitive)
            return parts[0] + f"{sensitive}/[REDACTED]"
    return path_str


def render_brand_header() -> None:
    """Render top product header and operating badge."""
    col1, col2 = st.columns([3, 1])
    with col1:
        st.title("🛡️ MacGuard AI")
        st.caption("Safety-First macOS Storage Intelligence & Controlled Cleanup")
    with col2:
        mode = st.session_state.get("current_mode", "ANALYZE")
        mode_colors = {
            "ANALYZE": "🔵 ANALYZE (Read-Only)",
            "REVIEW": "🟡 REVIEW (Human Confirmation)",
            "CLEAN": "🟢 CLEAN (Controlled Trash)",
        }
        st.markdown(f"**Current Mode:**\n`{mode_colors.get(mode, mode)}`")
        if st.session_state.get("is_demo_mode", False):
            st.markdown("🧪 **DEMO DATA / SANDBOX** *(Synthetic • Zero Real Impact)*")


def render_safety_notice(context: str = "general") -> None:
    """Render standardized safety boundary notice."""
    if st.session_state.get("is_demo_mode", False):
        st.info(
            "🧪 **PRESENTATION DEMO DATA / SANDBOX ACTIVE**: "
            "All displayed paths and metrics are synthetic presentation items. "
            "Real filesystem operations, approvals, and mutations are completely isolated and cannot affect your actual filesystem or audit history."
        )

    if context == "general":
        st.info(
            "🔒 **MacGuard Safety Invariant**: Permanent deletion is **disabled**. "
            "MacGuard AI only moves explicitly approved, allowlisted items to macOS Trash "
            "(`~/.Trash`) with pre- and post-mutation integrity verification."
        )
    elif context == "review":
        st.warning(
            "⚠️ **Human Review Boundary**: Approvals require conscious, explicit consent. "
            "Granting an approval generates a cryptographic HMAC-SHA256 authorization record. "
            "Approval does not delete files — it only authorizes controlled moving to Trash."
        )
    elif context == "execution":
        st.error(
            "🛡️ **Pre-Execution Check**: Before moving any item, MacGuard will re-verify the HMAC signature, "
            "confirm path containment, inspect non-following `os.lstat()` metadata against pre-execution snapshots, "
            "and verify post-move integrity. Fails closed on any unexpected state."
        )


def risk_badge(risk: RiskLevel) -> str:
    """Return a styled risk badge string."""
    if risk == RiskLevel.LOW:
        return "🟢 **LOW RISK**"
    elif risk == RiskLevel.MEDIUM:
        return "🟡 **MEDIUM RISK**"
    elif risk == RiskLevel.HIGH:
        return "🔴 **HIGH RISK (Protected)**"
    else:
        return "⚪ **UNKNOWN RISK (Conservative)**"


def safety_status_badge(status: SafetyStatus) -> str:
    """Return a styled safety status badge."""
    if status == SafetyStatus.ELIGIBLE_FOR_REVIEW:
        return "✅ **Eligible for Human Review**"
    elif status == SafetyStatus.MANUAL_REVIEW_REQUIRED:
        return "⚠️ **Manual Review Required**"
    else:
        return "🚫 **Blocked / No Action**"


def render_storage_stats_cards(
    total_bytes: int,
    used_bytes: int,
    free_bytes: int,
    usage_percent: float,
) -> None:
    """Render summary metric cards for system disk storage consumption."""
    from app.tools.storage_scanner import format_bytes_binary, format_bytes_decimal

    st.markdown("#### 🖥️ **System Disk State (Physical Filesystem)**")
    cols = st.columns(4)
    with cols[0]:
        st.metric(
            "Total Disk Capacity",
            format_bytes_decimal(total_bytes),
            help=f"Decimal: {format_bytes_decimal(total_bytes)} | Binary: {format_bytes_binary(total_bytes)} ({total_bytes:,} bytes)",
        )
    with cols[1]:
        st.metric(
            "System Used Space",
            format_bytes_decimal(used_bytes),
            help=f"Strong Alignment — live filesystem measurement ({format_bytes_decimal(used_bytes)} / {format_bytes_binary(used_bytes)}); minor difference from macOS Storage UI due to dynamic snapshot/purgeable calculation.",
        )
    with cols[2]:
        st.metric(
            "System Free Space",
            format_bytes_decimal(free_bytes),
            help=f"Live filesystem available capacity: {format_bytes_decimal(free_bytes)} ({format_bytes_binary(free_bytes)}).",
        )
    with cols[3]:
        st.metric(
            "Disk Allocation",
            f"{usage_percent:.1f}%",
            help="Physical APFS container disk allocation percentage.",
        )


from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence, Union


@dataclass(frozen=True)
class HierarchyPresentation:
    """Presentation metadata for nested/hierarchical candidate relationships."""
    path: str
    is_nested: bool
    parent_path: Optional[str]
    parent_name: Optional[str]
    children_paths: list[str]
    hierarchy_badge: str
    display_prefix: str
    size_note: str


def get_item_hierarchy_info(items: Sequence[Any]) -> dict[str, HierarchyPresentation]:
    """
    Calculate parent-child hierarchy presentation metadata for a sequence of
    StorageItem, StorageCandidate, StorageRecommendation, or ReviewItem objects.

    Guarantees:
    - Identifies nested paths contained inside higher-level directory candidates.
    - Prevents visual ambiguity: clearly tags nested items as 'Included in parent'.
    - Performs zero filesystem mutation.
    """
    from app.safety.canonicalizer import canonicalize_path, is_contained_within

    if not items:
        return {}

    # Extract raw path string from any supported object type
    extracted_paths: list[str] = []
    for it in items:
        if hasattr(it, "path"):
            extracted_paths.append(str(it.path))
        elif hasattr(it, "candidate") and hasattr(it.candidate, "path"):
            extracted_paths.append(str(it.candidate.path))
        elif hasattr(it, "canonical_path"):
            extracted_paths.append(str(it.canonical_path))
        elif isinstance(it, dict) and "path" in it:
            extracted_paths.append(str(it["path"]))
        elif isinstance(it, str):
            extracted_paths.append(it)

    # Resolve canonical paths
    resolved: list[tuple[str, Path]] = []
    for raw in extracted_paths:
        try:
            canon = canonicalize_path(raw).canonical_path
        except Exception:
            canon = Path(raw).expanduser().resolve()
        resolved.append((raw, canon))

    result: dict[str, HierarchyPresentation] = {}

    for raw, canon in resolved:
        # Find deepest ancestor in the list
        deepest_parent_raw: Optional[str] = None
        deepest_parent_canon: Optional[Path] = None

        children_raw: list[str] = []

        for other_raw, other_canon in resolved:
            if other_raw == raw:
                continue

            # Check if other is parent of current
            try:
                if is_contained_within(canon, other_canon):
                    if deepest_parent_canon is None or len(other_canon.parts) > len(deepest_parent_canon.parts):
                        deepest_parent_raw = other_raw
                        deepest_parent_canon = other_canon
            except Exception:
                pass

            # Check if other is child of current
            try:
                if is_contained_within(other_canon, canon):
                    children_raw.append(other_raw)
            except Exception:
                pass

        if deepest_parent_raw is not None:
            parent_name = Path(deepest_parent_raw).name or deepest_parent_raw
            result[raw] = HierarchyPresentation(
                path=raw,
                is_nested=True,
                parent_path=deepest_parent_raw,
                parent_name=parent_name,
                children_paths=children_raw,
                hierarchy_badge=f"↳ Included in parent candidate ({parent_name})",
                display_prefix="  ↳ ",
                size_note=f"Included in parent candidate ({parent_name}) — not additive",
            )
        elif children_raw:
            child_count = len(children_raw)
            result[raw] = HierarchyPresentation(
                path=raw,
                is_nested=False,
                parent_path=None,
                parent_name=None,
                children_paths=children_raw,
                hierarchy_badge=f"📂 Container Parent (Includes {child_count} nested item{'s' if child_count > 1 else ''})",
                display_prefix="",
                size_note=f"Total container size; includes {child_count} nested item(s)",
            )
        else:
            result[raw] = HierarchyPresentation(
                path=raw,
                is_nested=False,
                parent_path=None,
                parent_name=None,
                children_paths=[],
                hierarchy_badge="Top-level Candidate",
                display_prefix="",
                size_note="Direct candidate",
            )

    return result


