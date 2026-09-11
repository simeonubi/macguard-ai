from __future__ import annotations

from typing import Optional
import streamlit as st

from app.analysis.models import RiskLevel
from app.safety.approval import ApprovalRecord
from app.safety.path_validator import Operation
from app.safety.review import ApprovalStatus, ReviewItem
from app.tools.storage_scanner import format_bytes
from app.ui.components import (
    get_item_hierarchy_info,
    render_brand_header,
    render_safety_notice,
    risk_badge,
    safety_status_badge,
)
from app.ui.state import get_services, init_app_state, navigate_to


def render_review_page() -> None:
    """Render the Human Review & Explicit Approval page."""
    init_app_state()
    services = get_services()
    approval_service = services["approval_service"]

    if "approved_records" not in st.session_state:
        st.session_state.approved_records = {}
    if "rejected_paths" not in st.session_state:
        st.session_state.rejected_paths = set()

    render_brand_header()
    st.markdown("### 🛡️ Human Review & Explicit Approval Workflow")
    render_safety_notice(context="review")

    review_items: list[ReviewItem] = st.session_state.get("review_items", [])

    if not review_items:
        st.info("No items queued for review. Please run a diagnostic scan first.")
        if st.button("🔍 Go to Scan"):
            navigate_to("Scan")
            st.rerun()
        return

    # Hierarchy map for clear parent/child relationship presentation
    hierarchy_map = get_item_hierarchy_info(review_items)

    # Partition review items into strictly separated presentation categories:
    # 1. Eligible items: LOW risk, size > 0, size >= min threshold, valid recommendation
    eligible_items: list[ReviewItem] = [
        it
        for it in review_items
        if it.is_eligible_for_approval
        and it.candidate.size_bytes > 0
        and it.risk_level not in (RiskLevel.HIGH, RiskLevel.UNKNOWN)
    ]
    # 2. Blocked items: HIGH or UNKNOWN risk
    blocked_items: list[ReviewItem] = [
        it for it in review_items if it.risk_level in (RiskLevel.HIGH, RiskLevel.UNKNOWN)
    ]
    # 3. Ineligible items: Zero-byte, negligible-size, or non-cleanup categories
    ineligible_items: list[ReviewItem] = [
        it for it in review_items if it not in eligible_items and it not in blocked_items
    ]

    # Count statistics
    approved_map = st.session_state.approved_records
    rejected_set = st.session_state.rejected_paths

    eligible_count = len(eligible_items)
    approved_count = len(approved_map)
    rejected_count = len(rejected_set)
    ineligible_count = len(ineligible_items)
    blocked_count = len(blocked_items)

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Eligible for Approval", eligible_count)
    with col2:
        st.metric("Approved", approved_count)
    with col3:
        st.metric("Rejected", rejected_count)
    with col4:
        st.metric("Not Eligible", ineligible_count)
    with col5:
        st.metric("Safety Blocked", blocked_count)

    st.markdown("---")

    # Global explicit consent declaration
    st.markdown("#### 1. Mandatory Informed Consent Declaration")
    consent_given = st.checkbox(
        "I understand that approving an item grants cryptographic HMAC-SHA256 authorization to "
        "move that specific item to macOS Trash (~/.Trash) during controlled execution. "
        "I confirm that I have reviewed the target paths.",
        value=False,
    )

    if not consent_given:
        st.info("⚠️ You must check the informed consent box above before approving items.")

    st.markdown("---")
    st.markdown("#### 2. Candidate Items for Review & Approval")

    if not eligible_items:
        st.info("No items are currently eligible for cleanup approval.")
    else:
        for idx, item in enumerate(eligible_items):
            cand = item.candidate
            path = cand.path
            is_approved = path in approved_map
            is_rejected = path in rejected_set
            hier = hierarchy_map.get(path)

            with st.container():
                c1, c2 = st.columns([3, 1])
                with c1:
                    display_title = (
                        f"{hier.display_prefix}**Eligible Item {idx + 1}:** `{path}`"
                        if hier
                        else f"**Eligible Item {idx + 1}:** `{path}`"
                    )
                    st.markdown(display_title)

                    size_caption = f"**Size:** {format_bytes(cand.size_bytes)}"
                    if hier and hier.is_nested:
                        size_caption += f" *(Included in parent: `{hier.parent_name}`)*"

                    st.caption(
                        f"{size_caption} | "
                        f"**Category:** {cand.category.value.title()} | "
                        f"**Risk Tier:** {item.risk_level.value}"
                    )
                    if hier and hier.is_nested:
                        st.info(f"↳ **Contained inside parent candidate:** `{hier.parent_path}`")
                    elif hier and hier.children_paths:
                        st.caption(f"📂 **Container Directory**: Encompasses {len(hier.children_paths)} nested sub-item(s).")

                    st.write(f"**Rationale:** {item.recommendation.rationale}")
                    if item.recommendation.historical_context:
                        h_ctx = item.recommendation.historical_context
                        boost_tag = "🔥 **High Growth Area** | " if h_ctx.priority_boost else ""
                        st.info(f"📈 **Historical Context:** {boost_tag}{h_ctx.context_summary}")
                    if item.recommendation.duplicate_context:
                        dup_icon = "🔗" if item.recommendation.duplicate_context.is_hardlink_only else "📑"
                        st.info(f"{dup_icon} **Duplicate Context:** {item.recommendation.duplicate_context.explanation}")
                with c2:
                    st.markdown(risk_badge(item.risk_level))
                    if is_approved:
                        st.markdown("**Status:** `🟢 APPROVED`")
                    elif is_rejected:
                        st.markdown("**Status:** `🔴 REJECTED`")
                    else:
                        st.markdown("**Status:** `🔵 PENDING APPROVAL`")

                # Actions row
                if not is_approved and not is_rejected:
                    btn_col1, btn_col2 = st.columns([1, 1])
                    with btn_col1:
                        if st.button("✅ Approve Item", key=f"approve_{idx}", disabled=not consent_given, type="primary"):
                            record, err = approval_service.request_approval(item.recommendation, operation=Operation.CLEAN)
                            if record:
                                approved_record, msg = approval_service.approve(record.approval_id, explicit_consent=consent_given)
                                if approved_record:
                                    st.session_state.approved_records[path] = approved_record
                                    st.success(f"Item approved! Approval ID: {approved_record.approval_id[:8]}...")
                                    st.rerun()
                                else:
                                    st.error(f"Approval failed: {msg}")
                            else:
                                st.error(f"Safety Engine rejected approval request: {err}")
                    with btn_col2:
                        if st.button("❌ Reject Item", key=f"reject_{idx}"):
                            record, _ = approval_service.request_approval(item.recommendation, operation=Operation.CLEAN)
                            if record:
                                approval_service.reject(record.approval_id, reason="Rejected by human reviewer in UI")
                            st.session_state.rejected_paths.add(path)
                            st.info("Item marked as rejected.")
                            st.rerun()

                elif is_approved:
                    rec: ApprovalRecord = approved_map[path]
                    st.success(
                        f"🔒 **Cryptographically Signed & Approved**\n\n"
                        f"- Approval ID: `{rec.approval_id}`\n"
                        f"- Risk: `{rec.risk_level.value}`\n"
                        f"- Expires: `{rec.expires_at.strftime('%Y-%m-%d %H:%M:%S UTC')}`"
                    )
                elif is_rejected:
                    st.caption("Item was rejected by human reviewer.")

                st.markdown("---")

    # Section 3: Not Eligible for Cleanup
    if ineligible_items:
        st.markdown("#### 3. ⚠️ Not Eligible for Cleanup")
        st.caption(
            "These items were discovered during diagnostic scanning but are excluded from cleanup review "
            "(e.g., zero-byte empty files, items below the minimum size threshold, or manual inspection items). "
            "They cannot be approved for cleanup."
        )
        for idx, item in enumerate(ineligible_items):
            cand = item.candidate
            path = cand.path
            hier = hierarchy_map.get(path)

            if cand.size_bytes <= 0:
                exclusion_reason = "0 B — No reclaimable storage. Excluded from cleanup review."
            elif (
                "minimum cleanup threshold" in item.recommendation.rationale.lower()
                or "below configured" in item.recommendation.rationale.lower()
            ):
                exclusion_reason = "Below configured cleanup threshold. Excluded from cleanup review."
            else:
                exclusion_reason = item.recommendation.rationale

            with st.container():
                c1, c2 = st.columns([3, 1])
                with c1:
                    display_title = (
                        f"{hier.display_prefix}**Item:** `{path}`"
                        if hier
                        else f"**Item:** `{path}`"
                    )
                    st.markdown(display_title)
                    st.caption(
                        f"**Size:** {format_bytes(cand.size_bytes)} | "
                        f"**Category:** {cand.category.value.title()} | "
                        f"**Risk Tier:** {item.risk_level.value}"
                    )
                    st.write(f"**Reason for Exclusion:** {exclusion_reason}")
                with c2:
                    st.markdown(risk_badge(item.risk_level))
                    st.markdown("**Status:** `⚪ NOT ELIGIBLE`")
                st.markdown("---")

    # Section 4: Blocked by Safety Policy
    if blocked_items:
        st.markdown("#### 4. 🛑 Blocked by Safety Policy")
        st.caption(
            "High-risk and unclassified items are strictly blocked from automated cleanup approval by MacGuard AI safety policy. "
            "These items cannot be approved for cleanup."
        )
        for idx, item in enumerate(blocked_items):
            cand = item.candidate
            path = cand.path
            hier = hierarchy_map.get(path)

            with st.container():
                c1, c2 = st.columns([3, 1])
                with c1:
                    display_title = (
                        f"{hier.display_prefix}**Protected Item:** `{path}`"
                        if hier
                        else f"**Protected Item:** `{path}`"
                    )
                    st.markdown(display_title)
                    st.caption(
                        f"**Size:** {format_bytes(cand.size_bytes)} | "
                        f"**Category:** {cand.category.value.title()} | "
                        f"**Risk Tier:** {item.risk_level.value}"
                    )
                    st.error(f"🛑 **BLOCKED BY SAFETY POLICY**: {item.review_message}")
                    st.write(f"**Rationale:** {item.recommendation.rationale}")
                with c2:
                    st.markdown(risk_badge(item.risk_level))
                    st.markdown("**Status:** `🛑 BLOCKED`")
                st.markdown("---")

    if approved_count > 0:
        st.success(f"🎉 **{approved_count} item(s) are approved and ready for controlled execution.**")
        if st.button("🗑️ Proceed to Controlled Execution", type="primary", use_container_width=True):
            navigate_to("Execution")
            st.rerun()

