from __future__ import annotations

from typing import Optional
import streamlit as st

from app.analysis.models import RiskLevel, StorageCategory
from app.analysis.recommendations import RecommendationAction, SafetyStatus, StorageRecommendation
from app.tools.storage_scanner import format_bytes, format_bytes_decimal
from app.ui.components import (
    get_item_hierarchy_info,
    render_brand_header,
    render_safety_notice,
    risk_badge,
    safety_status_badge,
)
from app.ui.state import get_services, init_app_state, navigate_to


def render_recommendations_page() -> None:
    """Render the Explainable Recommendations & AI Insights page."""
    init_app_state()
    services = get_services()
    exp_service = services["explanation_service"]

    render_brand_header()
    st.markdown("### 💡 Deterministic Recommendations & AI Explanations")
    render_safety_notice(context="general")

    recommendations: list[StorageRecommendation] = st.session_state.get("recommendations", [])
    is_demo = st.session_state.get("is_demo_mode", False)

    if not recommendations:
        st.info("No active recommendations found. Please run a scan from the **Scan** tab or load demo data.")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("🔍 Go to Scan Storage", type="primary", use_container_width=True):
                navigate_to("Scan")
                st.rerun()
        with c2:
            if st.button("📊 Return to Dashboard", use_container_width=True):
                navigate_to("Dashboard")
                st.rerun()
        return

    # Hierarchy map for clear parent/child relationship presentation
    hierarchy_map = get_item_hierarchy_info(recommendations)

    if is_demo:
        st.caption("ℹ️ **Mode:** `🧪 Presentation Demo Data` — Showing simulated realistic findings.")

    # Filter & Sort bar
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        risk_filter = st.selectbox(
            "Filter Risk Level:",
            options=["All Risks", "LOW", "MEDIUM", "HIGH", "UNKNOWN"],
            index=0,
        )
    with col2:
        cat_filter = st.selectbox(
            "Filter Category:",
            options=["All Categories"] + [c.value.title() for c in StorageCategory],
            index=0,
        )
    with col3:
        status_filter = st.selectbox(
            "Filter Safety Status:",
            options=["All Statuses", "Eligible for Review", "Manual Review Required", "Blocked"],
            index=0,
        )
    with col4:
        sort_by = st.selectbox(
            "Sort Order:",
            options=["Largest Size First", "Smallest First", "Highest Confidence", "Path Name"],
            index=0,
        )

    # Apply filters
    filtered_recs = list(recommendations)
    if risk_filter != "All Risks":
        filtered_recs = [r for r in filtered_recs if r.candidate.risk_level.value == risk_filter]
    if cat_filter != "All Categories":
        filtered_recs = [r for r in filtered_recs if r.candidate.category.value.title() == cat_filter]
    if status_filter != "All Statuses":
        if status_filter == "Eligible for Review":
            filtered_recs = [r for r in filtered_recs if r.safety_status == SafetyStatus.ELIGIBLE_FOR_REVIEW.value]
        elif status_filter == "Manual Review Required":
            filtered_recs = [r for r in filtered_recs if r.safety_status == SafetyStatus.MANUAL_REVIEW_REQUIRED.value]
        elif status_filter == "Blocked":
            filtered_recs = [r for r in filtered_recs if r.safety_status == SafetyStatus.BLOCKED.value]

    # Apply sorting
    if sort_by == "Largest Size First":
        filtered_recs.sort(key=lambda r: r.candidate.size_bytes, reverse=True)
    elif sort_by == "Smallest First":
        filtered_recs.sort(key=lambda r: r.candidate.size_bytes)
    elif sort_by == "Highest Confidence":
        filtered_recs.sort(key=lambda r: r.confidence, reverse=True)
    elif sort_by == "Path Name":
        filtered_recs.sort(key=lambda r: r.candidate.path)

    st.markdown(f"**Showing {len(filtered_recs)} of {len(recommendations)} recommendation(s)**")
    st.markdown("---")

    for idx, rec in enumerate(filtered_recs):
        cand = rec.candidate
        hier = hierarchy_map.get(cand.path)

        with st.container():
            c1, c2 = st.columns([3, 1])
            with c1:
                display_title = f"{hier.display_prefix}`{cand.path}`" if hier else f"`{cand.path}`"
                st.markdown(f"#### {display_title}")

                size_caption = f"**Size:** {format_bytes_decimal(cand.size_bytes)}"
                if hier and hier.is_nested:
                    size_caption += f" *(Included in parent: `{hier.parent_name}`)*"

                st.caption(
                    f"{size_caption} | "
                    f"**Category:** {cand.category.value.title()} | "
                    f"**Confidence:** {rec.confidence:.0%}"
                )
                if hier and hier.is_nested:
                    st.info(f"↳ **Contained in parent candidate:** `{hier.parent_path}`")
                elif hier and hier.children_paths:
                    st.caption(f"📂 **Container Directory**: Includes {len(hier.children_paths)} nested candidate item(s).")
            with c2:
                st.markdown(f"{risk_badge(cand.risk_level)}")
                st.markdown(f"{safety_status_badge(rec.safety_status)}")

            # Recommendation Action Text
            if rec.action == RecommendationAction.REVIEW_FOR_CLEANUP:
                action_text = "🟢 **Eligible for controlled Trash review**"
            elif rec.action == RecommendationAction.MANUAL_REVIEW:
                action_text = "🟡 **Manual review required (Caution)**"
            else:
                action_text = "🔴 **Safety Blocked — No Automated Action**"

            st.write(f"**Recommendation:** {action_text}")
            st.write(f"**Rationale:** {rec.rationale}")
            if rec.historical_context:
                boost_badge = "🔥 **High Growth Velocity Priority** | " if rec.historical_context.priority_boost else ""
                st.info(f"📈 **Historical Context:** {boost_badge}{rec.historical_context.context_summary}")
            if rec.duplicate_context:
                dup_icon = "🔗" if rec.duplicate_context.is_hardlink_only else "📑"
                st.info(f"{dup_icon} **Duplicate Context:** {rec.duplicate_context.explanation}")

            # AI Explanation section
            with st.expander("🤖 AI Natural Language Explanation & Context"):
                exp_key = f"exp_{cand.path}"
                existing_exp = st.session_state.ai_explanations.get(exp_key)

                if existing_exp:
                    if isinstance(existing_exp, dict) and existing_exp.get("status") == "UNAVAILABLE":
                        st.warning(
                            f"⚠️ **Local AI explanation unavailable**\n\n"
                            f"{existing_exp.get('detail', 'Local AI explanation is currently unavailable.')}\n\n"
                            f"🔒 *The deterministic MacGuard recommendation remains authoritative.*"
                        )
                        if existing_exp.get("deterministic_explanation"):
                            st.info(f"📋 **Deterministic Rationale:** {existing_exp['deterministic_explanation']}")
                        if st.button("🔄 Retry Local AI", key=f"retry_ai_{idx}"):
                            del st.session_state.ai_explanations[exp_key]
                            st.rerun()
                    else:
                        summary_text = existing_exp.get("summary", "") if isinstance(existing_exp, dict) else getattr(existing_exp, "summary", "")
                        if isinstance(existing_exp, dict):
                            detail_text = existing_exp.get("explanation", cand.reason)
                            guidance = existing_exp.get("user_guidance")
                        else:
                            detail_text = getattr(existing_exp, "explanation", cand.reason)
                            guidance = getattr(existing_exp, "user_guidance", None)

                        if summary_text:
                            st.markdown(f"**AI Summary:**\n{summary_text}")
                        st.markdown(f"**Detailed Breakdown:**\n{detail_text}")
                        if guidance:
                            st.caption(f"💡 *Guidance:* {guidance}")
                        st.caption("🔒 *Note: AI explanations are purely informational and carry zero authorization to execute cleanup.*")
                else:
                    if st.button("✨ Explain Finding with Local AI", key=f"btn_ai_{idx}"):
                        with st.spinner("Analyzing with local LLM explanation engine..."):
                            context = st.session_state.get("analysis_context")
                            if context is not None:
                                res = exp_service.explain_candidate_safe(context, cand.path)
                                st.session_state.ai_explanations[exp_key] = res
                                st.rerun()
                            else:
                                st.warning("Analysis context unavailable. Please rerun scan.")

            st.markdown("---")

    # Bottom action
    c1, c2 = st.columns([1, 1])
    with c1:
        if st.button("🛡️ Proceed to Human Review & Approvals", type="primary", use_container_width=True):
            navigate_to("Review")
            st.rerun()
    with c2:
        if st.button("🤖 Ask AI Assistant About Findings", use_container_width=True):
            navigate_to("Agent")
            st.rerun()
