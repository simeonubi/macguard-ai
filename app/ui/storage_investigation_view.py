"""
MacGuard AI Phase 12 — Streamlit Storage Investigator & Batch Cleanup View.

Provides an interactive dashboard answering:
- "Why is my Mac full?"
- "What is actually consuming the space?"
- "What can I safely reclaim?"
- "How much can I recover?"

Includes:
- Progressive investigation trigger (Levels 1–3)
- Physical disk vs analyzed breakdown
- Local AI reasoning explanation
- Batch grouping and human approval workflow
"""

from __future__ import annotations

import streamlit as st
import pandas as pd

from app.analysis.storage_investigator import StorageInvestigator
from app.llm.storage_investigator_llm import OllamaStorageInvestigator
from app.models.investigation import InvestigationLevel, ReclaimConfidence, StorageInvestigationEvidence, StorageInvestigationResult
from app.safety.batch_approval import BatchApprovalCoordinator
from app.tools.storage_scanner import format_bytes


def render_storage_investigation_page() -> None:
    """Render the main Storage Investigator Streamlit view."""
    st.markdown("# 🔬 **Storage Investigator & Practical Cleanup**")
    st.caption("Investigate why your Mac is full, discover large reclaimable consumers, and review cleanup plans.")

    # Initialize session state for investigation
    if "investigation_result" not in st.session_state:
        st.session_state.investigation_result = None
    if "batch_execution_report" not in st.session_state:
        st.session_state.batch_execution_report = None

    # 1. Investigation Control Bar
    with st.container():
        col1, col2, col3 = st.columns([2, 2, 2])
        with col1:
            level_choice = st.selectbox(
                "Investigation Depth:",
                options=["TARGETED (Level 2 — Fast)", "DEEP (Level 3 — Broad)", "HEALTH (Level 1 — Quick Stats)"],
                index=0,
                help="TARGETED inspects high-value caches, developer tools, AI models, and logs. DEEP inspects all user files.",
            )
        with col2:
            st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
            run_btn = st.button("🚀 **Investigate My Storage**", type="primary", use_container_width=True)
        with col3:
            st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
            ai_btn = st.button("🤖 **Investigate with Local AI**", use_container_width=True)

    # 2. Run Investigation if clicked
    if run_btn or (ai_btn and st.session_state.investigation_result is None):
        inv_level = InvestigationLevel.TARGETED
        if "HEALTH" in level_choice:
            inv_level = InvestigationLevel.HEALTH
        elif "DEEP" in level_choice:
            inv_level = InvestigationLevel.DEEP

        with st.spinner("Investigating storage consumers safely (read-only)..."):
            investigator = StorageInvestigator()
            evidence, cleanup_plan = investigator.investigate(level=inv_level)

            llm_investigator = OllamaStorageInvestigator()
            if ai_btn:
                result = llm_investigator.investigate(evidence, cleanup_plan, fallback_to_deterministic=True)
            else:
                result = llm_investigator.investigate_deterministic(evidence, cleanup_plan)

            st.session_state.investigation_result = result
            st.session_state.batch_execution_report = None

    result: StorageInvestigationResult | None = st.session_state.investigation_result

    if result is None:
        st.info("Click **'Investigate My Storage'** above to begin an intelligent, read-only analysis of your storage.")
        return

    evidence = result.evidence
    cleanup_plan = result.cleanup_plan

    # 3. Storage Health & Disk Summary
    st.markdown("---")
    st.markdown("### 📊 **Storage Health Overview**")

    m_col1, m_col2, m_col3, m_col4 = st.columns(4)
    with m_col1:
        st.metric("Physical Free Space", evidence.disk_free_human, delta=f"{evidence.disk_used_human} used", delta_color="inverse")
    with m_col2:
        st.metric("Total Reclaimable", evidence.total_reclaimable_human, help="High confidence + Review required storage")
    with m_col3:
        st.metric("High Confidence (Safe)", format_bytes(evidence.reclaimable_high_confidence_bytes))
    with m_col4:
        st.metric("Review Required", format_bytes(evidence.reclaimable_review_required_bytes))

    # Executive Summary Banner
    severity_color = "🔴" if result.severity == "CRITICAL" else ("🟡" if result.severity == "WARNING" else "🟢")
    st.info(f"{severity_color} **Summary:** {result.summary_text}")

    # 4. Local AI Reasoning / Notes
    if result.is_ai_reasoned:
        st.markdown("#### 🤖 **Local AI Storage Insights**")
        st.caption(result.ai_status_message or "Analyzed with Ollama")
    else:
        st.markdown("#### 🛡️ **Deterministic Storage Insights**")
        st.caption(result.ai_status_message or "Deterministic rules engine")

    for note in result.reasoning_notes:
        st.markdown(f"- {note}")

    # 5. Top Storage Consumers Table
    st.markdown("---")
    st.markdown("### 🏆 **Top Storage Consumers**")

    if evidence.top_consumers:
        table_data = []
        for it in evidence.top_consumers[:15]:
            table_data.append({
                "Evidence ID": it.evidence_id,
                "Category": it.category.value,
                "Subcategory": it.subcategory,
                "Size": it.size_human,
                "Confidence": it.reclaim_confidence.value,
                "Running Process": ", ".join(it.associated_processes) if it.associated_processes else ("In Use" if it.currently_in_use else "No"),
                "Path": it.path,
                "Consequence": it.cleanup_consequence or "N/A",
            })
        df = pd.DataFrame(table_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No significant storage consumer items found in this scope.")

    # 6. Cleanup Plan & Batch Approval Section
    st.markdown("---")
    st.markdown("### 📦 **Practical Cleanup Plan & Batch Approval**")
    st.caption("Approve verified cleanup batches. Every action is individually verified, HMAC-signed, and moved to Trash.")

    coordinator = BatchApprovalCoordinator()
    groups = coordinator.group_cleanup_plan(cleanup_plan)

    if not groups:
        st.success("🎉 No actionable cleanup candidates discovered. Your storage is clean!")
        return

    # Render Batch Cards with Selection
    selected_items = []
    for grp in groups:
        with st.expander(f"📁 **{grp.title}** ({grp.total_human} — {len(grp.items)} items)", expanded=True):
            st.write(grp.description)
            batch_check = st.checkbox(f"Select entire batch: {grp.title} ({grp.total_human})", key=f"chk_grp_{grp.group_id}")
            if batch_check:
                selected_items.extend(grp.items)
            else:
                # Individual checkboxes inside group
                for it in grp.items:
                    item_check = st.checkbox(
                        f"`{it.path}` ({it.size_human}) — {it.description}",
                        key=f"chk_item_{it.evidence_id}",
                    )
                    if item_check:
                        selected_items.append(it)

    # Action buttons for Batch
    total_selected_bytes = sum(it.size_bytes for it in selected_items)
    st.markdown(f"**Total Selected for Cleanup:** `{format_bytes(total_selected_bytes)}` ({len(selected_items)} items)")

    btn_col1, btn_col2 = st.columns([2, 4])
    with btn_col1:
        approve_batch_btn = st.button("🗑️ **Approve & Move Selected to Trash**", type="primary", disabled=len(selected_items) == 0)

    if approve_batch_btn and selected_items:
        with st.spinner("Processing batch approval, HMAC signing, and controlled execution..."):
            report = coordinator.approve_and_execute_batch(selected_items)
            st.session_state.batch_execution_report = report

    # 7. Batch Execution Report Display
    rep = st.session_state.batch_execution_report
    if rep:
        st.markdown("---")
        st.markdown("### 📜 **Batch Execution Results**")
        if rep.successful_items > 0:
            st.success(f"✅ Successfully moved {rep.successful_items} items to macOS Trash. Freed: **{rep.bytes_freed_human}**.")
        if rep.failed_items > 0:
            st.error(f"⚠️ {rep.failed_items} items could not be moved. Errors: {'; '.join(rep.errors)}")
