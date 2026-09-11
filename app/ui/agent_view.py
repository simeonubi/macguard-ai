from __future__ import annotations
from pathlib import Path

import streamlit as st

from app.agent.orchestrator import MacGuardAgent
from app.ui.components import render_brand_header, render_safety_notice, risk_badge, safety_status_badge
from app.ui.state import get_services, init_app_state


def render_agent_page() -> None:
    """Render the Conversational Agentic Intelligence interface."""
    init_app_state()
    render_brand_header()
    st.markdown("## 🤖 **MacGuard AI Agent**")
    render_safety_notice(context="general")

    st.caption(
        "Ask questions about your macOS storage, analyze findings, and get intelligent, "
        "deterministic recommendations for human review."
    )

    st.info(
        "🔒 **AI Capability Boundary**: The AI assistant can inspect, explain, summarize, and prioritize "
        "storage findings. It has **zero execution authority** and cannot approve, delete, or move files. "
        "Any cleanup requires conscious, explicit human approval in the Human Review queue."
    )

    services = get_services()
    if "agent" not in st.session_state:
        st.session_state.agent = MacGuardAgent(
            audit_repo=services["audit_repository"],
        )

    if "agent_messages" not in st.session_state:
        st.session_state.agent_messages = []

    candidates = st.session_state.get("candidates", [])
    recommendations = st.session_state.get("recommendations", [])
    is_demo = st.session_state.get("is_demo_mode", False)

    if is_demo:
        st.caption("ℹ️ **Active Data:** `🧪 Presentation Demo Mode`")

    # Retrieve scan_path safely
    context = st.session_state.get("analysis_context")
    if context is not None and hasattr(context, "scan_path") and context.scan_path:
        scan_path = str(context.scan_path)
    elif "scan_path" in st.session_state and isinstance(st.session_state.scan_path, str):
        scan_path = st.session_state.scan_path
    else:
        scan_path = str(Path.home())

    # Quick prompt shortcuts (Safe Questions)
    st.markdown("### 💡 **Example Safe Questions**")
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("📊 Storage Overview", use_container_width=True):
            st.session_state.pending_agent_prompt = "What is consuming the most storage?"
        if st.button("📂 Largest Caches", use_container_width=True):
            st.session_state.pending_agent_prompt = "What are the largest cache directories?"
    with col2:
        if st.button("🎯 Priority Recommendations", use_container_width=True):
            st.session_state.pending_agent_prompt = "Which storage candidates should I review first?"
        if st.button("🛑 Blocked Safety Items", use_container_width=True):
            st.session_state.pending_agent_prompt = "Which items are blocked by safety policy?"
    with col3:
        if st.button("💻 Developer Storage", use_container_width=True):
            st.session_state.pending_agent_prompt = "Why is my developer storage large?"
        if st.button("📜 Audit Trail Summary", use_container_width=True):
            st.session_state.pending_agent_prompt = "Summarize recent cleanup and audit history."

    st.markdown("---")

    # Render conversation history
    for msg in st.session_state.agent_messages:
        with st.chat_message(msg["role"]):
            if msg["role"] == "user":
                st.markdown(msg["content"])
            else:
                resp = msg.get("response")
                if resp:
                    # 1. Deterministic Verified Facts
                    st.markdown("#### 📊 **MacGuard Verified Storage Facts**")
                    facts = resp.deterministic_facts
                    fcol1, fcol2, fcol3, fcol4 = st.columns(4)
                    with fcol1:
                        st.metric(
                            "Total Findings",
                            facts.get("total_candidates_found", 0),
                            help=f"Total storage occupied: {facts.get('total_candidate_size', '0 B')}",
                        )
                    with fcol2:
                        cleanup_count = facts.get("eligible_for_cleanup_review_count", facts.get("eligible_for_review_count", 0))
                        cleanup_size = facts.get("eligible_for_cleanup_review_size", facts.get("eligible_for_review_size", "0 B"))
                        st.metric(
                            "Eligible for Review",
                            f"{cleanup_count} ({cleanup_size})",
                            help="Low-risk caches and logs eligible for explicit human review.",
                        )
                    with fcol3:
                        manual_count = facts.get("manual_review_required_count", 0)
                        manual_size = facts.get("manual_review_required_size", "0 B")
                        st.metric(
                            "Manual Review Required",
                            f"{manual_count} ({manual_size})",
                            help="Medium-risk developer or application items requiring caution.",
                        )
                    with fcol4:
                        blocked_count = facts.get("blocked_count", facts.get("high_risk_count", 0)) + facts.get("unknown_count", facts.get("unknown_risk_count", 0))
                        st.metric(
                            "Blocked / Protected",
                            f"{blocked_count}",
                            help="High-risk system/user documents and unknown items strictly blocked from automated action.",
                        )

                    # 2. AI Explanation / Reasoning
                    st.markdown("#### 🧠 **AI Explanation & Context**")
                    if resp.fallback_used:
                        st.caption("ℹ️ *Generated via deterministic MacGuard engine.*")
                    clean_explanation = (
                        MacGuardAgent._clean_llm_response(resp.explanation)
                        if hasattr(MacGuardAgent, "_clean_llm_response")
                        else resp.explanation
                    )
                    st.markdown(clean_explanation)

                    # 3. Prioritized candidates table if available
                    if resp.priorities:
                        st.markdown("#### 🎯 **Prioritized Storage Items**")
                        for p in resp.priorities:
                            with st.expander(f"#{p.priority_rank}: {p.path} ({p.size_bytes} B)"):
                                st.write(f"**Category:** {p.category.value} | **Risk:** {p.risk_level.value} | **Status:** {p.safety_status}")
                                st.write(f"**Reasoning:** {p.reasoning}")

                    # 4. Recommended Next Step
                    st.markdown("---")
                    st.info(f"👉 **Recommended Next Step:** {resp.recommended_next_step}")
                else:
                    st.markdown(msg["content"])

    # Chat Input
    prompt_to_send = None
    if st.session_state.get("pending_agent_prompt"):
        prompt_to_send = st.session_state.pending_agent_prompt
        st.session_state.pending_agent_prompt = None

    user_input = st.chat_input("Ask MacGuard AI about your storage findings...")
    if user_input:
        prompt_to_send = user_input

    if prompt_to_send:
        # Display user message
        st.session_state.agent_messages.append({"role": "user", "content": prompt_to_send})
        with st.chat_message("user"):
            st.markdown(prompt_to_send)

        with st.chat_message("assistant"):
            with st.spinner("MacGuard Agent analyzing storage findings..."):
                response = st.session_state.agent.handle_request(
                    user_request=prompt_to_send,
                    candidates=candidates,
                    recommendations=recommendations,
                    scan_path=scan_path,
                )

                st.session_state.agent_messages.append({
                    "role": "assistant",
                    "content": response.summary,
                    "response": response,
                })

                st.rerun()
