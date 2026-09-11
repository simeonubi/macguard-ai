from __future__ import annotations

import os
from pathlib import Path
import streamlit as st

from app.llm.ollama_client import OllamaClient
from app.ui.components import render_brand_header, render_safety_notice
from app.ui.state import get_services, init_app_state


def render_settings_page() -> None:
    """Render the MacGuard AI Settings & Environment Diagnostic page."""
    init_app_state()
    services = get_services()
    audit_repo = services["audit_repository"]

    render_brand_header()
    st.markdown("### ⚙️ System Settings & Environment Configuration")
    render_safety_notice(context="general")

    # Section 1: Storage Analysis
    st.markdown("#### 1. 📂 Storage Analysis & Candidate Thresholds")
    rec_engine = services.get("recommendation_engine")
    current_threshold_kb = int(rec_engine.min_cleanup_size_bytes / 1024) if rec_engine else 0

    col_s1, col_s2 = st.columns(2)
    with col_s1:
        new_threshold_kb = st.number_input(
            "Minimum Candidate Size for Cleanup Review (KB)",
            min_value=0,
            max_value=1024 * 1024,
            value=current_threshold_kb,
            step=64,
            help="Items below this size threshold and zero-byte items are excluded from cleanup review. Diagnostic scanning continues to discover all items regardless of this threshold.",
        )
        if rec_engine and new_threshold_kb * 1024 != rec_engine.min_cleanup_size_bytes:
            rec_engine.min_cleanup_size_bytes = new_threshold_kb * 1024
            st.success(f"Updated cleanup eligibility threshold to {new_threshold_kb} KB ({rec_engine.min_cleanup_size_bytes} bytes).")

    with col_s2:
        st.text_input("Active User Home Directory", value=str(Path.home()), disabled=True)

    st.markdown("---")

    # Section 2: Local AI & LLM
    st.markdown("#### 2. 🤖 Local AI & LLM Configuration")
    col1, col2 = st.columns(2)

    ollama_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    ollama_model = os.getenv("OLLAMA_MODEL", "llama3.2")

    with col1:
        st.text_input("Ollama Base URL", value=ollama_url, disabled=True)
        st.text_input("Configured LLM Model", value=ollama_model, disabled=True)

    with col2:
        st.markdown("**Local Ollama Service Connectivity:**")
        if st.button("🔄 Test Ollama Connectivity", use_container_width=True):
            with st.spinner("Pinging local Ollama daemon..."):
                client = OllamaClient()
                is_avail = client.is_available()
                if is_avail:
                    st.success("🟢 **Ollama is connected and running locally!**")
                else:
                    st.warning("🟡 **Ollama is not currently reachable.** MacGuard AI will automatically use deterministic fallback explanations.")
        else:
            st.caption("Click above to verify local Ollama daemon connectivity.")

    st.markdown("---")

    # Section 3: Persistent Storage
    st.markdown("#### 3. 📜 Persistent Storage & Audit Database")
    st.text_input("SQLite Audit Database Path", value=str(audit_repo._db_path), disabled=True)
    st.caption("Stores immutable cryptographic audit trails and execution records locally.")

    st.markdown("---")

    # Section 4: Safety Invariants
    st.markdown("#### 4. 🛡️ Core Safety Policies & System Invariants (Non-Disableable)")
    st.info(
        "🔒 **Safety Governance Notice**: All safety policies are immutable core invariants of the MacGuard AI engine. "
        "They cannot be bypassed, overridden, or disabled by user settings or AI prompts."
    )

    st.markdown(
        """
        - **Zero Permanent Deletion**: MacGuard strictly forbids `os.remove`, `rm`, and unlinking. Only controlled moves to `~/.Trash` are permitted.
        - **Human Sovereign Gate**: Mutating actions mandate conscious, explicit human consent. AI models have zero execution authority.
        - **Cryptographic Authorization**: Approvals are signed with runtime HMAC-SHA256 tokens with strict replay and expiration controls.
        - **Integrity Snapshots**: Non-following `os.lstat()` and SHA-256 pre/post integrity checks guarantee safe transitions.
        - **Fail-Closed Policy**: Any discrepancy or unexpected state aborts operations immediately.
        """
    )

    st.markdown("---")
    st.caption("MacGuard AI — Version 1.1.0-production | Production Ready")
