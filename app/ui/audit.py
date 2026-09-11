from __future__ import annotations

from typing import Optional
import streamlit as st

from app.audit.models import AuditEventType
from app.audit.repository import AuditRepository
from app.tools.storage_scanner import format_bytes
from app.ui.components import render_brand_header, render_safety_notice
from app.ui.state import get_services, init_app_state


def render_audit_page() -> None:
    """Render the Persistent SQLite Audit Log viewer."""
    init_app_state()
    services = get_services()
    audit_repo: AuditRepository = services["audit_repository"]

    render_brand_header()
    st.markdown("### 📜 Cryptographic Audit Log & Forensic History (Read-Only)")
    render_safety_notice(context="general")

    st.caption(
        "All MacGuard AI lifecycle actions (approval requests, cryptographic HMAC signing, execution claims, "
        "pre/post-move integrity checks, controlled Trash moves, and token consumption) are immutably logged to SQLite. "
        "Cryptographic secret keys and raw file contents are strictly excluded."
    )

    # Check for incomplete / interrupted executions (Crash Recovery)
    try:
        incomplete = audit_repo.get_incomplete_executions()
        if incomplete:
            st.error(
                f"⚠️ **Crash / Interruption Anomaly Detected**: {len(incomplete)} execution(s) were initiated "
                "in a previous session but never completed. In accordance with MacGuard's fail-closed policy, "
                "**no automated retries will be performed**. Human inspection is required."
            )
            with st.expander("🔍 View Incomplete Execution Details"):
                for inc in incomplete:
                    st.write(
                        f"- **Execution ID:** `{inc.execution_id}` | **Approval ID:** `{inc.approval_id[:8]}...` | "
                        f"**Path:** `{inc.canonical_path}` | **Status:** `{inc.status}` | **Started:** {inc.start_time}"
                    )
    except Exception as e:
        st.warning(f"Could not query incomplete executions: {e}")

    # Filter Controls
    st.markdown("#### 🔍 **Audit Event Filters**")
    col1, col2, col3 = st.columns(3)
    with col1:
        event_types = ["ALL"] + [et.value for et in AuditEventType]
        selected_event_type = st.selectbox("Filter Event Type:", options=event_types, index=0)
    with col2:
        selected_status = st.selectbox("Filter Status:", options=["ALL", "SUCCESS", "BLOCKED", "FAILED", "PENDING", "APPROVED", "CONSUMED"], index=0)
    with col3:
        path_query = st.text_input("Search Path / Keyword:", value="")

    limit = st.slider("Max Events to Display:", min_value=10, max_value=200, value=50, step=10)

    try:
        events = audit_repo.get_filtered_events(
            event_type=None if selected_event_type == "ALL" else selected_event_type,
            status=None if selected_status == "ALL" else selected_status,
            path_query=path_query if path_query.strip() else None,
            limit=limit,
        )
    except Exception as e:
        st.error(f"Failed to query audit repository: {e}")
        return

    st.markdown(f"**Found {len(events)} recorded audit event(s)**")

    if not events:
        st.info("No audit events match the selected filter criteria.")
        return

    # Render events in an interactive table
    event_rows = []
    for ev in events:
        event_rows.append(
            {
                "Timestamp (UTC)": ev.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "Event Type": ev.event_type.value,
                "Status": ev.status,
                "Risk": ev.risk_level.value,
                "Target Path": ev.canonical_path,
                "Actor": ev.actor,
                "Rationale": ev.reason or "-",
                "Execution ID": ev.execution_id or "-",
                "Approval ID": f"{ev.approval_id[:8]}..." if ev.approval_id else "-",
            }
        )

    st.dataframe(event_rows, use_container_width=True)

    with st.expander("🔍 Inspect Structured Forensic Event Payloads"):
        for idx, ev in enumerate(events[:25]):
            st.markdown(f"**Event {idx + 1}:** `{ev.event_type.value}` ({ev.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')})")
            st.json(
                {
                    "event_id": ev.event_id,
                    "timestamp": ev.timestamp.isoformat(),
                    "event_type": ev.event_type.value,
                    "status": ev.status,
                    "canonical_path": ev.canonical_path,
                    "execution_id": ev.execution_id,
                    "approval_id": ev.approval_id,
                    "actor": ev.actor,
                    "reason": ev.reason,
                    "metadata": ev.metadata,
                }
            )
            st.markdown("---")
