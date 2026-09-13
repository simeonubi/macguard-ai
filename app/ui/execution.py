from __future__ import annotations

from typing import Optional
import streamlit as st

from app.execution.models import ExecutionStatus, TrashExecutionResult
from app.safety.approval import ApprovalRecord
from app.safety.review import ApprovalStatus, ReviewItem
from app.tools.storage_scanner import format_bytes
from app.ui.components import render_brand_header, render_safety_notice, risk_badge
from app.ui.state import get_services, init_app_state, navigate_to


def render_execution_page() -> None:
    """Render the Controlled Trash Execution & Verification page."""
    init_app_state()
    services = get_services()
    trash_executor = services["trash_executor"]

    if "approved_records" not in st.session_state:
        st.session_state.approved_records = {}
    if "consumed_records" not in st.session_state:
        st.session_state.consumed_records = {}

    render_brand_header()
    st.markdown("### 🗑️ Controlled Cleanup Execution (Trash-Only)")
    render_safety_notice(context="execution")

    approved_map: dict[str, ApprovalRecord] = st.session_state.approved_records

    if not approved_map:
        st.info("No approved items ready for execution. Please approve eligible items on the **Review** tab.")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("🔍 Go to Scan"):
                navigate_to("Scan")
                st.rerun()
        with c2:
            if st.button("🛡️ Go to Human Review"):
                navigate_to("Review")
                st.rerun()
        return

    st.markdown(f"**{len(approved_map)} item(s) are approved and waiting for controlled execution.**")
    st.markdown("**Safe Human Workflow:** `1. Review` ➔ `2. Approve` ➔ `3. Dry Run Simulation (Non-destructive)` ➔ `4. Controlled Move to Trash`")

    st.warning(
        "⚠️ **Controlled Trash Move Guarantee (Permanent Deletion Strictly Disabled)**:\n\n"
        "MacGuard AI **never permanently deletes files**. When you execute below, the selected item will be "
        "safely moved to an isolated directory inside your macOS Trash (`~/.Trash`). Permanent deletion (`rm`, `unlink`, `purge`) is strictly disabled.\n\n"
        "**Verification Pipeline:**\n"
        "1. Re-canonicalize path & revalidate allowlist policy\n"
        "2. Verify cryptographic HMAC-SHA256 signature\n"
        "3. Verify approval expiration timestamp\n"
        "4. Re-check risk tier (HIGH and UNKNOWN remain blocked)\n"
        "5. Capture non-following `os.lstat()` integrity snapshot\n"
        "6. Atomically claim approval token (prevent double-execution)\n"
        "7. Move item strictly to isolated macOS Trash (`~/.Trash`)\n"
        "8. Verify post-move integrity (source absent, destination present, type/size/hash match)\n"
        "9. Record immutable audit record in SQLite database\n"
    )

    st.markdown("---")

    paths_to_remove = []

    # Map known candidates to lookup size
    candidate_map = {c.path: c for c in st.session_state.get("candidates", [])}

    for idx, (path, rec) in enumerate(list(approved_map.items())):
        cand = candidate_map.get(rec.path)
        if cand:
            size_label = format_bytes(cand.size_bytes)
        else:
            try:
                from pathlib import Path as P
                p_obj = P(rec.path)
                if p_obj.exists():
                    size_label = format_bytes(p_obj.stat().st_size) if p_obj.is_file() else "Directory"
                else:
                    size_label = "Verified Target"
            except Exception:
                size_label = "Verified Target"

        with st.container():
            c1, c2 = st.columns([3, 1])
            with c1:
                st.markdown(f"#### `{rec.path}`")
                st.caption(
                    f"**Size:** {size_label} | "
                    f"**Operation:** {rec.operation.value} | "
                    f"**Status:** `🟢 APPROVED` | "
                    f"**Approval ID:** `{rec.approval_id[:8]}...`"
                )
            with c2:
                st.markdown(risk_badge(rec.risk_level))
                st.markdown(f"**Expires:** `{rec.expires_at.strftime('%H:%M:%S UTC')}`")

            # Action buttons: Dry Run Simulation + Real Controlled Move to Trash
            btn_c1, btn_c2 = st.columns([1, 1])
            with btn_c1:
                if st.button(f"🧪 Dry Run Simulation (Item {idx + 1})", key=f"dry_btn_{rec.approval_id}"):
                    with st.spinner("Simulating non-destructive dry-run..."):
                        planner = services["execution_planner"]
                        from app.execution.models import ExecutionAction
                        dry_plan, dry_err = planner.create_plan(rec, action=ExecutionAction.DRY_RUN)

                        if dry_plan is None or dry_plan.status == ExecutionStatus.BLOCKED:
                            block_reason = dry_err or (dry_plan.reason if dry_plan else "Planning safety check failed.")
                            st.error(f"❌ **Dry Run Planning Blocked (Failed Closed):** {block_reason}")
                            if "expired" in block_reason.lower():
                                st.info("ℹ️ Approval records expire after 15 minutes for safety. Please return to the **Human Review** tab to re-approve.")
                        else:
                            dry_executor = services["dry_run_executor"]
                            dry_result = dry_executor.execute_dry_run(dry_plan)
                            if dry_result.status == ExecutionStatus.DRY_RUN_COMPLETED:
                                st.info(
                                    f"🧪 **Dry Run Simulation Succeeded** (Non-destructive)\n\n"
                                    f"- **Target:** `{dry_result.canonical_path}`\n"
                                    f"- **Simulated Reclaim:** {format_bytes(dry_result.simulated_reclaimed_bytes)}\n"
                                    f"- **Message:** {dry_result.message}\n"
                                    f"- **Safety Confirmation:** {dry_result.safety_confirmation}"
                                )
                            else:
                                st.error(
                                    f"❌ **Dry Run Blocked (Failed Closed):** {dry_result.message}\n\n"
                                    f"Status: `{dry_result.status.value}`"
                                )

            with btn_c2:
                if st.button(f"🗑️ Safely Move to Trash (Item {idx + 1})", key=f"exec_btn_{rec.approval_id}", type="primary"):
                    with st.spinner("Executing controlled move & verifying integrity..."):
                        planner = services["execution_planner"]
                        from app.execution.models import ExecutionAction
                        plan, err = planner.create_plan(rec, action=ExecutionAction.TRASH)

                        if plan is None or plan.status == ExecutionStatus.BLOCKED:
                            block_reason = err or (plan.reason if plan else "Planning safety check failed.")
                            st.error(f"❌ **Execution Planning Blocked (Failed Closed):** {block_reason}")
                            if "expired" in block_reason.lower():
                                st.info("ℹ️ Approval records expire after 15 minutes for safety. Please return to the **Human Review** tab to re-approve.")
                        else:
                            result: TrashExecutionResult = trash_executor.execute_trash(plan)
                            st.session_state.execution_results.append(result)

                            if result.status == ExecutionStatus.TRASH_SUCCEEDED and result.integrity_verified:
                                st.session_state.consumed_records[path] = rec
                                paths_to_remove.append(path)

                                st.success(
                                    f"✅ **Move Verified & Succeeded!**\n\n"
                                    f"- **Execution ID:** `{result.execution_id}`\n"
                                    f"- **Moved to Trash:** {format_bytes(result.reclaimed_bytes)}\n"
                                    f"- **Active-path storage removed:** {format_bytes(result.reclaimed_bytes)}\n"
                                    f"- **Physical disk space:** *Not yet reclaimed — Trash must be emptied*\n"
                                    f"- **Destination:** `{result.trash_destination_path}`\n"
                                    f"- **Integrity Verified:** Yes (`source absent` and `destination verified in Trash`)\n"
                                    f"- **Audit Event:** Persisted to SQLite"
                                )
                            else:
                                st.error(
                                    f"❌ **Execution Blocked / Failed (Failed Closed):** {result.message}\n\n"
                                    f"Status: `{result.status.value}`"
                                )

            st.markdown("---")

    for p in paths_to_remove:
        st.session_state.approved_records.pop(p, None)

    # History of executed items in current session
    if st.session_state.get("execution_results"):
        st.subheader("📜 Current Session Execution Log")
        for res in reversed(st.session_state.execution_results):
            if res.status == ExecutionStatus.TRASH_SUCCEEDED:
                st.info(
                    f"🟢 **Moved to Trash:** `{res.source_path}` → `{res.trash_destination_path}` "
                    f"({format_bytes(res.reclaimed_bytes)}) | Execution ID: `{res.execution_id}`"
                )
            else:
                st.error(
                    f"🔴 **Execution Failed:** `{res.source_path}` | Error: {res.message}"
                )
