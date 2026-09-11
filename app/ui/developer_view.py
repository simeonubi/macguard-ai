"""
MacGuard AI v1.1 — Developer Storage Analysis UI.

Provides dedicated diagnostic visualization for developer ecosystems:
Xcode, Docker, Python (pip, venv, conda), Node.js (npm, yarn, node_modules),
Rust (cargo target), and local AI/ML model caches.

DISCOVERY != CATEGORIZATION != ANALYSIS != AUTHORIZATION
Developer Storage view is strictly informational and read-only.
It does not perform deletions, moves, or approvals.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from app.analysis.developer_analyzer import DeveloperStorageAnalyzer
from app.models.developer import (
    DeveloperStorageFinding,
    DeveloperStorageGroup,
    DeveloperStorageSubtype,
    DeveloperStorageSummary,
    StaleStatus,
)
from app.models.scan_result import ScanResult
from app.tools.storage_scanner import format_bytes, format_bytes_decimal
from app.ui.components import (
    alias_and_redact_path,
    render_brand_header,
    render_safety_notice,
)
from app.ui.state import navigate_to


SUBTYPE_ICONS: dict[str, str] = {
    "PYTHON_VENV": "🐍 Python Virtual Environments",
    "NODE_MODULES": "📦 Node.js node_modules",
    "PYTHON_CACHE": "🐍 Python Caches (pip / bytecode)",
    "BUILD_OUTPUT": "🏗️ Build Outputs & DerivedData",
    "PACKAGE_CACHE": "📦 Package Manager Caches",
    "CONTAINER_STORAGE": "🐳 Docker & Container Storage",
    "ML_MODELS": "🧠 AI / ML Model Caches",
    "ML_DATASETS": "📊 AI / ML Datasets",
    "IDE_CACHE": "💻 IDE & Editor Caches",
    "SOURCE_REPO": "📂 Source Code Repositories",
    "OTHER_DEVELOPER": "🛠️ Other Developer Storage",
}


def _get_or_compute_developer_summary() -> DeveloperStorageSummary | None:
    """Retrieve existing DeveloperStorageSummary or derive it from completed ScanResult."""
    # Check if explicitly stored in session state
    if "developer_summary" in st.session_state and st.session_state.developer_summary is not None:
        return st.session_state.developer_summary

    # Derive on-the-fly from active scan_results / scan_result if present
    scan_res = st.session_state.get("scan_results") or st.session_state.get("scan_result")
    if scan_res is not None and isinstance(scan_res, ScanResult):
        analyzer = DeveloperStorageAnalyzer()
        summary = analyzer.analyze_scan_result(scan_res)
        st.session_state.developer_summary = summary
        return summary

    return None


def render_developer_storage_page() -> None:
    """Render the Developer Storage & Tooling Analytics view."""
    render_brand_header()
    render_safety_notice("general")

    st.markdown("## 🛠️ **Developer Storage & Tooling Diagnostics**")
    st.caption("Deep inspection of build artifacts, package caches, virtual environments, and local AI/ML models.")

    dev_summary = _get_or_compute_developer_summary()

    if dev_summary is None or dev_summary.total_findings_count == 0:
        st.info("ℹ️ **No Developer Storage Analysis Available**")
        st.markdown(
            "Run a storage scan from the **Scan Storage** tab to discover developer tools, "
            "package caches, and virtual environments across your workspace."
        )
        col1, col2 = st.columns([1, 4])
        with col1:
            if st.button("🔍 Go to Scan Storage", key="dev_goto_scan"):
                navigate_to("Scan")
                st.rerun()
        return

    # Top Metric Cards
    mcol1, mcol2, mcol3, mcol4 = st.columns(4)
    with mcol1:
        st.metric("Total Logical Storage", format_bytes_decimal(dev_summary.total_logical_bytes))
    with mcol2:
        st.metric("Physical Storage", format_bytes_decimal(dev_summary.total_unique_bytes))
    with mcol3:
        st.metric("Developer Artifacts", f"{dev_summary.total_findings_count:,}")
    with mcol4:
        st.metric("Stale Artifacts (>90d)", f"{len(dev_summary.stale_findings):,}")

    st.markdown("---")

    # Developer Storage Groups Breakdown
    st.markdown("### 🎛️ **Ecosystem & Subtype Breakdown**")

    if dev_summary.groups:
        group_rows = []
        for g in dev_summary.groups:
            sub_key = g.subtype.value if hasattr(g.subtype, "value") else str(g.subtype)
            group_rows.append({
                "Ecosystem / Subtype": SUBTYPE_ICONS.get(sub_key, g.title),
                "Logical Size": format_bytes_decimal(g.total_logical_bytes),
                "Physical Size": format_bytes_decimal(g.unique_physical_bytes),
                "Item Count": g.item_count,
                "Stale Items (>90d)": g.stale_item_count,
                "Stale Bytes": format_bytes_decimal(g.stale_bytes),
                "Raw Bytes": g.total_logical_bytes,
            })

        df_groups = pd.DataFrame(group_rows)
        st.dataframe(
            df_groups.drop(columns=["Raw Bytes"]),
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.caption("No grouped developer storage artifacts detected.")

    st.markdown("---")

    # Filterable Findings Table (Bounded to top 50)
    st.markdown("### 📋 **Granular Developer Artifacts**")

    all_findings: list[DeveloperStorageFinding] = []
    for g in dev_summary.groups:
        all_findings.extend(g.findings)

    if all_findings:
        filter_col1, filter_col2 = st.columns([2, 2])
        with filter_col1:
            selected_subtypes = st.multiselect(
                "Filter by Subtype:",
                options=[g.subtype.value for g in dev_summary.groups],
                default=[],
                format_func=lambda x: SUBTYPE_ICONS.get(x, x),
                key="dev_subtype_filter",
            )
        with filter_col2:
            stale_only = st.checkbox("Show Stale Items Only (>90 days old)", value=False, key="dev_stale_filter")

        filtered_findings = all_findings
        if selected_subtypes:
            filtered_findings = [f for f in filtered_findings if (f.subtype.value if hasattr(f.subtype, "value") else str(f.subtype)) in selected_subtypes]
        if stale_only:
            filtered_findings = [f for f in filtered_findings if f.stale_status in (StaleStatus.POTENTIALLY_STALE_90D, StaleStatus.POTENTIALLY_STALE_180D)]

        # Sort by size descending and bound to top 50
        sorted_findings = sorted(filtered_findings, key=lambda x: x.size_bytes, reverse=True)[:50]

        finding_rows = []
        for f in sorted_findings:
            sub_name = f.subtype.value if hasattr(f.subtype, "value") else str(f.subtype)
            stale_name = f.stale_status.value if hasattr(f.stale_status, "value") else str(f.stale_status)
            finding_rows.append({
                "Subtype": sub_name,
                "Size": format_bytes_decimal(f.size_bytes),
                "Type": f.item_type,
                "Staleness": stale_name,
                "Evidence": f.evidence,
                "Path": alias_and_redact_path(f.path),
            })

        st.caption(f"Displaying top {len(sorted_findings)} developer artifact(s) (ordered by size):")
        st.dataframe(pd.DataFrame(finding_rows), use_container_width=True, hide_index=True)
    else:
        st.caption("No individual developer findings to list.")

    # Project Associations if present
    if dev_summary.projects:
        st.markdown("---")
        st.markdown("### 📁 **Project Storage Breakdown**")
        proj_rows = []
        for p in dev_summary.projects[:20]:
            proj_rows.append({
                "Project": p.project_name,
                "Logical Size": format_bytes_decimal(p.total_bytes),
                "Physical Size": format_bytes_decimal(p.unique_physical_bytes),
                "Artifacts": p.findings_count,
                "Subtypes": ", ".join(s.value if hasattr(s, "value") else str(s) for s in p.subtypes),
                "Project Root": alias_and_redact_path(p.project_root),
            })
        st.dataframe(pd.DataFrame(proj_rows), use_container_width=True, hide_index=True)

    st.markdown("---")

    # Workflow Actions (Informational Only)
    acol1, acol2 = st.columns([1, 1])
    with acol1:
        if st.button("💡 View Actionable Recommendations", key="dev_goto_recs"):
            navigate_to("Recommendations")
            st.rerun()
    with acol2:
        if st.button("🤖 Ask AI Agent about Developer Storage", key="dev_goto_agent"):
            navigate_to("Agent")
            st.rerun()
