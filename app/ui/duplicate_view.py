"""
MacGuard AI v1.1 — Duplicate & Redundancy Explorer UI.

Provides dedicated, read-only visualization for identical duplicate files,
potential reclaimable storage, and APFS hardlink deduplication.

DISCOVERY != ANALYSIS != AUTHORIZATION
Duplicate Explorer is strictly informational and read-only.
Hardlink-only clusters strictly report 0 B wasted.
No automatic deduplication or deletion controls exist.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from app.analysis.duplicate_detector import DuplicateDetector
from app.models.duplicate import (
    DuplicateCluster,
    DuplicateFile,
    DuplicateScanSummary,
)
from app.models.scan_result import ScanResult
from app.tools.storage_scanner import format_bytes, format_bytes_decimal
from app.ui.components import (
    alias_and_redact_path,
    render_brand_header,
    render_safety_notice,
)
from app.ui.state import navigate_to


def _get_or_compute_duplicates() -> tuple[list[DuplicateCluster], DuplicateScanSummary | None]:
    """Retrieve existing duplicate clusters and summary or compute from active scan results."""
    clusters: list[DuplicateCluster] = st.session_state.get("duplicate_clusters", [])
    summary: DuplicateScanSummary | None = st.session_state.get("duplicate_summary")

    if clusters and summary:
        return clusters, summary

    # Derive on-the-fly from active scan_results if present and not yet computed
    scan_res = st.session_state.get("scan_results") or st.session_state.get("scan_result")
    if scan_res is not None and isinstance(scan_res, ScanResult) and scan_res.items:
        detector = DuplicateDetector()
        clusters, summary = detector.find_duplicates(scan_res)
        st.session_state.duplicate_clusters = clusters
        st.session_state.duplicate_summary = summary
        return clusters, summary

    return clusters, summary


def render_duplicate_explorer_page() -> None:
    """Render the Duplicate & Redundancy Explorer view."""
    render_brand_header()
    render_safety_notice("general")

    st.markdown("## 📑 **Duplicate & Redundancy Explorer**")
    st.caption("Byte-exact identical file clustering with APFS hardlink awareness and potential space recovery analytics.")

    clusters, summary = _get_or_compute_duplicates()

    if not clusters or summary is None or summary.total_clusters == 0:
        st.info("ℹ️ **No Duplicate Clusters Detected**")
        st.markdown(
            "No duplicate files have been identified in the current scan results. "
            "Run a storage scan from the **Scan Storage** tab to discover redundant files."
        )
        col1, col2 = st.columns([1, 4])
        with col1:
            if st.button("🔍 Go to Scan Storage", key="dup_goto_scan"):
                navigate_to("Scan")
                st.rerun()
        return

    # Metrics Row
    mcol1, mcol2, mcol3, mcol4 = st.columns(4)
    with mcol1:
        st.metric("Duplicate Clusters", f"{summary.total_clusters:,}")
    with mcol2:
        st.metric("Total Duplicate Files", f"{summary.total_duplicate_files:,}")
    with mcol3:
        st.metric("Potential Reclaimable Space", format_bytes_decimal(summary.potential_reclaimable_bytes))
    with mcol4:
        st.metric("Skipped Large Files (>5GB)", f"{summary.skipped_large_files:,}")

    st.markdown("---")

    # Hardlink Explanation Box
    st.markdown("### 🔗 **Hardlink & Physical Storage Invariant**")
    st.info(
        "💡 **APFS Hardlinks**: Files that share the exact same physical inode on disk share data blocks. "
        "MacGuard accurately detects hardlinks and reports **0 B wasted** for hardlinked copies, "
        "ensuring potential reclaimable space is never falsely inflated."
    )

    st.markdown("---")

    # Interactive Bounded Cluster Browser
    st.markdown("### 🔍 **Duplicate Clusters Browser**")

    # Sort clusters: largest wasted space first, then largest file size
    sorted_clusters = sorted(clusters, key=lambda c: (c.wasted_bytes, c.file_size_bytes), reverse=True)

    # Bounded Display (Top 50 clusters)
    display_limit = 50
    bounded_clusters = sorted_clusters[:display_limit]

    cluster_labels = []
    for i, c in enumerate(bounded_clusters, start=1):
        is_hl = c.wasted_bytes == 0 and c.hardlink_count > 0
        hl_tag = " [Hardlinks — 0 B Wasted]" if is_hl else f" [Wasted: {format_bytes_decimal(c.wasted_bytes)}]"
        cluster_labels.append(f"Cluster #{i}: {format_bytes_decimal(c.file_size_bytes)} per file ({len(c.files)} files){hl_tag}")

    selected_idx = st.selectbox(
        "Select a Duplicate Cluster to Inspect:",
        options=list(range(len(bounded_clusters))),
        format_func=lambda idx: cluster_labels[idx],
        key="dup_cluster_selectbox",
    )

    if selected_idx is not None and selected_idx < len(bounded_clusters):
        selected_cluster = bounded_clusters[selected_idx]

        sc_col1, sc_col2, sc_col3, sc_col4 = st.columns(4)
        with sc_col1:
            st.markdown(f"**File Size:** `{format_bytes_decimal(selected_cluster.file_size_bytes)}`")
        with sc_col2:
            st.markdown(f"**Instances:** `{len(selected_cluster.files)}`")
        with sc_col3:
            st.markdown(f"**Hardlinked Copies:** `{selected_cluster.hardlink_count}`")
        with sc_col4:
            if selected_cluster.wasted_bytes == 0:
                st.markdown("**Wasted Space:** `0 B (Hardlink-only)`")
            else:
                st.markdown(f"**Wasted Space:** `{format_bytes_decimal(selected_cluster.wasted_bytes)}`")

        # Files in Selected Cluster
        st.markdown("#### 📁 **Files in this Cluster:**")
        file_rows = []
        for f in selected_cluster.files:
            file_rows.append({
                "Path": alias_and_redact_path(f.path),
                "Size": format_bytes_decimal(f.size_bytes),
                "Inode": str(f.inode) if f.inode is not None else "N/A",
                "Hardlink?": "🔗 Yes" if f.is_hardlink else "📄 No",
                "Hash Status": "✅ SHA-256 Verified" if f.full_sha256 else "Partial Verified",
            })

        st.dataframe(pd.DataFrame(file_rows), use_container_width=True, hide_index=True)

    st.markdown("---")

    # Overview Table of Top Clusters
    st.markdown("### 📊 **Top Duplicate Clusters Summary**")
    summary_rows = []
    for i, c in enumerate(bounded_clusters[:25], start=1):
        summary_rows.append({
            "Cluster": f"#{i}",
            "File Size": format_bytes_decimal(c.file_size_bytes),
            "File Count": len(c.files),
            "Hardlinks": c.hardlink_count,
            "Potential Savings": format_bytes_decimal(c.wasted_bytes),
            "Sample Path": alias_and_redact_path(c.files[0].path) if c.files else "N/A",
        })

    st.dataframe(pd.DataFrame(summary_rows), use_container_width=True, hide_index=True)

    st.markdown("---")

    # Action Links (Informational Only)
    acol1, acol2 = st.columns([1, 1])
    with acol1:
        if st.button("💡 View Actionable Recommendations", key="dup_goto_recs"):
            navigate_to("Recommendations")
            st.rerun()
    with acol2:
        if st.button("🤖 Ask AI Agent about Duplicate Files", key="dup_goto_agent"):
            navigate_to("Agent")
            st.rerun()
