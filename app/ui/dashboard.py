from pathlib import Path
from typing import Optional
import altair as alt
import pandas as pd
import streamlit as st

from app.analysis.models import RiskLevel, StorageCategory
from app.tools.storage_scanner import format_bytes, format_bytes_decimal
from app.ui.components import (
    render_brand_header,
    render_safety_notice,
    render_storage_stats_cards,
    risk_badge,
)
from app.ui.demo import generate_demo_dataset
from app.ui.state import get_services, init_app_state, navigate_to
from app.ui.storage_intelligence import render_storage_intelligence_view


def render_dashboard() -> None:
    """Render the Main Storage Overview and System Dashboard."""
    init_app_state()
    services = get_services()
    scanner = services["scanner"]

    render_brand_header()
    st.markdown("### 📊 Executive System Storage Overview")
    render_safety_notice(context="general")

    # 1. Fetch System Disk Usage (Physical Filesystem)
    try:
        usage = scanner.get_disk_usage("/")
    except Exception as e:
        st.error(f"Failed to read disk usage: {e}")
        return

    render_storage_stats_cards(
        total_bytes=usage.total_bytes,
        used_bytes=usage.used_bytes,
        free_bytes=usage.free_bytes,
        usage_percent=usage.usage_percent,
    )

    # Progress bar for disk capacity
    st.progress(min(max(usage.usage_percent / 100.0, 0.0), 1.0))

    st.markdown("---")

    tab_overview, tab_intelligence = st.tabs([
        "📊 Current Scope & System Overview",
        "📈 Storage Intelligence & History",
    ])

    with tab_intelligence:
        render_storage_intelligence_view()

    with tab_overview:
        candidates = st.session_state.get("candidates", [])
        is_demo = st.session_state.get("is_demo_mode", False)

        # 2. Executive Quick Actions Bar
        st.markdown("#### ⚡ **Quick Workflow Actions**")
        cta1, cta2, cta3, cta4, cta5, cta6 = st.columns(6)
        with cta1:
            if st.button("🔍 Scan", type="primary", use_container_width=True):
                navigate_to("Scan")
                st.rerun()
        with cta2:
            if st.button("🛠️ Developer", use_container_width=True):
                navigate_to("DeveloperStorage")
                st.rerun()
        with cta3:
            if st.button("📑 Duplicates", use_container_width=True):
                navigate_to("Duplicates")
                st.rerun()
        with cta4:
            if st.button("💡 Recommendations", use_container_width=True, disabled=not candidates):
                navigate_to("Recommendations")
                st.rerun()
        with cta5:
            if st.button("🛡️ Review", use_container_width=True, disabled=not candidates):
                navigate_to("Review")
                st.rerun()
        with cta6:
            if st.button("🤖 Agent", use_container_width=True):
                navigate_to("Agent")
                st.rerun()

        st.markdown("---")

        # 3. First-run onboarding state if no scan active
        if not candidates:
            st.markdown("### 🚀 **Welcome to MacGuard AI**")
            st.write(
                "MacGuard AI combines deterministic safety rules with local AI agent intelligence to "
                "help you audit and manage storage without risking your personal documents or system integrity."
            )

            st.markdown(
                """
                **How MacGuard AI Protects Your System:**
                - 🔍 **Read-Only Diagnostics**: Scans your storage hierarchy safely without any filesystem modification.
                - 🛡️ **Zero Permanent Deletion**: Files are strictly moved to macOS Trash (`~/.Trash`) with pre- and post-integrity checks.
                - 🔒 **Cryptographic Approvals**: Every cleanup requires explicit human approval signed with HMAC-SHA256 tokens.
                - 🤖 **Zero-Authority AI**: The AI assistant provides explanations and recommendations but cannot delete or move files.
                """
            )

            ob_c1, ob_c2 = st.columns([1, 1])
            with ob_c1:
                if st.button("🚀 Start Storage Diagnostic Scan", type="primary", use_container_width=True):
                    navigate_to("Scan")
                    st.rerun()
            with ob_c2:
                if st.button("🧪 Load Presentation Demo Data (Sandbox)", use_container_width=True):
                    items, demo_cands, demo_recs, demo_revs, demo_ctx = generate_demo_dataset()
                    st.session_state.scan_results = items
                    st.session_state.candidates = demo_cands
                    st.session_state.recommendations = demo_recs
                    st.session_state.review_items = demo_revs
                    st.session_state.analysis_context = demo_ctx
                    st.session_state.is_demo_mode = True
                    st.success("Loaded safe presentation demo dataset! Explore charts, recommendations, and review queue.")
                    st.rerun()

            st.markdown("---")
            return

        # 4. Active Scan / Demo Scope Metrics
        analyzer = services["analyzer"]
        reclaimable_bytes = analyzer.calculate_reclaimable_bytes(candidates)
        physical_coverage = analyzer.calculate_physical_coverage_bytes(candidates)
        eligible_count = sum(1 for c in candidates if c.risk_level == RiskLevel.LOW)
        manual_count = sum(1 for c in candidates if c.risk_level == RiskLevel.MEDIUM)
        blocked_count = sum(1 for c in candidates if c.risk_level in (RiskLevel.HIGH, RiskLevel.UNKNOWN))

        scope_header = "🛡️ **MacGuard Storage Analysis (Scanned Scope)**"
        if is_demo:
            scope_header += " — `🧪 PRESENTATION DEMO MODE`"
        st.markdown(f"#### {scope_header}")

        col_a, col_b, col_c, col_d = st.columns(4)
        with col_a:
            st.metric("Identified Candidates", f"{len(candidates)} items")
        with col_b:
            st.metric("Total Analyzed Size", format_bytes_decimal(physical_coverage))
        with col_c:
            st.metric("Eligible for Cleanup Review", format_bytes_decimal(reclaimable_bytes), help=f"{eligible_count} candidate(s) with LOW risk")
        with col_d:
            st.metric("Manual Review / Protected", f"{manual_count + blocked_count} item(s)", help=f"{manual_count} manual review, {blocked_count} strictly blocked")

        st.markdown("---")

        # 5. Visual Charts & Storage Breakdown
        col1, col2 = st.columns([1, 1])

        with col1:
            st.subheader("📂 Storage by Category")
            category_data: dict[str, dict[str, int]] = {}
            for cat in StorageCategory:
                matching = [c for c in candidates if c.category == cat]
                category_data[cat.value] = {
                    "count": len(matching),
                    "size": sum(m.size_bytes for m in matching),
                }

            cat_chart_rows = [
                {
                    "Category": cat_name.replace("_", " ").title(),
                    "Storage (MB)": round(stats["size"] / (1024 * 1024), 1),
                    "Formatted Size": format_bytes_decimal(stats["size"]),
                    "Items": stats["count"],
                }
                for cat_name, stats in category_data.items()
                if stats["size"] > 0
            ]

            if cat_chart_rows:
                df_cat = pd.DataFrame(cat_chart_rows)
                chart_cat = (
                    alt.Chart(df_cat)
                    .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4, color="#3b82f6")
                    .encode(
                        x=alt.X("Category:N", sort="-y", title="Storage Category", axis=alt.Axis(labelAngle=0)),
                        y=alt.Y(
                            "Storage (MB):Q",
                            scale=alt.Scale(domainMin=0, zero=True, clamp=True),
                            axis=alt.Axis(title="Storage (MB)", tickMinStep=1),
                        ),
                        tooltip=[
                            alt.Tooltip("Category:N", title="Category"),
                            alt.Tooltip("Formatted Size:N", title="Total Size"),
                            alt.Tooltip("Storage (MB):Q", title="Size (MB)", format=",.1f"),
                            alt.Tooltip("Items:Q", title="Count"),
                        ],
                    )
                    .properties(height=260)
                )
                st.altair_chart(chart_cat, use_container_width=True)
            else:
                st.write("All scanned items are currently unclassified.")

            cat_rows = []
            for cat_name, stats in category_data.items():
                if stats["count"] > 0:
                    cat_rows.append(
                        {
                            "Category": cat_name.replace("_", " ").title(),
                            "Items": stats["count"],
                            "Total Size": format_bytes_decimal(stats["size"]),
                        }
                    )
            if cat_rows:
                st.table(cat_rows)

        with col2:
            st.subheader("🛡️ Safety & Risk Distribution")
            risk_counts = {
                "LOW (Eligible for Review)": sum(1 for c in candidates if c.risk_level == RiskLevel.LOW),
                "MEDIUM (Manual Caution)": sum(1 for c in candidates if c.risk_level == RiskLevel.MEDIUM),
                "HIGH (Protected System/User)": sum(1 for c in candidates if c.risk_level == RiskLevel.HIGH),
                "UNKNOWN (Conservative Block)": sum(1 for c in candidates if c.risk_level == RiskLevel.UNKNOWN),
            }

            risk_colors = {
                "LOW": "#10b981",
                "MEDIUM": "#f59e0b",
                "HIGH": "#ef4444",
                "UNKNOWN": "#64748b",
            }
            risk_chart_rows = [
                {
                    "Risk Tier": k.split(" ")[0],
                    "Count": v,
                }
                for k, v in risk_counts.items()
                if v > 0
            ]
            if risk_chart_rows:
                df_risk = pd.DataFrame(risk_chart_rows)
                chart_risk = (
                    alt.Chart(df_risk)
                    .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
                    .encode(
                        x=alt.X("Risk Tier:N", sort=None, title="Risk Tier", axis=alt.Axis(labelAngle=0)),
                        y=alt.Y(
                            "Count:Q",
                            scale=alt.Scale(domainMin=0, zero=True, clamp=True),
                            axis=alt.Axis(title="Item Count", tickMinStep=1),
                        ),
                        color=alt.Color(
                            "Risk Tier:N",
                            scale=alt.Scale(
                                domain=list(risk_colors.keys()),
                                range=list(risk_colors.values()),
                            ),
                            legend=None,
                        ),
                        tooltip=[
                            alt.Tooltip("Risk Tier:N", title="Risk Tier"),
                            alt.Tooltip("Count:Q", title="Item Count"),
                        ],
                    )
                    .properties(height=260)
                )
                st.altair_chart(chart_risk, use_container_width=True)

            for risk_label, count in risk_counts.items():
                st.metric(label=risk_label, value=count)

        st.markdown("---")

        # 6. Top Candidates Table
        st.subheader("🔍 Top Identified Storage Candidates")
        display_data = []
        for c in sorted(candidates, key=lambda x: x.size_bytes, reverse=True)[:20]:
            display_data.append(
                {
                    "Path": c.path,
                    "Size": format_bytes_decimal(c.size_bytes),
                    "Category": c.category.value.title(),
                    "Risk": c.risk_level.value,
                    "Confidence": f"{c.confidence:.0%}",
                    "Reason": c.reason,
                }
            )
        st.dataframe(display_data, use_container_width=True)
