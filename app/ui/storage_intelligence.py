"""
MacGuard AI v1.1 — Storage Intelligence & Historical Visualization View.

This module provides Streamlit rendering for historical storage trends,
category growth velocity, developer tooling changes, and bounded top-N consumers.

DISCOVERY != CATEGORIZATION != ANALYSIS != AUTHORIZATION
Storage intelligence is strictly observational. Historical growth never creates
cleanup recommendations, approvals, or execution actions.
"""

from __future__ import annotations

import datetime
from typing import List, Optional
import altair as alt
import pandas as pd
import streamlit as st

from app.analysis.storage_history import StorageHistoryRepository
from app.analysis.storage_trends import StorageTrendsEngine
from app.models.category import SmartCategory
from app.models.developer import DeveloperStorageSubtype
from app.models.scan_result import ScanStatus
from app.models.scan_scope import ScopeIdentifier
from app.models.storage_history import (
    CategoryTrend,
    DeveloperTrend,
    LargeConsumerSnapshotItem,
    StorageSnapshot,
    StorageTrendReport,
    TrendDirection,
)
from app.tools.storage_scanner import format_bytes, format_bytes_decimal
from app.ui.state import get_services, init_app_state


def get_trend_badge(direction: TrendDirection) -> str:
    """Return accessible text and icon for trend direction."""
    if direction == TrendDirection.GROWING:
        return "🔺 **Growing**"
    elif direction == TrendDirection.SHRINKING:
        return "🔻 **Shrinking**"
    elif direction == TrendDirection.STABLE:
        return "🔹 **Stable**"
    else:
        return "⚪ **Undetermined**"


def format_timestamp(ts: float) -> str:
    """Format Unix timestamp into human-readable local datetime."""
    try:
        dt = datetime.datetime.fromtimestamp(ts)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "N/A"


def render_storage_intelligence_page() -> None:
    """
    Render the standalone Storage Intelligence & Historical Trends page with brand header and safety notice.
    """
    init_app_state()
    from app.ui.components import render_brand_header, render_safety_notice

    render_brand_header()
    render_safety_notice(context="general")
    render_storage_intelligence_view()


def render_storage_intelligence_view(
    scope_id: ScopeIdentifier = ScopeIdentifier.HOME,
    root_path: Optional[str] = None,
) -> None:
    """
    Main entry point for rendering the Storage Intelligence & Historical Trends section.
    """
    services = get_services()
    history_repo: StorageHistoryRepository = services.get(
        "storage_history", StorageHistoryRepository()
    )
    trends_engine: StorageTrendsEngine = services.get(
        "storage_trends", StorageTrendsEngine()
    )

    st.markdown("### 📈 **Storage Intelligence & Historical Trends**")
    st.caption("Deterministic historical tracking and growth analytics across discovery scans")

    # Scope selector & historical snapshot querying
    scope_options = [
        ScopeIdentifier.HOME,
        ScopeIdentifier.DEVELOPER,
        ScopeIdentifier.USER_CACHES,
        ScopeIdentifier.DOWNLOADS,
        ScopeIdentifier.DOCUMENTS,
        ScopeIdentifier.CUSTOM,
    ]
    scope_labels = {
        ScopeIdentifier.HOME: "🏠 User Home Directory",
        ScopeIdentifier.DEVELOPER: "🛠️ Developer Workspace",
        ScopeIdentifier.USER_CACHES: "⚡ User Caches",
        ScopeIdentifier.DOWNLOADS: "📥 Downloads Directory",
        ScopeIdentifier.DOCUMENTS: "📄 Documents Directory",
        ScopeIdentifier.CUSTOM: "📁 Custom / Comprehensive Scope",
    }

    selected_scope = st.selectbox(
        "Scan Scope for Intelligence:",
        options=scope_options,
        index=0,
        format_func=lambda s: scope_labels.get(s, s.value),
        key="storage_intelligence_scope_select",
    )

    # Determine canonical root path for the selected scope
    import os
    from pathlib import Path

    if selected_scope == ScopeIdentifier.HOME:
        canonical_root = os.path.normpath(str(Path.home().resolve()))
    elif selected_scope == ScopeIdentifier.DEVELOPER:
        canonical_root = os.path.normpath(str(Path.home().resolve() / "Projects"))
    elif selected_scope == ScopeIdentifier.USER_CACHES:
        canonical_root = os.path.normpath(str(Path.home().resolve() / "Library" / "Caches"))
    elif selected_scope == ScopeIdentifier.DOWNLOADS:
        canonical_root = os.path.normpath(str(Path.home().resolve() / "Downloads"))
    elif selected_scope == ScopeIdentifier.DOCUMENTS:
        canonical_root = os.path.normpath(str(Path.home().resolve() / "Documents"))
    elif selected_scope == ScopeIdentifier.CUSTOM:
        if root_path is not None:
            canonical_root = os.path.normpath(str(root_path))
        else:
            custom_choice = st.radio(
                "Custom Scope Target:",
                options=["System Root (Comprehensive)", "Custom Specific Directory Path"],
                index=0,
                horizontal=True,
                key="storage_intelligence_custom_choice",
            )
            if custom_choice == "System Root (Comprehensive)":
                canonical_root = "/"
            else:
                user_custom_path = st.text_input(
                    "Target Directory Path",
                    value=str(Path.home()),
                    key="storage_intelligence_custom_path",
                )
                canonical_root = os.path.normpath(str(Path(user_custom_path).expanduser().resolve()))
    else:
        canonical_root = os.path.normpath(str(root_path or Path.home().resolve()))

    try:
        snapshots: List[StorageSnapshot] = history_repo.get_snapshot_history(
            selected_scope, limit=90, root_path=canonical_root
        )
    except Exception as exc:
        st.error("Storage history database is temporarily unavailable. Please run a new scan to initialize history.")
        return

    # 1. Zero Snapshots: Friendly Empty State
    if not snapshots:
        st.info(
            f"ℹ️ **No Historical Scans Recorded for {scope_labels.get(selected_scope, selected_scope.value)}**\n\n"
            "Run a diagnostic scan in **Scan Storage** to begin tracking storage trends, category velocity, and developer metrics over time."
        )
        return

    latest_snapshot = snapshots[0]

    selected_baseline_label = "Previous Consecutive Scan"
    prev_snapshot: Optional[StorageSnapshot] = None
    if len(snapshots) > 1:
        history_choices = ["Previous Consecutive Scan"] + [
            f"Scan from {format_timestamp(s.timestamp)} ({format_bytes_decimal(s.total_bytes)})"
            for s in snapshots[1:]
        ]
        selected_baseline_label = st.selectbox(
            "Compare Current Scan Against:",
            options=history_choices,
            index=0,
            key="history_baseline_select",
        )
        if selected_baseline_label == "Previous Consecutive Scan":
            prev_snapshot = snapshots[1]
        else:
            selected_idx = history_choices.index(selected_baseline_label)
            prev_snapshot = snapshots[selected_idx]

    comparison_metric_label = (
        "Change Since Previous Scan"
        if selected_baseline_label == "Previous Consecutive Scan"
        else "Change Since Baseline"
    )

    # Generate Deterministic Trend Report
    trend_report = trends_engine.compare_snapshots(current=latest_snapshot, previous=prev_snapshot)

    # 3. Overview Metric Cards
    render_overview_cards(
        latest_snapshot,
        trend_report,
        prev_snapshot,
        comparison_label=comparison_metric_label,
    )

    st.markdown("---")

    # 4. Incomplete Scan Warning Banner
    if latest_snapshot.status != ScanStatus.COMPLETED:
        st.warning(
            f"⚠️ **Partial Scan Observation**: Current scan completed with status `{latest_snapshot.status.value}`. "
            "Storage metrics and trend values reflect partial scan coverage."
        )

    # 5. "What's Growing?" Insights
    render_whats_growing(trend_report)

    st.markdown("---")

    # 6. Storage Usage Over Time Chart
    render_storage_history_chart(snapshots, target_scope=selected_scope, target_root=canonical_root)

    st.markdown("---")

    # 7. Category Intelligence & Trends
    render_category_intelligence(trend_report, latest_snapshot)

    st.markdown("---")

    # 8. Developer Tooling Trends
    render_developer_trends(trend_report)

    st.markdown("---")

    # 9. Largest Storage Consumers
    render_large_consumers(latest_snapshot)

    st.markdown("---")
    st.info(
        "🔒 **Observational Boundary**: Storage trends provide analytical visibility into drive utilization. "
        "Historical growth is strictly informational and does not grant or alter cleanup authorization."
    )

    recs_in_state = st.session_state.get("recommendations", [])
    if recs_in_state:
        if st.button("💡 Review Current Recommendations", key="btn_hist_to_recommendations", use_container_width=True):
            from app.ui.state import navigate_to
            navigate_to("Recommendations")
            st.rerun()


def render_overview_cards(
    latest: StorageSnapshot,
    report: StorageTrendReport,
    prev: Optional[StorageSnapshot],
    comparison_label: str = "Change Since Baseline",
) -> None:
    """Render top summary metric cards."""
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            label="Current Scanned Storage",
            value=format_bytes_decimal(latest.total_bytes),
            help=f"Exact size: {latest.total_bytes:,} bytes across {latest.files_count} files and {latest.directories_count} directories.",
        )

    with col2:
        if report.is_comparable and report.overall_trend.percentage_change is not None:
            pct = report.overall_trend.percentage_change
            abs_str = format_bytes_decimal(abs(report.overall_trend.absolute_change))
            sign = "+" if report.overall_trend.absolute_change > 0 else ("-" if report.overall_trend.absolute_change < 0 else "")
            st.metric(
                label=comparison_label,
                value=f"{sign}{abs_str}",
                delta=f"{sign}{pct:.2f}%",
                delta_color="inverse" if report.overall_trend.absolute_change > 0 else "normal",
            )
        else:
            help_text = (
                "The previous scan used a different scope, so MacGuard will not interpret the difference as storage growth or shrinkage."
                if prev is not None
                else "No previous comparable scan available."
            )
            st.metric(label=comparison_label, value="—", help=help_text)

    with col3:
        if report.is_comparable:
            st.metric(
                label="Trend Classification",
                value=report.overall_trend.direction.value.title(),
                help=report.overall_trend.explanation,
            )
        elif prev is not None:
            st.metric(
                label="Trend Classification",
                value="No Comparable Baseline",
                help="The previous scan used a different scope, so MacGuard will not interpret the difference as storage growth or shrinkage.",
            )
        else:
            st.metric(label="Trend Classification", value="First Baseline", help="Need at least 2 scans to classify trend.")

    with col4:
        st.metric(
            label="Last Scan Recorded",
            value=format_timestamp(latest.timestamp),
            help=f"Scan duration: {latest.duration_seconds:.2f}s | Status: {latest.status.value}",
        )


def render_whats_growing(
    report: StorageTrendReport,
    current_candidates: Optional[Sequence[StorageCandidate]] = None,
) -> None:
    """Render the concise deterministic 'What's Growing?' section."""
    st.markdown("#### 🔍 **What's Growing?**")

    if not report.is_comparable:
        st.write("Growth analysis requires at least two comparable scans for this scope.")
        return

    growing_cats = [c for c in report.category_trends if c.direction == TrendDirection.GROWING and c.absolute_change > 0]
    growing_devs = [d for d in report.developer_trends if d.direction == TrendDirection.GROWING and d.absolute_change > 0]

    if not growing_cats and not growing_devs:
        st.success("✨ **Storage is broadly stable.** No categories or developer storage areas showed significant growth since the previous scan.")
        return

    cands = current_candidates if current_candidates is not None else st.session_state.get("candidates", [])
    insights = []
    if growing_cats:
        for idx, cat in enumerate(growing_cats[:3], start=1):
            title = cat.category.value.replace("_", " ").title()
            legacy_cat = cat.category.to_legacy_storage_category()
            matching_cands = [c for c in cands if c.category == legacy_cat]
            cand_count_str = f" — `{len(matching_cands)}` candidate(s) available for review" if matching_cands else " — *No active cleanup candidates in current scan*"
            insights.append(f"{idx}. **{title}**: +{format_bytes_decimal(cat.absolute_change)} (+{cat.percentage_change:.1f}%){cand_count_str}")

    if growing_devs:
        for idx, dev in enumerate(growing_devs[:2], start=len(insights) + 1):
            title = dev.subtype.value.replace("_", " ").title()
            insights.append(f"{idx}. **Developer - {title}**: +{format_bytes_decimal(dev.absolute_change)} (+{dev.percentage_change:.1f}%)")

    for ins in insights:
        st.markdown(f"- {ins}")

    if current_candidates and any(c.category in [gc.category.to_legacy_storage_category() for gc in growing_cats] for c in current_candidates):
        from app.ui.state import navigate_to
        if st.button("🛡️ Investigate Growing Categories in Human Review", key="btn_growing_to_review"):
            navigate_to("Review")
            st.rerun()


def render_storage_history_chart(
    snapshots: List[StorageSnapshot],
    target_scope: Optional[ScopeIdentifier] = None,
    target_root: Optional[str] = None,
) -> None:
    """Render historical storage utilization line/area chart using Altair."""
    st.markdown("#### 📊 **Storage Usage Over Time**")

    if not snapshots:
        return

    # Filter snapshots to only those sharing the exact scope_id and canonical root_path,
    # strictly preventing visual connection of incompatible scope/root measurements.
    import os

    effective_scope = target_scope if target_scope is not None else snapshots[0].scope_id
    effective_root = os.path.normpath(str(target_root)) if target_root is not None else os.path.normpath(str(snapshots[0].root_path))

    compatible_snapshots = [
        s for s in snapshots
        if s.scope_id == effective_scope and os.path.normpath(str(s.root_path)) == effective_root
    ]

    if len(compatible_snapshots) < 2:
        st.info("Run another scan later with the same scope to compare storage usage over time on this chart.")
        return

    # Prepare chronologically sorted dataframe
    chronological = sorted(compatible_snapshots, key=lambda s: s.timestamp)
    chart_data = []
    for s in chronological:
        chart_data.append(
            {
                "Date": format_timestamp(s.timestamp),
                "Storage_GB": round(s.total_bytes / (1000 * 1000 * 1000), 2),
                "Formatted_Size": format_bytes_decimal(s.total_bytes),
                "Files": s.files_count,
            }
        )

    df = pd.DataFrame(chart_data)

    chart = (
        alt.Chart(df)
        .mark_area(
            line={"color": "#3b82f6", "width": 2},
            color=alt.Gradient(
                gradient="linear",
                stops=[
                    alt.GradientStop(color="rgba(59, 130, 246, 0.4)", offset=0),
                    alt.GradientStop(color="rgba(59, 130, 246, 0.02)", offset=1),
                ],
                x1=1,
                x2=1,
                y1=1,
                y2=0,
            ),
            point=alt.OverlayMarkDef(color="#3b82f6", size=60),
        )
        .encode(
            x=alt.X("Date:N", title="Scan Date / Time", sort=None, axis=alt.Axis(labelAngle=-25)),
            y=alt.Y(
                "Storage_GB:Q",
                title="Analyzed Storage (GB)",
                scale=alt.Scale(domainMin=0, zero=True),
                axis=alt.Axis(tickMinStep=1),
            ),
            tooltip=[
                alt.Tooltip("Date:N", title="Scan Time"),
                alt.Tooltip("Formatted_Size:N", title="Analyzed Storage"),
                alt.Tooltip("Files:Q", title="Total Files"),
            ],
        )
        .properties(height=280)
    )

    st.altair_chart(chart, use_container_width=True)


def render_category_intelligence(
    report: StorageTrendReport,
    latest: StorageSnapshot,
) -> None:
    """Render horizontal category breakdown chart and category trends table."""
    st.markdown("#### 📂 **Category Storage Trends & Breakdown**")

    col1, col2 = st.columns([1, 1])

    with col1:
        st.markdown("**Current Category Breakdown**")
        if latest.categories:
            cat_chart_rows = [
                {
                    "Category": c.category.value.replace("_", " ").title(),
                    "Storage (GB)": round(c.total_bytes / (1000 * 1000 * 1000), 2),
                    "Size": format_bytes_decimal(c.total_bytes),
                    "Items": c.item_count,
                }
                for c in latest.categories
                if c.total_bytes > 0
            ]
            if cat_chart_rows:
                df_cat = pd.DataFrame(cat_chart_rows)
                cat_chart = (
                    alt.Chart(df_cat)
                    .mark_bar(cornerRadiusTopRight=4, cornerRadiusBottomRight=4, color="#3b82f6")
                    .encode(
                        y=alt.Y("Category:N", sort="-x", title=None),
                        x=alt.X("Storage (GB):Q", scale=alt.Scale(domainMin=0, zero=True), title="Storage (GB)"),
                        tooltip=[
                            alt.Tooltip("Category:N", title="Category"),
                            alt.Tooltip("Size:N", title="Total Size"),
                            alt.Tooltip("Items:Q", title="Items Count"),
                        ],
                    )
                    .properties(height=260)
                )
                st.altair_chart(cat_chart, use_container_width=True)
            else:
                st.write("No categorical data available in this scan.")
        else:
            st.write("No categories recorded.")

    with col2:
        st.markdown("**Category Velocity (vs Baseline)**")
        if report.category_trends:
            table_rows = []
            for t in report.category_trends:
                direction_icon = "🔺" if t.direction == TrendDirection.GROWING else ("🔻" if t.direction == TrendDirection.SHRINKING else "🔹")
                sign = "+" if t.absolute_change > 0 else ""
                pct_str = f"{sign}{t.percentage_change:.1f}%" if t.percentage_change is not None else "—"
                table_rows.append(
                    {
                        "Category": t.category.value.replace("_", " ").title(),
                        "Current": format_bytes_decimal(t.current_bytes),
                        "Previous": format_bytes_decimal(t.previous_bytes),
                        "Change": f"{sign}{format_bytes_decimal(t.absolute_change)}",
                        "Change %": pct_str,
                        "Status": f"{direction_icon} {t.direction.value.title()}",
                    }
                )
            st.dataframe(table_rows, use_container_width=True)
        else:
            st.write("Category trends will appear after a second scan.")


def render_developer_trends(report: StorageTrendReport) -> None:
    """Render developer storage breakdown and trends table."""
    st.markdown("#### 🛠️ **Developer Tooling & Artifact Trends**")

    if not report.developer_trends:
        st.info("No developer storage items detected in current or baseline scans.")
        return

    dev_rows = []
    for d in report.developer_trends:
        direction_icon = "🔺" if d.direction == TrendDirection.GROWING else ("🔻" if d.direction == TrendDirection.SHRINKING else "🔹")
        sign = "+" if d.absolute_change > 0 else ""
        pct_str = f"{sign}{d.percentage_change:.1f}%" if d.percentage_change is not None else "—"
        dev_rows.append(
            {
                "Subtype": d.subtype.value.replace("_", " ").title(),
                "Current Size": format_bytes_decimal(d.current_bytes),
                "Previous Size": format_bytes_decimal(d.previous_bytes),
                "Change": f"{sign}{format_bytes_decimal(d.absolute_change)}",
                "Velocity": pct_str,
                "Trend": f"{direction_icon} {d.direction.value.title()}",
            }
        )
    st.dataframe(dev_rows, use_container_width=True)


def render_large_consumers(latest: StorageSnapshot) -> None:
    """Render the top storage consumers table from the snapshot."""
    st.markdown("#### 📦 **Largest Storage Consumers (Top 20)**")

    if not latest.top_consumers:
        st.write("No large storage consumer artifacts recorded in this snapshot.")
        return

    from app.ui.components import alias_and_redact_path

    rows = []
    for c in latest.top_consumers:
        rows.append(
            {
                "Rank": f"#{c.rank}",
                "Path": alias_and_redact_path(c.path),
                "Size": format_bytes_decimal(c.size_bytes),
                "Category": c.category.value.replace("_", " ").title(),
                "Confidence": c.confidence.value,
            }
        )
    st.dataframe(rows, use_container_width=True)
