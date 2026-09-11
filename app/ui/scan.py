import os
from pathlib import Path
import time
from typing import Optional
import altair as alt
import pandas as pd
import streamlit as st

from app.analysis.categorizer import SmartCategorizer
from app.analysis.developer_analyzer import DeveloperStorageAnalyzer
from app.analysis.large_file_analyzer import LargeFileAnalyzer
from app.analysis.models import RiskLevel, StorageCategory
from app.analysis.storage_history import StorageHistoryRepository
from app.llm.models import AnalysisContext
from app.models.scan_result import DiscoveredItem, ScanResult, ScanStatus
from app.models.scan_scope import ScopeIdentifier
from app.tools.storage_scanner import StorageItem, format_bytes, format_bytes_decimal
from app.ui.components import (
    get_item_hierarchy_info,
    render_brand_header,
    render_safety_notice,
    risk_badge,
)
from app.ui.demo import generate_demo_dataset
from app.ui.state import get_services, init_app_state, navigate_to


def render_scan_page() -> None:
    """Render the Scan Storage page and workflow."""
    init_app_state()
    services = get_services()
    scanner = services["scanner"]
    analyzer = services["analyzer"]
    rec_engine = services["recommendation_engine"]
    approval_service = services["approval_service"]

    render_brand_header()
    st.markdown("### 🔍 Storage Diagnostic Scanner (Read-Only)")
    render_safety_notice(context="general")

    st.write(
        "MacGuard AI inspects your macOS storage hierarchy safely without modifying, moving, "
        "or deleting any files. Choose a scan scope below to begin diagnostic analysis."
    )

    # Scope selection
    scan_scope = st.radio(
        "Scan Scope:",
        options=[
            "Recommended User Storage Scope (Fast & Targeted)",
            "System Root & Home Directory (Comprehensive)",
            "Custom Specific Directory",
        ],
        index=0,
    )

    with st.expander("⚙️ Scan Depth & Limit Settings", expanded=(scan_scope != "Recommended User Storage Scope (Fast & Targeted)")):
        col1, col2 = st.columns(2)
        with col1:
            top_dirs_limit = st.slider("Max Subdirectories per Target", min_value=3, max_value=30, value=10)
        with col2:
            top_files_limit = st.slider("Max Large Files per Target", min_value=3, max_value=30, value=10)

        custom_target_path = ""
        if scan_scope == "Custom Specific Directory":
            custom_target_path = st.text_input("Target Directory Path", value=str(Path.home()))

    scan_col1, scan_col2 = st.columns([2, 1])
    with scan_col1:
        start_scan = st.button("🚀 Run Read-Only Diagnostic Scan", type="primary", use_container_width=True)
    with scan_col2:
        load_demo = st.button("🧪 Load Presentation Demo Data", use_container_width=True)

    if load_demo:
        items, demo_cands, demo_recs, demo_revs, demo_ctx = generate_demo_dataset()
        st.session_state.scan_results = items
        st.session_state.candidates = demo_cands
        st.session_state.recommendations = demo_recs
        st.session_state.review_items = demo_revs
        st.session_state.analysis_context = demo_ctx
        st.session_state.is_demo_mode = True
        st.success("Loaded safe presentation demo dataset! (Zero filesystem impact).")
        st.rerun()

    if start_scan:
        st.session_state.is_demo_mode = False
        with st.spinner("Inspecting filesystem (read-only)..."):
            items: list[StorageItem] = []
            start_time = time.time()

            try:
                if scan_scope == "Recommended User Storage Scope (Fast & Targeted)":
                    scope_id = ScopeIdentifier.HOME
                    root_path = str(Path.home())
                    common_targets = scanner.get_common_user_storage_targets()
                    for target in common_targets:
                        try:
                            dirs = scanner.get_top_directories(path=target, limit=top_dirs_limit)
                            files = scanner.get_large_files(path=target, limit=top_files_limit)
                            items.extend(dirs)
                            items.extend(files)
                        except (PermissionError, OSError):
                            continue

                elif scan_scope == "System Root & Home Directory (Comprehensive)":
                    scope_id = ScopeIdentifier.HOME
                    root_path = str(Path.home())
                    home_dir = str(Path.home())
                    dirs = scanner.get_top_directories(path="/", limit=top_dirs_limit)
                    files = scanner.get_large_files(path=home_dir, limit=top_files_limit)
                    items.extend(dirs)
                    items.extend(files)

                elif scan_scope == "Custom Specific Directory":
                    scope_id = ScopeIdentifier.CUSTOM
                    root_path = custom_target_path
                    if custom_target_path and os.path.exists(custom_target_path):
                        dirs = scanner.get_top_directories(path=custom_target_path, limit=top_dirs_limit)
                        files = scanner.get_large_files(path=custom_target_path, limit=top_files_limit)
                        items.extend(dirs)
                        items.extend(files)
                    else:
                        st.error(f"Path does not exist: {custom_target_path}")
                        return

                # Deduplicate items by canonical path
                seen_paths = set()
                deduped_items: list[StorageItem] = []
                for it in items:
                    if it.path not in seen_paths:
                        seen_paths.add(it.path)
                        deduped_items.append(it)

                # Deterministic Analysis (with hierarchical deduplication)
                candidates = analyzer.analyze_items(deduped_items, deduplicate=True)
                recommendations = rec_engine.recommend_many(candidates)
                review_items = approval_service.create_review_items(recommendations)

                # Build Analysis Context for Explanation Service
                total_bytes = sum(c.size_bytes for c in candidates)
                safety_summary = {
                    "LOW": sum(1 for c in candidates if c.risk_level == RiskLevel.LOW),
                    "MEDIUM": sum(1 for c in candidates if c.risk_level == RiskLevel.MEDIUM),
                    "HIGH": sum(1 for c in candidates if c.risk_level == RiskLevel.HIGH),
                    "UNKNOWN": sum(1 for c in candidates if c.risk_level == RiskLevel.UNKNOWN),
                }
                context = AnalysisContext(
                    scan_id=f"scan-{len(candidates)}-items",
                    scan_path=custom_target_path if scan_scope == "Custom Specific Directory" else str(Path.home()),
                    total_scanned_items=len(candidates),
                    total_size_bytes=total_bytes,
                    candidates=candidates,
                    recommendations=recommendations,
                    safety_summary=safety_summary,
                )

                st.session_state.scan_path = context.scan_path
                st.session_state.scan_results = deduped_items
                st.session_state.candidates = candidates
                st.session_state.recommendations = recommendations
                st.session_state.review_items = review_items
                st.session_state.analysis_context = context

                # Minimal Scan -> Storage History Persistence (Phase 5D)
                # Build canonical ScanResult & DiscoveredItem list from completed scan
                end_time = time.time()
                duration_seconds = max(0.0, round(end_time - start_time, 4))

                discovered_items: list[DiscoveredItem] = []
                files_count = 0
                directories_count = 0
                total_scanned_bytes = sum(it.size_bytes for it in deduped_items)

                for it in deduped_items:
                    mtime = end_time
                    st_ino = 0
                    st_dev = 0
                    is_symlink = False
                    try:
                        st_stat = os.lstat(it.path)
                        mtime = st_stat.st_mtime
                        st_ino = st_stat.st_ino
                        st_dev = st_stat.st_dev
                        is_symlink = os.path.islink(it.path)
                    except (PermissionError, OSError):
                        pass

                    if it.item_type == "directory":
                        directories_count += 1
                    else:
                        files_count += 1

                    try:
                        p_item = Path(it.path)
                        p_root = Path(root_path)
                        if p_item.is_relative_to(p_root):
                            depth = len(p_item.relative_to(p_root).parts)
                        else:
                            depth = len(p_item.parts)
                    except Exception:
                        depth = 1

                    cat_res = SmartCategorizer.categorize_path(it.path, item_type=it.item_type)

                    discovered_items.append(
                        DiscoveredItem(
                            path=it.path,
                            size_bytes=it.size_bytes,
                            item_type=it.item_type,
                            depth=depth,
                            mtime=mtime,
                            st_ino=st_ino,
                            st_dev=st_dev,
                            is_symlink=is_symlink,
                            parent_path=str(Path(it.path).parent),
                            category=cat_res.category,
                            confidence=cat_res.confidence,
                            category_rule=cat_res.matched_rule,
                        )
                    )

                scan_result = ScanResult(
                    scope_id=scope_id,
                    root_path=root_path,
                    status=ScanStatus.COMPLETED,
                    start_time=start_time,
                    end_time=end_time,
                    duration_seconds=duration_seconds,
                    files_count=files_count,
                    directories_count=directories_count,
                    total_bytes=total_scanned_bytes,
                    items=discovered_items,
                    skipped_entries_count=0,
                    permission_errors_count=0,
                )

                # Summarize developer and large file intelligence using existing analyzers
                dev_analyzer = DeveloperStorageAnalyzer()
                dev_summary = dev_analyzer.analyze_scan_result(scan_result)

                large_analyzer = LargeFileAnalyzer(developer_analyzer=dev_analyzer)
                large_summary = large_analyzer.analyze_scan_result(scan_result)

                # Persist completed scan into StorageHistoryRepository
                storage_history: Optional[StorageHistoryRepository] = services.get("storage_history")
                if storage_history is None:
                    storage_history = StorageHistoryRepository()

                storage_history.record_snapshot(
                    scan_result=scan_result,
                    category_summaries=large_summary.category_summaries,
                    developer_summary=dev_summary,
                    large_file_summary=large_summary,
                )

                st.success(
                    f"✅ Scan completed successfully! Found {len(candidates)} candidate items "
                    f"totaling {format_bytes_decimal(total_bytes)} of unique storage."
                )

            except Exception as e:
                st.error(f"Scan encountered an unexpected error: {e}")
                return

    # Display results if available
    if st.session_state.get("scan_results"):
        st.markdown("---")
        candidates = st.session_state.candidates
        is_demo = st.session_state.get("is_demo_mode", False)

        header_text = "📋 Scan Summary & Storage Visualizations"
        if is_demo:
            header_text += " — `🧪 PRESENTATION DEMO MODE`"
        st.subheader(header_text)

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Items Scanned", len(st.session_state.scan_results))
        with col2:
            st.metric("Storage Candidates", len(candidates))
        with col3:
            total_size = sum(c.size_bytes for c in candidates)
            st.metric("Total Candidate Size", format_bytes_decimal(total_size))
        with col4:
            eligible_size = sum(c.size_bytes for c in candidates if c.risk_level == RiskLevel.LOW)
            st.metric("Eligible for Review", format_bytes_decimal(eligible_size))

        tab_table, tab_charts, tab_next = st.tabs(["📋 Candidate Table", "📊 Storage Visualizations", "👉 Next Steps"])

        with tab_table:
            sorted_items = sorted(st.session_state.scan_results, key=lambda x: x.size_bytes, reverse=True)[:40]
            hierarchy_map = get_item_hierarchy_info(sorted_items)

            table_rows = []
            for it in sorted_items:
                hier = hierarchy_map.get(it.path)
                display_path = f"{hier.display_prefix}{it.path}" if hier else it.path
                hierarchy_status = hier.hierarchy_badge if hier else "Top-level candidate"
                size_str = f"{format_bytes_decimal(it.size_bytes)} (Included in parent)" if hier and hier.is_nested else format_bytes_decimal(it.size_bytes)

                table_rows.append({
                    "Type": it.item_type.title(),
                    "Path": display_path,
                    "Size": size_str,
                    "Hierarchy": hierarchy_status,
                })

            st.dataframe(table_rows, use_container_width=True)
            st.caption(
                "💡 **Hierarchy Note**: Nested items located inside parent candidates are labeled "
                "with `↳ Included in parent candidate` and are accounted under the parent container to prevent double counting."
            )

        with tab_charts:
            chart_col1, chart_col2 = st.columns(2)
            with chart_col1:
                st.markdown("#### 📂 **Storage by Category (MB)**")
                cat_rows = []
                for cat in StorageCategory:
                    matching = [c for c in candidates if c.category == cat]
                    total_mb = sum(m.size_bytes for m in matching) / (1024 * 1024)
                    if total_mb > 0:
                        cat_rows.append({
                            "Category": cat.value.replace("_", " ").title(),
                            "Storage (MB)": round(total_mb, 1),
                            "Formatted Size": format_bytes_decimal(sum(m.size_bytes for m in matching)),
                            "Count": len(matching),
                        })
                if cat_rows:
                    df_cat = pd.DataFrame(cat_rows)
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
                                alt.Tooltip("Count:Q", title="Items"),
                            ],
                        )
                        .properties(height=280)
                    )
                    st.altair_chart(chart_cat, use_container_width=True)
                else:
                    st.caption("No category data available.")

            with chart_col2:
                st.markdown("#### 🛡️ **Risk Tier Distribution (Item Count)**")
                risk_colors = {
                    "LOW (Eligible)": "#10b981",
                    "MEDIUM (Manual)": "#f59e0b",
                    "HIGH (Protected)": "#ef4444",
                    "UNKNOWN (Blocked)": "#64748b",
                }
                risk_rows = []
                for tier_label, r_level in [
                    ("LOW (Eligible)", RiskLevel.LOW),
                    ("MEDIUM (Manual)", RiskLevel.MEDIUM),
                    ("HIGH (Protected)", RiskLevel.HIGH),
                    ("UNKNOWN (Blocked)", RiskLevel.UNKNOWN),
                ]:
                    matching = [c for c in candidates if c.risk_level == r_level]
                    if matching:
                        risk_rows.append({
                            "Risk Tier": tier_label,
                            "Count": len(matching),
                            "Total Size": format_bytes_decimal(sum(c.size_bytes for c in matching)),
                        })
                if risk_rows:
                    df_risk = pd.DataFrame(risk_rows)
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
                                alt.Tooltip("Total Size:N", title="Total Size"),
                            ],
                        )
                        .properties(height=280)
                    )
                    st.altair_chart(chart_risk, use_container_width=True)
                else:
                    st.caption("No risk tier data available.")

            st.markdown("#### 🔍 **Largest Storage Consumers**")
            top_candidates = sorted(candidates, key=lambda x: x.size_bytes, reverse=True)[:8]
            top_rows = []
            for c in top_candidates:
                p = Path(c.path)
                name = p.name or c.path
                if len(p.parts) > 1 and len(name) < 18:
                    display_name = f"{p.parts[-2]}/{name}"
                else:
                    display_name = name
                size_mb = round(c.size_bytes / (1024 * 1024), 1)
                top_rows.append({
                    "Target Item": display_name,
                    "Size (MB)": size_mb,
                    "Formatted Size": format_bytes_decimal(c.size_bytes),
                    "Category": c.category.value.replace("_", " ").title(),
                    "Risk Level": c.risk_level.value,
                    "Full Path": c.path,
                    "Reason": c.reason or "Identified storage consumer",
                })
            if top_rows:
                df_top = pd.DataFrame(top_rows)
                chart_top = (
                    alt.Chart(df_top)
                    .mark_bar(cornerRadiusTopRight=4, cornerRadiusBottomRight=4, color="#6366f1")
                    .encode(
                        y=alt.Y("Target Item:N", sort="-x", title="Target Candidate", axis=alt.Axis(labelLimit=350)),
                        x=alt.X(
                            "Size (MB):Q",
                            scale=alt.Scale(domainMin=0, zero=True, clamp=True),
                            axis=alt.Axis(title="Size (MB)", tickMinStep=1),
                        ),
                        tooltip=[
                            alt.Tooltip("Full Path:N", title="Full Path"),
                            alt.Tooltip("Formatted Size:N", title="Size"),
                            alt.Tooltip("Size (MB):Q", title="Size (MB)", format=",.1f"),
                            alt.Tooltip("Category:N", title="Category"),
                            alt.Tooltip("Risk Level:N", title="Risk Level"),
                            alt.Tooltip("Reason:N", title="Analysis Reason"),
                        ],
                    )
                    .properties(height=alt.Step(32))
                )
                st.altair_chart(chart_top, use_container_width=True)
                st.caption("💡 *Hover over any bar to view the complete unabbreviated filesystem path, category, and risk details.*")

        with tab_next:
            st.info(
                "👉 Proceed to the **Recommendations** tab to inspect explainable recommendations "
                "and AI insights, then open **Human Review** to explicitly approve eligible items."
            )
            c1, c2 = st.columns(2)
            with c1:
                if st.button("💡 View Recommendations", type="primary", use_container_width=True):
                    navigate_to("Recommendations")
                    st.rerun()
            with c2:
                if st.button("🛡️ Open Human Review Queue", use_container_width=True):
                    navigate_to("Review")
                    st.rerun()
