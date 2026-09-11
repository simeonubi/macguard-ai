from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is in sys.path
_project_root = str(Path(__file__).resolve().parent.parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import streamlit as st

from app.ui.agent_view import render_agent_page
from app.ui.audit import render_audit_page
from app.ui.dashboard import render_dashboard
from app.ui.developer_view import render_developer_storage_page
from app.ui.duplicate_view import render_duplicate_explorer_page
from app.ui.execution import render_execution_page
from app.ui.recommendations import render_recommendations_page
from app.ui.review import render_review_page
from app.ui.scan import render_scan_page
from app.ui.settings import render_settings_page
from app.ui.storage_intelligence import render_storage_intelligence_page
from app.ui.state import (
    init_app_state,
    navigate_to,
    set_operating_mode,
    sync_mode_and_navigation,
)


def main() -> None:
    """Main Streamlit multi-page application entrypoint."""
    st.set_page_config(
        page_title="MacGuard AI - macOS Storage Intelligence",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    init_app_state()
    sync_mode_and_navigation()

    # Sidebar Navigation
    with st.sidebar:
        st.markdown("## 🛡️ **MacGuard AI**")
        st.caption("Safety-First macOS Storage Intelligence")

        st.markdown("---")

        # Operating Mode Switcher
        st.markdown("### 🎛️ **Operating Mode**")
        mode_options = ["ANALYZE", "REVIEW", "CLEAN", "AGENT"]
        current_mode = st.session_state.get("current_mode", "ANALYZE")
        current_mode_idx = mode_options.index(current_mode) if current_mode in mode_options else 0

        st.radio(
            "Select Mode:",
            options=mode_options,
            index=current_mode_idx,
            key="mode_radio",
            on_change=lambda: set_operating_mode(st.session_state.mode_radio),
            help=(
                "ANALYZE: Read-only storage scanning & discovery.\n"
                "REVIEW: Human review & explicit HMAC approval.\n"
                "CLEAN: Controlled execution (Trash move with post-verification).\n"
                "AGENT: Conversational AI analysis & reasoning."
            ),
        )

        st.markdown("---")

        # Navigation Tabs
        nav_options = [
            "Dashboard",
            "Scan",
            "DeveloperStorage",
            "Duplicates",
            "StorageIntelligence",
            "Recommendations",
            "Review",
            "Execution",
            "Agent",
            "Audit",
            "Settings",
        ]

        nav_icons = {
            "Dashboard": "📊 Dashboard",
            "Scan": "🔍 Scan Storage",
            "DeveloperStorage": "🛠️ Developer Storage",
            "Duplicates": "📑 Duplicate Explorer",
            "StorageIntelligence": "📈 Storage Intelligence & History",
            "Recommendations": "💡 Recommendations",
            "Review": "🛡️ Human Review",
            "Execution": "🗑️ Controlled Execution",
            "Agent": "🤖 AI Agent",
            "Audit": "📜 Audit Log",
            "Settings": "⚙️ Settings",
        }

        current_tab = st.session_state.get("current_tab", "Dashboard")
        current_nav_idx = nav_options.index(current_tab) if current_tab in nav_options else 0

        st.selectbox(
            "Navigation:",
            options=nav_options,
            index=current_nav_idx,
            key="nav_selectbox",
            on_change=lambda: navigate_to(st.session_state.nav_selectbox),
            format_func=lambda x: nav_icons.get(x, x),
        )

        st.markdown("---")
        st.caption("🔒 **Safety Policy**: Permanent deletion is permanently disabled.")

    # Page Routing
    active_tab = st.session_state.get("current_tab", "Dashboard")

    if active_tab == "Dashboard":
        render_dashboard()
    elif active_tab in ("DeveloperStorage", "Developer Storage"):
        render_developer_storage_page()
    elif active_tab in ("Duplicates", "Duplicate Explorer", "DuplicateExplorer"):
        render_duplicate_explorer_page()
    elif active_tab in ("StorageIntelligence", "Storage Intelligence"):
        render_storage_intelligence_page()
    elif active_tab == "Agent":
        render_agent_page()
    elif active_tab == "Scan":
        render_scan_page()
    elif active_tab == "Recommendations":
        render_recommendations_page()
    elif active_tab == "Review":
        render_review_page()
    elif active_tab == "Execution":
        render_execution_page()
    elif active_tab == "Audit":
        render_audit_page()
    elif active_tab == "Settings":
        render_settings_page()
    else:
        render_dashboard()


if __name__ == "__main__":
    main()
