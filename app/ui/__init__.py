from __future__ import annotations

from app.ui.agent_view import render_agent_page
from app.ui.app import main
from app.ui.audit import render_audit_page
from app.ui.dashboard import render_dashboard
from app.ui.execution import render_execution_page
from app.ui.recommendations import render_recommendations_page
from app.ui.review import render_review_page
from app.ui.scan import render_scan_page
from app.ui.settings import render_settings_page
from app.ui.storage_intelligence import (
    render_storage_intelligence_page,
    render_storage_intelligence_view,
)
from app.ui.state import (
    get_services,
    init_app_state,
    navigate_to,
    set_operating_mode,
    sync_mode_and_navigation,
)

__all__ = [
    "main",
    "init_app_state",
    "get_services",
    "navigate_to",
    "set_operating_mode",
    "sync_mode_and_navigation",
    "render_agent_page",
    "render_dashboard",
    "render_scan_page",
    "render_recommendations_page",
    "render_review_page",
    "render_execution_page",
    "render_audit_page",
    "render_settings_page",
    "render_storage_intelligence_page",
    "render_storage_intelligence_view",
]

