from __future__ import annotations

from typing import Any, Optional
import streamlit as st

from app.analysis.recommendations import RecommendationEngine
from app.analysis.storage_analyzer import StorageAnalyzer
from app.audit.repository import AuditRepository
from app.execution.executor import DryRunExecutor
from app.execution.planner import ExecutionPlanner
from app.execution.trash_executor import TrashExecutor
from app.llm.explanation_service import ExplanationService
from app.safety.approval_service import ApprovalService
from app.safety.path_validator import PathValidator
from app.tools.storage_scanner import StorageScanner


def get_services() -> dict[str, Any]:
    """
    Retrieve or initialize backend services in session state.

    Guarantees:
    - Backend services remain authoritative.
    - No cryptographic secrets or HMAC keys are stored in session state.
    """
    if "scanner" not in st.session_state:
        st.session_state.scanner = StorageScanner()
    if "analyzer" not in st.session_state:
        st.session_state.analyzer = StorageAnalyzer()
    if "recommendation_engine" not in st.session_state:
        st.session_state.recommendation_engine = RecommendationEngine()
    if "path_validator" not in st.session_state:
        st.session_state.path_validator = PathValidator()
    if "approval_service" not in st.session_state:
        st.session_state.approval_service = ApprovalService(
            path_validator=st.session_state.path_validator
        )
    if "execution_planner" not in st.session_state:
        st.session_state.execution_planner = ExecutionPlanner(
            approval_service=st.session_state.approval_service,
            path_validator=st.session_state.path_validator,
        )
    if "dry_run_executor" not in st.session_state:
        st.session_state.dry_run_executor = DryRunExecutor(
            approval_service=st.session_state.approval_service,
            path_validator=st.session_state.path_validator,
        )
    if "audit_repository" not in st.session_state:
        st.session_state.audit_repository = AuditRepository()
    if "trash_executor" not in st.session_state:
        st.session_state.trash_executor = TrashExecutor(
            approval_service=st.session_state.approval_service,
            path_validator=st.session_state.path_validator,
            audit_repo=st.session_state.audit_repository,
        )
    if "explanation_service" not in st.session_state:
        st.session_state.explanation_service = ExplanationService()
    if "storage_history" not in st.session_state:
        from app.analysis.storage_history import StorageHistoryRepository
        st.session_state.storage_history = StorageHistoryRepository()
    if "storage_trends" not in st.session_state:
        from app.analysis.storage_trends import StorageTrendsEngine
        st.session_state.storage_trends = StorageTrendsEngine()

    return {
        "scanner": st.session_state.scanner,
        "analyzer": st.session_state.analyzer,
        "recommendation_engine": st.session_state.recommendation_engine,
        "path_validator": st.session_state.path_validator,
        "approval_service": st.session_state.approval_service,
        "execution_planner": st.session_state.execution_planner,
        "dry_run_executor": st.session_state.dry_run_executor,
        "audit_repository": st.session_state.audit_repository,
        "trash_executor": st.session_state.trash_executor,
        "explanation_service": st.session_state.explanation_service,
        "storage_history": st.session_state.storage_history,
        "storage_trends": st.session_state.storage_trends,
    }


def init_app_state() -> None:
    """Initialize application-level session state variables."""
    get_services()

    if "current_mode" not in st.session_state:
        st.session_state.current_mode = "ANALYZE"

    if "scan_results" not in st.session_state:
        st.session_state.scan_results = None

    if "scan_path" not in st.session_state:
        from pathlib import Path
        st.session_state.scan_path = str(Path.home())

    if "candidates" not in st.session_state:
        st.session_state.candidates = []

    if "recommendations" not in st.session_state:
        st.session_state.recommendations = []

    if "review_items" not in st.session_state:
        st.session_state.review_items = []

    if "analysis_context" not in st.session_state:
        st.session_state.analysis_context = None

    if "ai_explanations" not in st.session_state:
        st.session_state.ai_explanations = {}

    if "execution_results" not in st.session_state:
        st.session_state.execution_results = []

    if "current_tab" not in st.session_state:
        st.session_state.current_tab = "Dashboard"

    if "pending_tab" not in st.session_state:
        st.session_state.pending_tab = None

    if "pending_mode" not in st.session_state:
        st.session_state.pending_mode = None

    if "mode_radio" not in st.session_state:
        st.session_state.mode_radio = st.session_state.current_mode

    if "nav_selectbox" not in st.session_state:
        st.session_state.nav_selectbox = st.session_state.current_tab


MODE_TO_DEFAULT_TAB = {
    "ANALYZE": "Dashboard",
    "REVIEW": "Review",
    "CLEAN": "Execution",
    "AGENT": "Agent",
}

TAB_TO_MODE = {
    "Dashboard": "ANALYZE",
    "Scan": "ANALYZE",
    "DeveloperStorage": "ANALYZE",
    "Developer Storage": "ANALYZE",
    "Duplicates": "ANALYZE",
    "Duplicate Explorer": "ANALYZE",
    "DuplicateExplorer": "ANALYZE",
    "StorageIntelligence": "ANALYZE",
    "Storage Intelligence": "ANALYZE",
    "Recommendations": "ANALYZE",
    "Review": "REVIEW",
    "Execution": "CLEAN",
    "Agent": "AGENT",
}


def set_operating_mode(mode_name: str) -> None:
    """
    Request an operating mode change and synchronize the corresponding primary workflow tab.

    Safe Lifecycle Invariant:
    Does NOT mutate widget-bound keys (mode_radio / nav_selectbox) directly during
    page execution. Sets authoritative state and pending transitions, which are reconciled
    at the top of the script lifecycle in sync_mode_and_navigation() before widgets render.
    """
    if mode_name not in ["ANALYZE", "REVIEW", "CLEAN", "AGENT"]:
        mode_name = "ANALYZE"

    st.session_state.current_mode = mode_name
    st.session_state.pending_mode = mode_name

    if mode_name == "REVIEW":
        st.session_state.current_tab = "Review"
        st.session_state.pending_tab = "Review"
    elif mode_name == "CLEAN":
        st.session_state.current_tab = "Execution"
        st.session_state.pending_tab = "Execution"
    elif mode_name == "AGENT":
        st.session_state.current_tab = "Agent"
        st.session_state.pending_tab = "Agent"
    elif mode_name == "ANALYZE":
        if st.session_state.get("current_tab") not in [
            "Dashboard",
            "Scan",
            "DeveloperStorage",
            "Developer Storage",
            "Duplicates",
            "Duplicate Explorer",
            "DuplicateExplorer",
            "StorageIntelligence",
            "Storage Intelligence",
            "Recommendations",
            "Audit",
            "Settings",
        ]:
            st.session_state.current_tab = "Dashboard"
            st.session_state.pending_tab = "Dashboard"


def navigate_to(tab_name: str) -> None:
    """
    Request navigation to a specific UI tab and synchronize the corresponding operating mode.

    Safe Lifecycle Invariant:
    Does NOT mutate widget-bound keys (mode_radio / nav_selectbox) directly during
    page rendering. Sets authoritative state and pending transitions, which are reconciled
    at the top of the script lifecycle in sync_mode_and_navigation() before widgets render.
    """
    valid_tabs = [
        "Dashboard",
        "Scan",
        "DeveloperStorage",
        "Developer Storage",
        "Duplicates",
        "Duplicate Explorer",
        "DuplicateExplorer",
        "StorageIntelligence",
        "Storage Intelligence",
        "Recommendations",
        "Review",
        "Execution",
        "Agent",
        "Audit",
        "Settings",
    ]
    if tab_name not in valid_tabs:
        tab_name = "Dashboard"

    if tab_name in ("StorageIntelligence", "Storage Intelligence"):
        canonical_tab = "StorageIntelligence"
    elif tab_name in ("DeveloperStorage", "Developer Storage"):
        canonical_tab = "DeveloperStorage"
    elif tab_name in ("Duplicates", "Duplicate Explorer", "DuplicateExplorer"):
        canonical_tab = "Duplicates"
    else:
        canonical_tab = tab_name

    st.session_state.current_tab = canonical_tab
    st.session_state.pending_tab = canonical_tab

    if canonical_tab in TAB_TO_MODE:
        target_mode = TAB_TO_MODE[canonical_tab]
        st.session_state.current_mode = target_mode
        st.session_state.pending_mode = target_mode


def sync_mode_and_navigation() -> None:
    """
    Reconcile Authoritative Application State and Streamlit Widget State.
    MUST be executed at the start of main(), strictly BEFORE sidebar widgets are instantiated.

    Rules:
    1. Apply any pending tab / mode transitions requested by page buttons or events.
    2. Enforce mode <-> tab primary workflow invariants.
    3. Synchronize widget-bound session state keys (`mode_radio`, `nav_selectbox`)
       strictly BEFORE widget creation.
    """
    # 1. Apply pending transitions if present
    if st.session_state.get("pending_tab"):
        st.session_state.current_tab = st.session_state.pending_tab
        st.session_state.pending_tab = None

    if st.session_state.get("pending_mode"):
        st.session_state.current_mode = st.session_state.pending_mode
        st.session_state.pending_mode = None

    current_tab = st.session_state.get("current_tab", "Dashboard")
    current_mode = st.session_state.get("current_mode", "ANALYZE")

    # 2. Enforce mode <-> tab invariants
    if current_mode == "REVIEW" and current_tab not in ["Review", "Audit", "Settings"]:
        current_tab = "Review"
        st.session_state.current_tab = current_tab
    elif current_mode == "CLEAN" and current_tab not in ["Execution", "Audit", "Settings"]:
        current_tab = "Execution"
        st.session_state.current_tab = current_tab
    elif current_mode == "AGENT" and current_tab not in ["Agent", "Audit", "Settings"]:
        current_tab = "Agent"
        st.session_state.current_tab = current_tab
    elif current_mode == "ANALYZE" and current_tab in ["Review", "Execution", "Agent"]:
        current_tab = "Dashboard"
        st.session_state.current_tab = current_tab

    # 3. Synchronize widget-bound session state keys BEFORE widget instantiation
    st.session_state.mode_radio = current_mode
    st.session_state.nav_selectbox = current_tab


