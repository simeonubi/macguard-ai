from __future__ import annotations

from app.analysis.models import RiskLevel, StorageCandidate, StorageCategory
from app.analysis.recommendations import RecommendationAction, SafetyStatus, StorageRecommendation
from app.llm.models import AnalysisContext
from app.safety.approval_service import ApprovalService
from app.safety.review import ReviewItem
from app.tools.storage_scanner import StorageItem


def generate_demo_dataset() -> tuple[list[StorageItem], list[StorageCandidate], list[StorageRecommendation], list[ReviewItem], AnalysisContext]:
    """
    Generate a realistic, completely isolated synthetic demo storage dataset.

    Safety Guarantees:
    - Zero filesystem interaction.
    - Clearly demarcated with [DEMO] prefixes.
    - Safe for live technical presentations, portfolio showcases, and UI walkthroughs.
    """
    demo_items = [
        # 1. Actionable Caches (LOW risk, Eligible)
        StorageItem(path="/Users/demo/Library/Caches/com.apple.dt.Xcode/DerivedData", size_bytes=14_800_000_000, item_type="directory"),
        StorageItem(path="/Users/demo/Library/Caches/Google/Chrome/Default/Cache", size_bytes=2_400_000_000, item_type="directory"),
        StorageItem(path="/Users/demo/Library/Caches/Homebrew/downloads", size_bytes=3_100_000_000, item_type="directory"),
        StorageItem(path="/Users/demo/Library/Caches/pip/wheels", size_bytes=1_250_000_000, item_type="directory"),

        # 2. Logs (LOW risk, Eligible)
        StorageItem(path="/Users/demo/Library/Logs/DiagnosticReports/old_crashes", size_bytes=850_000_000, item_type="directory"),
        StorageItem(path="/Users/demo/Library/Logs/system_archive.log", size_bytes=420_000_000, item_type="file"),

        # 3. Developer Artifacts (MEDIUM risk, Manual Review Required)
        StorageItem(path="/Users/demo/Projects/frontend-app/node_modules", size_bytes=4_200_000_000, item_type="directory"),
        StorageItem(path="/Users/demo/Projects/backend-service/.venv", size_bytes=1_800_000_000, item_type="directory"),
        StorageItem(path="/Users/demo/.docker/desktop-data/disk.raw", size_bytes=18_500_000_000, item_type="file"),

        # 4. User Documents & System Files (HIGH risk, Strictly Blocked)
        StorageItem(path="/Users/demo/Documents/Financial_Projections_2026.pdf", size_bytes=340_000_000, item_type="file"),
        StorageItem(path="/Users/demo/Desktop/Client_Presentations.key", size_bytes=520_000_000, item_type="file"),
        StorageItem(path="/System/Library/CoreServices/SystemVersion.bundle", size_bytes=1_100_000, item_type="directory"),

        # 5. Unknown Binary (UNKNOWN risk, Strictly Blocked)
        StorageItem(path="/Users/demo/Downloads/unidentified_payload.bin", size_bytes=950_000_000, item_type="file"),
    ]

    demo_candidates = [
        # Low risk
        StorageCandidate(
            path="/Users/demo/Library/Caches/com.apple.dt.Xcode/DerivedData",
            size_bytes=14_800_000_000,
            category=StorageCategory.CACHE,
            risk_level=RiskLevel.LOW,
            confidence=0.98,
            reason="Xcode build cache and intermediate artifacts (rebuildable upon project compile)",
            recommendation="Eligible for controlled Trash review",
            item_type="directory",
        ),
        StorageCandidate(
            path="/Users/demo/Library/Caches/Google/Chrome/Default/Cache",
            size_bytes=2_400_000_000,
            category=StorageCategory.CACHE,
            risk_level=RiskLevel.LOW,
            confidence=0.95,
            reason="Web browser temporary disk cache",
            recommendation="Eligible for controlled Trash review",
            item_type="directory",
        ),
        StorageCandidate(
            path="/Users/demo/Library/Caches/Homebrew/downloads",
            size_bytes=3_100_000_000,
            category=StorageCategory.CACHE,
            risk_level=RiskLevel.LOW,
            confidence=0.96,
            reason="Cached package manager tarball downloads",
            recommendation="Eligible for controlled Trash review",
            item_type="directory",
        ),
        StorageCandidate(
            path="/Users/demo/Library/Caches/pip/wheels",
            size_bytes=1_250_000_000,
            category=StorageCategory.CACHE,
            risk_level=RiskLevel.LOW,
            confidence=0.94,
            reason="Python wheel compilation cache",
            recommendation="Eligible for controlled Trash review",
            item_type="directory",
        ),
        StorageCandidate(
            path="/Users/demo/Library/Logs/DiagnosticReports/old_crashes",
            size_bytes=850_000_000,
            category=StorageCategory.LOGS,
            risk_level=RiskLevel.LOW,
            confidence=0.92,
            reason="Historical diagnostic crash logs older than 30 days",
            recommendation="Eligible for controlled Trash review",
            item_type="directory",
        ),
        StorageCandidate(
            path="/Users/demo/Library/Logs/system_archive.log",
            size_bytes=420_000_000,
            category=StorageCategory.LOGS,
            risk_level=RiskLevel.LOW,
            confidence=0.90,
            reason="Archived application log file",
            recommendation="Eligible for controlled Trash review",
            item_type="file",
        ),

        # Medium risk
        StorageCandidate(
            path="/Users/demo/Projects/frontend-app/node_modules",
            size_bytes=4_200_000_000,
            category=StorageCategory.DEVELOPMENT,
            risk_level=RiskLevel.MEDIUM,
            confidence=0.88,
            reason="Project npm dependencies directory. Re-creatable with npm install but may contain custom local builds.",
            recommendation="Manual review required",
            item_type="directory",
        ),
        StorageCandidate(
            path="/Users/demo/Projects/backend-service/.venv",
            size_bytes=1_800_000_000,
            category=StorageCategory.DEVELOPMENT,
            risk_level=RiskLevel.MEDIUM,
            confidence=0.85,
            reason="Python virtual environment. Re-creatable from requirements.txt.",
            recommendation="Manual review required",
            item_type="directory",
        ),
        StorageCandidate(
            path="/Users/demo/.docker/desktop-data/disk.raw",
            size_bytes=18_500_000_000,
            category=StorageCategory.DEVELOPMENT,
            risk_level=RiskLevel.MEDIUM,
            confidence=0.80,
            reason="Docker VM disk image containing containers and image layers.",
            recommendation="Manual review required",
            item_type="file",
        ),

        # High risk
        StorageCandidate(
            path="/Users/demo/Documents/Financial_Projections_2026.pdf",
            size_bytes=340_000_000,
            category=StorageCategory.DOCUMENTS,
            risk_level=RiskLevel.HIGH,
            confidence=0.99,
            reason="User document containing financial statements. Strictly protected from cleanup.",
            recommendation="Protected user document — do not delete",
            item_type="file",
        ),
        StorageCandidate(
            path="/Users/demo/Desktop/Client_Presentations.key",
            size_bytes=520_000_000,
            category=StorageCategory.DOCUMENTS,
            risk_level=RiskLevel.HIGH,
            confidence=0.99,
            reason="Active presentation deck on user desktop. Strictly protected.",
            recommendation="Protected user document — do not delete",
            item_type="file",
        ),
        StorageCandidate(
            path="/System/Library/CoreServices/SystemVersion.bundle",
            size_bytes=1_100_000,
            category=StorageCategory.APPLICATION_DATA,
            risk_level=RiskLevel.HIGH,
            confidence=1.0,
            reason="Core operating system bundle. Strictly protected by MacGuard safety policy.",
            recommendation="System protected item — immutable",
            item_type="directory",
        ),

        # Unknown risk
        StorageCandidate(
            path="/Users/demo/Downloads/unidentified_payload.bin",
            size_bytes=950_000_000,
            category=StorageCategory.UNKNOWN,
            risk_level=RiskLevel.UNKNOWN,
            confidence=0.40,
            reason="Unrecognized binary format in Downloads folder.",
            recommendation="Conservative non-action — manual user inspection only",
            item_type="file",
        ),
    ]

    demo_recommendations = [
        StorageRecommendation(
            candidate=demo_candidates[0],
            action=RecommendationAction.REVIEW_FOR_CLEANUP,
            rationale="Xcode DerivedData builds accumulate gigabytes over time and can be cleanly regenerated.",
            safety_status=SafetyStatus.ELIGIBLE_FOR_REVIEW.value,
            requires_approval=True,
            confidence=0.98,
        ),
        StorageRecommendation(
            candidate=demo_candidates[1],
            action=RecommendationAction.REVIEW_FOR_CLEANUP,
            rationale="Chrome disk cache contains cached HTTP web assets. Browser recreates automatically.",
            safety_status=SafetyStatus.ELIGIBLE_FOR_REVIEW.value,
            requires_approval=True,
            confidence=0.95,
        ),
        StorageRecommendation(
            candidate=demo_candidates[2],
            action=RecommendationAction.REVIEW_FOR_CLEANUP,
            rationale="Homebrew bottle download cache. Safe to move to Trash to reclaim disk space.",
            safety_status=SafetyStatus.ELIGIBLE_FOR_REVIEW.value,
            requires_approval=True,
            confidence=0.96,
        ),
        StorageRecommendation(
            candidate=demo_candidates[3],
            action=RecommendationAction.REVIEW_FOR_CLEANUP,
            rationale="Cached Python pip wheel archives. Re-downloadable when installing packages.",
            safety_status=SafetyStatus.ELIGIBLE_FOR_REVIEW.value,
            requires_approval=True,
            confidence=0.94,
        ),
        StorageRecommendation(
            candidate=demo_candidates[4],
            action=RecommendationAction.REVIEW_FOR_CLEANUP,
            rationale="Old crash diagnostics older than 30 days. Useful for forensic debugging but eligible for cleanup review.",
            safety_status=SafetyStatus.ELIGIBLE_FOR_REVIEW.value,
            requires_approval=True,
            confidence=0.92,
        ),
        StorageRecommendation(
            candidate=demo_candidates[5],
            action=RecommendationAction.REVIEW_FOR_CLEANUP,
            rationale="Archived log file. Safe for controlled Trash review.",
            safety_status=SafetyStatus.ELIGIBLE_FOR_REVIEW.value,
            requires_approval=True,
            confidence=0.90,
        ),
        StorageRecommendation(
            candidate=demo_candidates[6],
            action=RecommendationAction.MANUAL_REVIEW,
            rationale="Developer node_modules directory. Requires project-level developer confirmation before cleanup.",
            safety_status=SafetyStatus.MANUAL_REVIEW_REQUIRED.value,
            requires_approval=True,
            confidence=0.88,
        ),
        StorageRecommendation(
            candidate=demo_candidates[7],
            action=RecommendationAction.MANUAL_REVIEW,
            rationale="Python virtual environment. Manual developer review recommended.",
            safety_status=SafetyStatus.MANUAL_REVIEW_REQUIRED.value,
            requires_approval=True,
            confidence=0.85,
        ),
        StorageRecommendation(
            candidate=demo_candidates[8],
            action=RecommendationAction.MANUAL_REVIEW,
            rationale="Docker virtual disk. Large storage reclaim opportunity requiring Docker desktop verification.",
            safety_status=SafetyStatus.MANUAL_REVIEW_REQUIRED.value,
            requires_approval=True,
            confidence=0.80,
        ),
        StorageRecommendation(
            candidate=demo_candidates[9],
            action=RecommendationAction.NO_ACTION,
            rationale="Personal financial PDF document. Strictly protected by MacGuard safety policy.",
            safety_status=SafetyStatus.BLOCKED.value,
            requires_approval=True,
            confidence=0.99,
        ),
        StorageRecommendation(
            candidate=demo_candidates[10],
            action=RecommendationAction.NO_ACTION,
            rationale="Active presentation file on Desktop. Strictly protected from automated actions.",
            safety_status=SafetyStatus.BLOCKED.value,
            requires_approval=True,
            confidence=0.99,
        ),
        StorageRecommendation(
            candidate=demo_candidates[11],
            action=RecommendationAction.NO_ACTION,
            rationale="System CoreServices bundle. Absolute prohibition of cleanup under System Integrity policy.",
            safety_status=SafetyStatus.BLOCKED.value,
            requires_approval=True,
            confidence=1.0,
        ),
        StorageRecommendation(
            candidate=demo_candidates[12],
            action=RecommendationAction.NO_ACTION,
            rationale="Unclassified binary payload. Conservative fail-closed stance requires user manual handling.",
            safety_status=SafetyStatus.UNKNOWN.value,
            requires_approval=True,
            confidence=0.40,
        ),
    ]

    approval_service = ApprovalService()
    demo_review_items = approval_service.create_review_items(demo_recommendations)

    total_size = sum(c.size_bytes for c in demo_candidates)
    demo_context = AnalysisContext(
        scan_id="demo-portfolio-scan",
        scan_path="/Users/demo",
        total_scanned_items=len(demo_candidates),
        total_size_bytes=total_size,
        candidates=demo_candidates,
        recommendations=demo_recommendations,
        safety_summary={
            "LOW": 6,
            "MEDIUM": 3,
            "HIGH": 3,
            "UNKNOWN": 1,
        },
    )

    return demo_items, demo_candidates, demo_recommendations, demo_review_items, demo_context
