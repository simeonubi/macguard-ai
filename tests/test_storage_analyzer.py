from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.analysis.models import RiskLevel, StorageCandidate, StorageCategory
from app.analysis.rules import classify_path
from app.analysis.storage_analyzer import StorageAnalyzer
from app.tools.storage_scanner import StorageItem


def test_category_enum_values():
    expected = {
        "CACHE",
        "LOGS",
        "DEVELOPMENT",
        "APPLICATION_DATA",
        "MEDIA",
        "DOCUMENTS",
        "UNKNOWN",
    }
    actual = {cat.value for cat in StorageCategory}
    assert actual == expected


def test_risk_level_enum_values():
    expected = {"LOW", "MEDIUM", "HIGH", "UNKNOWN"}
    actual = {risk.value for risk in RiskLevel}
    assert actual == expected


def test_storage_candidate_validation_success():
    candidate = StorageCandidate(
        path="/Users/test/Library/Caches/com.example.app",
        size_bytes=1024 * 1024,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.95,
        reason="Test reason",
        recommendation="Test conservative recommendation",
        item_type="directory",
    )
    assert candidate.path == "/Users/test/Library/Caches/com.example.app"
    assert candidate.size_bytes == 1024 * 1024
    assert candidate.category == StorageCategory.CACHE
    assert candidate.risk_level == RiskLevel.LOW
    assert candidate.confidence == 0.95


def test_storage_candidate_negative_size_rejected():
    with pytest.raises(ValidationError):
        StorageCandidate(
            path="/Users/test/file.txt",
            size_bytes=-100,
            category=StorageCategory.DOCUMENTS,
            risk_level=RiskLevel.HIGH,
            confidence=0.9,
            reason="Test",
            recommendation="Test",
        )


def test_storage_candidate_empty_path_rejected():
    with pytest.raises(ValidationError):
        StorageCandidate(
            path="",
            size_bytes=100,
            category=StorageCategory.DOCUMENTS,
            risk_level=RiskLevel.HIGH,
            confidence=0.9,
            reason="Test",
            recommendation="Test",
        )


def test_storage_candidate_confidence_bounds():
    # Confidence > 1.0 rejected
    with pytest.raises(ValidationError):
        StorageCandidate(
            path="/Users/test/file.txt",
            size_bytes=100,
            category=StorageCategory.DOCUMENTS,
            risk_level=RiskLevel.HIGH,
            confidence=1.5,
            reason="Test",
            recommendation="Test",
        )

    # Confidence < 0.0 rejected
    with pytest.raises(ValidationError):
        StorageCandidate(
            path="/Users/test/file.txt",
            size_bytes=100,
            category=StorageCategory.DOCUMENTS,
            risk_level=RiskLevel.HIGH,
            confidence=-0.1,
            reason="Test",
            recommendation="Test",
        )


def test_classify_cache():
    paths = [
        "/Users/test/Library/Caches/com.apple.Safari",
        "/Users/test/.cache/pip/wheels",
        "/Users/test/project/_cacache/content-v2",
    ]
    analyzer = StorageAnalyzer()
    for p in paths:
        candidate = analyzer.analyze_path(p, size_bytes=5000)
        assert candidate.category == StorageCategory.CACHE
        assert candidate.risk_level == RiskLevel.LOW
        assert candidate.confidence >= 0.8
        assert "safe to delete" not in candidate.recommendation.lower()
        assert "review" in candidate.recommendation.lower()


def test_classify_logs():
    paths = [
        "/Users/test/Library/Logs/DiagnosticReports/crash.ips",
        "/var/log/system.log",
        "/Users/test/app.log",
        "/Users/test/old.log.gz",
    ]
    analyzer = StorageAnalyzer()
    for p in paths:
        candidate = analyzer.analyze_path(p, size_bytes=2000)
        assert candidate.category == StorageCategory.LOGS
        assert candidate.risk_level == RiskLevel.LOW
        assert candidate.confidence >= 0.8
        assert "safe to delete" not in candidate.recommendation.lower()


def test_classify_development():
    paths = [
        "/Users/test/projects/web/node_modules",
        "/Users/test/projects/python/.venv",
        "/Users/test/projects/python/__pycache__",
        "/Users/test/Library/Developer/Xcode/DerivedData/App-12345",
        "/Users/test/Library/Containers/com.docker.docker/Data/vms/0/Docker.raw",
    ]
    analyzer = StorageAnalyzer()
    for p in paths:
        candidate = analyzer.analyze_path(p, size_bytes=500000)
        assert candidate.category == StorageCategory.DEVELOPMENT
        assert candidate.risk_level == RiskLevel.MEDIUM
        assert candidate.confidence >= 0.85
        assert "safe to delete" not in candidate.recommendation.lower()


def test_classify_media():
    paths = [
        "/Users/test/Pictures/holiday.jpg",
        "/Users/test/Videos/recording.mov",
        "/Users/test/Music/track.mp3",
        "/Users/test/Photos/raw_shot.heic",
        "/Users/test/Downloads/movie.mp4",
    ]
    analyzer = StorageAnalyzer()
    for p in paths:
        candidate = analyzer.analyze_path(p, size_bytes=10000000)
        assert candidate.category == StorageCategory.MEDIA
        assert candidate.risk_level == RiskLevel.HIGH
        assert candidate.confidence >= 0.85
        assert "safe to delete" not in candidate.recommendation.lower()


def test_classify_documents():
    paths = [
        "/Users/test/Documents/thesis.pdf",
        "/Users/test/Work/contract.docx",
        "/Users/test/Finance/budget.xlsx",
        "/Users/test/notes.txt",
    ]
    analyzer = StorageAnalyzer()
    for p in paths:
        candidate = analyzer.analyze_path(p, size_bytes=200000)
        assert candidate.category == StorageCategory.DOCUMENTS
        assert candidate.risk_level == RiskLevel.HIGH
        assert candidate.confidence >= 0.85
        assert "safe to delete" not in candidate.recommendation.lower()


def test_classify_application_data():
    paths = [
        "/Users/test/Library/Application Support/Google/Chrome",
        "/Users/test/Library/Containers/com.apple.Notes",
    ]
    analyzer = StorageAnalyzer()
    for p in paths:
        candidate = analyzer.analyze_path(p, size_bytes=4000000)
        assert candidate.category == StorageCategory.APPLICATION_DATA
        assert candidate.risk_level == RiskLevel.HIGH
        assert candidate.confidence >= 0.85
        assert "safe to delete" not in candidate.recommendation.lower()


def test_classify_unknown():
    paths = [
        "/Users/test/random_unstructured_blob.xyz999",
        "/Users/test/misc/undetermined_binary",
    ]
    analyzer = StorageAnalyzer()
    for p in paths:
        candidate = analyzer.analyze_path(p, size_bytes=1000)
        assert candidate.category == StorageCategory.UNKNOWN
        assert candidate.risk_level == RiskLevel.UNKNOWN
        assert candidate.confidence == 0.0
        assert "manual review" in candidate.recommendation.lower()


def test_conservative_recommendations_never_authorize_cleanup():
    analyzer = StorageAnalyzer()
    test_paths = [
        "/Users/test/Library/Caches/com.test",
        "/Users/test/Library/Logs/test.log",
        "/Users/test/projects/node_modules",
        "/Users/test/Pictures/img.png",
        "/Users/test/Documents/doc.pdf",
        "/Users/test/Library/Application Support/App",
        "/Users/test/unknown.dat",
    ]
    for p in test_paths:
        candidate = analyzer.analyze_path(p)
        rec_lower = candidate.recommendation.lower()
        assert "safe to delete" not in rec_lower
        assert "delete automatically" not in rec_lower
        assert "delete now" not in rec_lower


def test_analyzer_with_storage_items():
    items = [
        StorageItem(path="/Users/test/Library/Caches/app", size_bytes=100, item_type="directory"),
        StorageItem(path="/Users/test/pic.png", size_bytes=200, item_type="file"),
        StorageItem(path="/Users/test/file.pdf", size_bytes=300, item_type="file"),
    ]
    analyzer = StorageAnalyzer()
    candidates = analyzer.analyze_items(items)

    assert len(candidates) == 3
    assert candidates[0].category == StorageCategory.CACHE
    assert candidates[0].size_bytes == 100
    assert candidates[1].category == StorageCategory.MEDIA
    assert candidates[1].size_bytes == 200
    assert candidates[2].category == StorageCategory.DOCUMENTS
    assert candidates[2].size_bytes == 300

    cat_summary = analyzer.summarize_by_category(candidates)
    assert cat_summary[StorageCategory.CACHE] == 100
    assert cat_summary[StorageCategory.MEDIA] == 200
    assert cat_summary[StorageCategory.DOCUMENTS] == 300
    assert cat_summary[StorageCategory.LOGS] == 0

    risk_summary = analyzer.summarize_by_risk(candidates)
    assert risk_summary[RiskLevel.LOW] == 100
    assert risk_summary[RiskLevel.HIGH] == 500
    assert risk_summary[RiskLevel.MEDIUM] == 0


def test_deterministic_output():
    analyzer = StorageAnalyzer()
    path = "/Users/test/Library/Caches/test_app"
    res1 = analyzer.analyze_path(path, size_bytes=1000)
    res2 = analyzer.analyze_path(path, size_bytes=1000)

    assert res1.category == res2.category
    assert res1.risk_level == res2.risk_level
    assert res1.confidence == res2.confidence
    assert res1.reason == res2.reason
    assert res1.recommendation == res2.recommendation


def test_hierarchical_deduplication_parent_child_overlap():
    """Test that parent directory candidate encompasses nested child file (e.g. Trivy DB)."""
    analyzer = StorageAnalyzer()
    parent = StorageCandidate(
        path="/Users/test/Library/Caches/trivy",
        size_bytes=1160000000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.95,
        reason="Cache dir",
        recommendation="Review for cleanup",
        item_type="directory",
    )
    child = StorageCandidate(
        path="/Users/test/Library/Caches/trivy/db/trivy.db",
        size_bytes=1140000000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.95,
        reason="Cache file",
        recommendation="Review for cleanup",
        item_type="file",
    )

    deduped = analyzer.deduplicate_candidates([parent, child])
    assert len(deduped) == 1
    assert deduped[0].path == "/Users/test/Library/Caches/trivy"
    assert deduped[0].size_bytes == 1160000000

    # Reverse input order must yield same deterministic result
    deduped_rev = analyzer.deduplicate_candidates([child, parent])
    assert len(deduped_rev) == 1
    assert deduped_rev[0].path == "/Users/test/Library/Caches/trivy"


def test_hierarchical_deduplication_nested_dir_and_nested_file():
    """Test parent directory encompassing both an intermediate subdirectory and nested file."""
    analyzer = StorageAnalyzer()
    parent_dir = StorageCandidate(
        path="/Users/test/Library/Caches/ms-playwright",
        size_bytes=553000000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.95,
        reason="Cache dir",
        recommendation="Review",
        item_type="directory",
    )
    nested_dir = StorageCandidate(
        path="/Users/test/Library/Caches/ms-playwright/chromium-1234",
        size_bytes=350000000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.95,
        reason="Sub cache dir",
        recommendation="Review",
        item_type="directory",
    )
    nested_file = StorageCandidate(
        path="/Users/test/Library/Caches/ms-playwright/chromium-1234/chrome-mac-arm64/Google Chrome.app",
        size_bytes=226000000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.95,
        reason="Binary file",
        recommendation="Review",
        item_type="file",
    )

    deduped = analyzer.deduplicate_candidates([nested_file, nested_dir, parent_dir])
    assert len(deduped) == 1
    assert deduped[0].path == "/Users/test/Library/Caches/ms-playwright"


def test_hierarchical_deduplication_independent_siblings():
    """Test independent sibling candidates are preserved without interference."""
    analyzer = StorageAnalyzer()
    c1 = StorageCandidate(
        path="/Users/test/Library/Caches/Google",
        size_bytes=2160000000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.95,
        reason="Cache dir",
        recommendation="Review",
        item_type="directory",
    )
    c2 = StorageCandidate(
        path="/Users/test/.cache/uv",
        size_bytes=1270000000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.85,
        reason="Cache dir",
        recommendation="Review",
        item_type="directory",
    )
    c3 = StorageCandidate(
        path="/Users/test/Library/Caches/trivy",
        size_bytes=1160000000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.95,
        reason="Cache dir",
        recommendation="Review",
        item_type="directory",
    )

    deduped = analyzer.deduplicate_candidates([c1, c2, c3])
    assert len(deduped) == 3
    paths = [c.path for c in deduped]
    assert "/Users/test/Library/Caches/Google" in paths
    assert "/Users/test/.cache/uv" in paths
    assert "/Users/test/Library/Caches/trivy" in paths


def test_hierarchical_deduplication_blocked_parent_with_low_risk_child():
    """Test that a child candidate is NOT discarded if its parent is blocked/high-risk and cannot be cleaned as a unit."""
    analyzer = StorageAnalyzer()
    blocked_parent = StorageCandidate(
        path="/Users/test/Documents",
        size_bytes=5000000000,
        category=StorageCategory.DOCUMENTS,
        risk_level=RiskLevel.HIGH,
        confidence=0.90,
        reason="User documents",
        recommendation="Retain",
        item_type="directory",
    )
    low_child = StorageCandidate(
        path="/Users/test/Documents/temp_build.log",
        size_bytes=50000000,
        category=StorageCategory.LOGS,
        risk_level=RiskLevel.LOW,
        confidence=0.90,
        reason="Log file",
        recommendation="Review",
        item_type="file",
    )

    deduped = analyzer.deduplicate_candidates([blocked_parent, low_child])
    # Both are preserved because the parent cannot be cleaned as a unit
    assert len(deduped) == 2
    paths = [c.path for c in deduped]
    assert "/Users/test/Documents" in paths
    assert "/Users/test/Documents/temp_build.log" in paths


def test_hierarchical_deduplication_multiple_nested_descendants():
    """Test tree with multiple nested files and directories across different branches."""
    analyzer = StorageAnalyzer()
    root_cache = StorageCandidate(
        path="/Users/test/.cache/uv",
        size_bytes=1270000000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.85,
        reason="UV cache",
        recommendation="Review",
        item_type="directory",
    )
    child1 = StorageCandidate(
        path="/Users/test/.cache/uv/archive-v0/file1",
        size_bytes=100000000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.85,
        reason="UV cache child",
        recommendation="Review",
        item_type="file",
    )
    child2 = StorageCandidate(
        path="/Users/test/.cache/uv/archive-v0/file2",
        size_bytes=50000000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.85,
        reason="UV cache child",
        recommendation="Review",
        item_type="file",
    )
    other_file = StorageCandidate(
        path="/Users/test/Library/Logs/Antigravity/main.log",
        size_bytes=134000,
        category=StorageCategory.LOGS,
        risk_level=RiskLevel.LOW,
        confidence=0.90,
        reason="Log file",
        recommendation="Review",
        item_type="file",
    )

    deduped = analyzer.deduplicate_candidates([child1, root_cache, child2, other_file])
    assert len(deduped) == 2
    paths = [c.path for c in deduped]
    assert "/Users/test/.cache/uv" in paths
    assert "/Users/test/Library/Logs/Antigravity/main.log" in paths


def test_hierarchical_deduplication_no_overlap():
    """Test that disjoint set of files and directories is unchanged."""
    analyzer = StorageAnalyzer()
    candidates = [
        StorageCandidate(
            path="/Users/test/Library/Caches/AppA",
            size_bytes=100,
            category=StorageCategory.CACHE,
            risk_level=RiskLevel.LOW,
            confidence=0.9,
            reason="A",
            recommendation="Review",
            item_type="directory",
        ),
        StorageCandidate(
            path="/Users/test/Library/Caches/AppB",
            size_bytes=200,
            category=StorageCategory.CACHE,
            risk_level=RiskLevel.LOW,
            confidence=0.9,
            reason="B",
            recommendation="Review",
            item_type="directory",
        ),
    ]

    deduped = analyzer.deduplicate_candidates(candidates)
    assert len(deduped) == 2


def test_hierarchical_deduplication_accurate_unique_total_size():
    """Test that candidate deduplication resolves double-counted total size."""
    analyzer = StorageAnalyzer()
    parent = StorageCandidate(
        path="/Users/test/Library/Caches/trivy",
        size_bytes=1160000000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.95,
        reason="Cache dir",
        recommendation="Review for cleanup",
        item_type="directory",
    )
    child = StorageCandidate(
        path="/Users/test/Library/Caches/trivy/db/trivy.db",
        size_bytes=1140000000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.95,
        reason="Cache file",
        recommendation="Review for cleanup",
        item_type="file",
    )
    sibling = StorageCandidate(
        path="/Users/test/Library/Caches/Google",
        size_bytes=2000000000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.95,
        reason="Cache dir",
        recommendation="Review for cleanup",
        item_type="directory",
    )

    all_cands = [parent, child, sibling]
    # Sum without deduplication double-counts child:
    double_counted_sum = sum(c.size_bytes for c in all_cands)
    assert double_counted_sum == 4300000000

    deduped = analyzer.deduplicate_candidates(all_cands)
    # Unique sum only counts parent and sibling:
    unique_sum = sum(c.size_bytes for c in deduped)
    assert unique_sum == 3160000000
    assert len(deduped) == 2


# ==============================================================================
# Edge-Case Accounting Tests (4 Dimensions: Presentation, Eligibility, Physical, Reclaimable)
# ==============================================================================

def test_edge_case_1_high_blocked_parent_plus_low_child():
    """
    Scenario 1: HIGH blocked parent + LOW child
    e.g. ~/Documents (HIGH, 5 GB) and ~/Documents/temp.log (LOW, 50 MB)
    """
    from app.analysis.recommendations import RecommendationEngine, SafetyStatus
    analyzer = StorageAnalyzer()
    rec_engine = RecommendationEngine()

    parent = StorageCandidate(
        path="/Users/test/Documents",
        size_bytes=5000000000,
        category=StorageCategory.DOCUMENTS,
        risk_level=RiskLevel.HIGH,
        confidence=0.90,
        reason="User docs",
        recommendation="Retain",
        item_type="directory",
    )
    child = StorageCandidate(
        path="/Users/test/Documents/temp.log",
        size_bytes=50000000,
        category=StorageCategory.LOGS,
        risk_level=RiskLevel.LOW,
        confidence=0.90,
        reason="Log file",
        recommendation="Review for cleanup",
        item_type="file",
    )

    cands = analyzer.deduplicate_candidates([parent, child])
    # 1. Candidate presentation: Both are presented (child is not discarded because parent is blocked)
    assert len(cands) == 2
    assert cands[0].path == "/Users/test/Documents"
    assert cands[1].path == "/Users/test/Documents/temp.log"

    # 2. Review eligibility: Parent is MANUAL_REVIEW_REQUIRED, Child is ELIGIBLE_FOR_REVIEW
    recs = rec_engine.recommend_many(cands)
    rec_map = {r.candidate.path: r for r in recs}
    assert rec_map["/Users/test/Documents"].safety_status == SafetyStatus.MANUAL_REVIEW_REQUIRED.value
    assert rec_map["/Users/test/Documents/temp.log"].safety_status == SafetyStatus.ELIGIBLE_FOR_REVIEW.value

    # 3. Physical coverage: 5 GB (parent encompasses child physically)
    phys_bytes = analyzer.calculate_physical_coverage_bytes(cands)
    assert phys_bytes == 5000000000

    # 4. Reclaimable / reviewable bytes: 50 MB (blocked parent does NOT inflate reclaimable total)
    reclaim_bytes = analyzer.calculate_reclaimable_bytes(cands)
    assert reclaim_bytes == 50000000


def test_edge_case_2_high_blocked_parent_plus_multiple_low_children():
    """
    Scenario 2: HIGH blocked parent + multiple LOW children
    e.g. ~/Documents (HIGH, 5 GB), ~/Documents/a.log (50 MB), ~/Documents/b.log (30 MB)
    """
    from app.analysis.recommendations import RecommendationEngine, SafetyStatus
    analyzer = StorageAnalyzer()
    rec_engine = RecommendationEngine()

    parent = StorageCandidate(
        path="/Users/test/Documents",
        size_bytes=5000000000,
        category=StorageCategory.DOCUMENTS,
        risk_level=RiskLevel.HIGH,
        confidence=0.90,
        reason="User docs",
        recommendation="Retain",
        item_type="directory",
    )
    child1 = StorageCandidate(
        path="/Users/test/Documents/a.log",
        size_bytes=50000000,
        category=StorageCategory.LOGS,
        risk_level=RiskLevel.LOW,
        confidence=0.90,
        reason="Log file",
        recommendation="Review for cleanup",
        item_type="file",
    )
    child2 = StorageCandidate(
        path="/Users/test/Documents/b.log",
        size_bytes=30000000,
        category=StorageCategory.LOGS,
        risk_level=RiskLevel.LOW,
        confidence=0.90,
        reason="Log file",
        recommendation="Review for cleanup",
        item_type="file",
    )

    cands = analyzer.deduplicate_candidates([parent, child1, child2])
    # 1. Candidate presentation: All 3 preserved
    assert len(cands) == 3

    # 2. Review eligibility
    recs = rec_engine.recommend_many(cands)
    assert sum(1 for r in recs if r.safety_status == SafetyStatus.ELIGIBLE_FOR_REVIEW.value) == 2
    assert sum(1 for r in recs if r.safety_status == SafetyStatus.MANUAL_REVIEW_REQUIRED.value) == 1

    # 3. Physical coverage: 5 GB
    assert analyzer.calculate_physical_coverage_bytes(cands) == 5000000000

    # 4. Reclaimable bytes: 80 MB
    assert analyzer.calculate_reclaimable_bytes(cands) == 80000000


def test_edge_case_3_medium_parent_plus_low_child():
    """
    Scenario 3: MEDIUM parent + LOW child
    e.g. ~/projects/node_modules (MEDIUM, 500 MB) + ~/projects/node_modules/.cache (LOW, 50 MB)
    """
    from app.analysis.recommendations import RecommendationEngine, SafetyStatus
    analyzer = StorageAnalyzer()
    rec_engine = RecommendationEngine()

    parent = StorageCandidate(
        path="/Users/test/projects/node_modules",
        size_bytes=500000000,
        category=StorageCategory.DEVELOPMENT,
        risk_level=RiskLevel.MEDIUM,
        confidence=0.90,
        reason="Dev modules",
        recommendation="Manual review",
        item_type="directory",
    )
    child = StorageCandidate(
        path="/Users/test/projects/node_modules/.cache",
        size_bytes=50000000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.90,
        reason="Cache folder",
        recommendation="Review for cleanup",
        item_type="directory",
    )

    cands = analyzer.deduplicate_candidates([parent, child])
    # 1. Candidate presentation: Both preserved (parent cannot be cleaned as a unit without caution)
    assert len(cands) == 2

    # 2. Review eligibility: Parent is MANUAL_REVIEW_REQUIRED, child is ELIGIBLE_FOR_REVIEW
    recs = rec_engine.recommend_many(cands)
    rec_map = {r.candidate.path: r for r in recs}
    assert rec_map["/Users/test/projects/node_modules"].safety_status == SafetyStatus.MANUAL_REVIEW_REQUIRED.value
    assert rec_map["/Users/test/projects/node_modules/.cache"].safety_status == SafetyStatus.ELIGIBLE_FOR_REVIEW.value

    # 3. Physical coverage: 500 MB
    assert analyzer.calculate_physical_coverage_bytes(cands) == 500000000

    # 4. Reclaimable bytes: 50 MB (medium parent does not inflate reclaimable total)
    assert analyzer.calculate_reclaimable_bytes(cands) == 50000000


def test_edge_case_4_low_parent_plus_low_child():
    """
    Scenario 4: LOW parent + LOW child
    e.g. ~/Library/Caches/trivy (LOW, 1.16 GB) + ~/Library/Caches/trivy/db/trivy.db (LOW, 1.14 GB)
    """
    from app.analysis.recommendations import RecommendationEngine, SafetyStatus
    analyzer = StorageAnalyzer()
    rec_engine = RecommendationEngine()

    parent = StorageCandidate(
        path="/Users/test/Library/Caches/trivy",
        size_bytes=1160000000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.95,
        reason="Cache dir",
        recommendation="Review for cleanup",
        item_type="directory",
    )
    child = StorageCandidate(
        path="/Users/test/Library/Caches/trivy/db/trivy.db",
        size_bytes=1140000000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.95,
        reason="Cache file",
        recommendation="Review for cleanup",
        item_type="file",
    )

    cands = analyzer.deduplicate_candidates([parent, child])
    # 1. Candidate presentation: Subsumed into parent (only 1 candidate)
    assert len(cands) == 1
    assert cands[0].path == "/Users/test/Library/Caches/trivy"

    # 2. Review eligibility: ELIGIBLE_FOR_REVIEW
    recs = rec_engine.recommend_many(cands)
    assert recs[0].safety_status == SafetyStatus.ELIGIBLE_FOR_REVIEW.value

    # 3. Physical coverage: 1.16 GB
    assert analyzer.calculate_physical_coverage_bytes(cands) == 1160000000

    # 4. Reclaimable bytes: 1.16 GB
    assert analyzer.calculate_reclaimable_bytes(cands) == 1160000000


def test_edge_case_5_low_sibling_directories():
    """
    Scenario 5: LOW sibling directories
    e.g. ~/Library/Caches/Google (2.16 GB) + ~/.cache/uv (1.27 GB)
    """
    from app.analysis.recommendations import RecommendationEngine, SafetyStatus
    analyzer = StorageAnalyzer()
    rec_engine = RecommendationEngine()

    s1 = StorageCandidate(
        path="/Users/test/Library/Caches/Google",
        size_bytes=2160000000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.95,
        reason="Google cache",
        recommendation="Review for cleanup",
        item_type="directory",
    )
    s2 = StorageCandidate(
        path="/Users/test/.cache/uv",
        size_bytes=1270000000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.85,
        reason="UV cache",
        recommendation="Review for cleanup",
        item_type="directory",
    )

    cands = analyzer.deduplicate_candidates([s1, s2])
    # 1. Candidate presentation: Both preserved
    assert len(cands) == 2

    # 2. Review eligibility: Both ELIGIBLE_FOR_REVIEW
    recs = rec_engine.recommend_many(cands)
    assert all(r.safety_status == SafetyStatus.ELIGIBLE_FOR_REVIEW.value for r in recs)

    # 3. Physical coverage: 3.43 GB
    assert analyzer.calculate_physical_coverage_bytes(cands) == 3430000000

    # 4. Reclaimable bytes: 3.43 GB
    assert analyzer.calculate_reclaimable_bytes(cands) == 3430000000


def test_edge_case_6_high_parent_plus_high_child():
    """
    Scenario 6: HIGH parent + HIGH child
    e.g. ~/Documents (HIGH, 5 GB) + ~/Documents/taxes.pdf (HIGH, 50 MB)
    """
    from app.analysis.recommendations import RecommendationEngine, SafetyStatus
    analyzer = StorageAnalyzer()
    rec_engine = RecommendationEngine()

    parent = StorageCandidate(
        path="/Users/test/Documents",
        size_bytes=5000000000,
        category=StorageCategory.DOCUMENTS,
        risk_level=RiskLevel.HIGH,
        confidence=0.90,
        reason="User docs",
        recommendation="Retain",
        item_type="directory",
    )
    child = StorageCandidate(
        path="/Users/test/Documents/taxes.pdf",
        size_bytes=50000000,
        category=StorageCategory.DOCUMENTS,
        risk_level=RiskLevel.HIGH,
        confidence=0.90,
        reason="Tax doc",
        recommendation="Retain",
        item_type="file",
    )

    cands = analyzer.deduplicate_candidates([parent, child])
    # 1. Candidate presentation: Child subsumed under parent (parent represents whole high-risk subtree)
    assert len(cands) == 1
    assert cands[0].path == "/Users/test/Documents"

    # 2. Review eligibility: MANUAL_REVIEW_REQUIRED
    recs = rec_engine.recommend_many(cands)
    assert recs[0].safety_status == SafetyStatus.MANUAL_REVIEW_REQUIRED.value

    # 3. Physical coverage: 5 GB
    assert analyzer.calculate_physical_coverage_bytes(cands) == 5000000000

    # 4. Reclaimable bytes: 0 B (HIGH risk items are never reclaimable)
    assert analyzer.calculate_reclaimable_bytes(cands) == 0


def test_edge_case_7_no_overlap_mixed_disjoint():
    """
    Scenario 7: No overlap (disjoint paths across multiple categories and risk levels)
    """
    from app.analysis.recommendations import RecommendationEngine, SafetyStatus
    analyzer = StorageAnalyzer()
    rec_engine = RecommendationEngine()

    c_cache = StorageCandidate(
        path="/Users/test/Library/Caches/AppA",
        size_bytes=100000000,
        category=StorageCategory.CACHE,
        risk_level=RiskLevel.LOW,
        confidence=0.95,
        reason="Cache",
        recommendation="Review",
        item_type="directory",
    )
    c_doc = StorageCandidate(
        path="/Users/test/Documents/Notes.pdf",
        size_bytes=200000000,
        category=StorageCategory.DOCUMENTS,
        risk_level=RiskLevel.HIGH,
        confidence=0.90,
        reason="Doc",
        recommendation="Retain",
        item_type="file",
    )
    c_dev = StorageCandidate(
        path="/Users/test/projects/lib/.venv",
        size_bytes=300000000,
        category=StorageCategory.DEVELOPMENT,
        risk_level=RiskLevel.MEDIUM,
        confidence=0.90,
        reason="Venv",
        recommendation="Review",
        item_type="directory",
    )

    cands = analyzer.deduplicate_candidates([c_cache, c_doc, c_dev])
    # 1. Candidate presentation: All 3 preserved
    assert len(cands) == 3

    # 2. Review eligibility
    recs = rec_engine.recommend_many(cands)
    status_counts = {r.safety_status: 0 for r in recs}
    for r in recs:
        status_counts[r.safety_status] += 1
    assert status_counts[SafetyStatus.ELIGIBLE_FOR_REVIEW.value] == 1
    assert status_counts[SafetyStatus.MANUAL_REVIEW_REQUIRED.value] == 2

    # 3. Physical coverage: 100M + 200M + 300M = 600M
    assert analyzer.calculate_physical_coverage_bytes(cands) == 600000000

    # 4. Reclaimable bytes: 100M (only low-risk cache is reclaimable)
    assert analyzer.calculate_reclaimable_bytes(cands) == 100000000


