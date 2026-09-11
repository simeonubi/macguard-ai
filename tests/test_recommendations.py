from __future__ import annotations

from pathlib import Path
import pytest
from pydantic import ValidationError

from app.analysis.models import RiskLevel, StorageCandidate, StorageCategory
from app.analysis.recommendations import (
    RecommendationAction,
    RecommendationEngine,
    SafetyStatus,
    StorageRecommendation,
)


def _make_candidate(
    category: StorageCategory,
    risk_level: RiskLevel,
    path: str = "/Users/test/sample",
    size_bytes: int = 1024,
    confidence: float = 0.9,
    reason: str = "Test reason",
    recommendation: str = "Test advisory",
) -> StorageCandidate:
    return StorageCandidate(
        path=path,
        size_bytes=size_bytes,
        category=category,
        risk_level=risk_level,
        confidence=confidence,
        reason=reason,
        recommendation=recommendation,
    )


# =====================================================================
# 1. MODEL & ENUM VALIDATION
# =====================================================================

def test_recommendation_action_enum_has_no_destructive_actions():
    action_values = {a.value for a in RecommendationAction}
    assert "clean" not in action_values
    assert "delete" not in action_values
    assert "remove" not in action_values
    assert action_values == {
        "review_for_cleanup",
        "manual_review",
        "ignore",
        "no_action",
    }


def test_storage_recommendation_validation_success():
    candidate = _make_candidate(StorageCategory.CACHE, RiskLevel.LOW)
    rec = StorageRecommendation(
        candidate=candidate,
        action=RecommendationAction.REVIEW_FOR_CLEANUP,
        rationale="Cache data identified.",
        requires_approval=True,
        safety_status=SafetyStatus.ELIGIBLE_FOR_REVIEW.value,
        confidence=0.9,
    )
    assert rec.candidate == candidate
    assert rec.action == RecommendationAction.REVIEW_FOR_CLEANUP
    assert rec.requires_approval is True
    assert rec.confidence == 0.9


def test_storage_recommendation_confidence_bounds():
    candidate = _make_candidate(StorageCategory.CACHE, RiskLevel.LOW)

    # Confidence > 1.0 rejected
    with pytest.raises(ValidationError):
        StorageRecommendation(
            candidate=candidate,
            action=RecommendationAction.MANUAL_REVIEW,
            rationale="Test",
            safety_status="manual_review_required",
            confidence=1.2,
        )

    # Confidence < 0.0 rejected
    with pytest.raises(ValidationError):
        StorageRecommendation(
            candidate=candidate,
            action=RecommendationAction.MANUAL_REVIEW,
            rationale="Test",
            safety_status="manual_review_required",
            confidence=-0.1,
        )


def test_storage_recommendation_immutability():
    candidate = _make_candidate(StorageCategory.CACHE, RiskLevel.LOW)
    rec = StorageRecommendation(
        candidate=candidate,
        action=RecommendationAction.REVIEW_FOR_CLEANUP,
        rationale="Cache",
        safety_status="eligible_for_review",
        confidence=0.9,
    )
    with pytest.raises(ValidationError):
        rec.action = RecommendationAction.IGNORE  # type: ignore


def test_storage_recommendation_extra_fields_rejected():
    candidate = _make_candidate(StorageCategory.CACHE, RiskLevel.LOW)
    with pytest.raises(ValidationError):
        StorageRecommendation(  # type: ignore
            candidate=candidate,
            action=RecommendationAction.MANUAL_REVIEW,
            rationale="Test",
            safety_status="manual_review_required",
            confidence=0.9,
            unauthorized_field="illegal",
        )


# =====================================================================
# 2. RECOMMENDATION RULES TESTS
# =====================================================================

def test_recommend_cache_low_risk():
    engine = RecommendationEngine()
    candidate = _make_candidate(StorageCategory.CACHE, RiskLevel.LOW)
    rec = engine.recommend(candidate)

    assert rec.action == RecommendationAction.REVIEW_FOR_CLEANUP
    assert rec.requires_approval is True
    assert rec.safety_status == SafetyStatus.ELIGIBLE_FOR_REVIEW.value
    assert "safe to delete" not in rec.rationale.lower()
    assert "human approval is required" in rec.rationale.lower()


def test_recommend_logs_low_risk():
    engine = RecommendationEngine()
    candidate = _make_candidate(StorageCategory.LOGS, RiskLevel.LOW)
    rec = engine.recommend(candidate)

    assert rec.action == RecommendationAction.REVIEW_FOR_CLEANUP
    assert rec.requires_approval is True
    assert rec.safety_status == SafetyStatus.ELIGIBLE_FOR_REVIEW.value
    assert "safe to delete" not in rec.rationale.lower()


def test_recommend_development_medium_risk():
    engine = RecommendationEngine()
    candidate = _make_candidate(StorageCategory.DEVELOPMENT, RiskLevel.MEDIUM)
    rec = engine.recommend(candidate)

    assert rec.action == RecommendationAction.MANUAL_REVIEW
    assert rec.requires_approval is True
    assert rec.safety_status == SafetyStatus.MANUAL_REVIEW_REQUIRED.value
    assert "manual review" in rec.rationale.lower()


def test_recommend_application_data_high_risk():
    engine = RecommendationEngine()
    candidate = _make_candidate(StorageCategory.APPLICATION_DATA, RiskLevel.HIGH)
    rec = engine.recommend(candidate)

    assert rec.action == RecommendationAction.MANUAL_REVIEW
    assert rec.requires_approval is True
    assert rec.safety_status == SafetyStatus.MANUAL_REVIEW_REQUIRED.value
    assert "application state" in rec.rationale.lower()


def test_recommend_media_high_risk():
    engine = RecommendationEngine()
    candidate = _make_candidate(StorageCategory.MEDIA, RiskLevel.HIGH)
    rec = engine.recommend(candidate)

    assert rec.action == RecommendationAction.MANUAL_REVIEW
    assert rec.requires_approval is True
    assert rec.safety_status == SafetyStatus.MANUAL_REVIEW_REQUIRED.value
    assert "personal user assets" in rec.rationale.lower()


def test_recommend_documents_high_risk():
    engine = RecommendationEngine()
    candidate = _make_candidate(StorageCategory.DOCUMENTS, RiskLevel.HIGH)
    rec = engine.recommend(candidate)

    assert rec.action == RecommendationAction.MANUAL_REVIEW
    assert rec.requires_approval is True
    assert rec.safety_status == SafetyStatus.MANUAL_REVIEW_REQUIRED.value
    assert "user-owned content" in rec.rationale.lower()


def test_recommend_unknown_category_or_risk():
    engine = RecommendationEngine()

    # Category UNKNOWN
    cand1 = _make_candidate(StorageCategory.UNKNOWN, RiskLevel.UNKNOWN)
    rec1 = engine.recommend(cand1)
    assert rec1.action == RecommendationAction.NO_ACTION
    assert rec1.safety_status == SafetyStatus.UNKNOWN.value

    # Risk UNKNOWN with otherwise categorized item
    cand2 = _make_candidate(StorageCategory.CACHE, RiskLevel.UNKNOWN)
    rec2 = engine.recommend(cand2)
    assert rec2.action == RecommendationAction.NO_ACTION
    assert rec2.safety_status == SafetyStatus.UNKNOWN.value


# =====================================================================
# 3. SAFETY INVARIANTS & INTEGRITY TESTS
# =====================================================================

def test_high_and_unknown_risk_never_receive_cleanup_action():
    engine = RecommendationEngine()
    test_candidates = [
        _make_candidate(StorageCategory.MEDIA, RiskLevel.HIGH),
        _make_candidate(StorageCategory.DOCUMENTS, RiskLevel.HIGH),
        _make_candidate(StorageCategory.APPLICATION_DATA, RiskLevel.HIGH),
        _make_candidate(StorageCategory.UNKNOWN, RiskLevel.HIGH),
        _make_candidate(StorageCategory.UNKNOWN, RiskLevel.UNKNOWN),
        _make_candidate(StorageCategory.CACHE, RiskLevel.HIGH),
        _make_candidate(StorageCategory.LOGS, RiskLevel.UNKNOWN),
    ]

    for cand in test_candidates:
        rec = engine.recommend(cand)
        assert rec.action != RecommendationAction.REVIEW_FOR_CLEANUP
        assert rec.action in (RecommendationAction.MANUAL_REVIEW, RecommendationAction.NO_ACTION)


def test_all_recommendations_mandate_human_approval():
    engine = RecommendationEngine()
    for cat in StorageCategory:
        for risk in RiskLevel:
            cand = _make_candidate(cat, risk)
            rec = engine.recommend(cand)
            assert rec.requires_approval is True


def test_deterministic_output():
    engine = RecommendationEngine()
    candidate = _make_candidate(StorageCategory.CACHE, RiskLevel.LOW)

    rec1 = engine.recommend(candidate)
    rec2 = engine.recommend(candidate)

    assert rec1.action == rec2.action
    assert rec1.rationale == rec2.rationale
    assert rec1.requires_approval == rec2.requires_approval
    assert rec1.safety_status == rec2.safety_status
    assert rec1.confidence == rec2.confidence


def test_batch_recommend_many():
    engine = RecommendationEngine()
    candidates = [
        _make_candidate(StorageCategory.CACHE, RiskLevel.LOW, path="/cache/a"),
        _make_candidate(StorageCategory.LOGS, RiskLevel.LOW, path="/log/b"),
        _make_candidate(StorageCategory.MEDIA, RiskLevel.HIGH, path="/media/c"),
    ]

    recs = engine.recommend_many(candidates)
    assert len(recs) == 3
    assert recs[0].action == RecommendationAction.REVIEW_FOR_CLEANUP
    assert recs[1].action == RecommendationAction.REVIEW_FOR_CLEANUP
    assert recs[2].action == RecommendationAction.MANUAL_REVIEW


def test_recommendation_engine_performs_zero_filesystem_mutation(tmp_path: Path):
    test_file = tmp_path / "recommendation_target.txt"
    test_file.write_text("immutable content")
    initial_stat = test_file.stat()

    candidate = StorageCandidate(
        path=str(test_file),
        size_bytes=initial_stat.st_size,
        category=StorageCategory.DOCUMENTS,
        risk_level=RiskLevel.HIGH,
        confidence=0.9,
        reason="Test",
        recommendation="Test",
    )

    engine = RecommendationEngine()
    rec = engine.recommend(candidate)
    engine.recommend_many([candidate, candidate])

    assert rec.action == RecommendationAction.MANUAL_REVIEW
    assert test_file.read_text() == "immutable content"
    current_stat = test_file.stat()
    assert current_stat.st_size == initial_stat.st_size
    assert current_stat.st_mtime == initial_stat.st_mtime


# =====================================================================
# 4. CANDIDATE QUALITY & SIZE THRESHOLD REGRESSION TESTS
# =====================================================================

def test_zero_byte_candidate_excluded_from_cleanup_review():
    """Verify zero-byte items are never recommended for cleanup review."""
    engine = RecommendationEngine()
    
    # 0-byte CACHE (normally reviewable)
    zero_cache = _make_candidate(StorageCategory.CACHE, RiskLevel.LOW, size_bytes=0)
    rec_cache = engine.recommend(zero_cache)
    assert rec_cache.action == RecommendationAction.NO_ACTION
    assert rec_cache.safety_status == SafetyStatus.MANUAL_REVIEW_REQUIRED.value
    assert "zero-byte" in rec_cache.rationale.lower()

    # 0-byte LOGS (normally reviewable)
    zero_logs = _make_candidate(StorageCategory.LOGS, RiskLevel.LOW, size_bytes=0)
    rec_logs = engine.recommend(zero_logs)
    assert rec_logs.action == RecommendationAction.NO_ACTION
    assert rec_logs.safety_status == SafetyStatus.MANUAL_REVIEW_REQUIRED.value
    assert "zero-byte" in rec_logs.rationale.lower()


def test_negligible_size_candidate_excluded_when_below_threshold():
    """Verify items below configurable minimum threshold are excluded from cleanup review."""
    # Configure 1 MB (1,048,576 bytes) threshold
    threshold = 1024 * 1024
    engine = RecommendationEngine(min_cleanup_size_bytes=threshold)

    # 500 KB item (below threshold) -> NO_ACTION
    small_cache = _make_candidate(StorageCategory.CACHE, RiskLevel.LOW, size_bytes=500 * 1024)
    rec_small = engine.recommend(small_cache)
    assert rec_small.action == RecommendationAction.NO_ACTION
    assert rec_small.safety_status == SafetyStatus.MANUAL_REVIEW_REQUIRED.value
    assert "below the minimum cleanup threshold" in rec_small.rationale.lower()

    # 2 MB item (above threshold) -> REVIEW_FOR_CLEANUP
    large_cache = _make_candidate(StorageCategory.CACHE, RiskLevel.LOW, size_bytes=2 * 1024 * 1024)
    rec_large = engine.recommend(large_cache)
    assert rec_large.action == RecommendationAction.REVIEW_FOR_CLEANUP
    assert rec_large.safety_status == SafetyStatus.ELIGIBLE_FOR_REVIEW.value


def test_configurable_threshold_per_call_override():
    """Verify threshold can be overridden per recommend or recommend_many call."""
    engine = RecommendationEngine(min_cleanup_size_bytes=0)
    cand_1kb = _make_candidate(StorageCategory.CACHE, RiskLevel.LOW, size_bytes=1024)

    # Default (0 threshold): 1 KB is eligible
    assert engine.recommend(cand_1kb).action == RecommendationAction.REVIEW_FOR_CLEANUP

    # Call-level override with 2048 bytes threshold: 1 KB is excluded
    rec_override = engine.recommend(cand_1kb, min_cleanup_size_bytes=2048)
    assert rec_override.action == RecommendationAction.NO_ACTION
    assert rec_override.safety_status == SafetyStatus.MANUAL_REVIEW_REQUIRED.value


def test_negative_threshold_raises_value_error():
    """Verify negative threshold is rejected during engine initialization."""
    with pytest.raises(ValueError, match="min_cleanup_size_bytes cannot be negative"):
        RecommendationEngine(min_cleanup_size_bytes=-5)


def test_zero_byte_and_negligible_candidates_in_approval_service():
    """Verify ApprovalService correctly marks zero-byte or negligible recommendations as ineligible for approval."""
    from app.safety.approval_service import ApprovalService

    engine = RecommendationEngine(min_cleanup_size_bytes=1024 * 1024)
    zero_cand = _make_candidate(StorageCategory.CACHE, RiskLevel.LOW, size_bytes=0)
    small_cand = _make_candidate(StorageCategory.CACHE, RiskLevel.LOW, size_bytes=512)
    valid_cand = _make_candidate(StorageCategory.CACHE, RiskLevel.LOW, size_bytes=5 * 1024 * 1024)

    recs = engine.recommend_many([zero_cand, small_cand, valid_cand])
    approval_service = ApprovalService()
    review_items = approval_service.create_review_items(recs)

    assert len(review_items) == 3
    # Zero-byte: ineligible
    assert review_items[0].is_eligible_for_approval is False
    # Negligible: ineligible
    assert review_items[1].is_eligible_for_approval is False
    # Valid size: eligible
    assert review_items[2].is_eligible_for_approval is True

