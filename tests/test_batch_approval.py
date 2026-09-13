"""
Unit and safety integration tests for Phase 12 Batch Approval Coordinator.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.analysis.models import RiskLevel
from app.audit.repository import AuditRepository
from app.execution.trash_executor import TrashExecutor
from app.models.category import SmartCategory
from app.models.investigation import (
    CleanupPlan,
    CleanupPlanItem,
    ReclaimConfidence,
)
from app.safety.approval_service import ApprovalService
from app.safety.batch_approval import BatchApprovalCoordinator
from app.safety.path_validator import PathValidator


@pytest.fixture
def batch_sandbox(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Create sandbox home, clean root, and sandbox trash."""
    home = tmp_path / "home"
    home.mkdir()
    clean_root = home / "Library" / "Caches"
    clean_root.mkdir(parents=True)
    trash_root = tmp_path / "sandbox_trash"
    trash_root.mkdir()

    # Create dummy cache files
    (clean_root / "pip").mkdir()
    with open(clean_root / "pip" / "cached.whl", "wb") as f:
        f.write(b"0" * 1024 * 1024)

    (clean_root / "app").mkdir()
    with open(clean_root / "app" / "temp.db", "wb") as f:
        f.write(b"0" * 2 * 1024 * 1024)

    return home, clean_root, trash_root


def test_batch_approval_grouping() -> None:
    plan = CleanupPlan(
        high_confidence_items=[
            CleanupPlanItem(
                evidence_id="ev_01",
                path="/Users/test/Library/Caches/pip",
                canonical_path="/Users/test/Library/Caches/pip",
                size_bytes=1000,
                category=SmartCategory.PACKAGE_MANAGERS,
                subcategory="pip_cache",
                tier=ReclaimConfidence.HIGH_CONFIDENCE,
            ),
            CleanupPlanItem(
                evidence_id="ev_02",
                path="/Users/test/Downloads/installer.dmg",
                canonical_path="/Users/test/Downloads/installer.dmg",
                size_bytes=5000,
                category=SmartCategory.DISK_IMAGES,
                subcategory="disk_image",
                tier=ReclaimConfidence.HIGH_CONFIDENCE,
            ),
        ],
        review_required_items=[
            CleanupPlanItem(
                evidence_id="ev_03",
                path="/Users/test/Library/Developer/Xcode/DerivedData",
                canonical_path="/Users/test/Library/Developer/Xcode/DerivedData",
                size_bytes=10000,
                category=SmartCategory.DEVELOPER_DATA,
                subcategory="xcode_derived_data",
                tier=ReclaimConfidence.REVIEW_REQUIRED,
            )
        ],
        total_reclaimable_bytes=16000,
    )

    coordinator = BatchApprovalCoordinator()
    groups = coordinator.group_cleanup_plan(plan)

    assert len(groups) >= 2
    group_ids = [g.group_id for g in groups]
    assert "safe_caches" in group_ids
    assert "installers" in group_ids


def test_batch_approval_and_execution_lifecycle(batch_sandbox: tuple[Path, Path, Path], tmp_path: Path) -> None:
    home, clean_root, trash_root = batch_sandbox
    db_path = tmp_path / "audit_test.db"
    audit_repo = AuditRepository(db_path=str(db_path))

    validator = PathValidator(home_dir=home, custom_allowlist_roots=[clean_root])
    approval_service = ApprovalService(path_validator=validator)
    trash_executor = TrashExecutor(
        approval_service=approval_service,
        path_validator=validator,
        audit_repo=audit_repo,
        trash_root=trash_root,
    )

    coordinator = BatchApprovalCoordinator(
        approval_service=approval_service,
        trash_executor=trash_executor,
        path_validator=validator,
        audit_repo=audit_repo,
    )

    target1 = clean_root / "pip"
    target2 = clean_root / "app"

    item1 = CleanupPlanItem(
        evidence_id="ev_1",
        path=str(target1),
        canonical_path=str(target1),
        size_bytes=1024 * 1024,
        category=SmartCategory.PACKAGE_MANAGERS,
        subcategory="pip_cache",
        tier=ReclaimConfidence.HIGH_CONFIDENCE,
        requires_review=False,
    )
    item2 = CleanupPlanItem(
        evidence_id="ev_2",
        path=str(target2),
        canonical_path=str(target2),
        size_bytes=2 * 1024 * 1024,
        category=SmartCategory.CACHES,
        subcategory="app_cache",
        tier=ReclaimConfidence.HIGH_CONFIDENCE,
        requires_review=False,
    )

    report = coordinator.approve_and_execute_batch(
        items=[item1, item2],
        actor="human_batch_tester",
        custom_trash_root=trash_root,
    )

    assert report.total_items == 2
    assert report.successful_items == 2
    assert report.failed_items == 0
    assert report.bytes_freed > 0

    # Ensure files moved to trash
    assert not target1.exists()
    assert not target2.exists()


def test_batch_approval_blocks_unallowlisted_target(batch_sandbox: tuple[Path, Path, Path], tmp_path: Path) -> None:
    """Ensure batch approval cannot be used to bypass PathValidator on unallowlisted paths."""
    home, clean_root, trash_root = batch_sandbox
    validator = PathValidator(home_dir=home, custom_allowlist_roots=[clean_root])
    approval_service = ApprovalService(path_validator=validator)
    coordinator = BatchApprovalCoordinator(
        approval_service=approval_service,
        path_validator=validator,
    )

    unallowlisted_target = home / "Documents" / "secret.txt"
    unallowlisted_target.parent.mkdir(parents=True, exist_ok=True)
    unallowlisted_target.write_text("protected")

    item = CleanupPlanItem(
        evidence_id="ev_bad",
        path=str(unallowlisted_target),
        canonical_path=str(unallowlisted_target),
        size_bytes=100,
        category=SmartCategory.DOCUMENTS,
        subcategory="secret",
        tier=ReclaimConfidence.HIGH_CONFIDENCE,
    )

    report = coordinator.approve_and_execute_batch(items=[item], custom_trash_root=trash_root)

    assert report.successful_items == 0
    assert report.failed_items == 1
    assert unallowlisted_target.exists()  # Remained untouched


def test_batch_execution_report_storage_metric_semantics(batch_sandbox: tuple[Path, Path, Path], tmp_path: Path) -> None:
    """
    Regression test verifying BatchExecutionReport storage metric properties:
    - bytes_moved_to_trash accurately mirrors bytes_freed
    - bytes_moved_to_trash_human produces formatted string
    - physical_disk_reclaimed_status states 'Not yet reclaimed — Trash must be emptied'
    """
    home, clean_root, trash_root = batch_sandbox
    validator = PathValidator(home_dir=home, custom_allowlist_roots=[clean_root])
    approval_service = ApprovalService(path_validator=validator)
    coordinator = BatchApprovalCoordinator(
        approval_service=approval_service,
        path_validator=validator,
    )

    target_dir = clean_root / "pip"
    item = CleanupPlanItem(
        evidence_id="ev_pip_test",
        path=str(target_dir),
        canonical_path=str(target_dir),
        size_bytes=1024 * 1024,
        category=SmartCategory.PACKAGE_MANAGERS,
        subcategory="pip_cache",
        tier=ReclaimConfidence.HIGH_CONFIDENCE,
    )

    report = coordinator.approve_and_execute_batch(items=[item], custom_trash_root=trash_root)

    assert report.successful_items == 1
    assert report.bytes_freed == 1024 * 1024
    assert report.bytes_moved_to_trash == 1024 * 1024
    assert report.bytes_moved_to_trash_human == "1.00 MB"
    assert report.bytes_freed_human == "1.00 MB"
    assert report.physical_disk_reclaimed_status == "Not yet reclaimed — Trash must be emptied"
