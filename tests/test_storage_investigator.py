"""
Unit and integration tests for Phase 12 Storage Investigator.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.analysis.detectors.base import BaseStorageDetector
from app.analysis.models import RiskLevel
from app.analysis.storage_investigator import StorageInvestigator
from app.models.category import SmartCategory
from app.models.investigation import (
    InvestigationLevel,
    ReclaimConfidence,
    StorageEvidenceItem,
)
from app.models.scan_scope import ScanScope, ScopeIdentifier
from app.tools.storage_scanner import DiskUsage, StorageScanner


class DummyDetector(BaseStorageDetector):
    def __init__(self, detector_id: str, name: str, items: list[StorageEvidenceItem]) -> None:
        self._id = detector_id
        self._name = name
        self._items = items

    @property
    def detector_id(self) -> str:
        return self._id

    @property
    def detector_name(self) -> str:
        return self._name

    def detect(self, scope, visited_inodes, scanner=None, path_validator=None):
        return list(self._items)


def test_storage_investigator_level1_health() -> None:
    mock_scanner = MagicMock(spec=StorageScanner)
    mock_scanner.get_disk_usage.return_value = DiskUsage(
        path="/Users/test",
        total_bytes=500_000_000_000,
        used_bytes=480_000_000_000,
        free_bytes=20_000_000_000,
    )

    investigator = StorageInvestigator(scanner=mock_scanner)
    scope = ScanScope(scope_id=ScopeIdentifier.HOME, root_path="/Users/test", description="Home")

    evidence, plan = investigator.investigate(scope=scope, level=InvestigationLevel.HEALTH)

    assert evidence.level == InvestigationLevel.HEALTH
    assert evidence.disk_free_bytes == 20_000_000_000
    assert len(evidence.items) == 0
    assert plan.total_reclaimable_bytes == 0


def test_storage_investigator_level2_targeted_isolation() -> None:
    item1 = StorageEvidenceItem(
        evidence_id="ev_001",
        path="/Users/test/Library/Caches/app",
        canonical_path="/Users/test/Library/Caches/app",
        size_bytes=100_000_000,
        category=SmartCategory.CACHES,
        risk_level=RiskLevel.LOW,
        reclaim_confidence=ReclaimConfidence.HIGH_CONFIDENCE,
        cleanup_allowed=True,
    )
    dummy_det = DummyDetector("dummy_cache", "Dummy Cache", [item1])

    mock_scanner = MagicMock(spec=StorageScanner)
    mock_scanner.get_disk_usage.return_value = DiskUsage(
        path="/Users/test",
        total_bytes=500_000_000_000,
        used_bytes=300_000_000_000,
        free_bytes=200_000_000_000,
    )

    investigator = StorageInvestigator(scanner=mock_scanner, custom_detectors=[dummy_det])
    scope = ScanScope(scope_id=ScopeIdentifier.HOME, root_path="/Users/test", description="Home")

    evidence, plan = investigator.investigate(scope=scope, level=InvestigationLevel.TARGETED)

    assert evidence.level == InvestigationLevel.TARGETED
    assert evidence.analyzed_bytes == 100_000_000
    assert evidence.reclaimable_high_confidence_bytes == 100_000_000
    assert len(evidence.items) == 1
    assert len(plan.high_confidence_items) == 1


def test_storage_investigator_system_data_semantics() -> None:
    """Ensure macOS-reported System Data number is stored accurately without conflating with analyzed storage."""
    mock_scanner = MagicMock(spec=StorageScanner)
    mock_scanner.get_disk_usage.return_value = DiskUsage(
        path="/Users/test",
        total_bytes=500_000_000_000,
        used_bytes=300_000_000_000,
        free_bytes=200_000_000_000,
    )

    investigator = StorageInvestigator(scanner=mock_scanner, custom_detectors=[])
    scope = ScanScope(scope_id=ScopeIdentifier.HOME, root_path="/Users/test", description="Home")

    evidence, plan = investigator.investigate(
        scope=scope,
        level=InvestigationLevel.TARGETED,
        macos_system_data_reported_bytes=119_000_000_000,  # 119 GB macOS reported System Data
    )

    assert evidence.macos_system_data_reported_bytes == 119_000_000_000
    assert evidence.analyzed_bytes == 0  # Does not claim 119GB equals analyzed bytes
