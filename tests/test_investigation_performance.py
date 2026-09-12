"""
Performance and benchmark tests for Phase 12 Storage Investigator.
"""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from app.analysis.storage_investigator import StorageInvestigator
from app.models.investigation import InvestigationLevel
from app.models.scan_scope import ScanScope, ScopeIdentifier
from app.tools.storage_scanner import DiskUsage, StorageScanner


def test_level1_health_performance(tmp_path: Path) -> None:
    """Level 1 Health check must complete almost instantaneously (< 100ms)."""
    mock_scanner = MagicMock(spec=StorageScanner)
    mock_scanner.get_disk_usage.return_value = DiskUsage(
        path=str(tmp_path),
        total_bytes=500_000_000_000,
        used_bytes=300_000_000_000,
        free_bytes=200_000_000_000,
    )

    investigator = StorageInvestigator(scanner=mock_scanner)
    scope = ScanScope(scope_id=ScopeIdentifier.HOME, root_path=str(tmp_path), description="Home")

    start = time.perf_counter()
    evidence, plan = investigator.investigate(scope=scope, level=InvestigationLevel.HEALTH)
    duration = time.perf_counter() - start

    assert duration < 0.1, f"Health check took too long: {duration:.4f}s"
    assert evidence.level == InvestigationLevel.HEALTH


def test_level2_targeted_performance_bounded(tmp_path: Path) -> None:
    """Level 2 Targeted investigation on empty or typical sandbox should complete quickly."""
    investigator = StorageInvestigator()
    scope = ScanScope(scope_id=ScopeIdentifier.HOME, root_path=str(tmp_path), description="Home")

    start = time.perf_counter()
    evidence, plan = investigator.investigate(scope=scope, level=InvestigationLevel.TARGETED)
    duration = time.perf_counter() - start

    assert duration < 2.0, f"Targeted investigation took too long on sandbox: {duration:.4f}s"
    assert evidence.level == InvestigationLevel.TARGETED
