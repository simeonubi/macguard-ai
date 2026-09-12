"""
MacGuard AI Phase 12 — Storage Investigator Engine.

Orchestrates progressive, read-only storage investigations across modular detectors.
Answers:
- "Why is my Mac full?"
- "What is actually consuming the space?"
- "What can I safely reclaim?"
- "How much can I recover?"

CORE INVARIANTS:
1. READ-ONLY: Never modifies, deletes, moves, or renames filesystem objects.
2. DETERMINISTIC: All totals, sizes, and safety boundaries are computed from deterministic evidence.
3. MODULAR: Orchestrates detectors via BaseStorageDetector interface.
4. INODE TRACKING: APFS inode sets prevent double-counting across detectors.
"""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Optional, Sequence

from app.analysis.detectors.aiml_detector import AIMLStorageDetector
from app.analysis.detectors.base import BaseStorageDetector
from app.analysis.detectors.cache_detector import CacheDetector
from app.analysis.detectors.developer_detector import DeveloperStorageDetector
from app.analysis.detectors.docker_detector import DockerDetector
from app.analysis.detectors.download_detector import DownloadDetector
from app.analysis.detectors.duplicate_detector import DuplicateStorageDetector
from app.analysis.detectors.evidence_aggregator import EvidenceAggregator
from app.analysis.detectors.large_file_detector import LargeFileDetector
from app.analysis.detectors.log_detector import LogDetector
from app.analysis.detectors.node_cache_detector import NodeCacheDetector
from app.analysis.detectors.python_cache_detector import PythonCacheDetector
from app.models.category import SmartCategory
from app.models.investigation import (
    CleanupPlan,
    InvestigationLevel,
    StorageEvidenceItem,
    StorageInvestigationEvidence,
)
from app.models.scan_scope import ScanScope, ScopeIdentifier
from app.safety.path_validator import PathValidator
from app.tools.storage_scanner import DiskUsage, StorageScanner


class StorageInvestigator:
    """
    Modular orchestrator for progressive MacGuard AI storage investigations.
    """

    def __init__(
        self,
        scanner: Optional[StorageScanner] = None,
        validator: Optional[PathValidator] = None,
        aggregator: Optional[EvidenceAggregator] = None,
        custom_detectors: Optional[Sequence[BaseStorageDetector]] = None,
    ) -> None:
        self._scanner = scanner or StorageScanner()
        self._validator = validator or PathValidator()
        self._aggregator = aggregator or EvidenceAggregator()

        if custom_detectors is not None:
            self._detectors: list[BaseStorageDetector] = list(custom_detectors)
        else:
            self._detectors = [
                CacheDetector(),
                PythonCacheDetector(),
                NodeCacheDetector(),
                DeveloperStorageDetector(),
                DockerDetector(),
                AIMLStorageDetector(),
                LogDetector(),
                DownloadDetector(),
                LargeFileDetector(),
                DuplicateStorageDetector(),
            ]

    def investigate(
        self,
        scope: Optional[ScanScope] = None,
        level: InvestigationLevel = InvestigationLevel.TARGETED,
        target_category: Optional[SmartCategory] = None,
        macos_system_data_reported_bytes: Optional[int] = None,
    ) -> tuple[StorageInvestigationEvidence, CleanupPlan]:
        """
        Execute a progressive storage investigation.

        Args:
            scope: ScanScope defining allowed paths and bounds (defaults to User Home).
            level: InvestigationLevel (HEALTH, TARGETED, DEEP, SPECIFIC).
            target_category: Optional SmartCategory filter for SPECIFIC level.
            macos_system_data_reported_bytes: Optional macOS-reported System Data number for context.
        """
        user_home = str(Path.home())
        effective_scope = scope or ScanScope(
            scope_id=ScopeIdentifier.HOME,
            root_path=user_home,
            description="User Home Scope",
        )
        target_path = effective_scope.root_path

        # 1. Fetch physical disk usage (Level 1 baseline)
        disk_usage = self._scanner.get_disk_usage(target_path)

        if level == InvestigationLevel.HEALTH:
            # Health check only returns physical usage and empty evidence
            return self._aggregator.aggregate(
                investigation_id=f"inv_health_{uuid.uuid4().hex[:8]}",
                level=InvestigationLevel.HEALTH,
                target_path=target_path,
                disk_usage=disk_usage,
                raw_items=[],
                macos_system_data_reported_bytes=macos_system_data_reported_bytes,
            )

        # 2. Determine active detectors based on level
        active_detectors: list[BaseStorageDetector] = []
        if level == InvestigationLevel.TARGETED:
            # Fast, high-value locations
            active_detectors = [
                d for d in self._detectors
                if not isinstance(d, (LargeFileDetector, DuplicateStorageDetector))
            ]
        elif level == InvestigationLevel.DEEP:
            # Full detector suite
            active_detectors = list(self._detectors)
        elif level == InvestigationLevel.SPECIFIC:
            # Filter detectors relevant to category if provided
            active_detectors = list(self._detectors)
        else:
            active_detectors = list(self._detectors)

        # 3. Run detectors with shared inode tracking to eliminate double-counting
        visited_inodes: set[tuple[int, int]] = set()
        raw_items: list[StorageEvidenceItem] = []

        for detector in active_detectors:
            try:
                findings = detector.detect(
                    scope=effective_scope,
                    visited_inodes=visited_inodes,
                    scanner=self._scanner,
                    path_validator=self._validator,
                )
                if target_category is not None:
                    findings = [f for f in findings if f.category == target_category]
                raw_items.extend(findings)
            except Exception:
                # Detector failures must fail safe and not abort the entire investigation
                continue

        # 4. Aggregate findings and compute deterministic totals
        run_id = f"inv_{level.value.lower()}_{uuid.uuid4().hex[:8]}"
        return self._aggregator.aggregate(
            investigation_id=run_id,
            level=level,
            target_path=target_path,
            disk_usage=disk_usage,
            raw_items=raw_items,
            macos_system_data_reported_bytes=macos_system_data_reported_bytes,
        )
