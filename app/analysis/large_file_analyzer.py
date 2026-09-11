"""
MacGuard AI v1.1 — Deterministic Large File Intelligence Analyzer.

This module identifies, ranks, and categorizes large storage consumers across
discovered filesystem items. It preserves semantic categories, integrates developer
storage context, resolves hierarchical containment to prevent double counting,
and computes deterministic attention prioritization scores.

DISCOVERY != CATEGORIZATION != ANALYSIS != AUTHORIZATION
This analyzer is strictly read-only and metadata-driven. It performs zero filesystem
mutations and possesses zero cleanup or execution authority.
"""

from __future__ import annotations

import os
from pathlib import PurePath
from typing import Dict, List, Optional, Sequence, Set, Tuple

from app.analysis.categorizer import SmartCategorizer
from app.analysis.developer_analyzer import DeveloperStorageAnalyzer
from app.models.category import ConfidenceLevel, SmartCategory
from app.models.developer import DeveloperStorageSubtype, StaleStatus
from app.models.large_file import (
    LargeFileCategorySummary,
    LargeFileDeveloperSummary,
    LargeFileFinding,
    LargeFileSummary,
)
from app.models.scan_result import DiscoveredItem, ScanResult
from app.safety.canonicalizer import is_contained_within
from app.tools.storage_scanner import format_bytes

# Default size threshold: 50 MiB (52,428,800 bytes)
DEFAULT_LARGE_FILE_THRESHOLD_BYTES: int = 50 * 1024 * 1024


class LargeFileAnalyzer:
    """
    Deterministic Large File & Storage Consumer Intelligence Engine.

    Consumes pre-discovered items and produces structured, ranked findings with
    category awareness, unique-byte accounting, and attention prioritization.
    """

    def __init__(
        self,
        default_threshold_bytes: int = DEFAULT_LARGE_FILE_THRESHOLD_BYTES,
        category_thresholds: Optional[Dict[SmartCategory, int]] = None,
        top_n_limit: int = 20,
        reference_time: Optional[float] = None,
        developer_analyzer: Optional[DeveloperStorageAnalyzer] = None,
    ) -> None:
        if default_threshold_bytes < 0:
            raise ValueError("default_threshold_bytes cannot be negative.")
        if top_n_limit < 1:
            raise ValueError("top_n_limit must be at least 1.")

        self.default_threshold_bytes = default_threshold_bytes
        self.category_thresholds: Dict[SmartCategory, int] = category_thresholds or {}
        self.top_n_limit = top_n_limit
        self.reference_time = reference_time
        self.developer_analyzer = developer_analyzer or DeveloperStorageAnalyzer(
            reference_time=reference_time
        )

    def get_threshold_for_category(self, category: SmartCategory) -> int:
        """Return the effective size threshold for a given SmartCategory."""
        return self.category_thresholds.get(category, self.default_threshold_bytes)

    def analyze_scan_result(
        self,
        scan_result: ScanResult,
        limit: Optional[int] = None,
    ) -> LargeFileSummary:
        """
        Analyze all discovered items in a ScanResult.
        """
        return self.analyze_items(
            items=scan_result.items,
            total_scanned_bytes=scan_result.total_bytes,
            limit=limit,
        )

    def analyze_items(
        self,
        items: Sequence[DiscoveredItem],
        total_scanned_bytes: Optional[int] = None,
        limit: Optional[int] = None,
    ) -> LargeFileSummary:
        """
        Deterministically analyze, filter, rank, and summarize large storage consumers.
        """
        effective_limit = limit if limit is not None else self.top_n_limit
        if effective_limit < 1:
            effective_limit = self.top_n_limit

        # Step 1: Pre-filter items exceeding category/default threshold
        qualified_items: List[Tuple[DiscoveredItem, SmartCategory, ConfidenceLevel, int]] = []
        for item in items:
            category = item.category
            confidence = item.confidence or ConfidenceLevel.HIGH

            if category is None:
                cat_result = SmartCategorizer.categorize_path(item.path, item_type=item.item_type)
                category = cat_result.category
                confidence = cat_result.confidence

            threshold = self.get_threshold_for_category(category)
            if item.size_bytes >= threshold:
                qualified_items.append((item, category, confidence, threshold))

        if not qualified_items:
            return LargeFileSummary(
                total_logical_bytes=0,
                total_unique_bytes=0,
                total_findings_count=0,
                size_threshold_bytes=self.default_threshold_bytes,
                scanned_total_bytes=total_scanned_bytes,
                findings=[],
                top_findings=[],
                category_summaries=[],
                developer_summaries=[],
            )

        # Step 2: Establish parent/child containment among qualified candidates
        containment_map: Dict[str, Optional[str]] = self._resolve_containment(
            [item for item, _, _, _ in qualified_items]
        )

        # Step 3: Build unranked findings with attention scores, developer context, and rationale
        unranked_findings: List[LargeFileFinding] = []
        for item, category, confidence, threshold in qualified_items:
            parent_path = containment_map.get(item.path)
            is_contained = parent_path is not None

            # Extract developer context if applicable
            dev_subtype: Optional[DeveloperStorageSubtype] = None
            proj_name: Optional[str] = None
            proj_root: Optional[str] = None
            stale_status: Optional[StaleStatus] = None

            dev_finding = self.developer_analyzer.analyze_item(item)
            if dev_finding is not None:
                dev_subtype = dev_finding.subtype
                proj_name = dev_finding.project_name
                _, proj_root = self.developer_analyzer._infer_project_association(item.path)
                stale_status = dev_finding.stale_status
            elif item.mtime > 0:
                # Basic stale check even if not developer category
                stale_status, _ = self.developer_analyzer._evaluate_age(item.mtime)

            # Compute attention score (0.0 - 100.0)
            attention_score = self._calculate_attention_score(
                size_bytes=item.size_bytes,
                category=category,
                stale_status=stale_status,
                is_contained=is_contained,
                dev_subtype=dev_subtype,
            )

            # Calculate storage percentage if total scanned storage is known
            storage_pct: Optional[float] = None
            if total_scanned_bytes is not None and total_scanned_bytes > 0:
                storage_pct = round(min(100.0, (item.size_bytes / total_scanned_bytes) * 100.0), 2)

            # Build rationale
            rationale = self._generate_rationale(
                item=item,
                category=category,
                dev_subtype=dev_subtype,
                proj_name=proj_name,
                stale_status=stale_status,
                is_contained=is_contained,
                parent_path=parent_path,
            )

            # Create unranked finding (rank will be populated after deterministic sort)
            finding = LargeFileFinding(
                path=item.path,
                size_bytes=item.size_bytes,
                category=category,
                confidence=confidence,
                rank=1,  # placeholder
                size_threshold_bytes=threshold,
                storage_percentage=storage_pct,
                attention_score=attention_score,
                rationale=rationale,
                developer_subtype=dev_subtype,
                project_name=proj_name,
                project_root=proj_root,
                stale_status=stale_status,
                parent_candidate_path=parent_path,
                is_contained=is_contained,
                item_type=item.item_type,
                mtime=item.mtime if item.mtime > 0 else None,
            )
            unranked_findings.append(finding)

        # Step 4: Deterministic Sort (primary: size descending, secondary: canonical path ascending)
        unranked_findings.sort(key=lambda f: (-f.size_bytes, f.path))

        # Step 5: Assign stable 1-based ranks
        ranked_findings: List[LargeFileFinding] = []
        for idx, f in enumerate(unranked_findings, start=1):
            ranked_findings.append(f.model_copy(update={"rank": idx}))

        # Step 6: Compute totals and summaries
        total_logical_bytes = sum(f.size_bytes for f in ranked_findings)
        total_unique_bytes = self._calculate_unique_physical_bytes(ranked_findings)
        top_findings = ranked_findings[:effective_limit]

        category_summaries = self._build_category_summaries(ranked_findings, total_logical_bytes)
        developer_summaries = self._build_developer_summaries(ranked_findings)

        return LargeFileSummary(
            total_logical_bytes=total_logical_bytes,
            total_unique_bytes=total_unique_bytes,
            total_findings_count=len(ranked_findings),
            size_threshold_bytes=self.default_threshold_bytes,
            scanned_total_bytes=total_scanned_bytes,
            findings=ranked_findings,
            top_findings=top_findings,
            category_summaries=category_summaries,
            developer_summaries=developer_summaries,
        )

    def _resolve_containment(self, items: Sequence[DiscoveredItem]) -> Dict[str, Optional[str]]:
        """
        Determine hierarchical containment among candidates.
        Returns a mapping of candidate path -> enclosing parent candidate path (or None).
        """
        # Sort items by path depth ascending (parents first)
        sorted_items = sorted(
            items,
            key=lambda item: (len(PurePath(os.path.normpath(item.path)).parts), item.path),
        )

        containment_map: Dict[str, Optional[str]] = {}
        for i, child in enumerate(sorted_items):
            child_norm = os.path.normpath(child.path)
            parent_found: Optional[str] = None
            for j in range(i):
                potential_parent = sorted_items[j]
                if potential_parent.item_type != "file":
                    parent_norm = os.path.normpath(potential_parent.path)
                    if is_contained_within(child_norm, parent_norm):
                        parent_found = potential_parent.path
                        break
            containment_map[child.path] = parent_found

        return containment_map

    def _calculate_unique_physical_bytes(self, findings: Sequence[LargeFileFinding]) -> int:
        """
        Calculate unique physical storage by omitting items contained within other findings.
        """
        if not findings:
            return 0

        # Only root-level findings in this set contribute to unique physical bytes
        return sum(f.size_bytes for f in findings if not f.is_contained)

    def _calculate_attention_score(
        self,
        size_bytes: int,
        category: SmartCategory,
        stale_status: Optional[StaleStatus],
        is_contained: bool,
        dev_subtype: Optional[DeveloperStorageSubtype] = None,
    ) -> float:
        """
        Compute a deterministic attention score (0.0 to 100.0).

        This score reflects how beneficial it is for a user to inspect this item.
        It is NOT a risk score, safety score, or deletion authorization.
        """
        # Base score derived from storage magnitude
        if size_bytes >= 10 * 1024 * 1024 * 1024:  # >= 10 GB
            score = 85.0
        elif size_bytes >= 2 * 1024 * 1024 * 1024:  # >= 2 GB
            score = 70.0
        elif size_bytes >= 500 * 1024 * 1024:       # >= 500 MB
            score = 55.0
        elif size_bytes >= 100 * 1024 * 1024:       # >= 100 MB
            score = 40.0
        else:                                       # < 100 MB
            score = 25.0

        # Category context adjustment
        high_attention_categories = {
            SmartCategory.CACHES,
            SmartCategory.LOGS,
            SmartCategory.DEVELOPER_DATA,
            SmartCategory.VIRTUAL_ENVIRONMENTS,
            SmartCategory.BUILD_ARTIFACTS,
            SmartCategory.PACKAGE_MANAGERS,
            SmartCategory.CONTAINERS,
            SmartCategory.ML_AI_DATA,
            SmartCategory.ARCHIVES,
            SmartCategory.DISK_IMAGES,
            SmartCategory.TEMPORARY_DATA,
        }
        if category in high_attention_categories:
            score += 5.0
        elif category in (SmartCategory.SYSTEM_DATA, SmartCategory.DOCUMENTS, SmartCategory.USER_DATA):
            score -= 10.0

        # Staleness adjustment (older items may represent forgotten storage)
        if stale_status == StaleStatus.POTENTIALLY_STALE_180D:
            score += 10.0
        elif stale_status == StaleStatus.POTENTIALLY_STALE_90D:
            score += 5.0

        # Developer subtype nuance
        if dev_subtype in (
            DeveloperStorageSubtype.BUILD_OUTPUT,
            DeveloperStorageSubtype.PACKAGE_CACHE,
            DeveloperStorageSubtype.PYTHON_CACHE,
        ):
            score += 5.0

        # Contained items receive a slight attenuation since parent candidate is visible
        if is_contained:
            score -= 5.0

        return round(max(0.0, min(100.0, score)), 1)

    def _generate_rationale(
        self,
        item: DiscoveredItem,
        category: SmartCategory,
        dev_subtype: Optional[DeveloperStorageSubtype],
        proj_name: Optional[str],
        stale_status: Optional[StaleStatus],
        is_contained: bool,
        parent_path: Optional[str],
    ) -> str:
        """Generate a deterministic, human-readable rationale."""
        size_str = format_bytes(item.size_bytes)
        parts = [f"Large {category.value.lower().replace('_', ' ')} item ({size_str})."]

        if dev_subtype is not None:
            parts.append(f"Identified as developer subtype: {dev_subtype.value}.")

        if proj_name:
            parts.append(f"Associated with project '{proj_name}'.")

        if stale_status in (StaleStatus.POTENTIALLY_STALE_90D, StaleStatus.POTENTIALLY_STALE_180D):
            parts.append("Item is potentially stale based on modification timestamp.")

        if is_contained and parent_path:
            parts.append(f"Contained inside parent candidate: '{parent_path}'.")

        return " ".join(parts)

    def _build_category_summaries(
        self,
        findings: List[LargeFileFinding],
        total_logical_bytes: int,
    ) -> List[LargeFileCategorySummary]:
        """Group large file findings by SmartCategory."""
        grouped: Dict[SmartCategory, List[LargeFileFinding]] = {}
        for f in findings:
            grouped.setdefault(f.category, []).append(f)

        summaries: List[LargeFileCategorySummary] = []
        for cat, cat_findings in grouped.items():
            cat_logical = sum(f.size_bytes for f in cat_findings)
            cat_unique = self._calculate_unique_physical_bytes(cat_findings)
            pct = round((cat_logical / total_logical_bytes) * 100.0, 2) if total_logical_bytes > 0 else 0.0

            summaries.append(
                LargeFileCategorySummary(
                    category=cat,
                    total_logical_bytes=cat_logical,
                    unique_physical_bytes=cat_unique,
                    item_count=len(cat_findings),
                    percentage_of_large_storage=pct,
                )
            )

        # Sort category summaries by unique physical bytes descending, then category name
        summaries.sort(key=lambda s: (-s.unique_physical_bytes, s.category.value))
        return summaries

    def _build_developer_summaries(
        self,
        findings: List[LargeFileFinding],
    ) -> List[LargeFileDeveloperSummary]:
        """Group large file findings by DeveloperStorageSubtype."""
        grouped: Dict[DeveloperStorageSubtype, List[LargeFileFinding]] = {}
        for f in findings:
            if f.developer_subtype is not None:
                grouped.setdefault(f.developer_subtype, []).append(f)

        summaries: List[LargeFileDeveloperSummary] = []
        for subtype, sub_findings in grouped.items():
            sub_logical = sum(f.size_bytes for f in sub_findings)
            sub_unique = self._calculate_unique_physical_bytes(sub_findings)

            summaries.append(
                LargeFileDeveloperSummary(
                    subtype=subtype,
                    total_logical_bytes=sub_logical,
                    unique_physical_bytes=sub_unique,
                    item_count=len(sub_findings),
                )
            )

        # Sort developer summaries by unique physical bytes descending, then subtype name
        summaries.sort(key=lambda s: (-s.unique_physical_bytes, s.subtype.value))
        return summaries
