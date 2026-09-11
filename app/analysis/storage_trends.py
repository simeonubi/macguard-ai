"""
MacGuard AI v1.1 — Deterministic Storage Trends Engine.

This module computes explainable, mathematically rigorous comparisons between
historical storage snapshots without performing any filesystem operations or
granting cleanup authority.

DISCOVERY != CATEGORIZATION != ANALYSIS != AUTHORIZATION
Trend analysis is strictly observational and analytics-driven.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from app.models.category import SmartCategory
from app.models.developer import DeveloperStorageSubtype
from app.models.scan_result import ScanStatus
from app.models.storage_history import (
    CategoryTrend,
    DeveloperTrend,
    StorageSnapshot,
    StorageTrend,
    StorageTrendReport,
    TrendDirection,
)
from app.tools.storage_scanner import format_bytes

DEFAULT_STABLE_THRESHOLD_PERCENT: float = 5.0


class StorageTrendsEngine:
    """
    Deterministic analytics engine for computing storage deltas, category growth velocity,
    and developer tooling trends over time.
    """

    def __init__(self, stable_threshold_percent: float = DEFAULT_STABLE_THRESHOLD_PERCENT) -> None:
        if stable_threshold_percent < 0.0:
            raise ValueError("stable_threshold_percent cannot be negative.")
        self.stable_threshold_percent = stable_threshold_percent

    def compare_snapshots(
        self,
        current: StorageSnapshot,
        previous: Optional[StorageSnapshot],
        stable_threshold_percent: Optional[float] = None,
    ) -> StorageTrendReport:
        """
        Compare two historical storage snapshots and generate a deterministic StorageTrendReport.
        """
        threshold = (
            stable_threshold_percent
            if stable_threshold_percent is not None
            else self.stable_threshold_percent
        )
        if threshold < 0.0:
            raise ValueError("stable_threshold_percent cannot be negative.")

        notes: List[str] = []

        # Case 1: First Scan (No Baseline Snapshot Available)
        if previous is None:
            return StorageTrendReport(
                scope_id=current.scope_id,
                root_path=current.root_path,
                current_snapshot_id=current.snapshot_id,
                previous_snapshot_id=None,
                current_timestamp=current.timestamp,
                previous_timestamp=None,
                is_comparable=False,
                overall_trend=StorageTrend(
                    metric="Total Storage",
                    current_value=current.total_bytes,
                    previous_value=0,
                    absolute_change=0,
                    percentage_change=None,
                    direction=TrendDirection.UNKNOWN,
                    explanation="Trend unavailable — this is the first recorded scan for this scope.",
                ),
                category_trends=[],
                developer_trends=[],
                largest_growing_category=None,
                largest_growing_developer_subtype=None,
                notes=["First recorded scan for this scope. Trend baselines will be established on subsequent scans."],
            )

        # Case 2: Incompatible Scopes or Roots
        if current.scope_id != previous.scope_id or current.root_path != previous.root_path:
            return StorageTrendReport(
                scope_id=current.scope_id,
                root_path=current.root_path,
                current_snapshot_id=current.snapshot_id,
                previous_snapshot_id=previous.snapshot_id,
                current_timestamp=current.timestamp,
                previous_timestamp=previous.timestamp,
                is_comparable=False,
                overall_trend=StorageTrend(
                    metric="Total Storage",
                    current_value=current.total_bytes,
                    previous_value=previous.total_bytes,
                    absolute_change=current.total_bytes - previous.total_bytes,
                    percentage_change=None,
                    direction=TrendDirection.UNKNOWN,
                    explanation="Snapshots are not comparable because scan scope or root directory differs.",
                ),
                category_trends=[],
                developer_trends=[],
                largest_growing_category=None,
                largest_growing_developer_subtype=None,
                notes=[
                    f"Incompatible scan comparison: '{current.scope_id.value}' ({current.root_path}) vs '{previous.scope_id.value}' ({previous.root_path})."
                ],
            )

        # Case 3: Incomplete / Partial Scan Warnings
        if current.status != ScanStatus.COMPLETED or previous.status != ScanStatus.COMPLETED:
            notes.append(
                f"Warning: One or both scans were not fully completed (Current: {current.status.value}, Previous: {previous.status.value}). Trend values may reflect partial scan coverage."
            )

        # 1. Compute Overall Volume Trend
        overall_trend = self._compute_metric_trend(
            metric_name="Total Storage",
            current_bytes=current.total_bytes,
            previous_bytes=previous.total_bytes,
            threshold_pct=threshold,
        )

        # 2. Compute Category Trends
        category_trends, largest_growing_cat = self._compute_category_trends(
            current=current,
            previous=previous,
            threshold_pct=threshold,
        )

        # 3. Compute Developer Subtype Trends
        developer_trends, largest_growing_dev = self._compute_developer_trends(
            current=current,
            previous=previous,
            threshold_pct=threshold,
        )

        return StorageTrendReport(
            scope_id=current.scope_id,
            root_path=current.root_path,
            current_snapshot_id=current.snapshot_id,
            previous_snapshot_id=previous.snapshot_id,
            current_timestamp=current.timestamp,
            previous_timestamp=previous.timestamp,
            is_comparable=True,
            overall_trend=overall_trend,
            category_trends=category_trends,
            developer_trends=developer_trends,
            largest_growing_category=largest_growing_cat,
            largest_growing_developer_subtype=largest_growing_dev,
            notes=notes,
        )

    def _compute_metric_trend(
        self,
        metric_name: str,
        current_bytes: int,
        previous_bytes: int,
        threshold_pct: float,
    ) -> StorageTrend:
        """Compute delta, percentage, direction, and explanation for an individual metric."""
        abs_change = current_bytes - previous_bytes

        pct_change: Optional[float] = None
        if previous_bytes > 0:
            pct_change = round((abs_change / previous_bytes) * 100.0, 2)
        elif current_bytes > 0:
            pct_change = 100.0
        else:
            pct_change = 0.0

        direction = self._classify_direction(pct_change, threshold_pct)
        explanation = self._build_explanation(metric_name, abs_change, pct_change, direction)

        return StorageTrend(
            metric=metric_name,
            current_value=current_bytes,
            previous_value=previous_bytes,
            absolute_change=abs_change,
            percentage_change=pct_change,
            direction=direction,
            explanation=explanation,
        )

    def _compute_category_trends(
        self,
        current: StorageSnapshot,
        previous: StorageSnapshot,
        threshold_pct: float,
    ) -> Tuple[List[CategoryTrend], Optional[SmartCategory]]:
        """Compute trends across all SmartCategories."""
        curr_map = {c.category: c for c in current.categories}
        prev_map = {c.category: c for c in previous.categories}
        all_categories = sorted(list(set(curr_map.keys()) | set(prev_map.keys())), key=lambda c: c.value)

        trends: List[CategoryTrend] = []
        for cat in all_categories:
            curr_item = curr_map.get(cat)
            prev_item = prev_map.get(cat)

            curr_bytes = curr_item.total_bytes if curr_item else 0
            prev_bytes = prev_item.total_bytes if prev_item else 0
            curr_count = curr_item.item_count if curr_item else 0
            prev_count = prev_item.item_count if prev_item else 0

            abs_change = curr_bytes - prev_bytes
            pct_change: Optional[float] = None
            if prev_bytes > 0:
                pct_change = round((abs_change / prev_bytes) * 100.0, 2)
            elif curr_bytes > 0:
                pct_change = 100.0
            else:
                pct_change = 0.0

            direction = self._classify_direction(pct_change, threshold_pct)
            cat_title = cat.value.replace("_", " ").title()
            explanation = self._build_explanation(cat_title, abs_change, pct_change, direction)

            trends.append(
                CategoryTrend(
                    category=cat,
                    current_bytes=curr_bytes,
                    previous_bytes=prev_bytes,
                    absolute_change=abs_change,
                    percentage_change=pct_change,
                    direction=direction,
                    current_item_count=curr_count,
                    previous_item_count=prev_count,
                    explanation=explanation,
                )
            )

        # Sort category trends by largest absolute increase descending, then category name
        trends.sort(key=lambda t: (-t.absolute_change, t.category.value))

        # Find category with largest positive growth
        largest_growth_cat = None
        growing = [t for t in trends if t.absolute_change > 0]
        if growing:
            largest_growth_cat = growing[0].category

        return trends, largest_growth_cat

    def _compute_developer_trends(
        self,
        current: StorageSnapshot,
        previous: StorageSnapshot,
        threshold_pct: float,
    ) -> Tuple[List[DeveloperTrend], Optional[DeveloperStorageSubtype]]:
        """Compute trends across all DeveloperStorageSubtypes."""
        curr_map = {d.subtype: d for d in current.developer_subtypes}
        prev_map = {d.subtype: d for d in previous.developer_subtypes}
        all_subtypes = sorted(list(set(curr_map.keys()) | set(prev_map.keys())), key=lambda s: s.value)

        trends: List[DeveloperTrend] = []
        for subtype in all_subtypes:
            curr_item = curr_map.get(subtype)
            prev_item = prev_map.get(subtype)

            curr_bytes = curr_item.total_bytes if curr_item else 0
            prev_bytes = prev_item.total_bytes if prev_item else 0

            abs_change = curr_bytes - prev_bytes
            pct_change: Optional[float] = None
            if prev_bytes > 0:
                pct_change = round((abs_change / prev_bytes) * 100.0, 2)
            elif curr_bytes > 0:
                pct_change = 100.0
            else:
                pct_change = 0.0

            direction = self._classify_direction(pct_change, threshold_pct)
            sub_title = subtype.value.replace("_", " ").title()
            explanation = self._build_explanation(sub_title, abs_change, pct_change, direction)

            trends.append(
                DeveloperTrend(
                    subtype=subtype,
                    current_bytes=curr_bytes,
                    previous_bytes=prev_bytes,
                    absolute_change=abs_change,
                    percentage_change=pct_change,
                    direction=direction,
                    explanation=explanation,
                )
            )

        # Sort developer trends by largest absolute increase descending, then subtype name
        trends.sort(key=lambda t: (-t.absolute_change, t.subtype.value))

        # Find subtype with largest positive growth
        largest_growth_dev = None
        growing = [t for t in trends if t.absolute_change > 0]
        if growing:
            largest_growth_dev = growing[0].subtype

        return trends, largest_growth_dev

    def _classify_direction(
        self,
        pct_change: Optional[float],
        threshold_pct: float,
    ) -> TrendDirection:
        """Classify trend direction based on percentage threshold."""
        if pct_change is None:
            return TrendDirection.UNKNOWN
        if pct_change > threshold_pct:
            return TrendDirection.GROWING
        elif pct_change < -threshold_pct:
            return TrendDirection.SHRINKING
        else:
            return TrendDirection.STABLE

    def _build_explanation(
        self,
        metric_name: str,
        abs_change: int,
        pct_change: Optional[float],
        direction: TrendDirection,
    ) -> str:
        """Build an explainable, deterministic natural language string."""
        abs_str = format_bytes(abs(abs_change))
        if direction == TrendDirection.GROWING:
            pct_str = f"+{pct_change:.2f}%" if pct_change is not None else ""
            return f"{metric_name} increased by {abs_str} ({pct_str}) since the previous scan."
        elif direction == TrendDirection.SHRINKING:
            pct_str = f"{pct_change:.2f}%" if pct_change is not None else ""
            return f"{metric_name} decreased by {abs_str} ({pct_str}) since the previous scan."
        elif direction == TrendDirection.STABLE:
            pct_str = f"{pct_change:.2f}%" if pct_change is not None else "0.00%"
            return f"{metric_name} remained stable ({pct_str} change)."
        else:
            return f"{metric_name} trend is undetermined."
