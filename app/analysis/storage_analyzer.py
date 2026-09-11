from __future__ import annotations

from typing import Optional, Sequence

from app.analysis.models import RiskLevel, StorageCandidate, StorageCategory
from app.analysis.rules import classify_path
from app.tools.storage_scanner import StorageItem


class StorageAnalyzer:
    """
    Deterministic Storage Intelligence Analyzer.

    Converts raw StorageScanner items and filesystem paths into structured,
    strongly typed StorageCandidate models with semantic categories,
    conservative risk evaluations, and advisory recommendations.

    This analyzer is strictly READ-ONLY and performs zero filesystem mutations.
    """

    def analyze_path(
        self,
        path: str,
        size_bytes: int = 0,
        item_type: Optional[str] = None,
    ) -> StorageCandidate:
        """
        Analyze a single path and return a structured StorageCandidate.
        """
        category, risk_level, confidence, reason, recommendation = classify_path(
            path=path,
            item_type=item_type,
        )

        return StorageCandidate(
            path=path,
            size_bytes=size_bytes,
            category=category,
            risk_level=risk_level,
            confidence=confidence,
            reason=reason,
            recommendation=recommendation,
            item_type=item_type,
        )

    def analyze_item(self, item: StorageItem) -> StorageCandidate:
        """
        Analyze a StorageItem discovered by StorageScanner.
        """
        return self.analyze_path(
            path=item.path,
            size_bytes=item.size_bytes,
            item_type=item.item_type,
        )

    def analyze_items(
        self,
        items: list[StorageItem],
        deduplicate: bool = False,
    ) -> list[StorageCandidate]:
        """
        Analyze a collection of StorageItems discovered by StorageScanner.
        Optionally applies deterministic hierarchical deduplication.
        """
        candidates = [self.analyze_item(item) for item in items]
        if deduplicate:
            return self.deduplicate_candidates(candidates)
        return candidates

    def deduplicate_candidates(
        self,
        candidates: Sequence[StorageCandidate],
    ) -> list[StorageCandidate]:
        """
        Deterministically deduplicate a collection of StorageCandidate objects by resolving
        hierarchical parent-descendant overlaps.

        Rules:
        1. If candidate A is a directory and candidate B is located strictly inside candidate A:
           - If candidate A is eligible for cleanup review (e.g. LOW risk CACHE/LOGS), candidate A
             encompasses candidate B. Candidate B is subsumed to prevent double-counting storage
             and duplicate/conflicting cleanup actions.
           - If candidate A and candidate B share the same risk level (e.g. both HIGH or both MEDIUM),
             candidate A represents the subtree and subsumes candidate B.
           - If candidate A is blocked / high risk (e.g. non-cleanable user documents or system root),
             but candidate B is an independently identified cleanable item (e.g. LOW risk), candidate B
             is NOT subsumed by the non-cleanable parent.
        2. Independent sibling paths, disjoint paths, and non-overlapping files are preserved.
        3. Deterministic ordering is preserved (sorted by size descending, then path).
        """
        if not candidates:
            return []

        from pathlib import Path
        from app.safety.canonicalizer import canonicalize_path, is_contained_within

        # Map each candidate to its canonical path
        resolved_candidates: list[tuple[Path, StorageCandidate]] = []
        for cand in candidates:
            try:
                canon = canonicalize_path(cand.path).canonical_path
            except Exception:
                canon = Path(cand.path).expanduser().resolve()
            resolved_candidates.append((canon, cand))

        # Sort candidates by path component length ascending so higher-level parents are evaluated first
        resolved_candidates.sort(key=lambda item: (len(item[0].parts), str(item[0])))

        retained: list[tuple[Path, StorageCandidate]] = []

        for path, cand in resolved_candidates:
            subsumed = False
            for parent_path, parent_cand in retained:
                # Parent candidate must be a directory (or not explicitly a file)
                if parent_cand.item_type != "file":
                    if is_contained_within(path, parent_path):
                        parent_is_cleanable = (parent_cand.risk_level == RiskLevel.LOW)
                        same_risk = (parent_cand.risk_level == cand.risk_level)

                        if parent_is_cleanable or same_risk:
                            subsumed = True
                            break

            if not subsumed:
                retained.append((path, cand))

        result = [cand for _, cand in retained]
        result.sort(key=lambda c: (-c.size_bytes, c.path))
        return result

    def calculate_physical_coverage_bytes(
        self,
        candidates: Sequence[StorageCandidate],
    ) -> int:
        """
        Calculate the unique physical storage footprint spanned by a candidate collection.
        Resolves physical containment so that nested files/directories inside parent
        directories are not double-counted.
        """
        if not candidates:
            return 0

        from pathlib import Path
        from app.safety.canonicalizer import canonicalize_path, is_contained_within

        resolved: list[tuple[Path, StorageCandidate]] = []
        for cand in candidates:
            try:
                canon = canonicalize_path(cand.path).canonical_path
            except Exception:
                canon = Path(cand.path).expanduser().resolve()
            resolved.append((canon, cand))

        # Sort by path depth ascending (parents first)
        resolved.sort(key=lambda item: (len(item[0].parts), str(item[0])))

        top_level: list[tuple[Path, StorageCandidate]] = []
        for path, cand in resolved:
            is_sub = False
            for parent_path, parent_cand in top_level:
                if parent_cand.item_type != "file" and is_contained_within(path, parent_path):
                    is_sub = True
                    break
            if not is_sub:
                top_level.append((path, cand))

        return sum(c.size_bytes for _, c in top_level)

    def calculate_reclaimable_bytes(
        self,
        candidates: Sequence[StorageCandidate],
    ) -> int:
        """
        Calculate the unique storage represented exclusively by candidates that are
        eligible for cleanup review (LOW risk). Blocked or high-risk parents do NOT
        inflate this total.
        """
        low_risk_candidates = [c for c in candidates if c.risk_level == RiskLevel.LOW]
        return self.calculate_physical_coverage_bytes(low_risk_candidates)

    def summarize_accounting(
        self,
        candidates: Sequence[StorageCandidate],
    ) -> dict[str, int]:
        """
        Return a comprehensive, disambiguated accounting breakdown:
        - total_physical_bytes: Physical disk space covered by candidate tree
        - reclaimable_bytes: Storage eligible for cleanup review (LOW risk)
        - manual_review_bytes: Storage requiring caution / manual inspection (MEDIUM risk)
        - blocked_bytes: Storage in protected system/user locations (HIGH risk)
        - unknown_bytes: Storage in unclassified locations (UNKNOWN risk)
        """
        return {
            "total_physical_bytes": self.calculate_physical_coverage_bytes(candidates),
            "reclaimable_bytes": self.calculate_reclaimable_bytes(candidates),
            "manual_review_bytes": sum(c.size_bytes for c in candidates if c.risk_level == RiskLevel.MEDIUM),
            "blocked_bytes": sum(c.size_bytes for c in candidates if c.risk_level == RiskLevel.HIGH),
            "unknown_bytes": sum(c.size_bytes for c in candidates if c.risk_level == RiskLevel.UNKNOWN),
        }

    def summarize_by_category(
        self,
        candidates: list[StorageCandidate],
    ) -> dict[StorageCategory, int]:
        """
        Aggregate total storage bytes grouped by StorageCategory.
        """
        summary: dict[StorageCategory, int] = {cat: 0 for cat in StorageCategory}
        for candidate in candidates:
            summary[candidate.category] += candidate.size_bytes
        return summary

    def summarize_by_risk(
        self,
        candidates: list[StorageCandidate],
    ) -> dict[RiskLevel, int]:
        """
        Aggregate total storage bytes grouped by RiskLevel.
        """
        summary: dict[RiskLevel, int] = {risk: 0 for risk in RiskLevel}
        for candidate in candidates:
            summary[candidate.risk_level] += candidate.size_bytes
        return summary


