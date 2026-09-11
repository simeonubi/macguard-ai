"""
MacGuard AI v1.1 — Deterministic Developer Storage Analyzer.

This module provides deep diagnostic intelligence for developer tooling,
virtual environments, package caches, build outputs, and AI/ML model repositories.

DISCOVERY != CATEGORIZATION != ANALYSIS != AUTHORIZATION
This analyzer is strictly read-only and informational. It does not perform
filesystem mutations and possesses zero cleanup or execution authority.
"""

from __future__ import annotations

import os
import time
from pathlib import Path, PurePath
from typing import Dict, List, Optional, Sequence, Set, Tuple

from app.analysis.categorizer import SmartCategorizer
from app.models.category import ConfidenceLevel, SmartCategory
from app.models.developer import (
    DeveloperProjectSummary,
    DeveloperStorageFinding,
    DeveloperStorageGroup,
    DeveloperStorageSubtype,
    DeveloperStorageSummary,
    StaleStatus,
)
from app.models.scan_result import DiscoveredItem, ScanResult
from app.safety.canonicalizer import is_contained_within


# Known container root directory names that hold distinct project subdirectories
PROJECT_CONTAINER_NAMES = frozenset({
    "projects",
    "developer",
    "workspace",
    "workspaces",
    "repos",
    "repositories",
    "code",
    "src",
    "work",
    "dev",
})

# Subtype display titles
SUBTYPE_TITLES: Dict[DeveloperStorageSubtype, str] = {
    DeveloperStorageSubtype.PYTHON_VENV: "Python Virtual Environments",
    DeveloperStorageSubtype.NODE_MODULES: "Node.js Dependencies (node_modules)",
    DeveloperStorageSubtype.PYTHON_CACHE: "Python & Test Caches (__pycache__, pytest)",
    DeveloperStorageSubtype.BUILD_OUTPUT: "Build Artifacts & DerivedData",
    DeveloperStorageSubtype.PACKAGE_CACHE: "Package Manager Caches (npm, Cargo, pip, Gradle)",
    DeveloperStorageSubtype.CONTAINER_STORAGE: "Containers & Virtual Disks (Docker, VMs)",
    DeveloperStorageSubtype.ML_MODELS: "Machine Learning Models & Weights",
    DeveloperStorageSubtype.ML_DATASETS: "Machine Learning Datasets & Artifacts",
    DeveloperStorageSubtype.IDE_CACHE: "IDE & Editor Caches",
    DeveloperStorageSubtype.SOURCE_REPO: "Source Code & Repositories",
    DeveloperStorageSubtype.OTHER_DEVELOPER: "Other Developer Storage",
}


class DeveloperStorageAnalyzer:
    """
    Analyzes discovered filesystem items to produce structured developer storage intelligence.
    """

    def __init__(
        self,
        large_artifact_threshold_bytes: int = 100 * 1024 * 1024,  # 100 MiB
        stale_threshold_days: float = 90.0,
        reference_time: Optional[float] = None,
    ) -> None:
        self.large_artifact_threshold_bytes = max(0, large_artifact_threshold_bytes)
        self.stale_threshold_days = max(0.0, stale_threshold_days)
        self.reference_time = reference_time

    def analyze_scan_result(self, scan_result: ScanResult) -> DeveloperStorageSummary:
        """Analyze all discovered items in a ScanResult."""
        return self.analyze_items(scan_result.items)

    def analyze_items(self, items: Sequence[DiscoveredItem]) -> DeveloperStorageSummary:
        """
        Deterministically analyze and group developer storage items.
        """
        findings: List[DeveloperStorageFinding] = []

        for item in items:
            finding = self.analyze_item(item)
            if finding is not None:
                findings.append(finding)

        return self._build_summary(findings)

    def analyze_item(self, item: DiscoveredItem) -> Optional[DeveloperStorageFinding]:
        """
        Analyze a single DiscoveredItem. Returns DeveloperStorageFinding if it is developer-related,
        or None if the item is not associated with developer storage.
        """
        # Ensure category is populated
        category = item.category
        confidence = item.confidence or ConfidenceLevel.HIGH
        category_rule = item.category_rule or "rule:unknown"

        if category is None:
            cat_result = SmartCategorizer.categorize_path(item.path, item_type=item.item_type)
            category = cat_result.category
            confidence = cat_result.confidence
            category_rule = cat_result.matched_rule

        # Check if item qualifies as developer storage
        subtype, is_dev = self._infer_developer_subtype(item.path, category, item.item_type)
        if not is_dev:
            return None

        # Determine project association
        project_name, project_root = self._infer_project_association(item.path)

        # Evaluate age / stale status
        stale_status, age_days = self._evaluate_age(item.mtime)

        # Large artifact check
        is_large = item.size_bytes >= self.large_artifact_threshold_bytes

        # Generate human-readable evidence
        evidence = self._generate_evidence(item.path, subtype, project_name, is_large, stale_status)

        return DeveloperStorageFinding(
            path=item.path,
            subtype=subtype,
            category=category,
            size_bytes=item.size_bytes,
            item_type=item.item_type,
            depth=item.depth,
            mtime=item.mtime,
            stale_status=stale_status,
            age_days=age_days,
            project_name=project_name,
            confidence=confidence,
            confidence_score=0.95 if confidence == ConfidenceLevel.HIGH else 0.80,
            evidence=evidence,
            is_large=is_large,
            parent_path=item.parent_path,
        )

    def _infer_developer_subtype(
        self,
        path: str,
        category: SmartCategory,
        item_type: Optional[str],
    ) -> Tuple[DeveloperStorageSubtype, bool]:
        """
        Deterministically infer the DeveloperStorageSubtype from path structure and semantic category.
        """
        pure = PurePath(os.path.normpath(path))
        parts = [p.lower() for p in pure.parts]
        name = pure.name.lower()
        suffix = pure.suffix.lower()

        # 1. Python Virtual Environments
        if category == SmartCategory.VIRTUAL_ENVIRONMENTS or any(
            p in (".venv", "venv", "virtualenv", ".virtualenvs", "env", "envs") for p in parts
        ) or "pyvenv.cfg" in name or "conda-meta" in parts:
            return DeveloperStorageSubtype.PYTHON_VENV, True

        # 2. Node Dependencies
        if "node_modules" in parts:
            return DeveloperStorageSubtype.NODE_MODULES, True

        # 3. Python & Test Caches
        if any(p in ("__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", "htmlcov") for p in parts) or suffix in (".pyc", ".pyo"):
            return DeveloperStorageSubtype.PYTHON_CACHE, True

        # 4. Build Artifacts & Output
        if category == SmartCategory.BUILD_ARTIFACTS or "deriveddata" in parts or any(
            parts[i] == "target" and i < len(parts) - 1 and parts[i+1] in ("debug", "release", "doc") for i in range(len(parts)-1)
        ) or any(p in (".next", ".nuxt", ".webpack", ".parcel-cache", "build", "dist") for p in parts):
            return DeveloperStorageSubtype.BUILD_OUTPUT, True

        # 5. Package Manager Caches
        if category == SmartCategory.PACKAGE_MANAGERS or any(
            p in (".npm", ".cargo", ".gradle", ".m2", ".nuget", ".pub-cache", ".pnpm-store", "_cacache") for p in parts
        ) or (any(p == "pip" for p in parts) and any(c in parts for c in ("cache", "wheels"))):
            return DeveloperStorageSubtype.PACKAGE_CACHE, True

        # 6. Containers & Virtual Disks
        if category == SmartCategory.CONTAINERS or any(
            p in ("com.docker.docker", "orbstack", "podman", "virtualbox", "parallels") for p in parts
        ) or name in ("docker.raw", "docker.qcow2"):
            return DeveloperStorageSubtype.CONTAINER_STORAGE, True

        # 7. ML Models
        if category == SmartCategory.ML_AI_DATA or any(
            p in ("huggingface", "ollama", "torch", "transformers", "checkpoints", "models", "weights") for p in parts
        ) or suffix in (".safetensors", ".ckpt", ".onnx", ".gguf", ".bin", ".pt", ".pth"):
            return DeveloperStorageSubtype.ML_MODELS, True

        # 8. ML Datasets
        if any(p in ("datasets", "experiments", "runs", "wandb", "mlruns") for p in parts):
            return DeveloperStorageSubtype.ML_DATASETS, True

        # 9. IDE / Editor Caches
        if any(p in (".vscode", ".idea", ".fleet") for p in parts):
            return DeveloperStorageSubtype.IDE_CACHE, True

        # 10. Source Repositories & Developer Code
        if category == SmartCategory.DEVELOPER_DATA or any(
            p in (".git", ".svn", ".hg", "projects", "workspace", "developer", "src") for p in parts
        ):
            if any(p in (".git", ".svn", ".hg") for p in parts):
                return DeveloperStorageSubtype.SOURCE_REPO, True
            return DeveloperStorageSubtype.OTHER_DEVELOPER, True

        return DeveloperStorageSubtype.OTHER_DEVELOPER, False

    def _infer_project_association(self, path: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Deterministically infer the project name and root directory from the path.
        """
        pure = PurePath(os.path.normpath(path))
        parts = pure.parts
        parts_lower = [p.lower() for p in parts]

        # Case 1: Path is inside a standard project container (e.g. ~/Projects/<project_name>/...)
        for i, part in enumerate(parts_lower):
            if part in PROJECT_CONTAINER_NAMES and i < len(parts) - 1:
                project_name = parts[i + 1]
                project_root = str(PurePath(*parts[: i + 2]))
                return project_name, project_root

        # Case 2: Path contains a .git repository root
        for i, part in enumerate(parts_lower):
            if part == ".git" and i > 0:
                project_name = parts[i - 1]
                project_root = str(PurePath(*parts[:i]))
                return project_name, project_root

        return None, None

    def _evaluate_age(self, mtime: float) -> Tuple[StaleStatus, Optional[float]]:
        """
        Evaluate staleness based on file modification time.
        """
        if mtime <= 0:
            return StaleStatus.UNKNOWN, None

        current_time = self.reference_time if self.reference_time is not None else time.time()
        elapsed_seconds = max(0.0, current_time - mtime)
        age_days = round(elapsed_seconds / 86400.0, 1)

        if age_days <= 30.0:
            return StaleStatus.RECENT, age_days
        elif age_days <= 90.0:
            return StaleStatus.MODERATE, age_days
        elif age_days <= 180.0:
            return StaleStatus.POTENTIALLY_STALE_90D, age_days
        else:
            return StaleStatus.POTENTIALLY_STALE_180D, age_days

    def _generate_evidence(
        self,
        path: str,
        subtype: DeveloperStorageSubtype,
        project_name: Optional[str],
        is_large: bool,
        stale_status: StaleStatus,
    ) -> str:
        """Generate deterministic rationale for the finding."""
        title = SUBTYPE_TITLES.get(subtype, "Developer artifact")
        evidence_parts = [f"Detected {title}."]

        if project_name:
            evidence_parts.append(f"Associated with project '{project_name}'.")

        if is_large:
            evidence_parts.append("Exceeds large artifact threshold.")

        if stale_status in (StaleStatus.POTENTIALLY_STALE_90D, StaleStatus.POTENTIALLY_STALE_180D):
            evidence_parts.append("Item is potentially stale based on last modification date.")

        return " ".join(evidence_parts)

    def _calculate_unique_physical_bytes(
        self,
        findings: Sequence[DeveloperStorageFinding],
    ) -> int:
        """
        Deduplicate physical storage coverage so that nested sub-items are not double-counted.
        """
        if not findings:
            return 0

        # Sort findings by path depth ascending (parents first)
        sorted_findings = sorted(findings, key=lambda f: (len(PurePath(f.path).parts), f.path))

        top_level: List[DeveloperStorageFinding] = []
        for finding in sorted_findings:
            is_nested = False
            for parent in top_level:
                if parent.item_type != "file" and is_contained_within(finding.path, parent.path):
                    is_nested = True
                    break
            if not is_nested:
                top_level.append(finding)

        return sum(f.size_bytes for f in top_level)

    def _build_summary(
        self,
        findings: List[DeveloperStorageFinding],
    ) -> DeveloperStorageSummary:
        """
        Aggregate and build the final DeveloperStorageSummary.
        """
        # Sort all findings deterministically by size descending, then path
        findings.sort(key=lambda f: (-f.size_bytes, f.path))

        total_logical_bytes = sum(f.size_bytes for f in findings)
        total_unique_bytes = self._calculate_unique_physical_bytes(findings)
        total_findings_count = len(findings)

        # 1. Group by Subtype
        grouped_by_subtype: Dict[DeveloperStorageSubtype, List[DeveloperStorageFinding]] = {}
        for f in findings:
            grouped_by_subtype.setdefault(f.subtype, []).append(f)

        groups: List[DeveloperStorageGroup] = []
        for subtype, sub_findings in grouped_by_subtype.items():
            sub_logical = sum(f.size_bytes for f in sub_findings)
            sub_unique = self._calculate_unique_physical_bytes(sub_findings)
            stale_items = [
                f for f in sub_findings
                if f.stale_status in (StaleStatus.POTENTIALLY_STALE_90D, StaleStatus.POTENTIALLY_STALE_180D)
            ]
            groups.append(
                DeveloperStorageGroup(
                    subtype=subtype,
                    title=SUBTYPE_TITLES.get(subtype, subtype.value),
                    total_logical_bytes=sub_logical,
                    unique_physical_bytes=sub_unique,
                    item_count=len(sub_findings),
                    findings=sub_findings,
                    stale_item_count=len(stale_items),
                    stale_bytes=sum(f.size_bytes for f in stale_items),
                )
            )

        # Sort groups by unique physical bytes descending
        groups.sort(key=lambda g: (-g.unique_physical_bytes, g.title))

        # 2. Group by Project
        grouped_by_project: Dict[str, List[DeveloperStorageFinding]] = {}
        for f in findings:
            if f.project_name:
                grouped_by_project.setdefault(f.project_name, []).append(f)

        projects: List[DeveloperProjectSummary] = []
        for proj_name, proj_findings in grouped_by_project.items():
            proj_root = PurePath(proj_findings[0].path)
            # Find base project root from any finding's parent path
            for f in proj_findings:
                _, inferred_root = self._infer_project_association(f.path)
                if inferred_root:
                    proj_root = PurePath(inferred_root)
                    break

            proj_logical = sum(f.size_bytes for f in proj_findings)
            proj_unique = self._calculate_unique_physical_bytes(proj_findings)
            subtypes = sorted(list({f.subtype for f in proj_findings}))

            projects.append(
                DeveloperProjectSummary(
                    project_name=proj_name,
                    project_root=str(proj_root),
                    total_bytes=proj_logical,
                    unique_physical_bytes=proj_unique,
                    subtypes=subtypes,
                    findings_count=len(proj_findings),
                )
            )

        # Sort projects by unique physical bytes descending
        projects.sort(key=lambda p: (-p.unique_physical_bytes, p.project_name))

        # 3. Filter Large Artifacts & Stale Findings
        large_artifacts = [f for f in findings if f.is_large]
        stale_findings = [
            f for f in findings
            if f.stale_status in (StaleStatus.POTENTIALLY_STALE_90D, StaleStatus.POTENTIALLY_STALE_180D)
        ]

        return DeveloperStorageSummary(
            total_logical_bytes=total_logical_bytes,
            total_unique_bytes=total_unique_bytes,
            total_findings_count=total_findings_count,
            groups=groups,
            projects=projects,
            large_artifacts=large_artifacts,
            stale_findings=stale_findings,
        )
