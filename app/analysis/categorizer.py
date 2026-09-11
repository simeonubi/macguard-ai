"""
MacGuard AI v1.1 — Deterministic Smart Storage Categorizer & Category Registry.

This module provides deterministic rule-based semantic categorization for discovered
filesystem items.

DISCOVERY != CATEGORIZATION != AUTHORIZATION
Categorization is strictly informational and read-only. It possesses zero execution,
approval, or deletion authority.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import PurePath
from typing import Callable, List, Optional, Sequence, Tuple

from app.models.category import CategoryResult, ConfidenceLevel, SmartCategory
from app.models.scan_result import DiscoveredItem


# Extension Sets
MEDIA_IMAGE_EXTENSIONS = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".webp",
    ".heic", ".heif", ".svg", ".raw", ".cr2", ".nef", ".arw", ".psd",
})

MEDIA_VIDEO_EXTENSIONS = frozenset({
    ".mov", ".mp4", ".m4v", ".mkv", ".avi", ".wmv", ".flv", ".webm",
    ".mpg", ".mpeg", ".3gp",
})

MEDIA_AUDIO_EXTENSIONS = frozenset({
    ".mp3", ".wav", ".aac", ".flac", ".m4a", ".ogg", ".aiff", ".alac", ".wma",
})

DOCUMENT_EXTENSIONS = frozenset({
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".rtf", ".pages", ".numbers", ".key", ".csv", ".tsv",
    ".odt", ".ods", ".odp", ".md", ".tex", ".epub",
})

ARCHIVE_EXTENSIONS = frozenset({
    ".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tbz", ".tar.xz", ".7z",
    ".rar", ".pkg", ".tar", ".gz", ".bz2", ".xz",
})

DISK_IMAGE_EXTENSIONS = frozenset({
    ".dmg", ".iso", ".sparseimage", ".sparsebundle", ".img", ".vmdk", ".qcow2",
})

LOG_EXTENSIONS = frozenset({
    ".log", ".crash", ".diag", ".ips", ".asl", ".out",
})

ML_MODEL_EXTENSIONS = frozenset({
    ".safetensors", ".ckpt", ".onnx", ".gguf", ".bin", ".pt", ".pth", ".h5", ".tflite",
})

SOURCE_CODE_EXTENSIONS = frozenset({
    ".py", ".rs", ".swift", ".go", ".cpp", ".c", ".h", ".hpp",
    ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".rb", ".php",
    ".sh", ".zsh", ".yaml", ".yml", ".toml", ".json", ".xml",
})


@dataclass(frozen=True)
class CategoryRule:
    """
    Represents a single deterministic categorization rule with precedence weighting.
    """

    rule_id: str
    category: SmartCategory
    confidence: ConfidenceLevel
    confidence_score: float
    priority: int
    description: str
    matcher: Callable[[PurePath, list[str], str, str, Optional[str]], bool]


class CategoryRegistry:
    """
    Extensible deterministic registry of category rules sorted by precedence priority.
    """

    def __init__(self) -> None:
        self._rules: List[CategoryRule] = []
        self._register_default_rules()

    def register_rule(self, rule: CategoryRule) -> None:
        """Register a custom categorization rule and maintain descending priority order."""
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority, reverse=True)

    def categorize_path(
        self,
        path: str,
        item_type: Optional[str] = None,
    ) -> CategoryResult:
        """
        Classify a filesystem path deterministically without reading file bytes.
        """
        normalized_path = os.path.normpath(path)
        pure_path = PurePath(normalized_path)
        parts = [p.lower() for p in pure_path.parts]
        filename = pure_path.name.lower()
        suffix = pure_path.suffix.lower()

        for rule in self._rules:
            try:
                if rule.matcher(pure_path, parts, filename, suffix, item_type):
                    return CategoryResult(
                        category=rule.category,
                        confidence=rule.confidence,
                        confidence_score=rule.confidence_score,
                        matched_rule=rule.rule_id,
                        rationale=rule.description,
                    )
            except Exception:
                continue

        return CategoryResult(
            category=SmartCategory.UNKNOWN,
            confidence=ConfidenceLevel.UNKNOWN,
            confidence_score=0.0,
            matched_rule="rule:unknown_fallback",
            rationale="Unclassified filesystem item. Path does not match any recognized deterministic category rule.",
        )

    def categorize_item(self, item: DiscoveredItem) -> CategoryResult:
        """Classify a DiscoveredItem instance."""
        return self.categorize_path(item.path, item_type=item.item_type)

    def attach_category(self, item: DiscoveredItem) -> DiscoveredItem:
        """Return a new DiscoveredItem populated with category intelligence."""
        result = self.categorize_item(item)
        return DiscoveredItem(
            path=item.path,
            size_bytes=item.size_bytes,
            item_type=item.item_type,
            depth=item.depth,
            mtime=item.mtime,
            st_ino=item.st_ino,
            st_dev=item.st_dev,
            is_symlink=item.is_symlink,
            parent_path=item.parent_path,
            category=result.category,
            confidence=result.confidence,
            category_rule=result.matched_rule,
        )

    def _register_default_rules(self) -> None:
        """Initialize standard MacGuard v1.1 deterministic classification rules."""

        # Priority 95: Virtual Environments
        self.register_rule(
            CategoryRule(
                rule_id="rule:virtual_environments",
                category=SmartCategory.VIRTUAL_ENVIRONMENTS,
                confidence=ConfidenceLevel.HIGH,
                confidence_score=0.95,
                priority=95,
                description="Detected Python or virtual environment directory.",
                matcher=lambda p, parts, name, ext, itype: any(
                    part in (".venv", "venv", "virtualenv", ".virtualenvs", "env", "envs")
                    for part in parts
                ) or "pyvenv.cfg" in name or "conda-meta" in parts or "site-packages" in parts,
            )
        )

        # Priority 90: Build Artifacts & DerivedData
        self.register_rule(
            CategoryRule(
                rule_id="rule:build_artifacts",
                category=SmartCategory.BUILD_ARTIFACTS,
                confidence=ConfidenceLevel.HIGH,
                confidence_score=0.95,
                priority=90,
                description="Detected compiler, bundler, or test build artifact location.",
                matcher=lambda p, parts, name, ext, itype: (
                    "deriveddata" in parts
                    or any(part in ("__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", "htmlcov") for part in parts)
                    or any(parts[i] == "target" and i < len(parts) - 1 and parts[i+1] in ("debug", "release", "doc") for i in range(len(parts) - 1))
                    or any(part in (".next", ".nuxt", ".webpack", ".parcel-cache") for part in parts)
                    or (any(part in ("build", "dist", "out") for part in parts) and any(parent in ("projects", "workspace", "developer", "src") for parent in parts))
                ),
            )
        )

        # Priority 88: Package Managers
        self.register_rule(
            CategoryRule(
                rule_id="rule:package_managers",
                category=SmartCategory.PACKAGE_MANAGERS,
                confidence=ConfidenceLevel.HIGH,
                confidence_score=0.95,
                priority=88,
                description="Detected package manager cache or dependency repository.",
                matcher=lambda p, parts, name, ext, itype: (
                    "node_modules" in parts
                    or "_cacache" in parts
                    or any(part in (".npm", ".cargo", ".gradle", ".m2", ".nuget", ".pub-cache", ".pnpm-store") for part in parts)
                    or (any(part == "pip" for part in parts) and any(c in parts for c in ("cache", "wheels")))
                ),
            )
        )

        # Priority 85: ML/AI Data & Models
        self.register_rule(
            CategoryRule(
                rule_id="rule:ml_ai_data",
                category=SmartCategory.ML_AI_DATA,
                confidence=ConfidenceLevel.HIGH,
                confidence_score=0.90,
                priority=85,
                description="Detected machine learning model cache, weights, or dataset repository.",
                matcher=lambda p, parts, name, ext, itype: (
                    any(part in ("huggingface", "ollama", "torch", "transformers", "checkpoints") for part in parts)
                    or any(part in ("models", "weights", "datasets") for part in parts)
                    or ext in ML_MODEL_EXTENSIONS
                ),
            )
        )

        # Priority 82: Containers & Virtual Disks
        self.register_rule(
            CategoryRule(
                rule_id="rule:containers",
                category=SmartCategory.CONTAINERS,
                confidence=ConfidenceLevel.HIGH,
                confidence_score=0.90,
                priority=82,
                description="Detected container engine or virtual machine disk image.",
                matcher=lambda p, parts, name, ext, itype: (
                    any(p in parts for p in ("com.docker.docker", "orbstack", "podman", "virtualbox", "parallels", "vmware"))
                    or name in ("docker.raw", "docker.qcow2")
                ),
            )
        )

        # Priority 80: Caches
        self.register_rule(
            CategoryRule(
                rule_id="rule:caches",
                category=SmartCategory.CACHES,
                confidence=ConfidenceLevel.HIGH,
                confidence_score=0.95,
                priority=80,
                description="Located within macOS user or application Caches directory.",
                matcher=lambda p, parts, name, ext, itype: (
                    any("library" == parts[i] and "caches" == parts[i+1] for i in range(len(parts)-1))
                    or any(part in (".cache", "caches", "cache") for part in parts)
                    or ext in (".cache", ".cached")
                ),
            )
        )

        # Priority 75: Logs
        self.register_rule(
            CategoryRule(
                rule_id="rule:logs",
                category=SmartCategory.LOGS,
                confidence=ConfidenceLevel.HIGH,
                confidence_score=0.90,
                priority=75,
                description="Located in system/application logs location or log file extension.",
                matcher=lambda p, parts, name, ext, itype: (
                    ext in LOG_EXTENSIONS
                    or name.endswith(".log.gz")
                    or name.endswith(".log.1")
                    or any("library" == parts[i] and "logs" == parts[i+1] for i in range(len(parts)-1))
                    or any(part in ("logs", "log") for part in parts)
                ),
            )
        )

        # Priority 70: Temporary Data
        self.register_rule(
            CategoryRule(
                rule_id="rule:temporary_data",
                category=SmartCategory.TEMPORARY_DATA,
                confidence=ConfidenceLevel.HIGH,
                confidence_score=0.90,
                priority=70,
                description="Located in temporary storage directory or temporary file extension.",
                matcher=lambda p, parts, name, ext, itype: (
                    any(part in ("tmp", "temp", ".trash") for part in parts)
                    or ext in (".tmp", ".temp", ".bak", ".swp", ".swo")
                ),
            )
        )

        # Priority 65: Disk Images
        self.register_rule(
            CategoryRule(
                rule_id="rule:disk_images",
                category=SmartCategory.DISK_IMAGES,
                confidence=ConfidenceLevel.HIGH,
                confidence_score=0.90,
                priority=65,
                description="Disk image or mountable filesystem archive.",
                matcher=lambda p, parts, name, ext, itype: ext in DISK_IMAGE_EXTENSIONS,
            )
        )

        # Priority 60: Archives
        self.register_rule(
            CategoryRule(
                rule_id="rule:archives",
                category=SmartCategory.ARCHIVES,
                confidence=ConfidenceLevel.HIGH,
                confidence_score=0.90,
                priority=60,
                description="Compressed archive or software distribution package.",
                matcher=lambda p, parts, name, ext, itype: (
                    ext in ARCHIVE_EXTENSIONS
                    or name.endswith(".tar.gz")
                    or name.endswith(".tar.bz2")
                    or name.endswith(".tar.xz")
                ),
            )
        )

        # Priority 55: Applications
        self.register_rule(
            CategoryRule(
                rule_id="rule:applications",
                category=SmartCategory.APPLICATIONS,
                confidence=ConfidenceLevel.HIGH,
                confidence_score=0.95,
                priority=55,
                description="macOS application bundle or Applications directory.",
                matcher=lambda p, parts, name, ext, itype: (
                    ext == ".app"
                    or any(part == "applications" for part in parts)
                ),
            )
        )

        # Priority 50: Developer Data / Source Projects
        self.register_rule(
            CategoryRule(
                rule_id="rule:developer_data",
                category=SmartCategory.DEVELOPER_DATA,
                confidence=ConfidenceLevel.HIGH,
                confidence_score=0.90,
                priority=50,
                description="Developer workspace, source code repository, or project source file.",
                matcher=lambda p, parts, name, ext, itype: (
                    any(part in (".git", ".svn", ".hg", "projects", "workspace", "developer", "src") for part in parts)
                    or ext in SOURCE_CODE_EXTENSIONS
                    or name in ("cargo.toml", "pyproject.toml", "package.json", "go.mod", "cmakelists.txt", "makefile")
                ),
            )
        )

        # Priority 45: Pictures / Images
        self.register_rule(
            CategoryRule(
                rule_id="rule:pictures",
                category=SmartCategory.PICTURES,
                confidence=ConfidenceLevel.HIGH,
                confidence_score=0.95,
                priority=45,
                description="User picture or image asset.",
                matcher=lambda p, parts, name, ext, itype: (
                    any(part in ("pictures", "photos") for part in parts)
                    or ext in MEDIA_IMAGE_EXTENSIONS
                ),
            )
        )

        # Priority 44: Movies / Videos
        self.register_rule(
            CategoryRule(
                rule_id="rule:movies",
                category=SmartCategory.MOVIES,
                confidence=ConfidenceLevel.HIGH,
                confidence_score=0.95,
                priority=44,
                description="User movie or video asset.",
                matcher=lambda p, parts, name, ext, itype: (
                    any(part in ("movies", "videos") for part in parts)
                    or ext in MEDIA_VIDEO_EXTENSIONS
                ),
            )
        )

        # Priority 43: Music / Audio
        self.register_rule(
            CategoryRule(
                rule_id="rule:music",
                category=SmartCategory.MUSIC,
                confidence=ConfidenceLevel.HIGH,
                confidence_score=0.95,
                priority=43,
                description="User music or audio asset.",
                matcher=lambda p, parts, name, ext, itype: (
                    any(part in ("music", "audio") for part in parts)
                    or ext in MEDIA_AUDIO_EXTENSIONS
                ),
            )
        )

        # Priority 40: Documents
        self.register_rule(
            CategoryRule(
                rule_id="rule:documents",
                category=SmartCategory.DOCUMENTS,
                confidence=ConfidenceLevel.HIGH,
                confidence_score=0.95,
                priority=40,
                description="User document or text asset.",
                matcher=lambda p, parts, name, ext, itype: (
                    any(part == "documents" for part in parts)
                    or ext in DOCUMENT_EXTENSIONS
                ),
            )
        )

        # Priority 35: Downloads
        self.register_rule(
            CategoryRule(
                rule_id="rule:downloads",
                category=SmartCategory.DOWNLOADS,
                confidence=ConfidenceLevel.MEDIUM,
                confidence_score=0.80,
                priority=35,
                description="Located in user Downloads directory.",
                matcher=lambda p, parts, name, ext, itype: any(part == "downloads" for part in parts),
            )
        )

        # Priority 34: Desktop
        self.register_rule(
            CategoryRule(
                rule_id="rule:desktop",
                category=SmartCategory.DESKTOP,
                confidence=ConfidenceLevel.MEDIUM,
                confidence_score=0.80,
                priority=34,
                description="Located on user Desktop.",
                matcher=lambda p, parts, name, ext, itype: any(part == "desktop" for part in parts),
            )
        )

        # Priority 30: System Data
        self.register_rule(
            CategoryRule(
                rule_id="rule:system_data",
                category=SmartCategory.SYSTEM_DATA,
                confidence=ConfidenceLevel.HIGH,
                confidence_score=0.95,
                priority=30,
                description="macOS system directory or core operating system component.",
                matcher=lambda p, parts, name, ext, itype: (
                    any(part in ("system", "usr", "bin", "sbin", "private") for part in parts)
                ),
            )
        )

        # Priority 20: User / Application Data
        self.register_rule(
            CategoryRule(
                rule_id="rule:user_data",
                category=SmartCategory.USER_DATA,
                confidence=ConfidenceLevel.MEDIUM,
                confidence_score=0.75,
                priority=20,
                description="User or application configuration and state data.",
                matcher=lambda p, parts, name, ext, itype: (
                    any(part in ("application support", "containers", "group containers") for part in parts)
                ),
            )
        )


# Global default categorizer instance
_DEFAULT_REGISTRY = CategoryRegistry()


class SmartCategorizer:
    """
    Public facade for deterministic storage categorization.
    """

    @staticmethod
    def categorize_path(path: str, item_type: Optional[str] = None) -> CategoryResult:
        """Classify a filesystem path."""
        return _DEFAULT_REGISTRY.categorize_path(path, item_type=item_type)

    @staticmethod
    def categorize_item(item: DiscoveredItem) -> CategoryResult:
        """Classify a DiscoveredItem."""
        return _DEFAULT_REGISTRY.categorize_item(item)

    @staticmethod
    def categorize_items(items: Sequence[DiscoveredItem]) -> List[DiscoveredItem]:
        """Categorize a sequence of DiscoveredItem models."""
        return [_DEFAULT_REGISTRY.attach_category(item) for item in items]
