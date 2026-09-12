"""
Unit tests for Phase 12 Modular Detectors.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.analysis.detectors.aiml_detector import AIMLStorageDetector
from app.analysis.detectors.cache_detector import CacheDetector
from app.analysis.detectors.developer_detector import DeveloperStorageDetector
from app.analysis.detectors.docker_detector import DockerDetector
from app.analysis.detectors.download_detector import DownloadDetector
from app.analysis.detectors.duplicate_detector import DuplicateStorageDetector
from app.analysis.detectors.large_file_detector import LargeFileDetector
from app.analysis.detectors.log_detector import LogDetector
from app.analysis.detectors.node_cache_detector import NodeCacheDetector
from app.analysis.detectors.python_cache_detector import PythonCacheDetector
from app.analysis.detectors.usage_inspector import detect_associated_running_processes, is_path_recently_modified
from app.models.category import SmartCategory
from app.models.investigation import ReclaimConfidence
from app.models.scan_scope import ScanScope, ScopeIdentifier
from app.safety.path_validator import PathValidator


@pytest.fixture
def mock_sandbox_home(tmp_path: Path) -> Path:
    """Create a temporary sandbox filesystem mimicking macOS home structure."""
    home = tmp_path / "fake_home"
    home.mkdir()
    (home / "Library" / "Caches" / "com.example.app").mkdir(parents=True)
    (home / "Library" / "Caches" / "pip").mkdir(parents=True)
    (home / ".cache" / "uv").mkdir(parents=True)
    (home / ".npm" / "_cacache").mkdir(parents=True)
    (home / "Library" / "Developer" / "Xcode" / "DerivedData").mkdir(parents=True)
    (home / "Library" / "Logs" / "AppLogs").mkdir(parents=True)
    (home / "Downloads").mkdir(parents=True)
    (home / ".cache" / "huggingface" / "hub").mkdir(parents=True)
    (home / "Library" / "Containers" / "com.docker.docker" / "Data" / "vms").mkdir(parents=True)

    # Add mock files
    with open(home / "Library" / "Caches" / "com.example.app" / "cache.db", "wb") as f:
        f.write(b"0" * (10 * 1024 * 1024))  # 10MB

    with open(home / "Library" / "Caches" / "pip" / "wheel.whl", "wb") as f:
        f.write(b"0" * (5 * 1024 * 1024))  # 5MB

    with open(home / "Downloads" / "installer.dmg", "wb") as f:
        f.write(b"0" * (25 * 1024 * 1024))  # 25MB

    with open(home / "Library" / "Developer" / "Xcode" / "DerivedData" / "build.o", "wb") as f:
        f.write(b"0" * (15 * 1024 * 1024))  # 15MB

    with open(home / ".cache" / "huggingface" / "hub" / "weights.bin", "wb") as f:
        f.write(b"0" * (60 * 1024 * 1024))  # 60MB

    with open(home / "Library" / "Containers" / "com.docker.docker" / "Data" / "vms" / "Docker.raw", "wb") as f:
        f.write(b"0" * (20 * 1024 * 1024))  # 20MB

    return home


def test_cache_detector(mock_sandbox_home: Path) -> None:
    scope = ScanScope(
        scope_id=ScopeIdentifier.HOME,
        root_path=str(mock_sandbox_home),
        description="Test Home Scope",
    )
    detector = CacheDetector()
    visited: set[tuple[int, int]] = set()

    validator = PathValidator(
        home_dir=mock_sandbox_home,
        custom_allowlist_roots=[
            mock_sandbox_home / "Library/Caches",
            mock_sandbox_home / ".cache",
            mock_sandbox_home / "Downloads",
            mock_sandbox_home / "Library/Developer/Xcode/DerivedData",
            mock_sandbox_home / "Library/Logs",
        ],
    )
    with patch("pathlib.Path.home", return_value=mock_sandbox_home):
        items = detector.detect(scope, visited, path_validator=validator)

    assert len(items) >= 1
    cache_item = next((it for it in items if "com.example.app" in it.path), None)
    assert cache_item is not None
    assert cache_item.category == SmartCategory.CACHES
    assert cache_item.is_cache is True
    assert cache_item.size_bytes >= 10 * 1024 * 1024


def test_python_cache_detector(mock_sandbox_home: Path) -> None:
    scope = ScanScope(
        scope_id=ScopeIdentifier.HOME,
        root_path=str(mock_sandbox_home),
        description="Test Home Scope",
    )
    detector = PythonCacheDetector()
    visited: set[tuple[int, int]] = set()

    validator = PathValidator(
        home_dir=mock_sandbox_home,
        custom_allowlist_roots=[
            mock_sandbox_home / "Library/Caches",
            mock_sandbox_home / ".cache",
            mock_sandbox_home / "Downloads",
            mock_sandbox_home / "Library/Developer/Xcode/DerivedData",
            mock_sandbox_home / "Library/Logs",
        ],
    )
    with patch("pathlib.Path.home", return_value=mock_sandbox_home):
        items = detector.detect(scope, visited, path_validator=validator)

    assert len(items) >= 1
    pip_item = next((it for it in items if "pip" in it.path), None)
    assert pip_item is not None
    assert pip_item.category == SmartCategory.PACKAGE_MANAGERS
    assert pip_item.is_developer is True


def test_docker_detector_read_only_invariant(mock_sandbox_home: Path) -> None:
    """Ensure Docker detector is strictly read-only, sets cleanup_allowed=False, and defaults to REVIEW_REQUIRED."""
    scope = ScanScope(
        scope_id=ScopeIdentifier.HOME,
        root_path=str(mock_sandbox_home),
        description="Test Home Scope",
    )
    detector = DockerDetector()
    visited: set[tuple[int, int]] = set()

    validator = PathValidator(
        home_dir=mock_sandbox_home,
        custom_allowlist_roots=[
            mock_sandbox_home / "Library/Caches",
            mock_sandbox_home / ".cache",
            mock_sandbox_home / "Downloads",
            mock_sandbox_home / "Library/Developer/Xcode/DerivedData",
            mock_sandbox_home / "Library/Logs",
        ],
    )
    with patch("pathlib.Path.home", return_value=mock_sandbox_home):
        items = detector.detect(scope, visited, path_validator=validator)

    assert len(items) >= 1
    docker_item = items[0]
    assert docker_item.is_docker is True
    assert docker_item.cleanup_allowed is False
    assert docker_item.reclaim_confidence in (ReclaimConfidence.REVIEW_REQUIRED, ReclaimConfidence.PROTECTED)
    assert "docker system prune" in (docker_item.reason_if_not_allowed or "")


def test_aiml_detector(mock_sandbox_home: Path) -> None:
    scope = ScanScope(
        scope_id=ScopeIdentifier.HOME,
        root_path=str(mock_sandbox_home),
        description="Test Home Scope",
    )
    detector = AIMLStorageDetector()
    visited: set[tuple[int, int]] = set()

    validator = PathValidator(
        home_dir=mock_sandbox_home,
        custom_allowlist_roots=[
            mock_sandbox_home / "Library/Caches",
            mock_sandbox_home / ".cache",
            mock_sandbox_home / "Downloads",
            mock_sandbox_home / "Library/Developer/Xcode/DerivedData",
            mock_sandbox_home / "Library/Logs",
        ],
    )
    with patch("pathlib.Path.home", return_value=mock_sandbox_home):
        items = detector.detect(scope, visited, path_validator=validator)

    assert len(items) >= 1
    hf_item = items[0]
    assert hf_item.is_ai_ml is True
    assert hf_item.category == SmartCategory.ML_AI_DATA
    assert hf_item.reclaim_confidence == ReclaimConfidence.REVIEW_REQUIRED


def test_download_detector(mock_sandbox_home: Path) -> None:
    scope = ScanScope(
        scope_id=ScopeIdentifier.HOME,
        root_path=str(mock_sandbox_home),
        description="Test Home Scope",
    )
    detector = DownloadDetector()
    visited: set[tuple[int, int]] = set()

    validator = PathValidator(
        home_dir=mock_sandbox_home,
        custom_allowlist_roots=[
            mock_sandbox_home / "Library/Caches",
            mock_sandbox_home / ".cache",
            mock_sandbox_home / "Downloads",
            mock_sandbox_home / "Library/Developer/Xcode/DerivedData",
            mock_sandbox_home / "Library/Logs",
        ],
    )
    with patch("pathlib.Path.home", return_value=mock_sandbox_home):
        items = detector.detect(scope, visited, path_validator=validator)

    assert len(items) >= 1
    dmg_item = next((it for it in items if "installer.dmg" in it.path), None)
    assert dmg_item is not None
    assert dmg_item.category == SmartCategory.DISK_IMAGES
    assert dmg_item.reclaim_confidence == ReclaimConfidence.HIGH_CONFIDENCE


def test_usage_inspector_process_detection() -> None:
    # Test safe process inspection
    running, procs, in_use = detect_associated_running_processes("/Users/test/Library/Caches", app_hints=["python", "pytest"])
    assert isinstance(running, bool) or running is None
    assert isinstance(procs, list)
    assert isinstance(in_use, bool) or in_use is None


def test_weak_generic_process_signal_not_marked_in_use(mock_sandbox_home: Path) -> None:
    """Ensure generic runtimes (python/node) do not falsely mark package caches as currently in use."""
    scope = ScanScope(
        scope_id=ScopeIdentifier.HOME,
        root_path=str(mock_sandbox_home),
        description="Mock Home Scope",
    )
    validator = PathValidator()
    detector = PythonCacheDetector()
    visited: set[tuple[int, int]] = set()

    with patch("pathlib.Path.home", return_value=mock_sandbox_home):
        items = detector.detect(scope, visited, path_validator=validator)

    for item in items:
        # Generic python processes on the machine should not falsely set currently_in_use=True without open handles
        assert item.currently_in_use is not True
        assert item.active_dependency_detected is None  # Remains UNKNOWN

