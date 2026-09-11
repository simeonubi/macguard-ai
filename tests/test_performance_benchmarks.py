from __future__ import annotations

import tempfile
import time
from pathlib import Path

import pytest

from app.analysis.storage_analyzer import StorageAnalyzer
from app.tools.storage_scanner import StorageItem, StorageScanner


def test_large_file_scanner_heap_bounds_and_ordering() -> None:
    """Validate bounded min-heap accuracy for various N values."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        sizes = [100, 500, 200, 800, 300, 1000, 50, 900, 400, 700]
        for i, sz in enumerate(sizes):
            f = tmp_path / f"file_{i}.dat"
            f.write_bytes(b"X" * sz)

        scanner = StorageScanner()

        # N = 3
        top3 = scanner.get_large_files(tmpdir, limit=3)
        assert len(top3) == 3
        assert top3[0].size_bytes == 1000
        assert top3[1].size_bytes == 900
        assert top3[2].size_bytes == 800

        # N = 1
        top1 = scanner.get_large_files(tmpdir, limit=1)
        assert len(top1) == 1
        assert top1[0].size_bytes == 1000

        # N = 100 (more than available)
        top100 = scanner.get_large_files(tmpdir, limit=100)
        assert len(top100) == len(sizes)
        # Verify descending order
        for idx in range(len(top100) - 1):
            assert top100[idx].size_bytes >= top100[idx + 1].size_bytes

        # N = 0
        top0 = scanner.get_large_files(tmpdir, limit=0)
        assert top0 == []

        # N < 0
        top_neg = scanner.get_large_files(tmpdir, limit=-5)
        assert top_neg == []


def test_synthetic_storage_analyzer_benchmark_1000_items() -> None:
    """Benchmark StorageAnalyzer with 1,000 synthetic items."""
    items = [
        StorageItem(
            path=f"/Users/test/Library/Caches/app_{i}/data_{i}.cache",
            size_bytes=1024 * (i + 1),
            item_type="file",
        )
        for i in range(1000)
    ]

    analyzer = StorageAnalyzer()
    start = time.perf_counter()
    candidates = analyzer.analyze_items(items)
    duration_ms = (time.perf_counter() - start) * 1000.0

    assert len(candidates) == 1000
    # Must comfortably process 1,000 items in under 200ms
    assert duration_ms < 200.0
