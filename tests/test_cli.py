from __future__ import annotations

import io
import os
import tempfile
from unittest.mock import MagicMock

from app.cli import generate_diagnostic_report, run_cli
from app.tools.storage_scanner import DiskUsage, StorageItem, StorageScanner


def test_generate_diagnostic_report_with_mock():
    mock_scanner = MagicMock(spec=StorageScanner)
    mock_scanner.get_disk_usage.return_value = DiskUsage(
        path="/",
        total_bytes=100 * 1024 * 1024 * 1024,
        used_bytes=60 * 1024 * 1024 * 1024,
        free_bytes=40 * 1024 * 1024 * 1024,
    )
    mock_scanner.get_top_directories.return_value = [
        StorageItem(path="/Applications", size_bytes=20 * 1024 * 1024 * 1024, item_type="directory"),
        StorageItem(path="/Users", size_bytes=15 * 1024 * 1024 * 1024, item_type="directory"),
    ]
    mock_scanner.get_large_files.return_value = [
        StorageItem(path="/Users/mac/Downloads/big.iso", size_bytes=5 * 1024 * 1024 * 1024, item_type="file"),
        StorageItem(path="/Users/mac/Videos/movie.mov", size_bytes=2 * 1024 * 1024 * 1024, item_type="file"),
    ]

    report = generate_diagnostic_report(
        scanner=mock_scanner,
        root_path="/",
        home_path="/Users/mac",
        top_dirs_limit=10,
        top_files_limit=10,
    )

    # Disk usage checks
    assert "[Disk Usage]" in report
    assert "Total Space:     100.00 GB" in report
    assert "Used Space:      60.00 GB" in report
    assert "Free Space:      40.00 GB" in report
    assert "Percentage Used: 60.00%" in report

    # Top directories checks
    assert "[Largest Immediate Directories (/)]" in report
    assert "/Applications - 20.00 GB" in report
    assert "/Users - 15.00 GB" in report

    # Large files checks
    assert "[Largest Files in Home Directory (/Users/mac)]" in report
    assert "/Users/mac/Downloads/big.iso - 5.00 GB" in report
    assert "/Users/mac/Videos/movie.mov - 2.00 GB" in report

    # Safety statement check
    assert "No files were modified." in report


def test_generate_diagnostic_report_with_temp_files():
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create subdirectories and dummy files
        dir_a = os.path.join(temp_dir, "dir_a")
        dir_b = os.path.join(temp_dir, "dir_b")
        os.makedirs(dir_a, exist_ok=True)
        os.makedirs(dir_b, exist_ok=True)

        file1 = os.path.join(dir_a, "file1.bin")
        file2 = os.path.join(dir_b, "file2.bin")

        with open(file1, "wb") as f:
            f.write(b"0" * 1024 * 100)  # 100 KB
        with open(file2, "wb") as f:
            f.write(b"0" * 1024 * 200)  # 200 KB

        scanner = StorageScanner()
        report = generate_diagnostic_report(
            scanner=scanner,
            root_path=temp_dir,
            home_path=temp_dir,
            top_dirs_limit=5,
            top_files_limit=5,
        )

        assert "[Disk Usage]" in report
        assert "Percentage Used:" in report
        assert "[Largest Immediate Directories (" in report
        assert "dir_b" in report
        assert "dir_a" in report
        assert "[Largest Files in Home Directory (" in report
        assert "file2.bin" in report
        assert "file1.bin" in report
        assert "No files were modified." in report


def test_generate_diagnostic_report_empty():
    mock_scanner = MagicMock(spec=StorageScanner)
    mock_scanner.get_disk_usage.return_value = DiskUsage(
        path="/",
        total_bytes=0,
        used_bytes=0,
        free_bytes=0,
    )
    mock_scanner.get_top_directories.return_value = []
    mock_scanner.get_large_files.return_value = []

    report = generate_diagnostic_report(
        scanner=mock_scanner,
        root_path="/",
        home_path="/empty",
    )

    assert "Percentage Used: 0.00%" in report
    assert "No directories found or accessible." in report
    assert "No files found or accessible." in report
    assert "No files were modified." in report


def test_run_cli_output():
    out = io.StringIO()
    with tempfile.TemporaryDirectory() as temp_dir:
        exit_code = run_cli(
            args=[
                "--root-path", temp_dir,
                "--home-path", temp_dir,
                "--top-dirs-limit", "5",
                "--top-files-limit", "5",
            ],
            out=out,
        )
        assert exit_code == 0

    output_str = out.getvalue()
    assert "MacGuard AI - Storage Diagnostic Report" in output_str
    assert "[Disk Usage]" in output_str
    assert "No files were modified." in output_str


def test_run_cli_dry_run_option(monkeypatch):
    out = io.StringIO()
    # Mock input to exit review immediately ('q')
    monkeypatch.setattr("builtins.input", lambda prompt="": "q")
    with tempfile.TemporaryDirectory() as temp_dir:
        exit_code = run_cli(
            args=[
                "--root-path", temp_dir,
                "--home-path", temp_dir,
                "--dry-run",
            ],
            out=out,
        )
        assert exit_code == 0

    output_str = out.getvalue()
    assert "MacGuard AI — Storage Review & Human Confirmation" in output_str
    assert "Non-Destructive Mode: Zero files will be deleted or modified." in output_str


def test_run_cli_trash_option(monkeypatch):
    out = io.StringIO()
    monkeypatch.setattr("builtins.input", lambda prompt="": "q")
    with tempfile.TemporaryDirectory() as temp_dir:
        exit_code = run_cli(
            args=[
                "--root-path", temp_dir,
                "--home-path", temp_dir,
                "--trash",
            ],
            out=out,
        )
        assert exit_code == 0

    output_str = out.getvalue()
    assert "CONTROLLED TRASH EXECUTION" in output_str
    assert "Approved files will be moved to macOS Trash." in output_str
    assert "No permanent deletion will occur." in output_str


