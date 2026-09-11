from __future__ import annotations

import os
import secrets
import tempfile
import time
from pathlib import Path

import pytest

from app.execution.integrity import (
    PathIntegritySnapshot,
    capture_integrity_snapshot,
    compute_file_sha256,
    verify_post_execution_integrity,
    verify_pre_execution_integrity,
)


def test_compute_file_sha256():
    with tempfile.TemporaryDirectory() as temp_dir:
        test_file = Path(temp_dir) / "sample.txt"
        test_file.write_text("MacGuard Integrity Test Content", encoding="utf-8")

        digest = compute_file_sha256(test_file)
        assert digest is not None
        assert len(digest) == 64

        # Nonexistent file returns None
        assert compute_file_sha256(Path(temp_dir) / "nonexistent.txt") is None

        # Directory returns None
        assert compute_file_sha256(temp_dir) is None


def test_capture_integrity_snapshot_regular_file():
    with tempfile.TemporaryDirectory() as temp_dir:
        test_file = Path(temp_dir) / "test_file.cache"
        content = "Cache content 12345"
        test_file.write_text(content, encoding="utf-8")
        approval_id = secrets.token_hex(16)

        snapshot = capture_integrity_snapshot(test_file, approval_id=approval_id, compute_hash=True)

        assert snapshot.canonical_path == str(test_file.resolve())
        assert snapshot.item_type == "file"
        assert snapshot.size_bytes == len(content.encode("utf-8"))
        assert snapshot.is_symlink is False
        assert snapshot.approval_id == approval_id
        assert snapshot.content_sha256 is not None
        assert snapshot.inode > 0


def test_capture_integrity_snapshot_directory():
    with tempfile.TemporaryDirectory() as temp_dir:
        sub_dir = Path(temp_dir) / "test_dir"
        sub_dir.mkdir()
        approval_id = secrets.token_hex(16)

        snapshot = capture_integrity_snapshot(sub_dir, approval_id=approval_id, compute_hash=True)

        assert snapshot.canonical_path == str(sub_dir.resolve())
        assert snapshot.item_type == "directory"
        assert snapshot.is_symlink is False
        assert snapshot.content_sha256 is None


def test_pre_execution_integrity_unchanged_file_passes():
    with tempfile.TemporaryDirectory() as temp_dir:
        test_file = Path(temp_dir) / "data.log"
        test_file.write_text("Normal log content", encoding="utf-8")
        approval_id = secrets.token_hex(16)

        snapshot = capture_integrity_snapshot(test_file, approval_id=approval_id)
        valid, msg = verify_pre_execution_integrity(snapshot, test_file)

        assert valid is True
        assert "succeeded" in msg.lower()


def test_pre_execution_integrity_size_change_fails():
    with tempfile.TemporaryDirectory() as temp_dir:
        test_file = Path(temp_dir) / "data.log"
        test_file.write_text("Short", encoding="utf-8")
        approval_id = secrets.token_hex(16)

        snapshot = capture_integrity_snapshot(test_file, approval_id=approval_id)

        # Mutate file content and size
        test_file.write_text("Much longer modified content that changes file size", encoding="utf-8")

        valid, msg = verify_pre_execution_integrity(snapshot, test_file)
        assert valid is False
        assert "file size modified" in msg.lower() or "content hash mismatch" in msg.lower()


def test_pre_execution_integrity_content_modification_fails():
    with tempfile.TemporaryDirectory() as temp_dir:
        test_file = Path(temp_dir) / "data.log"
        test_file.write_text("AAAA", encoding="utf-8")
        approval_id = secrets.token_hex(16)

        snapshot = capture_integrity_snapshot(test_file, approval_id=approval_id)

        # Modify content with exact same size
        test_file.write_text("BBBB", encoding="utf-8")

        valid, msg = verify_pre_execution_integrity(snapshot, test_file)
        assert valid is False
        assert "content hash mismatch" in msg.lower()


def test_pre_execution_integrity_symlink_replacement_fails():
    with tempfile.TemporaryDirectory() as temp_dir:
        target_file = Path(temp_dir) / "data.log"
        target_file.write_text("Original content", encoding="utf-8")
        approval_id = secrets.token_hex(16)

        snapshot = capture_integrity_snapshot(target_file, approval_id=approval_id)

        # Attacker replaces target file with symlink pointing elsewhere
        os.remove(target_file)
        secret_file = Path(temp_dir) / "secret.txt"
        secret_file.write_text("Top secret", encoding="utf-8")
        os.symlink(secret_file, target_file)

        valid, msg = verify_pre_execution_integrity(snapshot, target_file)
        assert valid is False
        assert "target path mismatch" in msg.lower() or "symbolic link" in msg.lower() or "symlink" in msg.lower()


def test_pre_execution_integrity_type_change_fails():
    with tempfile.TemporaryDirectory() as temp_dir:
        target_file = Path(temp_dir) / "data.log"
        target_file.write_text("Original content", encoding="utf-8")
        approval_id = secrets.token_hex(16)

        snapshot = capture_integrity_snapshot(target_file, approval_id=approval_id)

        # Replace file with directory
        os.remove(target_file)
        target_file.mkdir()

        valid, msg = verify_pre_execution_integrity(snapshot, target_file)
        assert valid is False
        assert "regular file" in msg.lower()


def test_post_execution_integrity_valid_move():
    with tempfile.TemporaryDirectory() as temp_dir:
        source_dir = Path(temp_dir) / "source"
        trash_dir = Path(temp_dir) / "trash"
        source_dir.mkdir()
        trash_dir.mkdir()

        source_file = source_dir / "item.cache"
        source_file.write_text("Sample cached data", encoding="utf-8")
        approval_id = secrets.token_hex(16)

        snapshot = capture_integrity_snapshot(source_file, approval_id=approval_id)

        # Simulate move
        dest_item = trash_dir / "MacGuard_subdir" / "item.cache"
        dest_item.parent.mkdir(parents=True)
        os.rename(source_file, dest_item)

        valid, msg = verify_post_execution_integrity(
            snapshot=snapshot,
            canonical_source_path=source_file,
            destination_path=dest_item,
            trash_root=trash_dir,
        )

        assert valid is True
        assert "succeeded" in msg.lower()


def test_post_execution_integrity_source_still_exists_fails():
    with tempfile.TemporaryDirectory() as temp_dir:
        source_dir = Path(temp_dir) / "source"
        trash_dir = Path(temp_dir) / "trash"
        source_dir.mkdir()
        trash_dir.mkdir()

        source_file = source_dir / "item.cache"
        source_file.write_text("Sample cached data", encoding="utf-8")
        approval_id = secrets.token_hex(16)

        snapshot = capture_integrity_snapshot(source_file, approval_id=approval_id)

        # Simulate copy instead of move (source still exists)
        dest_item = trash_dir / "MacGuard_subdir" / "item.cache"
        dest_item.parent.mkdir(parents=True)
        dest_item.write_text("Sample cached data", encoding="utf-8")

        valid, msg = verify_post_execution_integrity(
            snapshot=snapshot,
            canonical_source_path=source_file,
            destination_path=dest_item,
            trash_root=trash_dir,
        )

        assert valid is False
        assert "source" in msg.lower() and "exists" in msg.lower()


def test_post_execution_integrity_destination_escapes_trash_fails():
    with tempfile.TemporaryDirectory() as temp_dir:
        source_dir = Path(temp_dir) / "source"
        trash_dir = Path(temp_dir) / "trash"
        outside_dir = Path(temp_dir) / "outside"
        source_dir.mkdir()
        trash_dir.mkdir()
        outside_dir.mkdir()

        source_file = source_dir / "item.cache"
        source_file.write_text("Sample cached data", encoding="utf-8")
        approval_id = secrets.token_hex(16)

        snapshot = capture_integrity_snapshot(source_file, approval_id=approval_id)

        # Destination is outside trash root
        dest_item = outside_dir / "item.cache"
        os.rename(source_file, dest_item)

        valid, msg = verify_post_execution_integrity(
            snapshot=snapshot,
            canonical_source_path=source_file,
            destination_path=dest_item,
            trash_root=trash_dir,
        )

        assert valid is False
        assert "escapes trash root" in msg.lower()
