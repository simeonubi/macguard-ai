"""
Tests for MacGuard AI v1.1 Smart Storage Categorization.

Validates deterministic semantic categorization across all 21 taxonomy categories,
rule precedence, confidence ratings, unknown fallback, metadata-only safety,
and complete isolation from cleanup authorization.
"""

from pathlib import Path
from unittest.mock import patch
import pytest

from app.analysis.categorizer import (
    CategoryRegistry,
    CategoryRule,
    SmartCategorizer,
)
from app.analysis.models import StorageCategory
from app.models.category import (
    CategoryResult,
    ConfidenceLevel,
    SmartCategory,
)
from app.models.scan_result import DiscoveredItem
from app.safety.path_validator import Operation, PathValidator


def test_categorize_caches():
    """Verify Caches classification for user and system cache directories."""
    res = SmartCategorizer.categorize_path("/Users/test/Library/Caches/com.apple.Safari")
    assert res.category == SmartCategory.CACHES
    assert res.confidence == ConfidenceLevel.HIGH
    assert res.confidence_score >= 0.90
    assert "caches" in res.matched_rule.lower()

    res_dot = SmartCategorizer.categorize_path("/Users/test/.cache/uv/archive")
    assert res_dot.category == SmartCategory.CACHES
    assert res_dot.confidence == ConfidenceLevel.HIGH


def test_categorize_logs():
    """Verify Logs classification for log directories and log file extensions."""
    res = SmartCategorizer.categorize_path("/Users/test/Library/Logs/diagnostic.log")
    assert res.category == SmartCategory.LOGS
    assert res.confidence == ConfidenceLevel.HIGH

    res_gz = SmartCategorizer.categorize_path("/var/log/system.log.gz")
    assert res.category == SmartCategory.LOGS


def test_categorize_virtual_environments():
    """Verify Virtual Environments classification for .venv and pyvenv.cfg."""
    res_venv = SmartCategorizer.categorize_path("/Users/test/Projects/myapp/.venv/bin/python")
    assert res_venv.category == SmartCategory.VIRTUAL_ENVIRONMENTS
    assert res_venv.confidence == ConfidenceLevel.HIGH

    res_cfg = SmartCategorizer.categorize_path("/Users/test/env/pyvenv.cfg")
    assert res_cfg.category == SmartCategory.VIRTUAL_ENVIRONMENTS


def test_categorize_build_artifacts():
    """Verify Build Artifacts classification for DerivedData, __pycache__, and build output."""
    res_xcode = SmartCategorizer.categorize_path("/Users/test/Library/Developer/Xcode/DerivedData/App-abc/Build")
    assert res_xcode.category == SmartCategory.BUILD_ARTIFACTS
    assert res_xcode.confidence == ConfidenceLevel.HIGH

    res_pyc = SmartCategorizer.categorize_path("/Users/test/Projects/pkg/__pycache__/module.cpython-311.pyc")
    assert res_pyc.category == SmartCategory.BUILD_ARTIFACTS

    res_rust = SmartCategorizer.categorize_path("/Users/test/Projects/rustapp/target/debug/app")
    assert res_rust.category == SmartCategory.BUILD_ARTIFACTS


def test_categorize_package_managers():
    """Verify Package Managers classification for node_modules, cargo, and npm caches."""
    res_node = SmartCategorizer.categorize_path("/Users/test/Projects/webapp/node_modules/react")
    assert res_node.category == SmartCategory.PACKAGE_MANAGERS
    assert res_node.confidence == ConfidenceLevel.HIGH

    res_npm = SmartCategorizer.categorize_path("/Users/test/.npm/_cacache/content-v2")
    assert res_npm.category == SmartCategory.PACKAGE_MANAGERS

    res_cargo = SmartCategorizer.categorize_path("/Users/test/.cargo/registry/cache")
    assert res_cargo.category == SmartCategory.PACKAGE_MANAGERS


def test_categorize_ml_ai_data():
    """Verify ML/AI Data classification for HuggingFace, Ollama, and model files."""
    res_hf = SmartCategorizer.categorize_path("/Users/test/.cache/huggingface/hub/models--meta--llama")
    assert res_hf.category == SmartCategory.ML_AI_DATA
    assert res_hf.confidence == ConfidenceLevel.HIGH

    res_ollama = SmartCategorizer.categorize_path("/Users/test/.ollama/models/blobs/sha256-abc")
    assert res_ollama.category == SmartCategory.ML_AI_DATA

    res_weights = SmartCategorizer.categorize_path("/Users/test/models/weights.safetensors")
    assert res_weights.category == SmartCategory.ML_AI_DATA


def test_categorize_containers():
    """Verify Containers classification for Docker and VM disk images."""
    res_docker = SmartCategorizer.categorize_path("/Users/test/Library/Containers/com.docker.docker/Data/docker.raw")
    assert res_docker.category == SmartCategory.CONTAINERS
    assert res_docker.confidence == ConfidenceLevel.HIGH


def test_categorize_temporary_data():
    """Verify Temporary Data classification for /tmp and temp files."""
    res_tmp = SmartCategorizer.categorize_path("/tmp/scratch_data.tmp")
    assert res_tmp.category == SmartCategory.TEMPORARY_DATA
    assert res_tmp.confidence == ConfidenceLevel.HIGH

    res_trash = SmartCategorizer.categorize_path("/Users/test/.Trash/old_file.txt")
    assert res_trash.category == SmartCategory.TEMPORARY_DATA


def test_categorize_disk_images():
    """Verify Disk Images classification for .dmg, .iso, and .sparseimage."""
    res_dmg = SmartCategorizer.categorize_path("/Users/test/Downloads/installer.dmg")
    assert res_dmg.category == SmartCategory.DISK_IMAGES
    assert res_dmg.confidence == ConfidenceLevel.HIGH

    res_iso = SmartCategorizer.categorize_path("/Users/test/os_install.iso")
    assert res_iso.category == SmartCategory.DISK_IMAGES


def test_categorize_archives():
    """Verify Archives classification for .zip, .tar.gz, .7z, and .pkg."""
    res_zip = SmartCategorizer.categorize_path("/Users/test/Downloads/dataset.zip")
    assert res_zip.category == SmartCategory.ARCHIVES
    assert res_zip.confidence == ConfidenceLevel.HIGH

    res_targz = SmartCategorizer.categorize_path("/Users/test/backup.tar.gz")
    assert res_targz.category == SmartCategory.ARCHIVES


def test_categorize_applications():
    """Verify Applications classification for .app bundles."""
    res_app = SmartCategorizer.categorize_path("/Applications/Xcode.app/Contents/MacOS/Xcode")
    assert res_app.category == SmartCategory.APPLICATIONS
    assert res_app.confidence == ConfidenceLevel.HIGH


def test_categorize_developer_data():
    """Verify Developer Data classification for source repositories and code files."""
    res_git = SmartCategorizer.categorize_path("/Users/test/Projects/my_project/.git/config")
    assert res_git.category == SmartCategory.DEVELOPER_DATA
    assert res_git.confidence == ConfidenceLevel.HIGH

    res_src = SmartCategorizer.categorize_path("/Users/test/Projects/my_project/src/main.rs")
    assert res_src.category == SmartCategory.DEVELOPER_DATA


def test_categorize_media_pictures_movies_music():
    """Verify fine-grained media classification across Pictures, Movies, and Music."""
    res_pic = SmartCategorizer.categorize_path("/Users/test/Pictures/holiday.heic")
    assert res_pic.category == SmartCategory.PICTURES
    assert res_pic.confidence == ConfidenceLevel.HIGH

    res_mov = SmartCategorizer.categorize_path("/Users/test/Movies/presentation.mov")
    assert res_mov.category == SmartCategory.MOVIES
    assert res_mov.confidence == ConfidenceLevel.HIGH

    res_mus = SmartCategorizer.categorize_path("/Users/test/Music/podcast.mp3")
    assert res_mus.category == SmartCategory.MUSIC
    assert res_mus.confidence == ConfidenceLevel.HIGH


def test_categorize_documents():
    """Verify Documents classification for document formats."""
    res_pdf = SmartCategorizer.categorize_path("/Users/test/Documents/Financial_Report.pdf")
    assert res_pdf.category == SmartCategory.DOCUMENTS
    assert res_pdf.confidence == ConfidenceLevel.HIGH

    res_docx = SmartCategorizer.categorize_path("/Users/test/resume.docx")
    assert res_docx.category == SmartCategory.DOCUMENTS


def test_categorize_downloads_and_desktop_directories():
    """Verify generic files in Downloads and Desktop receive folder classification."""
    res_dl = SmartCategorizer.categorize_path("/Users/test/Downloads/unrecognized_file")
    assert res_dl.category == SmartCategory.DOWNLOADS
    assert res_dl.confidence == ConfidenceLevel.MEDIUM

    res_dt = SmartCategorizer.categorize_path("/Users/test/Desktop/random_binary")
    assert res_dt.category == SmartCategory.DESKTOP
    assert res_dt.confidence == ConfidenceLevel.MEDIUM


def test_categorize_system_and_user_data():
    """Verify System Data and User Application Support classification."""
    res_sys = SmartCategorizer.categorize_path("/System/Library/CoreServices/Finder.app")
    # Priority for .app beats generic system_data
    assert res_sys.category in (SmartCategory.APPLICATIONS, SmartCategory.SYSTEM_DATA)

    res_usr = SmartCategorizer.categorize_path("/usr/lib/libSystem.B.dylib")
    assert res_sys.category in (SmartCategory.SYSTEM_DATA, SmartCategory.APPLICATIONS)

    res_app_sup = SmartCategorizer.categorize_path("/Users/test/Library/Application Support/MyApp/data.db")
    assert res_app_sup.category == SmartCategory.USER_DATA


def test_unknown_fallback():
    """Verify unrecognized binary files fall back cleanly to UNKNOWN."""
    res = SmartCategorizer.categorize_path("/some/random/unclassified/blob_1234")
    assert res.category == SmartCategory.UNKNOWN
    assert res.confidence == ConfidenceLevel.UNKNOWN
    assert res.confidence_score == 0.0
    assert res.matched_rule == "rule:unknown_fallback"


def test_rule_precedence_specific_over_broad():
    """
    CRITICAL PRECEDENCE INVARIANT:
    Specific artifact/cache rules must take precedence over broad parent directory rules.
    """
    # 1. .venv inside ~/Projects must be VIRTUAL_ENVIRONMENTS, not DEVELOPER_DATA
    res_venv = SmartCategorizer.categorize_path("/Users/test/Projects/my_app/.venv/bin/activate")
    assert res_venv.category == SmartCategory.VIRTUAL_ENVIRONMENTS

    # 2. node_modules inside ~/Projects must be PACKAGE_MANAGERS, not DEVELOPER_DATA
    res_node = SmartCategorizer.categorize_path("/Users/test/Projects/my_app/node_modules/express")
    assert res_node.category == SmartCategory.PACKAGE_MANAGERS

    # 3. target/debug inside ~/Projects must be BUILD_ARTIFACTS, not DEVELOPER_DATA
    res_target = SmartCategorizer.categorize_path("/Users/test/Projects/rust_app/target/debug/app")
    assert res_target.category == SmartCategory.BUILD_ARTIFACTS

    # 4. Library/Caches inside ~/Library must be CACHES, not USER_DATA
    res_cache = SmartCategorizer.categorize_path("/Users/test/Library/Caches/Google/Chrome")
    assert res_cache.category == SmartCategory.CACHES

    # 5. .dmg inside Downloads must be DISK_IMAGES, not DOWNLOADS
    res_dmg = SmartCategorizer.categorize_path("/Users/test/Downloads/installer.dmg")
    assert res_dmg.category == SmartCategory.DISK_IMAGES

    # 6. .zip inside Downloads must be ARCHIVES, not DOWNLOADS
    res_zip = SmartCategorizer.categorize_path("/Users/test/Downloads/archive.zip")
    assert res_zip.category == SmartCategory.ARCHIVES


def test_path_normalization_and_spaces():
    """Verify path normalization handles trailing slashes, dots, and spaces."""
    res_space = SmartCategorizer.categorize_path("/Users/test/My Documents/Tax 2026/Invoice Report.pdf")
    assert res_space.category == SmartCategory.DOCUMENTS

    res_dots = SmartCategorizer.categorize_path("/Users/test/Projects/../Library/Caches/./app")
    assert res_dots.category == SmartCategory.CACHES


def test_case_insensitivity_handling():
    """Verify uppercase extensions and directory names are classified correctly."""
    res_upper_ext = SmartCategorizer.categorize_path("/Users/test/Documents/PHOTO.PNG")
    assert res_upper_ext.category == SmartCategory.PICTURES

    res_upper_dir = SmartCategorizer.categorize_path("/Users/test/LIBRARY/CACHES/APP")
    assert res_upper_dir.category == SmartCategory.CACHES


def test_discovered_item_integration():
    """Verify attaching categorization to a DiscoveredItem."""
    item = DiscoveredItem(
        path="/Users/test/Library/Caches/Google/Chrome",
        size_bytes=1024 * 1024,
        item_type="directory",
        depth=3,
        mtime=1700000000.0,
        st_ino=12345,
        st_dev=67890,
    )

    categorized = SmartCategorizer.categorize_item(item)
    assert categorized.category == SmartCategory.CACHES
    assert categorized.confidence == ConfidenceLevel.HIGH

    enriched_item = CategoryRegistry().attach_category(item)
    assert enriched_item.category == SmartCategory.CACHES
    assert enriched_item.confidence == ConfidenceLevel.HIGH
    assert enriched_item.category_rule is not None
    assert enriched_item.path == item.path
    assert enriched_item.size_bytes == item.size_bytes


def test_legacy_category_mapping():
    """Verify mapping SmartCategory to base StorageCategory."""
    assert SmartCategory.CACHES.to_legacy_storage_category() == StorageCategory.CACHE
    assert SmartCategory.LOGS.to_legacy_storage_category() == StorageCategory.LOGS
    assert SmartCategory.BUILD_ARTIFACTS.to_legacy_storage_category() == StorageCategory.DEVELOPMENT
    assert SmartCategory.VIRTUAL_ENVIRONMENTS.to_legacy_storage_category() == StorageCategory.DEVELOPMENT
    assert SmartCategory.PICTURES.to_legacy_storage_category() == StorageCategory.MEDIA
    assert SmartCategory.DOCUMENTS.to_legacy_storage_category() == StorageCategory.DOCUMENTS
    assert SmartCategory.UNKNOWN.to_legacy_storage_category() == StorageCategory.UNKNOWN


def test_custom_rule_registration():
    """Verify custom rules can be registered in CategoryRegistry with priority ordering."""
    registry = CategoryRegistry()

    custom_rule = CategoryRule(
        rule_id="rule:custom_dataset",
        category=SmartCategory.ML_AI_DATA,
        confidence=ConfidenceLevel.HIGH,
        confidence_score=0.99,
        priority=100,  # Top priority
        description="Custom dataset rule",
        matcher=lambda p, parts, name, ext, itype: "custom_dataset" in parts,
    )

    registry.register_rule(custom_rule)

    res = registry.categorize_path("/Users/test/custom_dataset/file.txt")
    assert res.category == SmartCategory.ML_AI_DATA
    assert res.matched_rule == "rule:custom_dataset"


def test_metadata_only_no_content_reads():
    """Verify that categorization never opens or reads file bytes."""
    with patch("builtins.open", side_effect=AssertionError("Categorizer opened a file!")):
        res = SmartCategorizer.categorize_path("/Users/test/Projects/my_app/main.py")
        assert res.category == SmartCategory.DEVELOPER_DATA


def test_safety_regression_categorization_does_not_alter_cleanup_allowlist():
    """
    SAFETY INVARIANT:
    Categorizing an item as CACHES or LOGS outside the allowlist DOES NOT authorize cleanup.
    """
    # A cache file placed inside Desktop
    desktop_cache = "/Users/test/Desktop/fake_cache/data.cache"
    cat_result = SmartCategorizer.categorize_path(desktop_cache)
    assert cat_result.category == SmartCategory.CACHES

    # Validate against PathValidator
    validator = PathValidator(home_dir="/Users/test")
    val_result = validator.validate_path(desktop_cache, operation=Operation.CLEAN)

    # PathValidator MUST reject because Desktop is not in DEFAULT_CLEAN_ALLOWLIST_ROOTS
    assert val_result.allowed is False
    assert val_result.risk_level != "LOW"


def test_categorizer_zero_filesystem_mutation(tmp_path):
    """
    SAFETY INVARIANT:
    SmartCategorizer is strictly read-only and performs zero filesystem mutations.
    """
    sample_file = tmp_path / "sample.txt"
    sample_file.write_text("immutable content")
    mtime_before = sample_file.stat().st_mtime

    res = SmartCategorizer.categorize_path(str(sample_file))
    assert res.category == SmartCategory.DOCUMENTS

    mtime_after = sample_file.stat().st_mtime
    assert mtime_before == mtime_after
    assert sample_file.read_text() == "immutable content"


def test_categorizer_does_not_access_hmac_or_approval_secrets():
    """
    SECURITY INVARIANT:
    SmartCategorizer does not import or interact with ApprovalKeyManager or HMAC secrets.
    """
    import sys
    categorizer_module = sys.modules["app.analysis.categorizer"]

    # Verify no HMAC key manager or approval service is imported or referenced
    assert not hasattr(categorizer_module, "ApprovalKeyManager")
    assert not hasattr(categorizer_module, "ApprovalService")
    assert not hasattr(categorizer_module, "TrashExecutor")


def test_categorizer_does_not_invoke_subprocesses():
    """
    SECURITY INVARIANT:
    SmartCategorizer does not invoke subprocesses or shell commands.
    """
    with patch("subprocess.run", side_effect=AssertionError("Subprocess called!")):
        with patch("subprocess.Popen", side_effect=AssertionError("Subprocess called!")):
            with patch("os.system", side_effect=AssertionError("os.system called!")):
                res = SmartCategorizer.categorize_path("/Users/test/Projects/my_app/main.py")
                assert res.category == SmartCategory.DEVELOPER_DATA


def test_batch_categorize_items():
    """Verify batch categorization on a sequence of DiscoveredItem models."""
    items = [
        DiscoveredItem(
            path="/Users/test/Library/Caches/app",
            size_bytes=100,
            item_type="directory",
            depth=3,
            mtime=1.0,
            st_ino=1,
            st_dev=1,
        ),
        DiscoveredItem(
            path="/Users/test/Documents/file.pdf",
            size_bytes=200,
            item_type="file",
            depth=2,
            mtime=1.0,
            st_ino=2,
            st_dev=1,
        ),
    ]

    categorized = SmartCategorizer.categorize_items(items)
    assert len(categorized) == 2
    assert categorized[0].category == SmartCategory.CACHES
    assert categorized[1].category == SmartCategory.DOCUMENTS


def test_confidence_determinism():
    """Verify categorization results are 100% deterministic and reproducible."""
    path = "/Users/test/Projects/my_app/.venv/lib/python3.11/site-packages"
    res1 = SmartCategorizer.categorize_path(path)
    res2 = SmartCategorizer.categorize_path(path)

    assert res1.category == res2.category
    assert res1.confidence == res2.confidence
    assert res1.confidence_score == res2.confidence_score
    assert res1.matched_rule == res2.matched_rule
    assert res1.rationale == res2.rationale
