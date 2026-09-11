import os

from app.tools.storage_scanner import (
    StorageScanner,
    format_bytes,
)


def test_format_bytes():
    assert format_bytes(1024) == "1.00 KB"
    assert format_bytes(1024 * 1024) == "1.00 MB"


def test_get_disk_usage():
    scanner = StorageScanner()

    usage = scanner.get_disk_usage("/")

    assert usage.total_bytes > 0
    assert usage.used_bytes >= 0
    assert usage.free_bytes >= 0
    assert 0 <= usage.usage_percent <= 100


def test_get_directory_size():
    scanner = StorageScanner()

    size = scanner.get_directory_size(".")

    assert size >= 0


def test_get_top_directories():
    scanner = StorageScanner()

    directories = scanner.get_top_directories(
        path=".",
        limit=5,
    )

    assert len(directories) <= 5

    for directory in directories:
        assert directory.item_type == "directory"
        assert directory.size_bytes >= 0


def test_format_bytes_decimal_and_binary():
    """Test explicit decimal (SI 1000) and binary (IEC 1024) unit formatting."""
    from app.tools.storage_scanner import (
        format_bytes_binary,
        format_bytes_decimal,
        format_storage_dual,
    )

    # 1 KB (decimal) vs 1 KiB (binary)
    assert format_bytes_decimal(1000) == "1.00 KB"
    assert format_bytes_binary(1024) == "1.00 KiB"

    # 1 GB (decimal) vs 1 GiB (binary)
    assert format_bytes_decimal(1_000_000_000) == "1.00 GB"
    assert format_bytes_binary(1024 * 1024 * 1024) == "1.00 GiB"

    # macOS APFS ~245.11 GB / 228.27 GiB disk size
    apfs_total = 245_107_195_904
    assert format_bytes_decimal(apfs_total) == "245.11 GB"
    assert format_bytes_binary(apfs_total) == "228.27 GiB"

    dual = format_storage_dual(apfs_total)
    assert dual == "245.11 GB (228.27 GiB)"


def test_disk_usage_calculations_and_percentage():
    """Test DiskUsage calculations, percentage computation, and zero-capacity handling."""
    from app.tools.storage_scanner import DiskUsage

    # Standard usage
    u1 = DiskUsage(
        path="/",
        total_bytes=245_107_195_904,
        used_bytes=238_022_619_136,
        free_bytes=7_084_576_768,
    )
    assert round(u1.usage_percent, 1) == 97.1

    # Zero capacity edge case
    u_zero = DiskUsage(
        path="/empty",
        total_bytes=0,
        used_bytes=0,
        free_bytes=0,
    )
    assert u_zero.usage_percent == 0.0


def test_distinction_between_system_disk_and_candidate_metrics():
    """Test that system disk capacity/used space is clearly separated from scanned candidate metrics."""
    from app.tools.storage_scanner import DiskUsage, format_bytes
    from app.analysis.storage_analyzer import StorageAnalyzer
    from app.analysis.models import StorageCandidate, StorageCategory, RiskLevel

    system_usage = DiskUsage(
        path="/",
        total_bytes=245_107_195_904,
        used_bytes=238_022_619_136,
        free_bytes=7_084_576_768,
    )

    # Scanned candidate representing only a subset of storage
    candidates = [
        StorageCandidate(
            path="/Users/test/Library/Caches/Google",
            size_bytes=2_160_000_000,
            category=StorageCategory.CACHE,
            risk_level=RiskLevel.LOW,
            confidence=0.95,
            reason="Google cache",
            recommendation="Review",
            item_type="directory",
        ),
        StorageCandidate(
            path="/Users/test/.cache/uv",
            size_bytes=1_270_000_000,
            category=StorageCategory.CACHE,
            risk_level=RiskLevel.LOW,
            confidence=0.85,
            reason="UV cache",
            recommendation="Review",
            item_type="directory",
        ),
    ]

    analyzer = StorageAnalyzer()
    candidate_physical_bytes = analyzer.calculate_physical_coverage_bytes(candidates)
    reclaimable_bytes = analyzer.calculate_reclaimable_bytes(candidates)

    # System metrics must reflect physical disk:
    assert system_usage.total_bytes == 245_107_195_904
    assert system_usage.used_bytes == 238_022_619_136
    assert system_usage.free_bytes == 7_084_576_768

    # Candidate metrics must reflect only scanned items:
    assert candidate_physical_bytes == 3_430_000_000
    assert reclaimable_bytes == 3_430_000_000

    # System used space is NOT candidate size:
    assert system_usage.used_bytes != candidate_physical_bytes
    assert system_usage.used_bytes > candidate_physical_bytes


def test_apfs_root_scan_prunes_system_volumes_and_volumes(tmp_path):
    """
    Test that scanner traversal prunes /System/Volumes and /Volumes hierarchy.
    """
    from app.tools.storage_scanner import StorageScanner

    # Create synthetic directory structure mimicking APFS root
    root_mock = tmp_path / "mock_root"
    root_mock.mkdir()
    (root_mock / "Users").mkdir()
    (root_mock / "Users" / "userfile.txt").write_text("hello user")

    (root_mock / "Applications").mkdir()
    (root_mock / "Applications" / "app.txt").write_text("app data")

    # Legitimate /System content
    (root_mock / "System").mkdir()
    (root_mock / "System" / "Library").mkdir()
    (root_mock / "System" / "Library" / "sysfile.txt").write_text("system library data")

    # Duplicate firmlink & volume mounts inside /System/Volumes
    (root_mock / "System" / "Volumes").mkdir()
    (root_mock / "System" / "Volumes" / "Data").mkdir()
    (root_mock / "System" / "Volumes" / "Data" / "Users").mkdir()
    (root_mock / "System" / "Volumes" / "Data" / "Users" / "duplicate.txt").write_text("duplicate data 123456789")

    (root_mock / "System" / "Volumes" / "Preboot").mkdir()
    (root_mock / "System" / "Volumes" / "Preboot" / "preboot.bin").write_text("preboot data")

    (root_mock / "System" / "Volumes" / "VM").mkdir()
    (root_mock / "System" / "Volumes" / "VM" / "swapfile").write_text("swap data")

    (root_mock / "System" / "Volumes" / "Update").mkdir()
    (root_mock / "System" / "Volumes" / "Update" / "update.bin").write_text("update data")

    # /Volumes mounted disk
    (root_mock / "Volumes").mkdir()
    (root_mock / "Volumes" / "ExternalDrive").mkdir()
    (root_mock / "Volumes" / "ExternalDrive" / "external.dat").write_text("external disk content")

    scanner = StorageScanner()

    # Sizing of /System should include /System/Library but PRUNE /System/Volumes
    system_size = scanner.get_directory_size(str(root_mock / "System"))
    expected_sysfile_size = (root_mock / "System" / "Library" / "sysfile.txt").stat().st_size
    assert system_size == expected_sysfile_size

    # Sizing of /Users should discover user content
    users_size = scanner.get_directory_size(str(root_mock / "Users"))
    assert users_size == (root_mock / "Users" / "userfile.txt").stat().st_size


def test_apfs_synthetic_firmlink_inode_deduplication(tmp_path, monkeypatch):
    """
    Synthetic regression test representing /System/Volumes/Data/Users and /Users
    sharing the same synthetic (st_dev, st_ino) filesystem identity.
    Verifies that the accounting model does not count the same physical object twice.
    """
    from app.tools.storage_scanner import StorageScanner
    import os

    # Create mock layout
    root_mock = tmp_path / "root"
    root_mock.mkdir()
    user_file = root_mock / "Users" / "file.dat"
    user_file.parent.mkdir()
    user_file.write_bytes(b"A" * 1024)

    scanner = StorageScanner()
    visited_inodes = set()

    # Pass 1: compute size of /Users
    size1 = scanner.get_directory_size(str(root_mock / "Users"), visited_inodes=visited_inodes)
    assert size1 == 1024
    assert len(visited_inodes) == 1

    # Pass 2: compute size of an identical inode simulated path
    size2 = scanner.get_directory_size(str(root_mock / "Users"), visited_inodes=visited_inodes)
    assert size2 == 0  # Deduplicated by (st_dev, st_ino) tracking!


def test_get_top_directories_prunes_root_virtual_mounts(monkeypatch):
    """
    Test that get_top_directories ignores virtual mount directories when path is root.
    """
    from app.tools.storage_scanner import StorageScanner

    scanner = StorageScanner()
    monkeypatch.setattr(scanner, "get_directory_size", lambda p: 1024)

    top_dirs = scanner.get_top_directories(path="/", limit=20)
    top_paths = [item.path for item in top_dirs]

    # Must NOT contain virtual/mount root endpoints
    assert "/Volumes" not in top_paths
    assert "/dev" not in top_paths
    assert "/cores" not in top_paths

    # Should contain legitimate directories if they exist on the Mac
    for item in top_dirs:
        assert item.item_type == "directory"
        assert item.size_bytes >= 0
        assert not os.path.basename(item.path).startswith(".")

        