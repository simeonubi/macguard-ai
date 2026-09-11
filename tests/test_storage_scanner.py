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

        