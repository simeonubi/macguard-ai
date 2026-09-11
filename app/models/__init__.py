"""
MacGuard AI v1.1 Models Package.
"""

from app.models.category import CategoryResult, ConfidenceLevel, SmartCategory
from app.models.developer import (
    DeveloperProjectSummary,
    DeveloperStorageFinding,
    DeveloperStorageGroup,
    DeveloperStorageSubtype,
    DeveloperStorageSummary,
    StaleStatus,
)
from app.models.duplicate import (
    DuplicateCluster,
    DuplicateFile,
    DuplicateGroup,
    DuplicateScanSummary,
)
from app.models.duplicate_recommendation import DuplicateRecommendationContext
from app.models.historical_recommendation import (
    HistoricalContextLevel,
    HistoricalRecommendationContext,
)
from app.models.large_file import (
    LargeFileCategorySummary,
    LargeFileDeveloperSummary,
    LargeFileFinding,
    LargeFileSummary,
)
from app.models.scan_result import DiscoveredItem, ScanResult, ScanStatus
from app.models.scan_scope import (
    CANONICAL_SENSITIVE_EXCLUSIONS,
    ScanScope,
    ScopeIdentifier,
    TraversalLimits,
)
from app.models.storage_history import (
    CategorySnapshotItem,
    CategoryTrend,
    DeveloperSnapshotItem,
    DeveloperTrend,
    LargeConsumerSnapshotItem,
    StorageSnapshot,
    StorageTrend,
    StorageTrendReport,
    TrendDirection,
)

__all__ = [
    "CANONICAL_SENSITIVE_EXCLUSIONS",
    "CategoryResult",
    "CategorySnapshotItem",
    "CategoryTrend",
    "ConfidenceLevel",
    "DeveloperProjectSummary",
    "DeveloperSnapshotItem",
    "DeveloperStorageFinding",
    "DeveloperStorageGroup",
    "DeveloperStorageSubtype",
    "DeveloperStorageSummary",
    "DeveloperTrend",
    "DiscoveredItem",
    "DuplicateCluster",
    "DuplicateFile",
    "DuplicateGroup",
    "DuplicateRecommendationContext",
    "DuplicateScanSummary",
    "HistoricalContextLevel",
    "HistoricalRecommendationContext",
    "LargeConsumerSnapshotItem",
    "LargeFileCategorySummary",
    "LargeFileDeveloperSummary",
    "LargeFileFinding",
    "LargeFileSummary",
    "ScanResult",
    "ScanScope",
    "ScanStatus",
    "ScopeIdentifier",
    "SmartCategory",
    "StaleStatus",
    "StorageSnapshot",
    "StorageTrend",
    "StorageTrendReport",
    "TraversalLimits",
    "TrendDirection",
]


