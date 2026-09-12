"""
MacGuard AI Phase 12 Detectors Package.
"""

from app.analysis.detectors.aiml_detector import AIMLStorageDetector
from app.analysis.detectors.base import BaseStorageDetector
from app.analysis.detectors.cache_detector import CacheDetector
from app.analysis.detectors.developer_detector import DeveloperStorageDetector
from app.analysis.detectors.docker_detector import DockerDetector
from app.analysis.detectors.download_detector import DownloadDetector
from app.analysis.detectors.duplicate_detector import DuplicateStorageDetector
from app.analysis.detectors.evidence_aggregator import EvidenceAggregator
from app.analysis.detectors.large_file_detector import LargeFileDetector
from app.analysis.detectors.log_detector import LogDetector
from app.analysis.detectors.node_cache_detector import NodeCacheDetector
from app.analysis.detectors.python_cache_detector import PythonCacheDetector

__all__ = [
    "AIMLStorageDetector",
    "BaseStorageDetector",
    "CacheDetector",
    "DeveloperStorageDetector",
    "DockerDetector",
    "DownloadDetector",
    "DuplicateStorageDetector",
    "EvidenceAggregator",
    "LargeFileDetector",
    "LogDetector",
    "NodeCacheDetector",
    "PythonCacheDetector",
]
