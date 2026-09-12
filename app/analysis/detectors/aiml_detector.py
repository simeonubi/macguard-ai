"""
MacGuard AI Phase 12 — AI & Machine Learning Storage Detector.

Discovers Hugging Face model/dataset caches, Ollama local model weights,
PyTorch hub checkpoints, and ML artifact caches.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from app.analysis.detectors.base import BaseStorageDetector
from app.analysis.detectors.usage_inspector import detect_associated_running_processes, is_path_recently_modified
from app.analysis.models import RiskLevel
from app.models.category import SmartCategory
from app.models.investigation import ReclaimConfidence, StorageEvidenceItem
from app.models.scan_scope import ScanScope
from app.safety.canonicalizer import canonicalize_path
from app.safety.path_validator import Operation, PathValidator
from app.tools.storage_scanner import StorageScanner


class AIMLStorageDetector(BaseStorageDetector):
    """
    Detector for AI/ML model weights, hub caches, and datasets.
    """

    @property
    def detector_id(self) -> str:
        return "aiml_storage_detector"

    @property
    def detector_name(self) -> str:
        return "AI & Machine Learning Storage"

    def detect(
        self,
        scope: ScanScope,
        visited_inodes: set[tuple[int, int]],
        scanner: Optional[StorageScanner] = None,
        path_validator: Optional[PathValidator] = None,
    ) -> list[StorageEvidenceItem]:
        items: list[StorageEvidenceItem] = []
        validator = path_validator or PathValidator()
        user_home = Path.home()

        targets = [
            (user_home / ".cache" / "huggingface" / "hub", "hf_models", "Hugging Face Models", "huggingface"),
            (user_home / ".cache" / "huggingface" / "datasets", "hf_datasets", "Hugging Face Datasets", "huggingface"),
            (user_home / ".cache" / "huggingface", "hf_cache", "Hugging Face Cache", "huggingface"),
            (user_home / ".ollama" / "models", "ollama_models", "Ollama Model Weights", "ollama"),
            (user_home / ".cache" / "torch" / "hub" / "checkpoints", "torch_checkpoints", "PyTorch Checkpoints", "torch"),
            (user_home / ".cache" / "torch", "torch_cache", "PyTorch Cache", "torch"),
            (user_home / ".cache" / "kaggle", "kaggle_cache", "Kaggle Cache", "kaggle"),
            (user_home / ".cache" / "wandb", "wandb_cache", "Weights & Biases Artifacts", "wandb"),
        ]

        seen_paths: set[str] = set()
        idx = 1
        for path_obj, subcat, desc, tool_name in targets:
            if not path_obj.exists() or not scope.is_path_allowed(str(path_obj)):
                continue

            path_str = str(path_obj)
            c_path = canonicalize_path(path_str).path_str
            if c_path in seen_paths:
                continue
            seen_paths.add(c_path)

            size, count = self.get_dir_size_and_count(path_str, visited_inodes, max_depth=8)
            if size < 50 * 1024 * 1024:  # 50MB minimum (AI/ML models are typically large)
                continue

            val_res = validator.validate_path(c_path, Operation.CLEAN)
            app_running, procs, in_use = detect_associated_running_processes(c_path, app_hints=[tool_name, "ollama"])
            recently_mod = is_path_recently_modified(c_path)

            # AI/ML caches can be redownloaded, but deleting active models requires user review
            is_active = app_running or (in_use is True)
            conf = ReclaimConfidence.REVIEW_REQUIRED if val_res.allowed and not is_active else (ReclaimConfidence.PROTECTED if not val_res.allowed else ReclaimConfidence.REVIEW_REQUIRED)

            item = StorageEvidenceItem(
                evidence_id=f"ev_aiml_{idx:03d}",
                path=path_str,
                canonical_path=c_path,
                size_bytes=size,
                item_count=count,
                category=SmartCategory.ML_AI_DATA,
                subcategory=subcat,
                source_app=desc,
                likely_owner="developer",
                is_cache=True,
                is_generated=False,
                is_developer=True,
                is_ai_ml=True,
                risk_level=RiskLevel.LOW if val_res.allowed else RiskLevel.HIGH,
                reclaim_confidence=conf,
                cleanup_allowed=val_res.allowed,
                reason_if_not_allowed=val_res.reason if not val_res.allowed else None,
                currently_in_use=in_use if in_use is not None else (True if app_running else None),
                associated_processes=procs,
                associated_application_running=app_running,
                recently_modified=recently_mod,
                reproducible_or_redownloadable=True,
                dependency_evidence=f"Model weights/dataset cache for {desc}. Can be redownloaded from Hugging Face / Ollama hub.",
                usage_evidence=f"Associated AI daemon/application active: {app_running}, open lock: {in_use}." if app_running is not None else None,
                cleanup_consequence="Requires re-downloading model weights or datasets next time they are invoked in code or CLI.",
                evidence_notes=f"{desc} consuming {size} bytes ({count} files/weights).",
            )
            items.append(item)
            idx += 1

        return items
