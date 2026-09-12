"""
MacGuard AI — Risk Level Model.
"""

from __future__ import annotations

from enum import Enum


class RiskLevel(str, Enum):
    """
    Risk rating indicating the potential impact if an item were to be modified.

    This rating does NOT imply permission to delete.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    UNKNOWN = "UNKNOWN"
