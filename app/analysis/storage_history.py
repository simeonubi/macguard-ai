"""
MacGuard AI v1.1 — Persistent Storage History Repository.

This module manages atomic, parameterized SQLite persistence for storage snapshots,
category breakdowns, developer tooling metrics, and bounded top-N consumers.

DISCOVERY != CATEGORIZATION != ANALYSIS != AUTHORIZATION
History persistence is strictly observational and analytics-driven. It performs zero
filesystem mutations and possesses zero cleanup or execution authority.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Union

from app.models.category import ConfidenceLevel, SmartCategory
from app.models.developer import (
    DeveloperStorageGroup,
    DeveloperStorageSubtype,
    DeveloperStorageSummary,
)
from app.models.large_file import LargeFileCategorySummary, LargeFileSummary
from app.models.scan_result import DiscoveredItem, ScanResult, ScanStatus
from app.models.scan_scope import ScopeIdentifier
from app.models.storage_history import (
    CategorySnapshotItem,
    DeveloperSnapshotItem,
    LargeConsumerSnapshotItem,
    StorageSnapshot,
)

DEFAULT_SNAPSHOT_RETENTION_COUNT: int = 365


def normalize_canonical_root(root_path: Union[str, Path]) -> str:
    """Normalize a path to a consistent canonical string representation."""
    if not root_path:
        return "/"
    return os.path.normpath(str(root_path))


def is_path_contained_in_root(item_path: Union[str, Path], root_path: Union[str, Path]) -> bool:
    """
    Determine if item_path is within or equal to root_path using
    proper filesystem path boundary semantics (avoiding naive string prefix matching).
    """
    try:
        norm_item = normalize_canonical_root(item_path)
        norm_root = normalize_canonical_root(root_path)

        if norm_root == "/":
            return norm_item.startswith("/")

        item_p = Path(norm_item)
        root_p = Path(norm_root)

        try:
            item_p.relative_to(root_p)
            return True
        except ValueError:
            return False
    except Exception:
        return False


def is_snapshot_scope_compatible(
    snapshot: StorageSnapshot,
    target_scope: ScopeIdentifier,
    target_root: Union[str, Path],
) -> bool:
    """
    Centralized compatibility and containment validator for historical snapshots.

    A snapshot is compatible with a target scope and target root path if:
    1. The snapshot's scope_id exactly matches target_scope.
    2. The snapshot's normalized root_path matches target_root's normalized path.
    3. If target_root is root ('/'):
       Normal absolute paths are considered within the root.
    4. If target_root is non-root (e.g. /Users/mac):
       snapshot.top_consumers must be present and non-empty.
       Every recorded consumer path must be contained within target_root.
       If top_consumers is missing or empty, returns False because there is
       insufficient historical metadata to establish containment.
    """
    if snapshot.scope_id != target_scope:
        return False

    norm_target_root = normalize_canonical_root(target_root)
    norm_snap_root = normalize_canonical_root(snapshot.root_path)

    if norm_snap_root != norm_target_root:
        return False

    # Root scope accepts all root-contained snapshots
    if norm_target_root == "/":
        return True

    # For non-root scopes, top_consumers must be present and non-empty
    if not snapshot.top_consumers:
        return False

    for consumer in snapshot.top_consumers:
        if not is_path_contained_in_root(consumer.path, norm_target_root):
            return False

    return True


class StorageHistoryRepository:
    """
    Thread-safe, atomic SQLite repository for recording and querying storage scan history.
    """

    def __init__(self, db_path: Optional[Union[str, Path]] = None) -> None:
        self._lock = threading.Lock()
        if db_path is not None:
            self._db_path = str(db_path)
        else:
            env_db = os.getenv("MACGUARD_HISTORY_DB")
            if env_db:
                self._db_path = env_db
            else:
                default_dir = Path.home() / ".macguard"
                default_dir.mkdir(parents=True, exist_ok=True)
                self._db_path = str(default_dir / "macguard_history.db")

        self._is_memory = self._db_path == ":memory:"
        self._mem_conn: Optional[sqlite3.Connection] = None
        if self._is_memory:
            self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._mem_conn.row_factory = sqlite3.Row
            self._mem_conn.execute("PRAGMA foreign_keys = ON;")
        elif not self._db_path.startswith(":"):
            Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)

        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self._is_memory and self._mem_conn is not None:
            return self._mem_conn
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _close_connection(self, conn: sqlite3.Connection) -> None:
        if not self._is_memory:
            conn.close()

    def _init_db(self) -> None:
        """Initialize database schema and performance indexes."""
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()

                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS storage_snapshots (
                        snapshot_id TEXT PRIMARY KEY,
                        scan_id TEXT NOT NULL UNIQUE,
                        timestamp REAL NOT NULL,
                        scope_id TEXT NOT NULL,
                        root_path TEXT NOT NULL,
                        status TEXT NOT NULL,
                        duration_seconds REAL NOT NULL,
                        files_count INTEGER NOT NULL,
                        directories_count INTEGER NOT NULL,
                        total_bytes INTEGER NOT NULL,
                        unique_bytes INTEGER,
                        skipped_entries_count INTEGER NOT NULL DEFAULT 0,
                        permission_errors_count INTEGER NOT NULL DEFAULT 0
                    )
                    """
                )

                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS category_storage_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        snapshot_id TEXT NOT NULL REFERENCES storage_snapshots(snapshot_id) ON DELETE CASCADE,
                        category TEXT NOT NULL,
                        total_bytes INTEGER NOT NULL,
                        item_count INTEGER NOT NULL
                    )
                    """
                )

                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS developer_storage_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        snapshot_id TEXT NOT NULL REFERENCES storage_snapshots(snapshot_id) ON DELETE CASCADE,
                        subtype TEXT NOT NULL,
                        total_bytes INTEGER NOT NULL,
                        unique_bytes INTEGER NOT NULL,
                        item_count INTEGER NOT NULL
                    )
                    """
                )

                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS large_consumer_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        snapshot_id TEXT NOT NULL REFERENCES storage_snapshots(snapshot_id) ON DELETE CASCADE,
                        rank INTEGER NOT NULL,
                        path TEXT NOT NULL,
                        size_bytes INTEGER NOT NULL,
                        category TEXT NOT NULL,
                        confidence TEXT NOT NULL
                    )
                    """
                )

                # Performance Indexes
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_snapshots_scope_time ON storage_snapshots(scope_id, timestamp DESC)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_snapshots_scan_id ON storage_snapshots(scan_id)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_cat_history_snap ON category_storage_history(snapshot_id)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_dev_history_snap ON developer_storage_history(snapshot_id)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_large_history_snap ON large_consumer_history(snapshot_id)"
                )

                conn.commit()
            finally:
                self._close_connection(conn)

    def record_snapshot(
        self,
        scan_result: ScanResult,
        category_summaries: Optional[List[LargeFileCategorySummary]] = None,
        developer_summary: Optional[DeveloperStorageSummary] = None,
        large_file_summary: Optional[LargeFileSummary] = None,
        scan_id: Optional[str] = None,
        max_retention: int = DEFAULT_SNAPSHOT_RETENTION_COUNT,
    ) -> StorageSnapshot:
        """
        Record a scan result as an immutable historical snapshot.
        Guarantees atomicity and idempotency via scan_id.
        """
        effective_scan_id = scan_id or f"scan_{scan_result.scope_id.value}_{int(scan_result.start_time)}_{scan_result.total_bytes}"

        with self._lock:
            # Idempotency check: if snapshot for this scan_id already exists, return it
            existing = self._get_snapshot_by_scan_id_unlocked(effective_scan_id)
            if existing is not None:
                return existing

            snapshot_id = str(uuid.uuid4())
            timestamp = scan_result.end_time if scan_result.end_time > 0 else time.time()

            # 1. Build Category Snapshot Items
            categories_map: Dict[SmartCategory, CategorySnapshotItem] = {}
            if category_summaries:
                for cs in category_summaries:
                    categories_map[cs.category] = CategorySnapshotItem(
                        category=cs.category,
                        total_bytes=cs.total_logical_bytes,
                        item_count=cs.item_count,
                    )
            elif scan_result.items:
                for item in scan_result.items:
                    cat = item.category or SmartCategory.UNKNOWN
                    if cat not in categories_map:
                        categories_map[cat] = CategorySnapshotItem(category=cat, total_bytes=0, item_count=0)
                    curr = categories_map[cat]
                    categories_map[cat] = CategorySnapshotItem(
                        category=cat,
                        total_bytes=curr.total_bytes + item.size_bytes,
                        item_count=curr.item_count + 1,
                    )

            category_items = sorted(list(categories_map.values()), key=lambda c: (-c.total_bytes, c.category.value))

            # 2. Build Developer Snapshot Items
            dev_items: List[DeveloperSnapshotItem] = []
            if developer_summary:
                for group in developer_summary.groups:
                    dev_items.append(
                        DeveloperSnapshotItem(
                            subtype=group.subtype,
                            total_bytes=group.total_logical_bytes,
                            unique_bytes=group.unique_physical_bytes,
                            item_count=group.item_count,
                        )
                    )
            dev_items.sort(key=lambda d: (-d.unique_bytes, d.subtype.value))

            # 3. Build Large Consumer Snapshot Items (Bounded Top 20)
            top_consumers: List[LargeConsumerSnapshotItem] = []
            if large_file_summary and large_file_summary.top_findings:
                for f in large_file_summary.top_findings[:20]:
                    top_consumers.append(
                        LargeConsumerSnapshotItem(
                            rank=f.rank,
                            path=f.path,
                            size_bytes=f.size_bytes,
                            category=f.category,
                            confidence=f.confidence,
                        )
                    )
            elif scan_result.items:
                sorted_items = sorted(scan_result.items, key=lambda it: -it.size_bytes)
                for rank_idx, item in enumerate(sorted_items[:20], start=1):
                    top_consumers.append(
                        LargeConsumerSnapshotItem(
                            rank=rank_idx,
                            path=item.path,
                            size_bytes=item.size_bytes,
                            category=item.category or SmartCategory.UNKNOWN,
                            confidence=ConfidenceLevel.HIGH,
                        )
                    )

            # 4. Unique bytes derivation
            unique_bytes = None
            if large_file_summary is not None:
                unique_bytes = large_file_summary.total_unique_bytes
            elif developer_summary is not None:
                unique_bytes = developer_summary.total_unique_bytes

            # 5. Persist Atomically
            conn = self._get_connection()
            try:
                with conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        """
                        INSERT INTO storage_snapshots (
                            snapshot_id, scan_id, timestamp, scope_id, root_path, status,
                            duration_seconds, files_count, directories_count, total_bytes,
                            unique_bytes, skipped_entries_count, permission_errors_count
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            snapshot_id,
                            effective_scan_id,
                            timestamp,
                            scan_result.scope_id.value,
                            scan_result.root_path,
                            scan_result.status.value,
                            scan_result.duration_seconds,
                            scan_result.files_count,
                            scan_result.directories_count,
                            scan_result.total_bytes,
                            unique_bytes,
                            scan_result.skipped_entries_count,
                            scan_result.permission_errors_count,
                        ),
                    )

                    for cat_item in category_items:
                        cursor.execute(
                            """
                            INSERT INTO category_storage_history (
                                snapshot_id, category, total_bytes, item_count
                            ) VALUES (?, ?, ?, ?)
                            """,
                            (snapshot_id, cat_item.category.value, cat_item.total_bytes, cat_item.item_count),
                        )

                    for dev_item in dev_items:
                        cursor.execute(
                            """
                            INSERT INTO developer_storage_history (
                                snapshot_id, subtype, total_bytes, unique_bytes, item_count
                            ) VALUES (?, ?, ?, ?, ?)
                            """,
                            (
                                snapshot_id,
                                dev_item.subtype.value,
                                dev_item.total_bytes,
                                dev_item.unique_bytes,
                                dev_item.item_count,
                            ),
                        )

                    for consumer in top_consumers:
                        cursor.execute(
                            """
                            INSERT INTO large_consumer_history (
                                snapshot_id, rank, path, size_bytes, category, confidence
                            ) VALUES (?, ?, ?, ?, ?, ?)
                            """,
                            (
                                snapshot_id,
                                consumer.rank,
                                consumer.path,
                                consumer.size_bytes,
                                consumer.category.value,
                                consumer.confidence.value,
                            ),
                        )

                # 6. Apply Retention Pruning
                if max_retention > 0:
                    self._prune_history_unlocked(conn, scan_result.scope_id, max_retention)

            finally:
                self._close_connection(conn)

            return StorageSnapshot(
                snapshot_id=snapshot_id,
                scan_id=effective_scan_id,
                timestamp=timestamp,
                scope_id=scan_result.scope_id,
                root_path=scan_result.root_path,
                status=scan_result.status,
                duration_seconds=scan_result.duration_seconds,
                files_count=scan_result.files_count,
                directories_count=scan_result.directories_count,
                total_bytes=scan_result.total_bytes,
                unique_bytes=unique_bytes,
                skipped_entries_count=scan_result.skipped_entries_count,
                permission_errors_count=scan_result.permission_errors_count,
                categories=category_items,
                developer_subtypes=dev_items,
                top_consumers=top_consumers,
            )

    def get_snapshot_by_id(self, snapshot_id: str) -> Optional[StorageSnapshot]:
        """Query a specific snapshot by its unique snapshot_id."""
        with self._lock:
            conn = self._get_connection()
            try:
                return self._fetch_full_snapshot(conn, "snapshot_id = ?", (snapshot_id,))
            finally:
                self._close_connection(conn)

    def get_snapshot_by_scan_id(self, scan_id: str) -> Optional[StorageSnapshot]:
        """Query a snapshot by its source scan_id."""
        with self._lock:
            conn = self._get_connection()
            try:
                return self._fetch_full_snapshot(conn, "scan_id = ?", (scan_id,))
            finally:
                self._close_connection(conn)

    def _get_snapshot_by_scan_id_unlocked(self, scan_id: str) -> Optional[StorageSnapshot]:
        conn = self._get_connection()
        try:
            return self._fetch_full_snapshot(conn, "scan_id = ?", (scan_id,))
        finally:
            self._close_connection(conn)

    def get_latest_snapshot(
        self,
        scope_id: ScopeIdentifier,
        root_path: Optional[str] = None,
    ) -> Optional[StorageSnapshot]:
        """Retrieve the most recent compatible snapshot for a given scope and optional normalized root path."""
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT snapshot_id FROM storage_snapshots WHERE scope_id = ? ORDER BY timestamp DESC",
                    (scope_id.value,),
                )
                rows = cursor.fetchall()
                for row in rows:
                    snap = self._fetch_full_snapshot(conn, "snapshot_id = ?", (row["snapshot_id"],))
                    if snap is not None:
                        target_root = root_path if root_path is not None else snap.root_path
                        if is_snapshot_scope_compatible(snap, scope_id, target_root):
                            return snap
                return None
            finally:
                self._close_connection(conn)

    def get_previous_snapshot(
        self,
        current_snapshot: StorageSnapshot,
    ) -> Optional[StorageSnapshot]:
        """
        Retrieve the latest comparable snapshot recorded prior to the given snapshot.
        Matches exact scope_id and canonical root_path with verified scope compatibility.
        """
        target_root = current_snapshot.root_path
        target_scope = current_snapshot.scope_id
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT snapshot_id FROM storage_snapshots
                    WHERE scope_id = ? AND timestamp < ?
                    ORDER BY timestamp DESC
                    """,
                    (
                        target_scope.value,
                        current_snapshot.timestamp,
                    ),
                )
                rows = cursor.fetchall()
                for row in rows:
                    snap = self._fetch_full_snapshot(conn, "snapshot_id = ?", (row["snapshot_id"],))
                    if snap is not None and is_snapshot_scope_compatible(snap, target_scope, target_root):
                        return snap
                return None
            finally:
                self._close_connection(conn)

    def get_snapshot_history(
        self,
        scope_id: ScopeIdentifier,
        limit: int = 50,
        root_path: Optional[str] = None,
    ) -> List[StorageSnapshot]:
        """Retrieve historical snapshots in descending chronological order matching exact scope and root_path with verified scope compatibility."""
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT snapshot_id FROM storage_snapshots WHERE scope_id = ? ORDER BY timestamp DESC",
                    (scope_id.value,),
                )
                rows = cursor.fetchall()
                snapshots: List[StorageSnapshot] = []
                for row in rows:
                    snap = self._fetch_full_snapshot(conn, "snapshot_id = ?", (row["snapshot_id"],))
                    if snap is not None:
                        target_root = root_path if root_path is not None else snap.root_path
                        if is_snapshot_scope_compatible(snap, scope_id, target_root):
                            snapshots.append(snap)
                            if len(snapshots) >= limit:
                                break
                return snapshots
            finally:
                self._close_connection(conn)

    def prune_history(self, scope_id: ScopeIdentifier, max_snapshots: int = DEFAULT_SNAPSHOT_RETENTION_COUNT) -> int:
        """Prune oldest snapshots exceeding max_snapshots for a designated scope."""
        with self._lock:
            conn = self._get_connection()
            try:
                return self._prune_history_unlocked(conn, scope_id, max_snapshots)
            finally:
                self._close_connection(conn)

    def _prune_history_unlocked(self, conn: sqlite3.Connection, scope_id: ScopeIdentifier, max_snapshots: int) -> int:
        """Internal helper to prune snapshots under existing lock and transaction."""
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT snapshot_id FROM storage_snapshots
            WHERE scope_id = ?
            ORDER BY timestamp DESC
            LIMIT -1 OFFSET ?
            """,
            (scope_id.value, max_snapshots),
        )
        expired_rows = cursor.fetchall()
        if not expired_rows:
            return 0

        expired_ids = [row["snapshot_id"] for row in expired_rows]
        placeholders = ",".join("?" * len(expired_ids))
        with conn:
            cursor.execute(
                f"DELETE FROM storage_snapshots WHERE snapshot_id IN ({placeholders})",
                tuple(expired_ids),
            )
        return len(expired_ids)

    def _fetch_full_snapshot(
        self,
        conn: sqlite3.Connection,
        where_clause: str,
        params: tuple,
    ) -> Optional[StorageSnapshot]:
        """Helper to reconstruct a complete StorageSnapshot from its child tables."""
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM storage_snapshots WHERE {where_clause} LIMIT 1", params)
        snap_row = cursor.fetchone()
        if snap_row is None:
            return None

        snap_id = snap_row["snapshot_id"]

        # Fetch categories
        cursor.execute(
            "SELECT category, total_bytes, item_count FROM category_storage_history WHERE snapshot_id = ? ORDER BY total_bytes DESC",
            (snap_id,),
        )
        cat_rows = cursor.fetchall()
        categories = [
            CategorySnapshotItem(
                category=SmartCategory(r["category"]),
                total_bytes=r["total_bytes"],
                item_count=r["item_count"],
            )
            for r in cat_rows
        ]

        # Fetch developer subtypes
        cursor.execute(
            "SELECT subtype, total_bytes, unique_bytes, item_count FROM developer_storage_history WHERE snapshot_id = ? ORDER BY unique_bytes DESC",
            (snap_id,),
        )
        dev_rows = cursor.fetchall()
        developer_subtypes = [
            DeveloperSnapshotItem(
                subtype=DeveloperStorageSubtype(r["subtype"]),
                total_bytes=r["total_bytes"],
                unique_bytes=r["unique_bytes"],
                item_count=r["item_count"],
            )
            for r in dev_rows
        ]

        # Fetch top consumers
        cursor.execute(
            "SELECT rank, path, size_bytes, category, confidence FROM large_consumer_history WHERE snapshot_id = ? ORDER BY rank ASC",
            (snap_id,),
        )
        consumer_rows = cursor.fetchall()
        top_consumers = [
            LargeConsumerSnapshotItem(
                rank=r["rank"],
                path=r["path"],
                size_bytes=r["size_bytes"],
                category=SmartCategory(r["category"]),
                confidence=ConfidenceLevel(r["confidence"]),
            )
            for r in consumer_rows
        ]

        return StorageSnapshot(
            snapshot_id=snap_row["snapshot_id"],
            scan_id=snap_row["scan_id"],
            timestamp=snap_row["timestamp"],
            scope_id=ScopeIdentifier(snap_row["scope_id"]),
            root_path=snap_row["root_path"],
            status=ScanStatus(snap_row["status"]),
            duration_seconds=snap_row["duration_seconds"],
            files_count=snap_row["files_count"],
            directories_count=snap_row["directories_count"],
            total_bytes=snap_row["total_bytes"],
            unique_bytes=snap_row["unique_bytes"],
            skipped_entries_count=snap_row["skipped_entries_count"],
            permission_errors_count=snap_row["permission_errors_count"],
            categories=categories,
            developer_subtypes=developer_subtypes,
            top_consumers=top_consumers,
        )
