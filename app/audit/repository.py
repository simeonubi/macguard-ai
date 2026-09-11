from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from app.analysis.models import RiskLevel
from app.audit.models import AuditEvent, AuditEventType, ExecutionRecord
from app.safety.path_validator import Operation


class AuditRepository:
    """
    Persistent, thread-safe SQLite audit repository for MacGuard AI.

    Guarantees:
    - 100% Parameterized SQL queries (zero string concatenation / SQL injection prevention).
    - Configurable database path via MACGUARD_AUDIT_DB environment variable or constructor.
    - Captures correlated execution_id and approval_id for complete audit trail reconstruction.
    - Detects interrupted/incomplete executions without performing automatic unsafe retries.
    - Zero secrets logged.
    """

    def __init__(self, db_path: Optional[Union[str, Path]] = None) -> None:
        self._lock = threading.Lock()
        if db_path is not None:
            self._db_path = str(db_path)
        else:
            env_db = os.getenv("MACGUARD_AUDIT_DB")
            if env_db:
                self._db_path = env_db
            else:
                default_dir = Path.home() / ".macguard"
                default_dir.mkdir(parents=True, exist_ok=True)
                self._db_path = str(default_dir / "macguard_audit.db")

        self._is_memory = self._db_path == ":memory:"
        if not self._is_memory and not self._db_path.startswith(":"):
            Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)

        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Initialize SQLite database schema with indexes."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    approval_id TEXT NOT NULL,
                    execution_id TEXT NOT NULL,
                    canonical_path TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    status TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    metadata TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS execution_records (
                    execution_id TEXT PRIMARY KEY,
                    approval_id TEXT NOT NULL,
                    canonical_path TEXT NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    reclaimed_bytes INTEGER NOT NULL DEFAULT 0,
                    destination_path TEXT NOT NULL DEFAULT '',
                    verified INTEGER NOT NULL DEFAULT 0,
                    message TEXT NOT NULL DEFAULT ''
                )
                """
            )
            # Create indexes for performance and query correlation
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_approval_id ON audit_events(approval_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_execution_id ON audit_events(execution_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON audit_events(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_executions_approval ON execution_records(approval_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_executions_status ON execution_records(status)")
            conn.commit()

    def record_event(self, event: AuditEvent) -> None:
        """Insert an immutable audit event record using parameterized SQL."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO audit_events (
                    event_id, timestamp, event_type, approval_id, execution_id,
                    canonical_path, operation, risk_level, status, actor, reason, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.timestamp.isoformat(),
                    event.event_type.value,
                    event.approval_id,
                    event.execution_id,
                    event.canonical_path,
                    event.operation.value,
                    event.risk_level.value,
                    event.status,
                    event.actor,
                    event.reason,
                    json.dumps(event.metadata),
                ),
            )
            conn.commit()

    def record_execution_start(
        self,
        execution_id: str,
        approval_id: str,
        canonical_path: str,
        action: str = "TRASH",
        status: str = "IN_PROGRESS",
        start_time: Optional[datetime] = None,
    ) -> None:
        """Record the initiation of an execution run for crash/interruption tracking."""
        st_iso = (start_time or datetime.now(timezone.utc)).isoformat()
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO execution_records (
                    execution_id, approval_id, canonical_path, action, status,
                    start_time, end_time, reclaimed_bytes, destination_path, verified, message
                ) VALUES (?, ?, ?, ?, ?, ?, NULL, 0, '', 0, '')
                """,
                (execution_id, approval_id, canonical_path, action, status, st_iso),
            )
            conn.commit()

    def record_execution_finish(
        self,
        execution_id: str,
        status: str,
        verified: bool,
        reclaimed_bytes: int = 0,
        destination_path: str = "",
        message: str = "",
    ) -> None:
        """Update an execution record upon completion or failure."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE execution_records
                SET status = ?, end_time = ?, reclaimed_bytes = ?, destination_path = ?, verified = ?, message = ?
                WHERE execution_id = ?
                """,
                (status, now, reclaimed_bytes, destination_path, 1 if verified else 0, message, execution_id),
            )
            conn.commit()

    def get_events_by_approval_id(self, approval_id: str) -> list[AuditEvent]:
        """Query audit events associated with a specific approval ID."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM audit_events WHERE approval_id = ? ORDER BY timestamp ASC",
                (approval_id,),
            )
            rows = cursor.fetchall()
            return [self._row_to_event(row) for row in rows]

    def get_events_by_execution_id(self, execution_id: str) -> list[AuditEvent]:
        """Query audit events associated with a specific execution ID."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM audit_events WHERE execution_id = ? ORDER BY timestamp ASC",
                (execution_id,),
            )
            rows = cursor.fetchall()
            return [self._row_to_event(row) for row in rows]

    def get_recent_events(self, limit: int = 50) -> list[AuditEvent]:
        """Retrieve recent audit events ordered by timestamp descending."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
            rows = cursor.fetchall()
            return [self._row_to_event(row) for row in rows]

    def get_filtered_events(
        self,
        event_type: Optional[Union[AuditEventType, str]] = None,
        status: Optional[str] = None,
        path_query: Optional[str] = None,
        approval_id: Optional[str] = None,
        execution_id: Optional[str] = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """
        Query audit events with optional parameterized filters.
        """
        clauses: list[str] = []
        params: list[Any] = []

        if event_type:
            et_val = event_type.value if isinstance(event_type, AuditEventType) else str(event_type)
            clauses.append("event_type = ?")
            params.append(et_val)

        if status:
            clauses.append("status = ?")
            params.append(status)

        if path_query:
            clauses.append("canonical_path LIKE ?")
            params.append(f"%{path_query}%")

        if approval_id:
            clauses.append("approval_id = ?")
            params.append(approval_id)

        if execution_id:
            clauses.append("execution_id = ?")
            params.append(execution_id)

        where_sql = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        query_sql = f"SELECT * FROM audit_events{where_sql} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query_sql, params)
            rows = cursor.fetchall()
            return [self._row_to_event(row) for row in rows]


    def get_execution_record(self, execution_id: str) -> Optional[ExecutionRecord]:
        """Retrieve a specific execution record."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM execution_records WHERE execution_id = ?",
                (execution_id,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return self._row_to_execution_record(row)

    def get_incomplete_executions(self) -> list[ExecutionRecord]:
        """
        Identify execution records that were started but never finalized (crash/interruption detection).
        """
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM execution_records
                WHERE status IN ('IN_PROGRESS', 'EXECUTION_CLAIMED') AND end_time IS NULL
                ORDER BY start_time DESC
                """
            )
            rows = cursor.fetchall()
            return [self._row_to_execution_record(row) for row in rows]

    def _row_to_event(self, row: sqlite3.Row) -> AuditEvent:
        return AuditEvent(
            event_id=row["event_id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            event_type=AuditEventType(row["event_type"]),
            approval_id=row["approval_id"],
            execution_id=row["execution_id"],
            canonical_path=row["canonical_path"],
            operation=Operation(row["operation"]),
            risk_level=RiskLevel(row["risk_level"]),
            status=row["status"],
            actor=row["actor"],
            reason=row["reason"],
            metadata=json.loads(row["metadata"]),
        )

    def _row_to_execution_record(self, row: sqlite3.Row) -> ExecutionRecord:
        return ExecutionRecord(
            execution_id=row["execution_id"],
            approval_id=row["approval_id"],
            canonical_path=row["canonical_path"],
            action=row["action"],
            status=row["status"],
            start_time=datetime.fromisoformat(row["start_time"]),
            end_time=datetime.fromisoformat(row["end_time"]) if row["end_time"] else None,
            reclaimed_bytes=row["reclaimed_bytes"],
            destination_path=row["destination_path"],
            verified=bool(row["verified"]),
            message=row["message"],
        )
