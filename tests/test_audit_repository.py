from __future__ import annotations

import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.analysis.models import RiskLevel
from app.audit.models import AuditEvent, AuditEventType, ExecutionRecord
from app.audit.repository import AuditRepository
from app.safety.path_validator import Operation


def test_audit_repository_initialization_and_schema():
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = Path(temp_dir) / "test_audit.db"
        repo = AuditRepository(db_path=db_path)

        assert db_path.exists()
        events = repo.get_recent_events()
        assert len(events) == 0


def test_audit_repository_record_event_and_query():
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = Path(temp_dir) / "test_audit.db"
        repo = AuditRepository(db_path=db_path)

        app_id = secrets.token_hex(16)
        exec_id = secrets.token_hex(8)

        event = AuditEvent(
            event_type=AuditEventType.APPROVAL_REQUESTED,
            approval_id=app_id,
            execution_id=exec_id,
            canonical_path="/Users/test/Library/Caches/sample",
            operation=Operation.CLEAN,
            risk_level=RiskLevel.LOW,
            status="PENDING",
            actor="safety_engine",
            reason="User requested approval review",
            metadata={"estimated_bytes": 1024},
        )

        repo.record_event(event)

        recent = repo.get_recent_events(limit=10)
        assert len(recent) == 1
        assert recent[0].approval_id == app_id
        assert recent[0].execution_id == exec_id
        assert recent[0].event_type == AuditEventType.APPROVAL_REQUESTED
        assert recent[0].metadata["estimated_bytes"] == 1024

        by_app = repo.get_events_by_approval_id(app_id)
        assert len(by_app) == 1
        assert by_app[0].event_id == event.event_id

        by_exec = repo.get_events_by_execution_id(exec_id)
        assert len(by_exec) == 1
        assert by_exec[0].event_id == event.event_id


def test_audit_repository_execution_lifecycle_tracking():
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = Path(temp_dir) / "test_audit.db"
        repo = AuditRepository(db_path=db_path)

        app_id = secrets.token_hex(16)
        exec_id = secrets.token_hex(8)
        start_time = datetime.now(timezone.utc)

        # 1. Start execution -> IN_PROGRESS
        repo.record_execution_start(
            execution_id=exec_id,
            approval_id=app_id,
            canonical_path="/Users/test/Library/Caches/cache_dir",
            action="TRASH",
            start_time=start_time,
        )

        rec = repo.get_execution_record(exec_id)
        assert rec is not None
        assert rec.status == "IN_PROGRESS"
        assert rec.verified is False

        # Incomplete execution is detected
        incomplete = repo.get_incomplete_executions()
        assert len(incomplete) == 1
        assert incomplete[0].execution_id == exec_id

        # 2. Finish execution -> TRASH_SUCCEEDED
        repo.record_execution_finish(
            execution_id=exec_id,
            status="TRASH_SUCCEEDED",
            reclaimed_bytes=50000,
            destination_path="/Users/test/.Trash/MacGuard_xyz/cache_dir",
            verified=True,
            message="Verified move to Trash",
        )

        rec_finished = repo.get_execution_record(exec_id)
        assert rec_finished is not None
        assert rec_finished.status == "TRASH_SUCCEEDED"
        assert rec_finished.verified is True
        assert rec_finished.reclaimed_bytes == 50000
        assert rec_finished.end_time is not None

        # Incomplete execution list is now empty
        assert len(repo.get_incomplete_executions()) == 0


def test_audit_repository_parameterized_sql_injection_safety():
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = Path(temp_dir) / "test_audit.db"
        repo = AuditRepository(db_path=db_path)

        malicious_path = "/Users/test/Library/Caches/'; DROP TABLE audit_events; --"
        app_id = secrets.token_hex(16)

        event = AuditEvent(
            event_type=AuditEventType.APPROVAL_REQUESTED,
            approval_id=app_id,
            canonical_path=malicious_path,
            status="PENDING",
            reason="Malicious path injection attempt",
        )
        repo.record_event(event)

        events = repo.get_recent_events()
        assert len(events) == 1
        assert events[0].canonical_path == malicious_path
