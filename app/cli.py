from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Callable, Optional, TextIO

# Ensure project root is in sys.path when running file directly
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from app.analysis.models import RiskLevel
from app.analysis.recommendations import RecommendationEngine
from app.analysis.storage_analyzer import StorageAnalyzer
from app.audit.repository import AuditRepository
from app.llm.explanation_service import ExplanationService
from app.llm.models import AnalysisContext
from app.safety.approval_service import ApprovalService
from app.safety.path_validator import Operation
from app.tools.storage_scanner import StorageScanner, format_bytes


def display_audit_log(
    audit_repo: Optional[AuditRepository] = None,
    limit: int = 25,
    out: Optional[TextIO] = None,
) -> None:
    """
    Display recent persistent SQLite audit log entries in a read-only table format.
    """
    if out is None:
        out = sys.stdout
    if audit_repo is None:
        audit_repo = AuditRepository()

    separator = "=" * 80
    print(separator, file=out)
    print("MacGuard AI — Persistent Audit Log (Read-Only)", file=out)
    print(separator, file=out)

    events = audit_repo.get_recent_events(limit=limit)
    if not events:
        print("No audit events recorded in database.", file=out)
        print(separator, file=out)
        return

    print(f"{'TIMESTAMP (UTC)':<20} | {'EVENT TYPE':<26} | {'STATUS':<10} | {'PATH'}", file=out)
    print("-" * 80, file=out)
    for ev in events:
        ts = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        print(f"{ts:<20} | {ev.event_type.value:<26} | {ev.status:<10} | {ev.canonical_path}", file=out)
        if ev.reason:
            print(f"   ↳ Rationale: {ev.reason}", file=out)
        if ev.execution_id:
            print(f"   ↳ Execution ID: {ev.execution_id} | Approval ID: {ev.approval_id[:8]}...", file=out)

    print(separator, file=out)
    print(f"Total entries shown: {len(events)}", file=out)


def generate_diagnostic_report(
    scanner: Optional[StorageScanner] = None,
    root_path: str = "/",
    home_path: Optional[str] = None,
    top_dirs_limit: int = 10,
    top_files_limit: int = 10,
) -> str:
    """
    Generate a read-only storage diagnostic report.

    This function performs read-only inspection using StorageScanner
    and does not modify any files on the filesystem.
    """
    if scanner is None:
        scanner = StorageScanner()

    if home_path is None:
        home_path = str(Path.home())

    lines: list[str] = []
    separator = "=" * 60

    lines.append(separator)
    lines.append("MacGuard AI - Storage Diagnostic Report")
    lines.append(separator)
    lines.append("")

    # A. Disk Usage
    disk_usage = scanner.get_disk_usage(root_path)
    lines.append("[Disk Usage]")
    lines.append(f"Target Path:     {disk_usage.path}")
    lines.append(f"Total Space:     {format_bytes(disk_usage.total_bytes)}")
    lines.append(f"Used Space:      {format_bytes(disk_usage.used_bytes)}")
    lines.append(f"Free Space:      {format_bytes(disk_usage.free_bytes)}")
    lines.append(f"Percentage Used: {disk_usage.usage_percent:.2f}%")
    lines.append("")

    # B. Largest Immediate Directories
    lines.append(f"[Largest Immediate Directories ({root_path})]")
    top_dirs = scanner.get_top_directories(path=root_path, limit=top_dirs_limit)
    if top_dirs:
        for idx, item in enumerate(top_dirs, start=1):
            formatted_size = format_bytes(item.size_bytes)
            lines.append(f"{idx:2d}. {item.path} - {formatted_size}")
    else:
        lines.append("No directories found or accessible.")
    lines.append("")

    # C. Largest Files in Home Directory
    lines.append(f"[Largest Files in Home Directory ({home_path})]")
    top_files = scanner.get_large_files(path=home_path, limit=top_files_limit)
    if top_files:
        for idx, item in enumerate(top_files, start=1):
            formatted_size = format_bytes(item.size_bytes)
            lines.append(f"{idx:2d}. {item.path} - {formatted_size}")
    else:
        lines.append("No files found or accessible.")
    lines.append("")

    # D. Safety Statement
    lines.append(separator)
    lines.append("Safety Status: No files were modified.")
    lines.append(separator)

    return "\n".join(lines)


def run_review_workflow(
    scanner: Optional[StorageScanner] = None,
    analyzer: Optional[StorageAnalyzer] = None,
    rec_engine: Optional[RecommendationEngine] = None,
    approval_service: Optional[ApprovalService] = None,
    exp_service: Optional[ExplanationService] = None,
    audit_repo: Optional[AuditRepository] = None,
    root_path: str = "/",
    home_path: Optional[str] = None,
    top_dirs_limit: int = 5,
    top_files_limit: int = 5,
    enable_trash: bool = False,
    input_func: Optional[Callable[[str], str]] = None,
    out: Optional[TextIO] = None,
) -> None:
    """
    Interactive terminal review and explicit human approval workflow.

    Safety Guarantee:
    - In dry-run mode: Performs ZERO filesystem mutations.
    - In trash mode: Moves explicitly approved items ONLY to macOS Trash. Zero permanent deletion.
    - Approval default is REJECTION ('N').
    - Authorizes only cryptographic HMAC approval records for future execution verification.
    - Persistent SQLite audit logging enabled.
    """
    if scanner is None:
        scanner = StorageScanner()
    if analyzer is None:
        analyzer = StorageAnalyzer()
    if rec_engine is None:
        rec_engine = RecommendationEngine()
    if approval_service is None:
        approval_service = ApprovalService()
    if exp_service is None:
        exp_service = ExplanationService()
    if audit_repo is None:
        audit_repo = AuditRepository()
    if home_path is None:
        home_path = str(Path.home())
    if input_func is None:
        input_func = input
    if out is None:
        out = sys.stdout

    separator = "=" * 65

    print(separator, file=out)
    if enable_trash:
        print("CONTROLLED TRASH EXECUTION", file=out)
        print("Approved files will be moved to macOS Trash.", file=out)
        print("No permanent deletion will occur.", file=out)
    else:
        print("MacGuard AI — Storage Review & Human Confirmation", file=out)
        print("Non-Destructive Mode: Zero files will be deleted or modified.", file=out)
    print(separator, file=out)
    print("", file=out)

    # 1. Scan and Analyze
    top_dirs = scanner.get_top_directories(path=root_path, limit=top_dirs_limit)
    top_files = scanner.get_large_files(path=home_path, limit=top_files_limit)
    all_items = top_dirs + top_files

    candidates = analyzer.analyze_items(all_items, deduplicate=True)
    recommendations = rec_engine.recommend_many(candidates)
    review_items = approval_service.create_review_items(recommendations)

    total_size = sum(c.size_bytes for c in candidates)
    safety_summary = {
        "LOW": sum(1 for c in candidates if c.risk_level == RiskLevel.LOW),
        "MEDIUM": sum(1 for c in candidates if c.risk_level == RiskLevel.MEDIUM),
        "HIGH": sum(1 for c in candidates if c.risk_level == RiskLevel.HIGH),
        "UNKNOWN": sum(1 for c in candidates if c.risk_level == RiskLevel.UNKNOWN),
    }
    context = AnalysisContext(
        scan_id="scan-cli-review",
        scan_path=root_path,
        total_scanned_items=len(candidates),
        total_size_bytes=total_size,
        candidates=candidates,
        recommendations=recommendations,
        safety_summary=safety_summary,
    )
    explanation = exp_service.explain_deterministic(context)

    # 2. Print Explanation
    print(f"Summary: {explanation.summary}", file=out)
    print("", file=out)
    print("Key Findings:", file=out)
    for finding in explanation.key_findings:
        print(f"  • {finding}", file=out)
    print("", file=out)

    # 3. Present Review Items
    print(separator, file=out)
    print(f"Found {len(review_items)} storage candidates for review:", file=out)
    print(separator, file=out)

    for idx, item in enumerate(review_items, start=1):
        cand = item.candidate
        status_label = "ELIGIBLE_FOR_REVIEW" if item.is_eligible_for_approval else "MANUAL_REVIEW_REQUIRED"
        print(f"\n{idx}. {cand.path}", file=out)
        print(f"   Size:     {format_bytes(cand.size_bytes)}", file=out)
        print(f"   Category: {cand.category.value}", file=out)
        print(f"   Risk:     {item.risk_level.value.upper()}", file=out)
        print(f"   Status:   {status_label}", file=out)
        print(f"   Action:   {item.recommendation.action.value}", file=out)
        print(f"   Reason:   {item.recommendation.rationale}", file=out)

    print("", file=out)
    print(separator, file=out)

    # 4. Interactive Review Prompt
    try:
        choice = input_func("Select an item number to review (or 'q' to quit): ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nExiting review.", file=out)
        return

    if not choice or choice.lower() == "q":
        print("Review session closed.", file=out)
        return

    try:
        item_idx = int(choice) - 1
        if item_idx < 0 or item_idx >= len(review_items):
            print("Invalid item selection.", file=out)
            return
    except ValueError:
        print("Invalid input. Please enter a valid item number.", file=out)
        return

    selected_item = review_items[item_idx]
    cand = selected_item.candidate
    rec = selected_item.recommendation

    print(f"\nReviewing candidate: {cand.path}", file=out)
    print(f"Risk Level: {selected_item.risk_level.value.upper()}", file=out)
    print(f"Safety Status: {selected_item.safety_status}", file=out)

    if not selected_item.is_eligible_for_approval:
        print(
            "\n[BLOCKED] This item is high-risk or unclassified. MacGuard AI mandates manual user inspection "
            "and cannot create a cleanup approval for this path.",
            file=out,
        )
        return

    print("\n⚠️  Human Approval Required", file=out)
    print("MacGuard has identified this item as eligible for review.", file=out)
    if enable_trash:
        print("Explicit approval will move this item to the macOS Trash (~/.Trash).", file=out)
        print("No permanent deletion will occur.", file=out)
    else:
        print("This approval DOES NOT delete or modify anything now.", file=out)
        print("It only creates a cryptographically signed authorization record for future execution verification.", file=out)

    try:
        confirm = input_func("\nDo you explicitly approve this proposed operation? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        confirm = "n"

    if confirm == "y":
        record, err = approval_service.request_approval(rec, operation=Operation.CLEAN)
        if err:
            print(f"\n[ERROR] Approval request failed: {err}", file=out)
            return

        approved_record, app_msg = approval_service.approve(
            record.approval_id,
            explicit_consent=True,
            reason="Human confirmed approval in CLI",
        )
        if approved_record:
            is_valid, v_msg = approval_service.verify_and_authorize(
                approved_record,
                target_path=approved_record.path,
                operation=Operation.CLEAN,
            )
            print(f"\n[APPROVED & HMAC-SIGNED]", file=out)
            print(f"Approval ID:  {approved_record.approval_id}", file=out)
            print(f"Target Path:  {approved_record.path}", file=out)
            print(f"Operation:    {approved_record.operation.value}", file=out)
            print(f"Risk Level:   {approved_record.risk_level.value}", file=out)
            print(f"Expires At:   {approved_record.expires_at.isoformat()}", file=out)
            print(f"Signature:    {approved_record.token_signature[:16]}...", file=out)
            print(f"Verified:     {v_msg}", file=out)

            from app.execution.executor import DryRunExecutor
            from app.execution.models import ExecutionAction, ExecutionStatus
            from app.execution.planner import ExecutionPlanner
            from app.execution.trash_executor import TrashExecutor

            planner = ExecutionPlanner(approval_service=approval_service)

            if enable_trash:
                plan, plan_msg = planner.create_plan(
                    approval_record=approved_record,
                    action=ExecutionAction.TRASH,
                )
                if plan and plan.status == ExecutionStatus.PLANNED:
                    trash_exec = TrashExecutor(
                        approval_service=approval_service,
                        audit_repo=audit_repo,
                    )
                    trash_res = trash_exec.execute_trash(plan)
                    print(f"\n[CONTROLLED TRASH EXECUTION RESULT]", file=out)
                    print(f"Execution ID: {trash_res.execution_id}", file=out)
                    print(f"Action:       {trash_res.action.value}", file=out)
                    print(f"Status:       {trash_res.status.value}", file=out)
                    print(f"Verified:     {trash_res.verified}", file=out)
                    print(f"Integrity:    {trash_res.integrity_verified}", file=out)
                    print(f"Destination:  {trash_res.trash_destination_path}", file=out)
                    print(f"Reclaimed:    {format_bytes(trash_res.reclaimed_bytes)}", file=out)
                    print(f"Message:      {trash_res.message}", file=out)
                    print(f"Safety Note:  {trash_res.safety_confirmation}", file=out)
                else:
                    print(f"\n[EXECUTION BLOCKED] {plan_msg}", file=out)
            else:
                print("Status:       READY_FOR_FUTURE_EXECUTION (Zero files were modified).", file=out)
                plan, plan_msg = planner.create_plan(
                    approval_record=approved_record,
                    action=ExecutionAction.DRY_RUN,
                )
                if plan and plan.status == ExecutionStatus.PLANNED:
                    executor = DryRunExecutor(approval_service=approval_service)
                    dry_res = executor.execute_dry_run(plan)
                    print(f"\n[DRY-RUN SIMULATION]", file=out)
                    print(f"Action:       {dry_res.action.value}", file=out)
                    print(f"Status:       {dry_res.status.value}", file=out)
                    print(f"Reclaimable:  {format_bytes(dry_res.simulated_reclaimed_bytes)}", file=out)
                    print(f"Safety Note:  {dry_res.safety_confirmation}", file=out)
        else:
            print(f"\n[ERROR] Approval grant failed: {app_msg}", file=out)
    else:
        record, _ = approval_service.request_approval(rec, operation=Operation.CLEAN)
        if record:
            approval_service.reject(record.approval_id, reason="Human rejected in CLI")
        print("\n[REJECTED] Operation was not approved. Default is rejection. No authorization granted.", file=out)


def run_cli(
    args: Optional[list[str]] = None,
    out: Optional[TextIO] = None,
) -> int:
    """
    Parse command-line arguments and run storage diagnostics, review, trash execution, or audit viewing.
    """
    if out is None:
        out = sys.stdout

    parser = argparse.ArgumentParser(
        prog="macguard",
        description="MacGuard AI - Safety-first, storage diagnostic, review & controlled trash tool.",
    )
    parser.add_argument(
        "--root-path",
        default="/",
        help="Root path for disk usage and immediate directory inspection (default: /)",
    )
    parser.add_argument(
        "--home-path",
        default=str(Path.home()),
        help="Home directory path for large file scanning (default: user home directory)",
    )
    parser.add_argument(
        "--top-dirs-limit",
        type=int,
        default=10,
        help="Number of largest immediate directories to display (default: 10)",
    )
    parser.add_argument(
        "--top-files-limit",
        type=int,
        default=10,
        help="Number of largest files in home directory to display (default: 10)",
    )
    parser.add_argument(
        "--review",
        action="store_true",
        help="Launch the interactive storage review and explicit human approval workflow.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run storage diagnostics and launch dry-run review simulation (DRY-RUN ONLY).",
    )
    parser.add_argument(
        "--trash",
        action="store_true",
        help="Launch interactive review with controlled move to macOS Trash for approved items.",
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Display recent persistent audit log entries (Read-Only).",
    )

    parsed_args = parser.parse_args(args)

    if parsed_args.audit:
        display_audit_log(out=out)
    elif parsed_args.trash:
        run_review_workflow(
            root_path=parsed_args.root_path,
            home_path=parsed_args.home_path,
            top_dirs_limit=parsed_args.top_dirs_limit,
            top_files_limit=parsed_args.top_files_limit,
            enable_trash=True,
            out=out,
        )
    elif parsed_args.review or parsed_args.dry_run:
        run_review_workflow(
            root_path=parsed_args.root_path,
            home_path=parsed_args.home_path,
            top_dirs_limit=parsed_args.top_dirs_limit,
            top_files_limit=parsed_args.top_files_limit,
            enable_trash=False,
            out=out,
        )
    else:
        report = generate_diagnostic_report(
            root_path=parsed_args.root_path,
            home_path=parsed_args.home_path,
            top_dirs_limit=parsed_args.top_dirs_limit,
            top_files_limit=parsed_args.top_files_limit,
        )
        print(report, file=out)

    return 0


def main() -> None:
    """CLI entrypoint."""
    sys.exit(run_cli())


if __name__ == "__main__":
    main()

