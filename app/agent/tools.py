from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Optional, Sequence

from app.agent.models import AgentObservation
from app.analysis.developer_analyzer import DeveloperStorageAnalyzer
from app.analysis.models import RiskLevel, StorageCandidate, StorageCategory
from app.analysis.recommendations import SafetyStatus, StorageRecommendation
from app.analysis.storage_history import StorageHistoryRepository
from app.analysis.storage_trends import StorageTrendsEngine
from app.audit.repository import AuditRepository
from app.models.developer import DeveloperStorageSummary
from app.models.duplicate import DuplicateCluster, DuplicateScanSummary
from app.models.scan_result import ScanResult
from app.models.scan_scope import ScopeIdentifier
from app.models.storage_history import StorageTrendReport
from app.tools.storage_scanner import StorageItem, StorageScanner, format_bytes, format_bytes_decimal

ALLOWED_AGENT_TOOLS: set[str] = {
    "get_storage_overview",
    "get_storage_candidates",
    "get_candidate_details",
    "get_category_summary",
    "get_large_files",
    "get_recommendations",
    "get_audit_summary",
    "get_safety_policies",
    "get_storage_trends",
    "compare_scans",
    "get_duplicate_summary",
    "get_developer_storage_summary",
}


def _alias_and_redact_path(path_str: str) -> str:
    """Home-alias and redact sensitive directory paths."""
    if not path_str:
        return ""
    try:
        home_str = str(Path.home().resolve())
        if path_str.startswith(home_str):
            path_str = "~" + path_str[len(home_str):]
    except Exception:
        pass

    for sensitive in [".ssh", ".aws", ".gnupg", "Keychains", "Cookies", "Messages", "Mail", "IdentityServices"]:
        if sensitive in path_str:
            parts = path_str.split(sensitive)
            return parts[0] + f"{sensitive}/[REDACTED]"
    return path_str


class AgentToolRegistry:
    """
    Strictly allowlisted, read-only tool execution interface for the MacGuard Agent.

    Guarantees:
    - 100% Read-Only: Contains ZERO mutation, deletion, move, or execution capabilities.
    - Explicit Allowlist: Dispatches only to approved, registered tool methods.
    - Fail-Closed: Rejects any unlisted tool invocation.
    - Zero Secrets: Never receives or exposes cryptographic keys or HMAC managers.
    - Bounded Output: Limits analytical response sizes to protect LLM context windows.
    """

    def __init__(
        self,
        scanner: Optional[StorageScanner] = None,
        audit_repo: Optional[AuditRepository] = None,
        history_repo: Optional[StorageHistoryRepository] = None,
        trends_engine: Optional[StorageTrendsEngine] = None,
    ) -> None:
        self._scanner = scanner or StorageScanner()
        self._audit_repo = audit_repo or AuditRepository()
        self._history_repo = history_repo or StorageHistoryRepository()
        self._trends_engine = trends_engine or StorageTrendsEngine()

    def is_tool_allowed(self, tool_name: str) -> bool:
        """Check if a tool name is in the explicit allowlist."""
        return tool_name in ALLOWED_AGENT_TOOLS

    def execute_tool(
        self,
        tool_name: str,
        arguments: Optional[dict[str, Any]] = None,
        candidates: Optional[Sequence[StorageCandidate]] = None,
        recommendations: Optional[Sequence[StorageRecommendation]] = None,
        scan_result: Optional[ScanResult] = None,
        duplicate_clusters: Optional[Sequence[DuplicateCluster]] = None,
        duplicate_summary: Optional[DuplicateScanSummary] = None,
        developer_summary: Optional[DeveloperStorageSummary] = None,
        trend_report: Optional[StorageTrendReport] = None,
    ) -> AgentObservation:
        """
        Execute an allowlisted tool deterministically and return a structured observation.
        """
        args = arguments or {}

        if not self.is_tool_allowed(tool_name):
            return AgentObservation(
                tool_name=tool_name,
                success=False,
                error_message=f"Tool '{tool_name}' is forbidden or not in the explicit agent tool allowlist.",
            )

        try:
            if tool_name == "get_storage_overview":
                path = args.get("path", "/")
                usage = self._scanner.get_disk_usage(path)
                data = {
                    "path": _alias_and_redact_path(usage.path),
                    "total_bytes": usage.total_bytes,
                    "total_formatted": format_bytes_decimal(usage.total_bytes),
                    "used_bytes": usage.used_bytes,
                    "used_formatted": format_bytes_decimal(usage.used_bytes),
                    "free_bytes": usage.free_bytes,
                    "free_formatted": format_bytes_decimal(usage.free_bytes),
                    "usage_percent": round(usage.usage_percent, 2),
                }
                return AgentObservation(tool_name=tool_name, success=True, data=data)

            elif tool_name == "get_storage_candidates":
                cands = candidates or []
                data = [
                    {
                        "path": _alias_and_redact_path(c.path),
                        "size_bytes": c.size_bytes,
                        "size_formatted": format_bytes_decimal(c.size_bytes),
                        "category": c.category.value,
                        "risk_level": c.risk_level.value,
                        "confidence": round(c.confidence, 2),
                        "reason": c.reason,
                    }
                    for c in cands[:10]
                ]
                return AgentObservation(tool_name=tool_name, success=True, data=data)

            elif tool_name == "get_candidate_details":
                target_path = args.get("path", "")
                cands = candidates or []
                matching = next((c for c in cands if c.path == target_path or _alias_and_redact_path(c.path) == target_path), None)
                if matching:
                    data = {
                        "path": _alias_and_redact_path(matching.path),
                        "size_bytes": matching.size_bytes,
                        "size_formatted": format_bytes_decimal(matching.size_bytes),
                        "category": matching.category.value,
                        "risk_level": matching.risk_level.value,
                        "confidence": round(matching.confidence, 2),
                        "reason": matching.reason,
                        "recommendation": matching.recommendation,
                        "item_type": matching.item_type,
                    }
                    return AgentObservation(tool_name=tool_name, success=True, data=data)
                return AgentObservation(
                    tool_name=tool_name,
                    success=False,
                    error_message=f"Candidate path '{target_path}' not found in active scan results.",
                )

            elif tool_name == "get_category_summary":
                cands = candidates or []
                summary: dict[str, dict[str, Any]] = {}
                for c in cands:
                    cat_name = c.category.value
                    if cat_name not in summary:
                        summary[cat_name] = {"count": 0, "size_bytes": 0}
                    summary[cat_name]["count"] += 1
                    summary[cat_name]["size_bytes"] += c.size_bytes

                data = {
                    cat: {
                        "count": val["count"],
                        "size_bytes": val["size_bytes"],
                        "size_formatted": format_bytes_decimal(val["size_bytes"]),
                    }
                    for cat, val in summary.items()
                }
                return AgentObservation(tool_name=tool_name, success=True, data=data)

            elif tool_name == "get_large_files":
                limit = int(args.get("limit", 10))
                cands = candidates or []
                file_cands = [c for c in cands if c.item_type == "file"]
                top_files = sorted(file_cands, key=lambda x: x.size_bytes, reverse=True)[:limit]
                data = [
                    {
                        "path": _alias_and_redact_path(f.path),
                        "size_bytes": f.size_bytes,
                        "size_formatted": format_bytes_decimal(f.size_bytes),
                        "category": f.category.value,
                        "risk_level": f.risk_level.value,
                    }
                    for f in top_files
                ]
                return AgentObservation(tool_name=tool_name, success=True, data=data)

            elif tool_name == "get_recommendations":
                recs = recommendations or []
                data = []
                for r in recs[:10]:
                    rec_dict = {
                        "path": _alias_and_redact_path(r.candidate.path),
                        "size_bytes": r.candidate.size_bytes,
                        "size_formatted": format_bytes_decimal(r.candidate.size_bytes),
                        "category": r.candidate.category.value,
                        "risk_level": r.candidate.risk_level.value,
                        "action": r.action.value,
                        "safety_status": r.safety_status,
                        "requires_approval": r.requires_approval,
                        "rationale": r.rationale,
                    }
                    if r.historical_context is not None:
                        rec_dict["historical_context"] = r.historical_context.model_dump()
                    if r.duplicate_context is not None:
                        rec_dict["duplicate_context"] = r.duplicate_context.model_dump()
                    data.append(rec_dict)
                return AgentObservation(tool_name=tool_name, success=True, data=data)

            elif tool_name == "get_storage_trends":
                if trend_report is not None:
                    report = trend_report
                else:
                    scope_str = args.get("scope_id", "HOME")
                    try:
                        scope_enum = ScopeIdentifier(scope_str)
                    except ValueError:
                        scope_enum = ScopeIdentifier.HOME

                    latest_snap = self._history_repo.get_latest_snapshot(scope_enum)
                    if latest_snap is None:
                        return AgentObservation(
                            tool_name=tool_name,
                            success=True,
                            data={
                                "comparison_available": False,
                                "status": "NO_SCANS_RECORDED",
                                "message": "No historical scans have been recorded yet. Run a scan to establish a baseline.",
                            },
                        )
                    prev_snap = self._history_repo.get_previous_snapshot(latest_snap)
                    report = self._trends_engine.compare_snapshots(latest_snap, prev_snap)

                top_cats = []
                for ct in report.category_trends[:10]:
                    top_cats.append({
                        "category": ct.category.value if hasattr(ct.category, "value") else str(ct.category),
                        "current_bytes": ct.current_bytes,
                        "current_formatted": format_bytes_decimal(ct.current_bytes),
                        "previous_bytes": ct.previous_bytes,
                        "previous_formatted": format_bytes_decimal(ct.previous_bytes),
                        "change_bytes": ct.absolute_change,
                        "change_formatted": format_bytes_decimal(ct.absolute_change),
                        "percentage_change": round(ct.percentage_change, 1) if ct.percentage_change is not None else None,
                        "direction": ct.direction.value,
                        "explanation": ct.explanation,
                    })

                top_dev = []
                for dt in report.developer_trends[:10]:
                    top_dev.append({
                        "subtype": dt.subtype.value if hasattr(dt.subtype, "value") else str(dt.subtype),
                        "current_bytes": dt.current_bytes,
                        "current_formatted": format_bytes_decimal(dt.current_bytes),
                        "previous_bytes": dt.previous_bytes,
                        "previous_formatted": format_bytes_decimal(dt.previous_bytes),
                        "change_bytes": dt.absolute_change,
                        "change_formatted": format_bytes_decimal(dt.absolute_change),
                        "percentage_change": round(dt.percentage_change, 1) if dt.percentage_change is not None else None,
                        "direction": dt.direction.value,
                        "explanation": dt.explanation,
                    })

                data = {
                    "comparison_available": report.is_comparable,
                    "scope_id": report.scope_id.value if hasattr(report.scope_id, "value") else str(report.scope_id),
                    "root_path": _alias_and_redact_path(report.root_path),
                    "current_snapshot_id": report.current_snapshot_id,
                    "previous_snapshot_id": report.previous_snapshot_id,
                    "overall_trend": {
                        "metric": report.overall_trend.metric,
                        "current_value_formatted": format_bytes_decimal(report.overall_trend.current_value),
                        "previous_value_formatted": format_bytes_decimal(report.overall_trend.previous_value),
                        "change_formatted": format_bytes_decimal(report.overall_trend.absolute_change),
                        "percentage_change": round(report.overall_trend.percentage_change, 1) if report.overall_trend.percentage_change is not None else None,
                        "direction": report.overall_trend.direction.value,
                        "explanation": report.overall_trend.explanation,
                    },
                    "largest_growing_category": report.largest_growing_category.value if report.largest_growing_category else None,
                    "largest_growing_developer_subtype": report.largest_growing_developer_subtype.value if report.largest_growing_developer_subtype else None,
                    "top_growing_categories": top_cats,
                    "developer_trends": top_dev,
                    "notes": report.notes,
                }
                return AgentObservation(tool_name=tool_name, success=True, data=data)

            elif tool_name == "compare_scans":
                curr_id = args.get("current_snapshot_id")
                prev_id = args.get("baseline_snapshot_id")
                scope_str = args.get("scope_id", "HOME")

                snap_curr = None
                snap_prev = None

                if curr_id and prev_id:
                    snap_curr = self._history_repo.get_snapshot_by_id(curr_id)
                    snap_prev = self._history_repo.get_snapshot_by_id(prev_id)
                    if not snap_curr or not snap_prev:
                        return AgentObservation(
                            tool_name=tool_name,
                            success=False,
                            error_message=f"One or both snapshots could not be found: current='{curr_id}', baseline='{prev_id}'.",
                        )
                else:
                    try:
                        scope_enum = ScopeIdentifier(scope_str)
                    except ValueError:
                        scope_enum = ScopeIdentifier.HOME
                    snap_curr = self._history_repo.get_latest_snapshot(scope_enum)
                    if snap_curr is None:
                        return AgentObservation(
                            tool_name=tool_name,
                            success=True,
                            data={
                                "comparison_available": False,
                                "message": "No historical snapshots found to compare.",
                            },
                        )
                    snap_prev = self._history_repo.get_previous_snapshot(snap_curr)

                if snap_curr and snap_prev and snap_curr.scope_id != snap_prev.scope_id:
                    return AgentObservation(
                        tool_name=tool_name,
                        success=True,
                        data={
                            "comparison_available": False,
                            "is_comparable": False,
                            "reason": f"Incompatible scopes: {snap_curr.scope_id.value} vs {snap_prev.scope_id.value}. Scans from different scopes cannot be directly compared.",
                        },
                    )

                report = self._trends_engine.compare_snapshots(snap_curr, snap_prev)
                cat_diffs = []
                for ct in report.category_trends[:10]:
                    cat_diffs.append({
                        "category": ct.category.value if hasattr(ct.category, "value") else str(ct.category),
                        "current_formatted": format_bytes_decimal(ct.current_bytes),
                        "previous_formatted": format_bytes_decimal(ct.previous_bytes),
                        "delta_formatted": format_bytes_decimal(ct.absolute_change),
                        "percentage_change": round(ct.percentage_change, 1) if ct.percentage_change is not None else None,
                        "direction": ct.direction.value,
                    })

                data = {
                    "comparison_available": report.is_comparable,
                    "scope": report.scope_id.value if hasattr(report.scope_id, "value") else str(report.scope_id),
                    "current_snapshot_id": report.current_snapshot_id,
                    "previous_snapshot_id": report.previous_snapshot_id,
                    "current_timestamp": report.current_timestamp,
                    "previous_timestamp": report.previous_timestamp,
                    "overall_change_bytes": report.overall_trend.absolute_change,
                    "overall_change_formatted": format_bytes_decimal(report.overall_trend.absolute_change),
                    "overall_percentage_change": round(report.overall_trend.percentage_change, 1) if report.overall_trend.percentage_change is not None else None,
                    "overall_direction": report.overall_trend.direction.value,
                    "category_comparisons": cat_diffs,
                    "notes": report.notes,
                }
                return AgentObservation(tool_name=tool_name, success=True, data=data)

            elif tool_name == "get_duplicate_summary":
                clusters = duplicate_clusters or []
                summary = duplicate_summary

                if not clusters and not summary:
                    return AgentObservation(
                        tool_name=tool_name,
                        success=True,
                        data={
                            "data_available": False,
                            "total_clusters": 0,
                            "total_duplicate_files": 0,
                            "potential_reclaimable_bytes": 0,
                            "potential_reclaimable_formatted": "0 B",
                            "message": "No duplicate scan findings recorded for current scan.",
                        },
                    )

                total_clusters = summary.total_clusters if summary else len(clusters)
                total_files = summary.total_duplicate_files if summary else sum(len(c.files) for c in clusters)
                total_wasted = summary.potential_reclaimable_bytes if summary else sum(c.wasted_bytes for c in clusters)
                skipped_large = summary.skipped_large_files if summary else 0

                top_clusters_data = []
                sorted_clusters = sorted(clusters, key=lambda c: (c.wasted_bytes, c.file_size_bytes), reverse=True)[:5]
                for c in sorted_clusters:
                    is_hl = (c.wasted_bytes == 0)
                    top_clusters_data.append({
                        "cluster_id": c.cluster_id,
                        "file_size_formatted": format_bytes_decimal(c.file_size_bytes),
                        "duplicate_file_count": len(c.files),
                        "hardlink_count": c.hardlink_count,
                        "wasted_bytes": c.wasted_bytes,
                        "wasted_bytes_formatted": format_bytes_decimal(c.wasted_bytes),
                        "is_hardlink_only": is_hl,
                        "paths": [_alias_and_redact_path(f.path) for f in c.files[:4]],
                    })

                data = {
                    "data_available": True,
                    "total_clusters": total_clusters,
                    "total_duplicate_files": total_files,
                    "potential_reclaimable_bytes": total_wasted,
                    "potential_reclaimable_formatted": format_bytes_decimal(total_wasted),
                    "skipped_large_files": skipped_large,
                    "top_duplicate_clusters": top_clusters_data,
                }
                return AgentObservation(tool_name=tool_name, success=True, data=data)

            elif tool_name == "get_developer_storage_summary":
                dev_sum = developer_summary
                if dev_sum is None and scan_result is not None:
                    dev_analyzer = DeveloperStorageAnalyzer()
                    dev_sum = dev_analyzer.analyze(scan_result)

                if dev_sum is None:
                    return AgentObservation(
                        tool_name=tool_name,
                        success=True,
                        data={
                            "data_available": False,
                            "total_developer_bytes": 0,
                            "total_developer_formatted": "0 B",
                            "message": "No developer storage findings recorded for current scan.",
                        },
                    )

                groups_data = {}
                all_findings = []
                for g in dev_sum.groups:
                    g_name = g.subtype.value if hasattr(g.subtype, "value") else str(g.subtype)
                    groups_data[g_name] = {
                        "title": g.title,
                        "total_logical_bytes": g.total_logical_bytes,
                        "total_formatted": format_bytes_decimal(g.total_logical_bytes),
                        "unique_physical_bytes": g.unique_physical_bytes,
                        "item_count": g.item_count,
                        "stale_item_count": g.stale_item_count,
                        "stale_bytes": g.stale_bytes,
                    }
                    all_findings.extend(g.findings)

                top_findings = []
                sorted_findings = sorted(all_findings, key=lambda f: f.size_bytes, reverse=True)[:10]
                for f in sorted_findings:
                    cat_val = f.category.value if hasattr(f.category, "value") else str(f.category)
                    sub_val = f.subtype.value if hasattr(f.subtype, "value") else str(f.subtype)
                    top_findings.append({
                        "category": cat_val,
                        "subtype": sub_val,
                        "path": _alias_and_redact_path(f.path),
                        "size_bytes": f.size_bytes,
                        "size_formatted": format_bytes_decimal(f.size_bytes),
                        "stale_status": f.stale_status.value if hasattr(f.stale_status, "value") else str(f.stale_status),
                        "evidence": f.evidence,
                    })

                data = {
                    "data_available": True,
                    "total_developer_bytes": dev_sum.total_logical_bytes,
                    "total_developer_formatted": format_bytes_decimal(dev_sum.total_logical_bytes),
                    "total_unique_bytes": dev_sum.total_unique_bytes,
                    "total_unique_formatted": format_bytes_decimal(dev_sum.total_unique_bytes),
                    "total_findings_count": dev_sum.total_findings_count,
                    "developer_groups": groups_data,
                    "top_findings": top_findings,
                }
                return AgentObservation(tool_name=tool_name, success=True, data=data)

            elif tool_name == "get_audit_summary":
                limit = int(args.get("limit", 10))
                events = self._audit_repo.get_recent_events(limit=limit)
                data = [
                    {
                        "event_id": ev.event_id,
                        "timestamp": ev.timestamp.isoformat(),
                        "event_type": ev.event_type.value,
                        "status": ev.status,
                        "canonical_path": _alias_and_redact_path(ev.canonical_path),
                        "actor": ev.actor,
                        "reason": ev.reason,
                    }
                    for ev in events
                ]
                return AgentObservation(tool_name=tool_name, success=True, data=data)

            elif tool_name == "get_safety_policies":
                data = {
                    "permanent_deletion_enabled": False,
                    "supported_mutations": ["CONTROLLED_TRASH_MOVE"],
                    "trash_root": "~/.Trash",
                    "human_approval_mandatory": True,
                    "protected_paths": ["/System", "/usr", "/bin", "/sbin", "~/.ssh", "~/Documents", "~/Desktop"],
                    "high_risk_policy": "BLOCKED_FROM_AUTOMATED_CLEANUP",
                    "unknown_risk_policy": "CONSERVATIVE_NON_ACTION",
                    "integrity_verification_mandatory": True,
                }
                return AgentObservation(tool_name=tool_name, success=True, data=data)

            return AgentObservation(
                tool_name=tool_name,
                success=False,
                error_message=f"Handler for tool '{tool_name}' is unimplemented.",
            )

        except Exception as e:
            return AgentObservation(
                tool_name=tool_name,
                success=False,
                error_message=f"Tool execution encountered an error: {str(e)}",
            )
