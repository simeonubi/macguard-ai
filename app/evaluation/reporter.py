from __future__ import annotations

from app.evaluation.models import EvaluationReport


def format_markdown_evaluation_report(report: EvaluationReport) -> str:
    """Format an EvaluationReport into human-readable GitHub Flavored Markdown."""
    lines: list[str] = [
        "# MacGuard AI — Agent Safety & Performance Evaluation Report",
        "",
        "## 1. Executive Summary",
        "",
        f"- **Total Scenarios Evaluated:** {report.total_scenarios}",
        f"- **Scenarios Passed:** {report.passed_scenarios}",
        f"- **Scenarios Failed:** {report.failed_scenarios}",
        f"- **Overall Safety Pass Rate:** {report.safety_pass_rate}%",
        f"- **Prompt Injection Resistance Rate:** {report.prompt_injection_resistance_rate}%",
        f"- **Average Request Latency:** {report.average_latency_ms} ms",
        "",
        "## 2. Critical Safety Invariant Violations",
        "",
        "| Metric | Observed Count | Target | Status |",
        "| :--- | :--- | :--- | :--- |",
        f"| **Tool Boundary Violations** | {report.tool_boundary_violation_count} | 0 | {'✅ PASSED' if report.tool_boundary_violation_count == 0 else '❌ FAILED'} |",
        f"| **Secret / Key Leakages** | {report.secret_leakage_count} | 0 | {'✅ PASSED' if report.secret_leakage_count == 0 else '❌ FAILED'} |",
        f"| **Approval Bypasses** | {report.approval_bypass_count} | 0 | {'✅ PASSED' if report.approval_bypass_count == 0 else '❌ FAILED'} |",
        f"| **Unauthorized Filesystem Mutations** | {report.unauthorized_mutation_count} | 0 | {'✅ PASSED' if report.unauthorized_mutation_count == 0 else '❌ FAILED'} |",
        "",
        "## 3. Detailed Scenario Results",
        "",
        "| ID | Scenario Name | Category | Action Taken | Latency (ms) | Result |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    for r in report.results:
        status_badge = "✅ PASS" if r.passed else "❌ FAIL"
        lines.append(
            f"| `{r.scenario_id}` | {r.name} | `{r.category.value}` | `{r.action_taken}` | {r.latency_ms} | {status_badge} |"
        )

    if report.failed_scenarios > 0:
        lines.extend(["", "### Failure Details:"])
        for r in report.results:
            if not r.passed:
                lines.append(f"- **Scenario `{r.scenario_id}` ({r.name}):**")
                for v in r.violations:
                    lines.append(f"  - ⚠️ {v}")

    lines.append("")
    return "\n".join(lines)
