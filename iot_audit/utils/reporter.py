"""
reporter.py — Structured Report Generation Engine

Supports three output formats:
  1. table   : Rich colorized terminal table (default, no file write)
  2. json    : Machine-readable JSON with full finding details
  3. markdown: Publication-ready Markdown with executive summary and remediations

Usage:
    from iot_audit.utils.reporter import generate_report, print_table
    generate_report(findings, format="json", output_path="findings.json")
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from jinja2 import Environment, BaseLoader
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from iot_audit.models import Finding
from iot_audit.core.verify import VerifyResult
from iot_audit.utils.scoring import severity_color, OWASP_IOT_TOP10

console = Console()


# ── Console table output ──────────────────────────────────────────────────────


def print_scan_table(findings: list[Finding], target: str) -> None:
    """Print a Rich-formatted vulnerability summary table to the terminal."""

    table = Table(
        title=f"[bold]IoT Security Audit — {target}[/bold]",
        box=box.DOUBLE_EDGE,
        show_lines=True,
        header_style="bold magenta",
    )

    table.add_column("Host", style="cyan", no_wrap=True)
    table.add_column("Audit ID", style="bold", no_wrap=True)
    table.add_column("Protocol", justify="center")
    table.add_column("Finding")
    table.add_column("CVSS", justify="center")
    table.add_column("Severity", justify="center")
    table.add_column("Status", justify="center")

    for f in findings:
        sev_color = severity_color(f.severity)
        verdict_display = (
            f"[bold red]VULNERABLE[/bold red]"
            if f.verdict == "VULNERABLE"
            else (
                "[bold green]PROTECTED[/bold green]"
                if f.verdict == "PROTECTED"
                else "[yellow]UNKNOWN[/yellow]"
            )
        )
        score_str = f"[{sev_color}]{f.cvss_score:.1f}[/{sev_color}]" if f.cvss_score else "—"
        table.add_row(
            f.host,
            f.audit_id,
            f"{f.protocol}:{f.port}",
            f.title[:55],
            score_str,
            f"[{sev_color}]{f.severity}[/{sev_color}]",
            verdict_display,
        )

    console.print(table)
    _print_summary_panel(findings)


def _print_summary_panel(findings: list[Finding]) -> None:
    """Print a compact executive summary panel."""
    total = len(findings)
    vuln = [f for f in findings if f.verdict == "VULNERABLE"]
    prot = [f for f in findings if f.verdict == "PROTECTED"]
    critical = [f for f in vuln if f.severity == "CRITICAL"]
    high = [f for f in vuln if f.severity == "HIGH"]

    risk = (
        "[bold red]CRITICAL RISK[/bold red]"
        if critical
        else (
            "[red]HIGH RISK[/red]"
            if high
            else (
                "[yellow]MEDIUM RISK[/yellow]"
                if vuln
                else "[green]LOW / SECURE[/green]"
            )
        )
    )

    summary = (
        f"Posture: {risk}\n"
        f"Total probes: {total}   "
        f"Vulnerable: [red]{len(vuln)}[/red]   "
        f"Protected: [green]{len(prot)}[/green]   "
        f"Critical: [bold red]{len(critical)}[/bold red]   "
        f"High: [red]{len(high)}[/red]"
    )
    console.print(Panel(summary, title="Executive Summary", border_style="magenta"))


# ── JSON export ───────────────────────────────────────────────────────────────


def _to_json(
    findings: list[Finding],
    verify_results: list[VerifyResult],
    target: str,
    tool_version: str = "0.1.0",
) -> dict:
    """Build the full JSON report dict."""
    vuln_count = sum(1 for f in findings if f.verdict == "VULNERABLE")
    max_score = max((f.cvss_score for f in findings), default=0.0)

    return {
        "scan_metadata": {
            "tool": "iot-audit-cli",
            "version": tool_version,
            "target": target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_probes": len(findings),
            "vulnerable_count": vuln_count,
            "max_cvss_score": max_score,
        },
        "findings": [f.to_dict() for f in findings],
        "verification_results": [v.to_dict() for v in verify_results],
        "owasp_coverage": _owasp_coverage(findings),
    }


def _owasp_coverage(findings: list[Finding]) -> dict:
    """Map findings to OWASP IoT Top 10 categories."""
    coverage: dict[str, list[str]] = {}
    for f in findings:
        if f.owasp:
            key = f.owasp.split("–")[0].strip()  # e.g. "I1"
            coverage.setdefault(key, [])
            if f.audit_id not in coverage[key]:
                coverage[key].append(f.audit_id)
    return coverage


# ── Markdown template ─────────────────────────────────────────────────────────

_MD_TEMPLATE = """\
# IoT Security Assessment Report

**Target:** `{{ meta.target }}`
**Generated:** {{ meta.timestamp }}
**Tool:** {{ meta.tool }} v{{ meta.version }}

---

## Executive Summary

| Metric | Value |
|:---|:---|
| Total Probes Executed | {{ meta.total_probes }} |
| Vulnerabilities Found | **{{ meta.vulnerable_count }}** |
| Highest CVSS Score | **{{ meta.max_cvss_score }}** |
| Risk Posture | **{{ risk_posture }}** |

---

## Vulnerability Findings

{% for f in findings %}
### {{ f.audit_id }} — {{ f.title }}

| Field | Detail |
|:---|:---|
| **Host** | `{{ f.host }}:{{ f.port }}` |
| **Protocol** | {{ f.protocol }} |
| **Verdict** | {{ f.verdict }} |
| **OWASP IoT** | {{ f.owasp_category }} |
| **CWE** | {{ f.cwe }} |
| **CVSS v3.1 Score** | {{ f.cvss_score }} ({{ f.severity }}) |
| **CVSS Vector** | `{{ f.cvss_vector }}` |

**Evidence:**
> {{ f.evidence }}

**Remediation:**
```
{{ f.remediation }}
```

---
{% endfor %}

## Defensive Verification Results

{% if verify_results %}
| Check ID | Description | Status | Detail |
|:---|:---|:---|:---|
{% for v in verify_results %}| {{ v.check_id }} | {{ v.description }} | {{ v.status }} | {{ v.detail }} |
{% endfor %}
{% else %}
*No verification checks were run. Use `iot-audit verify` to confirm hardening.*
{% endif %}

## OWASP IoT Top 10 Coverage

| Category | Title | Probes |
|:---|:---|:---|
{% for key, ids in owasp_coverage.items() %}| {{ key }} | {{ owasp_titles[key] }} | {{ ids | join(', ') }} |
{% endfor %}

---
*Report generated by iot-audit-cli — Academic Research Tool*
*All probes are non-destructive and read-only.*
"""


def _to_markdown(
    findings: list[Finding],
    verify_results: list[VerifyResult],
    target: str,
) -> str:
    """Render the Jinja2 markdown template."""
    data = _to_json(findings, verify_results, target)
    meta = data["scan_metadata"]

    max_score = meta["max_cvss_score"]
    if max_score >= 9.0:
        risk_posture = "🔴 CRITICAL"
    elif max_score >= 7.0:
        risk_posture = "🟠 HIGH"
    elif max_score >= 4.0:
        risk_posture = "🟡 MEDIUM"
    elif max_score > 0:
        risk_posture = "🟢 LOW"
    else:
        risk_posture = "✅ SECURE"

    owasp_titles = {k: v["title"] for k, v in OWASP_IOT_TOP10.items()}

    env = Environment(loader=BaseLoader())
    tmpl = env.from_string(_MD_TEMPLATE)
    return tmpl.render(
        meta=meta,
        findings=data["findings"],
        verify_results=[v.to_dict() for v in verify_results],
        owasp_coverage=data["owasp_coverage"],
        owasp_titles=owasp_titles,
        risk_posture=risk_posture,
    )


# ── Public API ────────────────────────────────────────────────────────────────


def generate_report(
    findings: list[Finding],
    target: str,
    fmt: str = "table",
    output_path: Optional[str] = None,
    verify_results: Optional[list[VerifyResult]] = None,
) -> Optional[str]:
    """
    Generate a report in the specified format.

    Args:
        findings:      List of Finding objects from auditor
        target:        Target subnet or host string
        fmt:           "table" | "json" | "markdown"
        output_path:   File path to write (required for json/markdown)
        verify_results: Optional verification results to include

    Returns:
        File path written, or None for table output.
    """
    verify_results = verify_results or []

    if fmt == "table":
        print_scan_table(findings, target)
        return None

    elif fmt == "json":
        data = _to_json(findings, verify_results, target)
        content = json.dumps(data, indent=2)
        _write(output_path or "findings.json", content)
        return output_path

    elif fmt == "markdown":
        content = _to_markdown(findings, verify_results, target)
        _write(output_path or "audit_report.md", content)
        return output_path

    else:
        raise ValueError(f"Unknown format: {fmt!r}. Choose from: table, json, markdown")


def _write(path: str, content: str) -> None:
    """Write content to file, creating parent directories as needed."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    try:
        console.print(f"[green][+] Report written to:[/green] {p.resolve()}")
    except UnicodeEncodeError:
        print(f"[+] Report written to: {p.resolve()}")

