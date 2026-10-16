"""
auditor.py — Non-Destructive Vulnerability Audit Orchestrator

Dispatches protocol-specific probes and collects Finding objects.
All probes are read-only / connect-only — no state is modified on the target.

OWASP IoT Top 10 mappings and CWE references are embedded in each Finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from rich.console import Console

from iot_audit.core.fingerprint import ServiceMap
from iot_audit.modules.http_probe import audit_http
from iot_audit.modules.mqtt_probe import audit_mqtt
from iot_audit.modules.rtsp_probe import audit_rtsp
from iot_audit.utils.scoring import compute_cvss

console = Console(stderr=True)

# ── Finding model ─────────────────────────────────────────────────────────────


@dataclass
class Finding:
    """
    A single vulnerability finding produced by an audit probe.

    Attributes:
        audit_id    : Unique probe identifier (e.g. AUDIT-MQTT-01)
        host        : Target IP
        port        : Target port
        protocol    : e.g. "MQTT", "RTSP", "HTTP"
        verdict     : "VULNERABLE" | "PROTECTED" | "UNKNOWN"
        title       : Short human-readable description
        evidence    : Raw evidence string (e.g. CONNACK return code)
        owasp       : OWASP IoT category (e.g. "I1 – Weak Passwords")
        cwe         : CWE identifier (e.g. "CWE-306")
        cvss_vector : CVSS v3.1 vector string
        cvss_score  : Calculated base score (0.0–10.0)
        severity    : "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"INFO"
        remediation : Actionable remediation instructions
    """

    audit_id: str
    host: str
    port: int
    protocol: str
    verdict: str
    title: str
    evidence: str = ""
    owasp: str = ""
    cwe: str = ""
    cvss_vector: str = ""
    cvss_score: float = 0.0
    severity: str = "INFO"
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "audit_id": self.audit_id,
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "verdict": self.verdict,
            "title": self.title,
            "evidence": self.evidence,
            "owasp_category": self.owasp,
            "cwe": self.cwe,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "severity": self.severity,
            "remediation": self.remediation,
        }


# ── Audit dispatcher ──────────────────────────────────────────────────────────


def run_audit(
    host: str,
    smap: ServiceMap,
    timeout: float = 2.0,
    verbose: bool = False,
) -> list[Finding]:
    """
    Run all applicable audit probes against *host* based on its *smap*.

    Args:
        host:    Target IP/hostname
        smap:    Fingerprint results from fingerprint.fingerprint()
        timeout: Per-probe timeout in seconds
        verbose: Enable probe-level logging

    Returns:
        List of Finding objects (one per probe executed).
    """
    findings: list[Finding] = []

    console.print(f"\n[bold magenta]🔬 Starting vulnerability audit on {host}[/bold magenta]")

    # ── MQTT ──────────────────────────────────────────────────────────────────
    if smap.has_port(1883):
        console.print("  [yellow]→ MQTT:1883 detected — running MQTT probes…[/yellow]")
        mqtt_findings = audit_mqtt(host, port=1883, tls=False, timeout=timeout, verbose=verbose)
        findings.extend(mqtt_findings)

    if smap.has_port(8883):
        console.print("  [yellow]→ MQTTS:8883 detected — running TLS MQTT probes…[/yellow]")
        mqtt_findings = audit_mqtt(host, port=8883, tls=True, timeout=timeout, verbose=verbose)
        findings.extend(mqtt_findings)

    # ── RTSP ──────────────────────────────────────────────────────────────────
    for rtsp_port in (554, 8554):
        if smap.has_port(rtsp_port):
            console.print(f"  [yellow]→ RTSP:{rtsp_port} detected — running RTSP probe…[/yellow]")
            rtsp_findings = audit_rtsp(host, port=rtsp_port, timeout=timeout, verbose=verbose)
            findings.extend(rtsp_findings)

    # ── HTTP ──────────────────────────────────────────────────────────────────
    for http_port in (80, 8080, 8443):
        if smap.has_port(http_port):
            console.print(f"  [yellow]→ HTTP:{http_port} detected — running HTTP probes…[/yellow]")
            http_findings = audit_http(host, port=http_port, timeout=timeout, verbose=verbose)
            findings.extend(http_findings)

    # ── Telnet ────────────────────────────────────────────────────────────────
    for telnet_port in (23, 2323):
        if smap.has_port(telnet_port):
            findings.append(
                Finding(
                    audit_id="AUDIT-TELNET-01",
                    host=host,
                    port=telnet_port,
                    protocol="Telnet",
                    verdict="VULNERABLE",
                    title="Insecure Legacy Telnet Daemon Active",
                    evidence=f"TCP port {telnet_port} is open and accepting connections",
                    owasp="I5 – Use of Insecure or Outdated Components",
                    cwe="CWE-319",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    cvss_score=9.1,
                    severity="CRITICAL",
                    remediation=(
                        "Disable Telnet daemon immediately. Replace with SSH (port 22). "
                        "Apply firewall rules to block ports 23 and 2323 externally."
                    ),
                )
            )

    if not findings:
        console.print(
            f"  [dim]No auditable services found on {host} — "
            "check fingerprint results or expand port list.[/dim]"
        )

    vuln_count = sum(1 for f in findings if f.verdict == "VULNERABLE")
    console.print(
        f"[bold {'red' if vuln_count else 'green'}]"
        f"✔ Audit complete — {vuln_count} vulnerability/ies found on {host}.[/bold {'red' if vuln_count else 'green'}]"
    )

    return findings

