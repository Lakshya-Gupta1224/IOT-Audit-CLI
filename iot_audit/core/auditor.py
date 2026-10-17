"""
auditor.py — Non-Destructive Vulnerability Audit Orchestrator

Dispatches protocol-specific probes and collects Finding objects.
All probes are read-only / connect-only — no state is modified on the target.

OWASP IoT Top 10 mappings and CWE references are embedded in each Finding.
"""

from __future__ import annotations

from typing import Optional

from rich.console import Console

from iot_audit.core.fingerprint import ServiceMap
from iot_audit.models import Finding
from iot_audit.modules.coap_probe import audit_coap
from iot_audit.modules.http_probe import audit_http
from iot_audit.modules.mqtt_probe import audit_mqtt
from iot_audit.modules.rtsp_probe import audit_rtsp
from iot_audit.utils.scoring import compute_cvss

console = Console(stderr=True)

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
    mqtt_ports = [s.port for s in smap.open_services if s.port == 1883 or s.service_guess == "MQTT"]
    for p in set(mqtt_ports):
        console.print(f"  [yellow]→ MQTT:{p} detected — running MQTT probes…[/yellow]")
        mqtt_findings = audit_mqtt(host, port=p, tls=False, timeout=timeout, verbose=verbose)
        findings.extend(mqtt_findings)

    mqtts_ports = [s.port for s in smap.open_services if s.port == 8883 or s.service_guess == "MQTTS"]
    for p in set(mqtts_ports):
        console.print(f"  [yellow]→ MQTTS:{p} detected — running TLS MQTT probes…[/yellow]")
        mqtt_findings = audit_mqtt(host, port=p, tls=True, timeout=timeout, verbose=verbose)
        findings.extend(mqtt_findings)

    # ── RTSP ──────────────────────────────────────────────────────────────────
    rtsp_ports = [s.port for s in smap.open_services if s.port in (554, 8554) or "RTSP" in s.service_guess]
    for p in set(rtsp_ports):
        console.print(f"  [yellow]→ RTSP:{p} detected — running RTSP probe…[/yellow]")
        rtsp_findings = audit_rtsp(host, port=p, timeout=timeout, verbose=verbose)
        findings.extend(rtsp_findings)

    # ── HTTP ──────────────────────────────────────────────────────────────────
    http_ports = [s.port for s in smap.open_services if s.port in (80, 8080, 8443) or "HTTP" in s.service_guess]
    for p in set(http_ports):
        console.print(f"  [yellow]→ HTTP:{p} detected — running HTTP probes…[/yellow]")
        http_findings = audit_http(host, port=p, timeout=timeout, verbose=verbose)
        findings.extend(http_findings)

    # ── CoAP ──────────────────────────────────────────────────────────────────
    coap_ports = [s.port for s in smap.open_services if s.port == 5683 or s.service_guess == "CoAP"]
    for p in set(coap_ports):
        console.print(f"  [yellow]→ CoAP:{p} detected — running CoAP probes…[/yellow]")
        coap_findings = audit_coap(host, port=p, timeout=timeout, verbose=verbose)
        findings.extend(coap_findings)

    # ── Telnet ────────────────────────────────────────────────────────────────
    telnet_ports = [s.port for s in smap.open_services if s.port in (23, 2323) or "Telnet" in s.service_guess]
    for telnet_port in set(telnet_ports):
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

