"""
cli.py — iot-audit-cli Main CLI Entrypoint

Commands:
  scan    : Discover IoT devices on a subnet via ARP/SSDP/mDNS
  audit   : Run full vulnerability assessment against target(s)
  verify  : Validate applied security hardening controls
  report  : Re-generate a report from a saved JSON findings file

Usage examples:
  iot-audit scan   -t 192.168.1.0/24
  iot-audit audit  -t 192.168.1.101 -f json -o findings.json
  iot-audit verify -t 192.168.1.101 -u admin -P secret
  iot-audit report -i findings.json -f markdown -o report.md
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich import print as rprint

from iot_audit import __version__

app = typer.Typer(
    name="iot-audit",
    help=(
        "[bold cyan]IoT Security Posture & Vulnerability Assessment Framework[/bold cyan]\n\n"
        "Non-destructive OWASP IoT Top 10 scanner for academic research testbeds.\n"
        "All probes are read-only and safe for lab environments."
    ),
    rich_markup_mode="rich",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()

# ── Version callback ──────────────────────────────────────────────────────────


def version_callback(value: bool) -> None:
    if value:
        rprint(f"[cyan]iot-audit-cli[/cyan] version [bold]{__version__}[/bold]")
        raise typer.Exit()


# ── Common options ────────────────────────────────────────────────────────────

_opt_target = typer.Option(
    ..., "--target", "-t",
    help="Target CIDR subnet (e.g. 192.168.1.0/24) or single IP.",
    show_default=False,
)
_opt_ports = typer.Option(
    None, "--ports", "-p",
    help="Comma-separated custom port list (default: standard IoT suite).",
)
_opt_timeout = typer.Option(0.5, "--timeout", help="Socket timeout in seconds.")
_opt_output = typer.Option(None, "--output", "-o", help="Output file path for report.")
_opt_format = typer.Option("table", "--format", "-f", help="Output format: table | json | markdown.")
_opt_username = typer.Option("", "--user", "-u", help="Username for verification testing.")
_opt_password = typer.Option("", "--pass", "-P", help="Password for verification testing.")
_opt_verbose = typer.Option(False, "--verbose", "-v", help="Enable verbose debug output.")
_opt_no_arp = typer.Option(False, "--no-arp", help="Skip Layer-2 ARP sweep (no administrator privilege required).")


# ── scan command ──────────────────────────────────────────────────────────────


@app.command()
def scan(
    target: str = _opt_target,
    timeout: float = _opt_timeout,
    ports: Optional[str] = _opt_ports,
    format: str = _opt_format,
    output: Optional[str] = _opt_output,
    verbose: bool = _opt_verbose,
    no_arp: bool = _opt_no_arp,
) -> None:
    """
    [bold]Discover IoT devices[/bold] on a subnet via ARP sweep, UPnP/SSDP, and mDNS.

    Outputs a device inventory table with IP, MAC, vendor (OUI), and hostname.
    Automatically runs service fingerprinting on discovered hosts.

    Examples:

        iot-audit scan -t 192.168.1.0/24

        iot-audit scan -t 192.168.1.0/24 -f json -o devices.json
    """
    _print_banner()

    from iot_audit.core.discovery import discover
    from iot_audit.core.fingerprint import fingerprint, DEFAULT_TCP_PORTS, DEFAULT_UDP_PORTS
    from rich.table import Table
    from rich import box

    port_list_tcp = _parse_ports(ports) if ports else DEFAULT_TCP_PORTS

    devices = discover(
        target,
        timeout=max(timeout, 1.0),
        verbose=verbose,
        no_arp=no_arp,
        probe_ports=port_list_tcp,
    )

    if not devices:
        console.print("[yellow]⚠  No devices discovered. Check your interface/permissions.[/yellow]")
        raise typer.Exit(1)

    # Fingerprint each discovered device
    all_service_maps = {}
    for dev in devices:
        smap = fingerprint(
            dev.ip,
            tcp_ports=port_list_tcp,
            timeout=timeout,
            verbose=verbose,
        )
        all_service_maps[dev.ip] = smap

    # Display results table
    table = Table(
        title=f"[bold]Device Discovery — {target}[/bold]",
        box=box.DOUBLE_EDGE,
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("IP Address", style="cyan")
    table.add_column("MAC Address")
    table.add_column("Vendor (OUI)")
    table.add_column("Hostname")
    table.add_column("Open Services")

    for dev in devices:
        smap = all_service_maps.get(dev.ip)
        services_str = (
            ", ".join(
                f"{s.service_guess}:{s.port}" for s in smap.open_services
            )
            if smap else "—"
        )
        table.add_row(
            dev.ip,
            dev.mac,
            dev.vendor,
            dev.hostname or "—",
            services_str or "[dim]none detected[/dim]",
        )

    console.print(table)

    if format == "json":
        from iot_audit.utils.reporter import resolve_report_path
        target_path = resolve_report_path(output, "devices.json")
        data = {
            "scan_target": target,
            "devices": [
                {
                    "ip": d.ip,
                    "mac": d.mac,
                    "vendor": d.vendor,
                    "hostname": d.hostname,
                    "open_services": [
                        {"port": s.port, "protocol": s.protocol, "service": s.service_guess}
                        for s in all_service_maps.get(d.ip, _empty_smap(d.ip)).open_services
                    ],
                }
                for d in devices
            ],
        }
        p = Path(target_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
        console.print(f"[green][+] Scan results saved to {p.resolve()}[/green]")


# ── audit command ─────────────────────────────────────────────────────────────


@app.command()
def audit(
    target: str = _opt_target,
    ports: Optional[str] = _opt_ports,
    timeout: float = _opt_timeout,
    format: str = _opt_format,
    output: Optional[str] = _opt_output,
    verbose: bool = _opt_verbose,
    no_arp: bool = _opt_no_arp,
) -> None:
    """
    [bold]Run a full vulnerability audit[/bold] against a target IP or subnet.

    Executes MQTT, RTSP, HTTP, CoAP, and Telnet probes mapped to OWASP IoT
    Top 10 and scored with CVSS v3.1 base metrics.

    Examples:

        iot-audit audit -t 192.168.1.101

        iot-audit audit -t 192.168.1.0/24 -f json -o findings.json

        iot-audit audit -t 192.168.1.101 -p 1883,554,80 -f markdown -o report.md
    """
    _print_banner()

    from iot_audit.core.discovery import discover, DiscoveredDevice
    from iot_audit.core.fingerprint import fingerprint, DEFAULT_TCP_PORTS
    from iot_audit.core.auditor import run_audit
    from iot_audit.utils.reporter import generate_report

    port_list_tcp = _parse_ports(ports) if ports else DEFAULT_TCP_PORTS

    # Resolve targets — single IP or subnet
    targets = _resolve_targets(target, timeout, verbose, no_arp=no_arp, probe_ports=port_list_tcp)

    all_findings = []
    for host in targets:
        smap = fingerprint(
            host,
            tcp_ports=port_list_tcp,
            timeout=timeout,
            verbose=verbose,
        )
        findings = run_audit(host, smap, timeout=timeout * 4, verbose=verbose)
        all_findings.extend(findings)

    if not all_findings:
        console.print("[yellow]⚠  No auditable services found. Try expanding port list with -p.[/yellow]")
        raise typer.Exit(0)

    generate_report(all_findings, target=target, fmt=format, output_path=output)


# ── verify command ────────────────────────────────────────────────────────────


@app.command()
def verify(
    target: str = _opt_target,
    ports: Optional[str] = _opt_ports,
    username: str = _opt_username,
    password: str = _opt_password,
    timeout: float = _opt_timeout,
    verbose: bool = _opt_verbose,
) -> None:
    """
    [bold]Validate security hardening[/bold] on a target device.

    Verifies that applied controls (auth, ACLs, TLS, HTTPS redirect) are
    actually enforced. Run AFTER applying remediation steps.

    Examples:

        iot-audit verify -t 192.168.1.101

        iot-audit verify -t 192.168.1.101 -u admin -P securepass --ports 1883,8883,80
    """
    _print_banner()

    from iot_audit.core.verify import run_verification

    port_list = _parse_ports(ports) if ports else [1883, 8883, 554, 80]

    run_verification(
        host=target,
        ports=port_list,
        username=username,
        password=password,
        timeout=max(timeout, 1.0),
        verbose=verbose,
    )


# ── report command ────────────────────────────────────────────────────────────


@app.command()
def report(
    input: str = typer.Option(..., "--input", "-i", help="Path to findings JSON file."),
    format: str = _opt_format,
    output: Optional[str] = _opt_output,
) -> None:
    """
    [bold]Regenerate a report[/bold] from a previously saved findings JSON file.

    Useful for producing Markdown reports from a JSON audit run in CI/CD.

    Examples:

        iot-audit report -i findings.json -f markdown -o report.md

        iot-audit report -i findings.json -f table
    """
    from iot_audit.models import Finding
    from iot_audit.utils.reporter import generate_report

    try:
        raw = json.loads(Path(input).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        console.print(f"[red]✗ Could not read {input}: {exc}[/red]")
        raise typer.Exit(1)

    target = raw.get("scan_metadata", {}).get("target", "unknown")
    findings = [
        Finding(
            audit_id=f.get("audit_id", ""),
            host=f.get("host", ""),
            port=f.get("port", 0),
            protocol=f.get("protocol", ""),
            verdict=f.get("verdict", "UNKNOWN"),
            title=f.get("title", ""),
            evidence=f.get("evidence", ""),
            owasp=f.get("owasp_category", ""),
            cwe=f.get("cwe", ""),
            cvss_vector=f.get("cvss_vector", ""),
            cvss_score=f.get("cvss_score", 0.0),
            severity=f.get("severity", "INFO"),
            remediation=f.get("remediation", ""),
        )
        for f in raw.get("findings", [])
    ]

    generate_report(findings, target=target, fmt=format, output_path=output)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _print_banner() -> None:
    console.print(
        Panel.fit(
            f"[bold cyan]iot-audit-cli[/bold cyan] v{__version__}\n"
            "[dim]OWASP IoT Top 10 · CVSS v3.1 · Non-Destructive · Academic Research[/dim]",
            border_style="cyan",
        )
    )


def _parse_ports(port_str: str) -> list[int]:
    """Parse a comma-separated port string into a list of ints."""
    try:
        return [int(p.strip()) for p in port_str.split(",") if p.strip()]
    except ValueError:
        console.print(f"[red]✗ Invalid port list: {port_str!r}[/red]")
        raise typer.Exit(1)


def _resolve_targets(
    target: str,
    timeout: float,
    verbose: bool,
    no_arp: bool = False,
    probe_ports: Optional[list[int]] = None,
) -> list[str]:
    """Return list of host IPs to audit. Discovers subnet, returns single IP if /32."""
    import ipaddress

    if "/" not in target:
        return [target]

    network = ipaddress.ip_network(target, strict=False)
    if network.num_addresses <= 2:
        return [str(h) for h in network.hosts()]

    from iot_audit.core.discovery import discover
    devices = discover(
        target,
        timeout=max(timeout, 1.0),
        verbose=verbose,
        no_arp=no_arp,
        probe_ports=probe_ports,
    )
    return [d.ip for d in devices]


def _empty_smap(ip: str):
    from iot_audit.core.fingerprint import ServiceMap
    return ServiceMap(host=ip)


# ── Entrypoint ────────────────────────────────────────────────────────────────


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", "-V",
        callback=version_callback,
        is_eager=True,
        help="Show tool version and exit.",
    ),
) -> None:
    """IoT Security Posture & Vulnerability Assessment Framework."""
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())


if __name__ == "__main__":
    app()

