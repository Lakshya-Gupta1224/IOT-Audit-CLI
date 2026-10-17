"""
fingerprint.py — IoT Protocol Service Fingerprinting Engine

Probes a set of IoT-relevant TCP/UDP ports on a target host using
non-blocking sockets with configurable timeouts. Captures banner strings
where available.

Default IoT port suite:
  TCP  23, 2323 : Telnet / legacy daemon
  TCP  80, 8080, 8443 : HTTP web management
  TCP  554, 8554 : RTSP media / camera streaming
  TCP  1883      : MQTT (plaintext)
  TCP  8883      : MQTT over TLS
  UDP  5683      : CoAP (Constrained Application Protocol)

Safety: connect-only probes — no data is written beyond the initial
        TCP SYN or minimal protocol banner request.
"""

from __future__ import annotations

import socket
import ssl
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

from rich.console import Console

console = Console(stderr=True)

# ── Port definitions ─────────────────────────────────────────────────────────

DEFAULT_TCP_PORTS: list[int] = [23, 80, 443, 554, 1883, 2323, 8080, 8081, 8443, 8554, 8883]
DEFAULT_UDP_PORTS: list[int] = [5683]

# ── Data models ──────────────────────────────────────────────────────────────


@dataclass
class ServiceInfo:
    """Result of probing a single port on a single host."""

    host: str
    port: int
    protocol: str  # "tcp" | "udp"
    open: bool
    banner: str = ""
    tls: bool = False
    latency_ms: float = 0.0
    service_guess: str = ""  # e.g. "MQTT", "RTSP", "HTTP"
    error: str = ""


@dataclass
class ServiceMap:
    """Aggregated fingerprint results for one host."""

    host: str
    services: list[ServiceInfo] = field(default_factory=list)

    @property
    def open_services(self) -> list[ServiceInfo]:
        return [s for s in self.services if s.open]

    def has_port(self, port: int) -> bool:
        return any(s.port == port and s.open for s in self.services)

    def get_service(self, port: int) -> Optional[ServiceInfo]:
        for s in self.services:
            if s.port == port and s.open:
                return s
        return None


# ── Service name heuristics ───────────────────────────────────────────────────

_PORT_GUESS: dict[int, str] = {
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    554: "RTSP",
    1883: "MQTT",
    2323: "Telnet-Alt",
    5683: "CoAP",
    8080: "HTTP-Alt",
    8081: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8554: "RTSP-Alt",
    8883: "MQTTS",
}

_BANNER_GUESS: list[tuple[bytes, str]] = [
    (b"MQTT", "MQTT"),
    (b"RTSP", "RTSP"),
    (b"HTTP", "HTTP"),
    (b"SSH", "SSH"),
    (b"220 ", "FTP/SMTP"),
]


def _guess_service(port: int, banner: bytes) -> str:
    for sig, name in _BANNER_GUESS:
        if sig in banner:
            return name
    return _PORT_GUESS.get(port, "unknown")


# ── TCP probe ────────────────────────────────────────────────────────────────

# Minimal banner-trigger payloads (safe reads — no writes to device state)
_BANNER_PROBES: dict[int, bytes] = {
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8081: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
    554: b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n",
    8554: b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n",
    1883: (
        # MQTT CONNECT packet: minimal anonymous attempt for banner — checked in auditor
        b"\x10\x0e"  # fixed header + remaining length 14
        b"\x00\x04MQTT"  # protocol name
        b"\x04"  # protocol level 4 (MQTT 3.1.1)
        b"\x00"  # connect flags: no auth, clean session
        b"\x00\x3c"  # keep-alive 60s
        b"\x00\x02id"  # client ID "id"
    ),
}


def _probe_tcp(
    host: str,
    port: int,
    timeout: float = 0.5,
    grab_banner: bool = True,
) -> ServiceInfo:
    """Attempt a TCP connection; optionally grab the banner."""
    import time

    t0 = time.monotonic()
    info = ServiceInfo(host=host, port=port, protocol="tcp", open=False)

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            info.latency_ms = (time.monotonic() - t0) * 1000
            info.open = True

            # Check for TLS on known secure ports
            if port in (443, 8443, 8883):
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    tls_sock = ctx.wrap_socket(sock, server_hostname=host)
                    info.tls = True
                    # Send probe over TLS
                    probe = _BANNER_PROBES.get(port, b"")
                    if probe and grab_banner:
                        tls_sock.sendall(probe)
                        raw = tls_sock.recv(512)
                        info.banner = raw.decode(errors="replace").strip()
                except ssl.SSLError:
                    info.tls = False  # TLS not negotiated

            else:
                # Plaintext banner grab
                probe = _BANNER_PROBES.get(port, b"")
                if probe and grab_banner:
                    try:
                        sock.sendall(probe)
                        sock.settimeout(timeout)
                        raw = sock.recv(512)
                        info.banner = raw.decode(errors="replace").strip()
                    except (socket.timeout, OSError):
                        pass

    except (ConnectionRefusedError, OSError):
        info.error = "refused"
    except socket.timeout:
        info.error = "timeout"
    except Exception as exc:
        info.error = str(exc)

    info.service_guess = _guess_service(port, info.banner.encode() if info.banner else b"")
    return info


# ── UDP probe (CoAP) ─────────────────────────────────────────────────────────

# CoAP GET request for /.well-known/core (RFC 6690) — safe discovery probe
_COAP_DISCOVERY = (
    b"\x40\x01"  # Ver=1, T=CON, TKL=0, Code=0.01 GET
    b"\x00\x01"  # Message ID
    b"\xbb.well-known\x04core"  # URI-Path options
)


def _probe_udp_coap(host: str, port: int = 5683, timeout: float = 1.0) -> ServiceInfo:
    """Send a CoAP GET /.well-known/core and inspect the response."""
    import time

    t0 = time.monotonic()
    info = ServiceInfo(host=host, port=port, protocol="udp", open=False)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_COAP_DISCOVERY, (host, port))
        data, _ = sock.recvfrom(1024)
        info.open = True
        info.latency_ms = (time.monotonic() - t0) * 1000
        info.service_guess = "CoAP"
        # Parse CoAP response code (byte 2, upper nibble=class, lower=detail)
        if len(data) >= 2:
            code_byte = data[1]
            cls = (code_byte >> 5) & 0x07
            detail = code_byte & 0x1F
            info.banner = f"CoAP {cls}.{detail:02d}"
    except socket.timeout:
        info.error = "no-response"
    except OSError as exc:
        info.error = str(exc)
    finally:
        sock.close()

    return info


# ── Main fingerprint orchestrator ─────────────────────────────────────────────


def fingerprint(
    host: str,
    tcp_ports: Optional[list[int]] = None,
    udp_ports: Optional[list[int]] = None,
    timeout: float = 0.5,
    verbose: bool = False,
    max_workers: int = 32,
) -> ServiceMap:
    """
    Probe *host* on all specified ports concurrently.

    Args:
        host:        Target IP or hostname
        tcp_ports:   List of TCP ports (defaults to DEFAULT_TCP_PORTS)
        udp_ports:   List of UDP ports (defaults to DEFAULT_UDP_PORTS)
        timeout:     Socket connection timeout in seconds
        verbose:     Print per-port results to stderr
        max_workers: Thread pool size

    Returns:
        ServiceMap with all probe results.
    """
    tcp_ports = tcp_ports or DEFAULT_TCP_PORTS
    udp_ports = udp_ports or DEFAULT_UDP_PORTS

    smap = ServiceMap(host=host)

    console.print(f"[cyan]🛰  Fingerprinting {host} ({len(tcp_ports)} TCP + {len(udp_ports)} UDP ports)…[/cyan]")

    # TCP probes — concurrent
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_probe_tcp, host, p, timeout): p for p in tcp_ports}
        for fut in as_completed(futures):
            info = fut.result()
            smap.services.append(info)
            if verbose:
                status = "[green]OPEN[/green]" if info.open else "[dim]closed[/dim]"
                console.print(
                    f"  TCP {info.port:5d} {status}  "
                    f"{info.service_guess:<10} {info.banner[:60]!r}"
                )

    # UDP probes — sequential (low volume)
    for port in udp_ports:
        if port == 5683:
            info = _probe_udp_coap(host, port, timeout=max(timeout, 1.0))
        else:
            info = ServiceInfo(host=host, port=port, protocol="udp", open=False, error="unsupported")
        smap.services.append(info)
        if verbose and info.open:
            console.print(f"  UDP {port:5d} [green]OPEN[/green]  {info.service_guess}  {info.banner}")

    open_count = len(smap.open_services)
    console.print(
        f"[bold green]✔ Fingerprint complete — {open_count} open service(s) on {host}.[/bold green]"
    )
    return smap

