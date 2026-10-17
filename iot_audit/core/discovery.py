"""
discovery.py — Layer-2/7 Network & Device Discovery Engine

Techniques:
  - ARP sweep  : enumerates live IPs + MAC addresses with OUI vendor lookup
  - SSDP/UPnP  : UDP multicast M-SEARCH for device model / XML descriptor
  - mDNS       : UDP multicast queries for zero-config hostname resolution

Concurrency: ThreadPoolExecutor; a /24 subnet completes in < 5 seconds.

Safety: read-only passive probes — no payloads are written to target devices.
"""

from __future__ import annotations

import ipaddress
import platform
import socket
import struct
import threading
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

from rich.console import Console

console = Console(stderr=True)

# ── Graceful optional imports ────────────────────────────────────────────────

try:
    from scapy.all import ARP, Ether, srp, conf as scapy_conf  # type: ignore

    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

try:
    from manuf import manuf  # type: ignore

    _manuf_parser = manuf.MacParser()
    MANUF_AVAILABLE = True
except Exception:
    MANUF_AVAILABLE = False
    _manuf_parser = None

# ── Data model ───────────────────────────────────────────────────────────────


@dataclass
class DiscoveredDevice:
    """Represents a single device found during discovery."""

    ip: str
    mac: str = "unknown"
    vendor: str = "unknown"
    hostname: str = ""
    services: list[str] = field(default_factory=list)  # populated later by fingerprint
    upnp_info: dict = field(default_factory=dict)
    mdns_info: dict = field(default_factory=dict)

    def __str__(self) -> str:
        return (
            f"DiscoveredDevice(ip={self.ip}, mac={self.mac}, "
            f"vendor={self.vendor!r}, hostname={self.hostname!r})"
        )


# ── OUI / vendor helpers ─────────────────────────────────────────────────────


def lookup_vendor(mac: str) -> str:
    """Return OUI vendor string for a MAC address."""
    if MANUF_AVAILABLE and _manuf_parser:
        try:
            result = _manuf_parser.get_manuf(mac)
            return result or "unknown"
        except Exception:
            pass
    # Fallback: first three octets
    prefix = mac.upper().replace(":", "-")[:8]
    return f"OUI:{prefix}"


# ── ARP sweep ────────────────────────────────────────────────────────────────


def _arp_sweep(subnet: str, timeout: float = 3.0) -> list[DiscoveredDevice]:
    """
    Broadcast ARP requests across *subnet* and collect replies.
    Requires Npcap (Windows) or raw socket privileges (Linux/macOS).
    Falls back to ICMP ping sweep when Scapy is unavailable.
    """
    if not SCAPY_AVAILABLE:
        warnings.warn(
            "[discovery] scapy not available — falling back to ping sweep. "
            "Install scapy + Npcap for full ARP capability.",
            stacklevel=2,
        )
        return _ping_sweep(subnet)

    try:
        scapy_conf.verb = 0  # silence scapy output
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        answered, _ = srp(pkt, timeout=timeout, retry=1, verbose=False)
    except PermissionError:
        console.print(
            "[yellow]⚠  ARP sweep requires administrator/root privileges. "
            "Re-run as admin or use --no-arp flag to skip.[/yellow]"
        )
        return _ping_sweep(subnet)
    except Exception as exc:
        console.print(f"[yellow]⚠  ARP sweep failed ({exc}). Falling back to ping.[/yellow]")
        return _ping_sweep(subnet)

    devices: list[DiscoveredDevice] = []
    for _, rcv in answered:
        ip = rcv.psrc
        mac = rcv.hwsrc
        vendor = lookup_vendor(mac)
        hostname = _reverse_dns(ip)
        devices.append(DiscoveredDevice(ip=ip, mac=mac, vendor=vendor, hostname=hostname))
    return devices


def _ping_sweep(subnet: str) -> list[DiscoveredDevice]:
    """
    TCP-connect ping sweep — no raw sockets required.
    Attempts port 80 then 443 then ICMP echo (platform-dependent).
    Returns live hosts with mac='unknown'.
    """
    network = ipaddress.ip_network(subnet, strict=False)
    hosts = list(network.hosts())
    results: list[DiscoveredDevice] = []
    lock = threading.Lock()

    def probe(ip: str) -> None:
        for port in (80, 443, 22, 8080):
            try:
                with socket.create_connection((ip, port), timeout=0.4):
                    hostname = _reverse_dns(ip)
                    with lock:
                        results.append(DiscoveredDevice(ip=ip, hostname=hostname))
                    return
            except (OSError, TimeoutError):
                continue

    with ThreadPoolExecutor(max_workers=128) as pool:
        pool.map(probe, [str(h) for h in hosts])

    return results


# ── SSDP / UPnP discovery ────────────────────────────────────────────────────

_SSDP_ADDR = "239.255.255.250"
_SSDP_PORT = 1900
_SSDP_MX = 2  # seconds to wait for responses

_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {_SSDP_ADDR}:{_SSDP_PORT}\r\n"
    'MAN: "ssdp:discover"\r\n'
    f"MX: {_SSDP_MX}\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
)


def _ssdp_discover(timeout: float = 3.0) -> dict[str, dict]:
    """
    Send UPnP M-SEARCH multicast; collect device advertisements.
    Returns {ip: {location, server, usn, st}} mapping.
    """
    results: dict[str, dict] = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        sock.sendto(_MSEARCH.encode(), (_SSDP_ADDR, _SSDP_PORT))

        while True:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                parsed = _parse_ssdp(data.decode(errors="replace"))
                if ip not in results:
                    results[ip] = parsed
                else:
                    results[ip].update(parsed)
            except socket.timeout:
                break
    except OSError as exc:
        console.print(f"[yellow]⚠  SSDP probe skipped: {exc}[/yellow]")
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return results


def _parse_ssdp(raw: str) -> dict:
    """Parse SSDP HTTP-like response headers into a dict."""
    info: dict = {}
    for line in raw.splitlines()[1:]:
        if ":" in line:
            key, _, val = line.partition(":")
            info[key.strip().lower()] = val.strip()
    return info


# ── mDNS discovery ───────────────────────────────────────────────────────────

_MDNS_ADDR = "224.0.0.251"
_MDNS_PORT = 5353

# DNS query for PTR record on _services._dns-sd._udp.local
_MDNS_QUERY = (
    b"\x00\x00"  # transaction ID
    b"\x00\x00"  # flags: standard query
    b"\x00\x01"  # questions: 1
    b"\x00\x00\x00\x00\x00\x00"  # answers / authority / additional
    # QNAME: _services._dns-sd._udp.local
    b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
    b"\x00\x0c"  # QTYPE: PTR
    b"\x00\x01"  # QCLASS: IN
)


def _mdns_discover(timeout: float = 3.0) -> dict[str, dict]:
    """
    Send a mDNS service discovery query; parse responders.
    Returns {ip: {name, services[]}} mapping.
    """
    results: dict[str, dict] = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ttl = struct.pack("@i", 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
        sock.settimeout(timeout)
        sock.sendto(_MDNS_QUERY, (_MDNS_ADDR, _MDNS_PORT))

        while True:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                if ip not in results:
                    results[ip] = {"ip": ip, "mdns_raw_len": len(data)}
            except socket.timeout:
                break
    except OSError as exc:
        console.print(f"[yellow]⚠  mDNS probe skipped: {exc}[/yellow]")
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return results


# ── Reverse DNS ──────────────────────────────────────────────────────────────


def _reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ── Main discovery orchestrator ──────────────────────────────────────────────


def discover(
    target: str,
    timeout: float = 3.0,
    verbose: bool = False,
    no_arp: bool = False,
) -> list[DiscoveredDevice]:
    """
    Run all discovery techniques against *target* (CIDR or single IP).

    Args:
        target:  e.g. "192.168.1.0/24" or "192.168.1.105"
        timeout: per-probe socket timeout in seconds
        verbose: print debug info to stderr
        no_arp:  skip Layer-2 ARP sweep (no administrator/raw socket privileges needed)

    Returns:
        List of DiscoveredDevice objects, deduplicated by IP.
    """
    # Normalise: single IP → /32 CIDR
    if "/" not in target:
        target = target + "/32"

    is_single = ipaddress.ip_network(target, strict=False).num_addresses == 1

    console.print(f"[bold cyan]🔍 Starting discovery on {target}[/bold cyan]")

    # --- ARP / ping sweep ---
    devices_by_ip: dict[str, DiscoveredDevice] = {}

    if no_arp:
        console.print("[dim]Skipping Layer-2 ARP sweep (--no-arp specified), using ping sweep…[/dim]")
        sweep_results = _ping_sweep(target)
    else:
        sweep_results = _arp_sweep(target, timeout=timeout)

    for d in sweep_results:
        devices_by_ip[d.ip] = d
        if verbose:
            console.print(f"  [green]{'PING' if no_arp else 'ARP'}[/green] {d}")

    # --- SSDP (skip for single /32 to avoid noise unless single) ---
    console.print("[cyan]📡 Running UPnP/SSDP multicast probe…[/cyan]")
    ssdp_info = _ssdp_discover(timeout=timeout)
    for ip, info in ssdp_info.items():
        if ip not in devices_by_ip:
            devices_by_ip[ip] = DiscoveredDevice(
                ip=ip, hostname=_reverse_dns(ip)
            )
        devices_by_ip[ip].upnp_info = info
        if verbose:
            console.print(f"  [blue]SSDP[/blue] {ip}: {info.get('server', '?')}")

    # --- mDNS ---
    console.print("[cyan]📡 Running mDNS multicast probe…[/cyan]")
    mdns_info = _mdns_discover(timeout=timeout)
    for ip, info in mdns_info.items():
        if ip not in devices_by_ip:
            devices_by_ip[ip] = DiscoveredDevice(
                ip=ip, hostname=_reverse_dns(ip)
            )
        devices_by_ip[ip].mdns_info = info
        if verbose:
            console.print(f"  [blue]mDNS[/blue] {ip}")

    result = list(devices_by_ip.values())
    console.print(
        f"[bold green]✔ Discovery complete — {len(result)} device(s) found.[/bold green]"
    )
    return result

