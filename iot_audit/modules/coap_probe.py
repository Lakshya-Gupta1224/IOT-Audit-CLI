"""
coap_probe.py — CoAP (Constrained Application Protocol) Vulnerability Probes

Probes:
  AUDIT-COAP-01 : Unauthenticated CoAP Resource Discovery (.well-known/core)
    Method: Send CoAP GET request to /.well-known/core (RFC 6690)
            over UDP port 5683.
    Safe:   Read-only GET. No POST/PUT/DELETE operations are performed.
    Result: 2.05 Content with link format resources = VULNERABLE (CWE-200)
            4.01 Unauthorized / Access Denied = PROTECTED
"""

from __future__ import annotations

import socket
from typing import Optional

from rich.console import Console

from iot_audit.models import Finding

console = Console(stderr=True)

# CoAP GET /.well-known/core RFC 6690 discovery packet
# Header: Ver=1(01b), Type=Confirmable(00b), Token Length=0(0000b) -> 0x40
# Code: 0.01 GET -> 0x01
# Message ID: 0x0001
# Option 11 (Uri-Path): Delta 11, Length 11 -> 0xbb, Value ".well-known"
# Option 11 (Uri-Path): Delta 0, Length 4 -> 0x04, Value "core"
_COAP_CORE_PROBE = (
    b"\x40\x01\x00\x01"
    b"\xbb.well-known\x04core"
)


def _send_coap_probe(
    host: str,
    port: int = 5683,
    timeout: float = 2.0,
) -> Optional[tuple[int, int, str]]:
    """
    Send CoAP probe to host:port.
    Returns (code_class, code_detail, payload_str) or None.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_COAP_CORE_PROBE, (host, port))
        data, _ = sock.recvfrom(2048)
        sock.close()

        if len(data) >= 4:
            code_byte = data[1]
            code_class = (code_byte >> 5) & 0x07
            code_detail = code_byte & 0x1F

            # CoAP payload marker is 0xFF
            payload_str = ""
            if b"\xff" in data:
                payload_bytes = data.split(b"\xff", 1)[1]
                payload_str = payload_bytes.decode(errors="replace").strip()

            return code_class, code_detail, payload_str
        return None
    except (socket.timeout, OSError):
        return None


def audit_coap(
    host: str,
    port: int = 5683,
    timeout: float = 2.0,
    verbose: bool = False,
) -> list[Finding]:
    """
    Execute CoAP security assessment against target host:port.
    """
    findings: list[Finding] = []
    console.print(f"    [dim]AUDIT-COAP-01: Probing CoAP /.well-known/core on {host}:{port}…[/dim]")

    result = _send_coap_probe(host, port, timeout=timeout)

    if result is None:
        verdict = "UNKNOWN"
        evidence = "No response received to CoAP discovery probe."
        severity = "INFO"
        score = 0.0
    else:
        cls, detail, payload = result
        code_str = f"{cls}.{detail:02d}"
        if cls == 2:  # 2.xx Success (typically 2.05 Content)
            verdict = "VULNERABLE"
            snippet = payload[:100] if payload else "Empty payload returned"
            evidence = (
                f"CoAP response code {code_str} (Success) returned without credentials. "
                f"Exposed resources: {snippet}"
            )
            severity = "MEDIUM"
            score = 5.3
        elif cls == 4:  # 4.xx Client Error (e.g. 4.01 Unauthorized)
            verdict = "PROTECTED"
            evidence = f"CoAP response code {code_str} — Access denied / authentication enforced."
            severity = "INFO"
            score = 0.0
        else:
            verdict = "UNKNOWN"
            evidence = f"CoAP returned unexpected response code {code_str}."
            severity = "INFO"
            score = 0.0

    if verbose and result:
        console.print(f"      CoAP Result: {result[0]}.{result[1]:02d} - {result[2][:50]}")

    findings.append(
        Finding(
            audit_id="AUDIT-COAP-01",
            host=host,
            port=port,
            protocol="CoAP",
            verdict=verdict,
            title="Unauthenticated CoAP Resource Discovery (.well-known/core)",
            evidence=evidence,
            owasp="I2 – Insecure Network Services",
            cwe="CWE-200",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            cvss_score=score,
            severity=severity,
            remediation=(
                "1. Enforce CoAP over DTLS (CoAPS on UDP 5684) with Pre-Shared Key (PSK) "
                "or X.509 certificate validation.\n"
                "2. Restrict /.well-known/core access to authenticated network segments.\n"
                "3. Disable discovery endpoints if not strictly required by application clients."
            ),
        )
    )

    return findings
