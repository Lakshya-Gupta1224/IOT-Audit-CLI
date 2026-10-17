"""
rtsp_probe.py — RTSP Stream Authentication Probe

Probe:
  AUDIT-RTSP-01 : Unauthenticated video stream access
    Method: Send an RTSP DESCRIBE request to common stream paths.
            Evaluate response status code.
    Safe:   No stream is captured; only the first response header is read.
    Result: 200 OK  = stream accessible without credentials (VULNERABLE)
            401/403 = authentication enforced (PROTECTED)
            404     = path not found (try next path)

Common RTSP paths probed (read-only):
  /live, /live/ch00_0, /stream1, /cam/realmonitor, /h264, /video1,
  /axis-media/media.amp, /MediaInput/h264
"""

from __future__ import annotations

import socket
from typing import Optional

from rich.console import Console

console = Console(stderr=True)

# Stream paths commonly found on IP cameras (descending prevalence)
_RTSP_PATHS = [
    "/live",
    "/stream1",
    "/live/ch00_0",
    "/cam/realmonitor",
    "/h264/ch01/main/av_stream",
    "/video1",
    "/MediaInput/h264",
    "/axis-media/media.amp",
    "/",
]

_RTSP_USER_AGENT = "iot-audit-cli/0.1 (research)"


def _rtsp_describe(
    host: str,
    port: int,
    path: str,
    timeout: float = 3.0,
) -> Optional[tuple[int, str]]:
    """
    Send RTSP DESCRIBE for *path* and return (status_code, status_line).
    Returns None on connection failure.
    """
    request = (
        f"DESCRIBE rtsp://{host}:{port}{path} RTSP/1.0\r\n"
        f"CSeq: 1\r\n"
        f"User-Agent: {_RTSP_USER_AGENT}\r\n"
        f"Accept: application/sdp\r\n"
        f"\r\n"
    )
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(request.encode())
            sock.settimeout(timeout)
            raw = sock.recv(512).decode(errors="replace")
            # Parse status line: "RTSP/1.0 200 OK"
            first_line = raw.split("\r\n")[0] if "\r\n" in raw else raw.split("\n")[0]
            parts = first_line.split(" ", 2)
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1]), first_line
            return None
    except (OSError, socket.timeout, UnicodeDecodeError):
        return None


from iot_audit.models import Finding  # noqa: E402


def audit_rtsp(
    host: str,
    port: int = 554,
    timeout: float = 3.0,
    verbose: bool = False,
) -> list[Finding]:
    """
    Run RTSP authentication audit on *host:port*.

    Returns:
        List of Finding objects.
    """
    findings: list[Finding] = []

    console.print(f"    [dim]AUDIT-RTSP-01: Probing {len(_RTSP_PATHS)} RTSP paths on {host}:{port}…[/dim]")

    hit_path: Optional[str] = None
    hit_code: Optional[int] = None
    hit_line: Optional[str] = None
    protected_path: Optional[str] = None

    for path in _RTSP_PATHS:
        result = _rtsp_describe(host, port, path, timeout)
        if result is None:
            continue
        code, line = result
        if verbose:
            console.print(f"      {path} → {code}")

        if code == 200:
            hit_path = path
            hit_code = code
            hit_line = line
            break  # Found unauthenticated stream — no need to probe further
        elif code in (401, 403):
            protected_path = path
            # Continue to check other paths — different paths may have different ACLs

    if hit_path:
        verdict, evidence, severity, score = (
            "VULNERABLE",
            f"RTSP DESCRIBE on {hit_path} returned {hit_line} — no authentication required.",
            "CRITICAL",
            9.1,
        )
    elif protected_path:
        verdict, evidence, severity, score = (
            "PROTECTED",
            f"RTSP DESCRIBE returned 401/403 on all probed paths — authentication enforced.",
            "INFO",
            0.0,
        )
    else:
        verdict, evidence, severity, score = (
            "UNKNOWN",
            "No RTSP response received on any probed path — service may use non-standard paths.",
            "INFO",
            0.0,
        )

    findings.append(
        Finding(
            audit_id="AUDIT-RTSP-01",
            host=host,
            port=port,
            protocol="RTSP",
            verdict=verdict,
            title="Unauthenticated RTSP Video Stream Access",
            evidence=evidence,
            owasp="I1 – Weak, Guessable, or Hardcoded Passwords",
            cwe="CWE-306",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            cvss_score=score,
            severity=severity,
            remediation=(
                "Enable digest authentication on all RTSP paths:\n"
                "  - For FFmpeg/Live555: add --rtsp-auth=digest flag\n"
                "  - For IP cameras: set stream authentication to 'Digest' in web UI\n"
                "  - Restrict RTSP (port 554) via firewall to trusted IPs only\n"
                "  - Use RTSPS (RTSP over TLS, port 322) for encrypted streams"
            ),
        )
    )

    return findings

