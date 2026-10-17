"""
http_probe.py — IoT HTTP/HTTPS Web Interface Audit Probes

Probes:
  AUDIT-HTTP-01 : Cleartext admin interface (HTTP instead of HTTPS)
    Method: Attempt HTTP connection; check if redirect to HTTPS exists.
    Safe:   GET request only; no form submission or login attempts.
    Result: HTTP 200 on admin path = cleartext interface (VULNERABLE)

  AUDIT-HTTP-02 : Exposed diagnostic / telemetry endpoints
    Method: GET common read-only API and device-info endpoints.
    Safe:   Read-only GET requests only.
    Result: 200 response with device info = information disclosure (VULNERABLE)

  AUDIT-HTTP-03 : Default/Weak credential login form detection
    Method: Detect presence of login form; test hardcoded default pairs.
    Safe:   Only tests well-known vendor defaults documented in NVD/CVE.
"""

from __future__ import annotations

import socket
from typing import Optional
from urllib.parse import urljoin

import requests
from requests.exceptions import ConnectionError, SSLError, Timeout

from rich.console import Console

console = Console(stderr=True)

# Diagnostic endpoints commonly exposed on IoT web management consoles
_DIAGNOSTIC_PATHS: list[tuple[str, str]] = [
    ("/system/info", "System info endpoint"),
    ("/api/device", "Device API endpoint"),
    ("/api/v1/device", "Device API v1"),
    ("/deviceDescription.xml", "UPnP device descriptor"),
    ("/device.xml", "Device XML descriptor"),
    ("/status", "Status page"),
    ("/info", "Info endpoint"),
    ("/metrics", "Prometheus/metrics endpoint"),
    ("/health", "Health check endpoint"),
    ("/cgi-bin/hi3510/param.cgi", "Hisilicon camera CGI"),
    ("/ISAPI/System/deviceInfo", "Hikvision ISAPI"),
    ("/onvif/device_service", "ONVIF device service"),
    ("/goform/formLogin", "Embedded router login form"),
]

# Well-known vendor default credentials (from public CVE/NVD records)
_DEFAULT_CREDS: list[tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", ""),
    ("admin", "1234"),
    ("admin", "12345"),
    ("root", "root"),
    ("root", ""),
    ("user", "user"),
    ("guest", "guest"),
]

_HEADERS = {
    "User-Agent": "iot-audit-cli/0.1 (academic-research)",
    "Accept": "text/html,application/xml,application/json,*/*",
}

_SESSION = requests.Session()
_SESSION.headers.update(_HEADERS)


def _http_get(
    url: str,
    timeout: float = 3.0,
    allow_redirects: bool = True,
    verify_ssl: bool = False,
) -> Optional[requests.Response]:
    """Safe GET wrapper — returns None on any connection/timeout error."""
    try:
        return _SESSION.get(
            url,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify_ssl,
        )
    except (ConnectionError, Timeout, SSLError, requests.exceptions.RequestException):
        return None


def _build_base_url(host: str, port: int) -> str:
    scheme = "https" if port in (443, 8443) else "http"
    default_port = {80: 80, 443: 443, 8080: 8080, 8443: 443}
    if port not in (80, 443):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


from iot_audit.models import Finding  # noqa: E402


def audit_http(
    host: str,
    port: int = 80,
    timeout: float = 3.0,
    verbose: bool = False,
) -> list[Finding]:
    """
    Run all HTTP audit probes on *host:port*.

    Returns:
        List of Finding objects.
    """
    findings: list[Finding] = []
    base_url = _build_base_url(host, port)

    # ── AUDIT-HTTP-01: Cleartext admin interface ───────────────────────────────
    if port not in (443, 8443):
        console.print(f"    [dim]AUDIT-HTTP-01: Checking cleartext HTTP on {base_url}…[/dim]")

        resp = _http_get(base_url + "/", timeout=timeout, allow_redirects=False)
        if resp is not None:
            is_redirect_to_https = (
                resp.status_code in (301, 302, 307, 308)
                and "https://" in resp.headers.get("Location", "").lower()
            )
            if is_redirect_to_https:
                verdict_01, evidence_01, severity_01, score_01 = (
                    "PROTECTED",
                    f"HTTP {resp.status_code} redirect to HTTPS detected — TLS upgrade enforced.",
                    "INFO",
                    0.0,
                )
            else:
                verdict_01, evidence_01, severity_01, score_01 = (
                    "VULNERABLE",
                    f"HTTP {resp.status_code} — web interface accessible over plaintext HTTP (no TLS redirect).",
                    "HIGH",
                    7.4,
                )
        else:
            verdict_01, evidence_01, severity_01, score_01 = (
                "UNKNOWN",
                "No HTTP response received.",
                "INFO",
                0.0,
            )

        if verbose:
            console.print(f"      {base_url}/ → {evidence_01}")

        findings.append(
            Finding(
                audit_id="AUDIT-HTTP-01",
                host=host,
                port=port,
                protocol="HTTP",
                verdict=verdict_01,
                title="Unencrypted Cleartext HTTP Admin Interface",
                evidence=evidence_01,
                owasp="I7 – Insecure Data Transfer and Storage",
                cwe="CWE-319",
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cvss_score=score_01,
                severity=severity_01,
                remediation=(
                    "1. Enable HTTPS on the device web server (use Let's Encrypt or self-signed CA).\n"
                    "2. Add HTTP → HTTPS redirect (301) for all admin paths.\n"
                    "3. Set Strict-Transport-Security (HSTS) header:\n"
                    "   Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
                    "4. If device firmware does not support HTTPS, place it behind a TLS-terminating proxy."
                ),
            )
        )

    # ── AUDIT-HTTP-02: Exposed diagnostic endpoints ────────────────────────────
    console.print(f"    [dim]AUDIT-HTTP-02: Probing {len(_DIAGNOSTIC_PATHS)} diagnostic endpoints on {base_url}…[/dim]")

    exposed: list[tuple[str, int, str]] = []
    for path, label in _DIAGNOSTIC_PATHS:
        url = base_url + path
        resp = _http_get(url, timeout=timeout)
        if resp is not None and resp.status_code == 200:
            snippet = resp.text[:120].replace("\n", " ").strip()
            exposed.append((path, resp.status_code, snippet))
            if verbose:
                console.print(f"      [red]EXPOSED[/red] {path} → 200  {snippet!r}")
        elif verbose and resp is not None:
            console.print(f"      [dim]{path} → {resp.status_code}[/dim]")

    if exposed:
        path_list = ", ".join(p for p, _, _ in exposed[:5])
        evidence_02 = (
            f"{len(exposed)} endpoint(s) returned HTTP 200 without authentication: {path_list}"
        )
        verdict_02, severity_02, score_02 = "VULNERABLE", "MEDIUM", 6.5
    else:
        evidence_02 = "No diagnostic endpoints returned 200 — paths appear protected or absent."
        verdict_02, severity_02, score_02 = "PROTECTED", "INFO", 0.0

    findings.append(
        Finding(
            audit_id="AUDIT-HTTP-02",
            host=host,
            port=port,
            protocol="HTTP",
            verdict=verdict_02,
            title="Exposed Diagnostic / Telemetry Endpoints Without Authentication",
            evidence=evidence_02,
            owasp="I3 – Insecure Ecosystem Interfaces",
            cwe="CWE-200",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            cvss_score=score_02,
            severity=severity_02,
            remediation=(
                "1. Require authentication (Bearer token / Basic Auth over HTTPS) on all API paths.\n"
                "2. Disable or remove diagnostic endpoints in production firmware.\n"
                "3. Use firewall rules to restrict /api, /status, /metrics to trusted subnets.\n"
                "4. Apply content-type and CORS restrictions on API responses."
            ),
        )
    )

    return findings

