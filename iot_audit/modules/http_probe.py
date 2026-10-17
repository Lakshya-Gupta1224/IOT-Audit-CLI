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

from typing import Any, Optional

import requests
from requests.auth import HTTPDigestAuth
from requests.exceptions import ConnectionError, SSLError, Timeout

from rich.console import Console

console = Console(stderr=True)

# Diagnostic endpoints commonly exposed on IoT web management consoles
_DIAGNOSTIC_PATHS: list[tuple[str, str]] = [
    ("/system/info", "System info endpoint"),
    ("/api/device", "Device API endpoint"),
    ("/api/v1/device", "Device API v1"),
    ("/status.json", "Device status JSON (IP camera / telemetry)"),
    ("/sensors.json", "Hardware sensors telemetry"),
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
    ("admin", "password"),
    ("admin", "pass"),
    ("pass", "admin"),
    ("root", "root"),
    ("root", ""),
    ("root", "admin"),
    ("root", "pass"),
    ("user", "user"),
    ("user", "password"),
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
    auth: Optional[Any] = None,
) -> Optional[requests.Response]:
    """Safe GET wrapper — returns None on any connection/timeout error."""
    try:
        return _SESSION.get(
            url,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify_ssl,
            auth=auth,
        )
    except (ConnectionError, Timeout, SSLError, requests.exceptions.RequestException):
        return None


def _http_post(
    url: str,
    data: dict,
    timeout: float = 3.0,
    allow_redirects: bool = False,
    verify_ssl: bool = False,
) -> Optional[requests.Response]:
    """Safe POST wrapper — returns None on any connection/timeout error."""
    try:
        return _SESSION.post(
            url,
            data=data,
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

    # ── AUDIT-HTTP-03: Default credential check ──────────────────────────────
    console.print(f"    [dim]AUDIT-HTTP-03: Checking for default credentials on {base_url}…[/dim]")
    auth_found = False
    valid_cred = None
    target_auth_path = None

    # Check root and common login paths for 401 Basic Auth or password forms
    candidate_paths = ["/", "/login", "/admin"]
    for path in candidate_paths:
        chk_resp = _http_get(base_url + path, timeout=timeout)
        if chk_resp is None:
            continue

        # Scenario A: HTTP 401 Unauthorized (Basic or Digest Auth Challenge)
        www_auth = chk_resp.headers.get("WWW-Authenticate", "").lower()
        if chk_resp.status_code == 401:
            auth_found = True
            target_auth_path = path
            is_digest = "digest" in www_auth
            for u, p in _DEFAULT_CREDS:
                auth_param = HTTPDigestAuth(u, p) if is_digest else (u, p)
                auth_resp = _http_get(base_url + path, timeout=timeout, auth=auth_param)
                if auth_resp is not None and auth_resp.status_code == 200:
                    valid_cred = (u, p)
                    break
            if valid_cred:
                break

        # Scenario B: Form with password input
        elif chk_resp.status_code == 200 and 'type="password"' in chk_resp.text.lower():
            auth_found = True
            target_auth_path = path
            for u, p in _DEFAULT_CREDS:
                post_data = {"username": u, "user": u, "password": p, "pass": p, "submit": "Login"}
                post_resp = _http_post(base_url + path, data=post_data, timeout=timeout)
                if post_resp is not None:
                    # Successful login usually results in 302 redirect or 200 without the password form
                    if post_resp.status_code in (301, 302, 303, 307):
                        valid_cred = (u, p)
                        break
                    elif post_resp.status_code == 200 and 'type="password"' not in post_resp.text.lower() and "invalid" not in post_resp.text.lower():
                        valid_cred = (u, p)
                        break
            if valid_cred:
                break

    if valid_cred:
        verdict_03 = "VULNERABLE"
        u, p = valid_cred
        cred_display = f"{u}:{p}" if p else f"{u}:<blank>"
        evidence_03 = f"Default credentials accepted on {target_auth_path}: '{cred_display}'"
        severity_03 = "CRITICAL"
        score_03 = 9.8
    elif auth_found:
        verdict_03 = "PROTECTED"
        evidence_03 = "Authentication required and tested default vendor credentials were all rejected."
        severity_03 = "INFO"
        score_03 = 0.0
    else:
        verdict_03 = "UNKNOWN"
        evidence_03 = "No HTTP Basic Authentication or web login form detected on common paths."
        severity_03 = "INFO"
        score_03 = 0.0

    if verbose:
        console.print(f"      HTTP-03 Result: {verdict_03} — {evidence_03}")

    findings.append(
        Finding(
            audit_id="AUDIT-HTTP-03",
            host=host,
            port=port,
            protocol="HTTP",
            verdict=verdict_03,
            title="Default or Hardcoded Web Interface Credentials",
            evidence=evidence_03,
            owasp="I1 – Weak, Guessable, or Hardcoded Passwords",
            cwe="CWE-521",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_score=score_03,
            severity=severity_03,
            remediation=(
                "1. Change default administrator passwords upon first deployment.\n"
                "2. Enforce strong password complexity requirements (minimum 12 characters, mixed case, symbols).\n"
                "3. Implement account lockout or progressive rate limiting after consecutive failed login attempts."
            ),
        )
    )

    return findings

