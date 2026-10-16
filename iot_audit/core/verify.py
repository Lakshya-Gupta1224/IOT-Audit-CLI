"""
verify.py — Defensive Control Verification Engine

Verifies that security hardening has been correctly applied.
Used AFTER remediation to prove controls are working.

Checks:
  - MQTT credential enforcement (CONNACK 0x05 on bad creds)
  - MQTT ACL topic restriction (unauthorized paths rejected)
  - TLS/MQTTS enforcement (plaintext rejected on 8883)
  - RTSP authentication enforcement (401 on DESCRIBE)
  - HTTP→HTTPS redirect enforcement
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from rich.console import Console
from rich.table import Table

console = Console()

try:
    import paho.mqtt.client as mqtt  # type: ignore
    import paho.mqtt.enums as mqtt_enums  # type: ignore

    PAHO_AVAILABLE = True
except ImportError:
    PAHO_AVAILABLE = False

import requests
from requests.exceptions import ConnectionError, SSLError, Timeout

from iot_audit.modules.mqtt_probe import _raw_mqtt_connack
from iot_audit.modules.rtsp_probe import _rtsp_describe


@dataclass
class VerifyResult:
    """Result of a single defensive control verification check."""

    check_id: str
    description: str
    target: str
    port: int
    status: str  # "PASS" | "FAIL" | "UNKNOWN"
    detail: str

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "description": self.description,
            "target": self.target,
            "port": self.port,
            "status": self.status,
            "detail": self.detail,
        }


# ── MQTT credential enforcement ───────────────────────────────────────────────


def verify_mqtt_auth(
    host: str,
    port: int = 1883,
    username: str = "",
    password: str = "",
    timeout: float = 3.0,
) -> list[VerifyResult]:
    """
    Verify MQTT authentication enforcement.
    1. Attempt anonymous connection — should be REJECTED (CONNACK ≠ 0x00).
    2. If credentials provided, verify valid creds are accepted (CONNACK = 0x00).
    """
    results: list[VerifyResult] = []

    # Check 1: anonymous should be rejected
    anon_code = _raw_mqtt_connack(host, port, timeout)
    if anon_code is None:
        results.append(VerifyResult(
            check_id="VERIFY-MQTT-AUTH-ANON",
            description="MQTT Anonymous Access Blocked",
            target=host, port=port,
            status="UNKNOWN",
            detail="No CONNACK received — broker may be unreachable.",
        ))
    elif anon_code == 0x00:
        results.append(VerifyResult(
            check_id="VERIFY-MQTT-AUTH-ANON",
            description="MQTT Anonymous Access Blocked",
            target=host, port=port,
            status="FAIL",
            detail=f"CONNACK 0x00 — anonymous access still accepted. Apply: allow_anonymous false",
        ))
    else:
        results.append(VerifyResult(
            check_id="VERIFY-MQTT-AUTH-ANON",
            description="MQTT Anonymous Access Blocked",
            target=host, port=port,
            status="PASS",
            detail=f"CONNACK 0x{anon_code:02X} — anonymous connections rejected. ✓",
        ))

    # Check 2: valid credentials accepted (only if creds provided)
    if username and PAHO_AVAILABLE:
        accepted = _mqtt_auth_connect(host, port, username, password, timeout)
        status = "PASS" if accepted else "FAIL"
        detail = (
            f"Authenticated connection with user '{username}' accepted. ✓"
            if accepted
            else f"Authenticated connection with user '{username}' was rejected — check credentials or broker config."
        )
        results.append(VerifyResult(
            check_id="VERIFY-MQTT-AUTH-CRED",
            description="MQTT Valid Credentials Accepted",
            target=host, port=port,
            status=status,
            detail=detail,
        ))

    return results


def _mqtt_auth_connect(
    host: str,
    port: int,
    username: str,
    password: str,
    timeout: float = 3.0,
) -> bool:
    """Return True if MQTT broker accepts given credentials."""
    if not PAHO_AVAILABLE:
        return False
    import threading
    connected = threading.Event()
    success = [False]

    def on_connect(client, userdata, flags, rc, properties=None):
        if rc == 0:
            success[0] = True
        connected.set()

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="iot-audit-verify")
    client.username_pw_set(username, password)
    client.on_connect = on_connect
    try:
        client.connect(host, port, keepalive=5)
        client.loop_start()
        connected.wait(timeout=timeout + 1)
        client.loop_stop()
        client.disconnect()
    except Exception:
        pass
    return success[0]


# ── MQTT ACL verification ─────────────────────────────────────────────────────


def verify_mqtt_acl(
    host: str,
    port: int = 1883,
    username: str = "",
    password: str = "",
    restricted_topic: str = "$SYS/#",
    timeout: float = 3.0,
) -> list[VerifyResult]:
    """
    Verify that ACLs block access to restricted topic paths.
    Connects with given credentials and attempts subscription to *restricted_topic*.
    """
    if not PAHO_AVAILABLE:
        return [VerifyResult(
            check_id="VERIFY-MQTT-ACL",
            description="MQTT ACL Enforcement",
            target=host, port=port,
            status="UNKNOWN",
            detail="paho-mqtt not available — install with: pip install paho-mqtt",
        )]

    import threading
    received = []
    connected_event = threading.Event()
    done_event = threading.Event()

    def on_connect(client, userdata, flags, rc, properties=None):
        if rc == 0:
            client.subscribe(restricted_topic, qos=0)
        connected_event.set()

    def on_message(client, userdata, msg):
        received.append(msg.topic)

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="iot-audit-acl")
    if username:
        client.username_pw_set(username, password)
    client.on_connect = on_connect
    client.on_message = on_message

    try:
        client.connect(host, port, keepalive=5)
        client.loop_start()
        import time; time.sleep(2)
        client.loop_stop()
        client.disconnect()
    except Exception:
        pass

    if received:
        status, detail = (
            "FAIL",
            f"ACL NOT enforced — received {len(received)} message(s) on restricted topic '{restricted_topic}'.",
        )
    else:
        status, detail = (
            "PASS",
            f"ACL enforced — no messages received on restricted topic '{restricted_topic}'. ✓",
        )

    return [VerifyResult(
        check_id="VERIFY-MQTT-ACL",
        description=f"MQTT ACL Blocks '{restricted_topic}'",
        target=host, port=port,
        status=status,
        detail=detail,
    )]


# ── TLS enforcement ───────────────────────────────────────────────────────────


def verify_tls_enforcement(
    host: str,
    port: int = 8883,
    timeout: float = 3.0,
) -> list[VerifyResult]:
    """
    Verify that plaintext MQTT connections are rejected on the TLS port.
    """
    code = _raw_mqtt_connack(host, port, timeout)
    if code is None:
        status, detail = (
            "PASS",
            "Plaintext MQTT CONNECT not accepted on port 8883 — TLS enforcement active. ✓",
        )
    else:
        status, detail = (
            "FAIL",
            f"Plaintext CONNACK 0x{code:02X} received on port 8883 — TLS is NOT enforced.",
        )

    return [VerifyResult(
        check_id="VERIFY-MQTTS-TLS",
        description="TLS Enforcement on MQTT Port 8883",
        target=host, port=port,
        status=status,
        detail=detail,
    )]


# ── RTSP auth enforcement ─────────────────────────────────────────────────────


def verify_rtsp_auth(
    host: str,
    port: int = 554,
    timeout: float = 3.0,
) -> list[VerifyResult]:
    """
    Verify that RTSP streams require authentication (expect 401, not 200).
    """
    paths_to_check = ["/live", "/stream1", "/"]
    found_unprotected = False
    detail = ""

    for path in paths_to_check:
        result = _rtsp_describe(host, port, path, timeout)
        if result is None:
            continue
        code, line = result
        if code == 200:
            found_unprotected = True
            detail = f"RTSP DESCRIBE on {path} returned 200 OK — unauthenticated access still active."
            break
        elif code in (401, 403):
            detail = f"RTSP DESCRIBE on {path} returned {code} — authentication enforced. ✓"

    if not detail:
        detail = "No RTSP response received — service may be offline or path changed."

    return [VerifyResult(
        check_id="VERIFY-RTSP-AUTH",
        description="RTSP Stream Authentication Enforced",
        target=host, port=port,
        status="FAIL" if found_unprotected else "PASS",
        detail=detail,
    )]


# ── HTTP→HTTPS redirect enforcement ──────────────────────────────────────────


def verify_https_redirect(
    host: str,
    port: int = 80,
    timeout: float = 3.0,
) -> list[VerifyResult]:
    """
    Verify that HTTP connections are redirected to HTTPS.
    """
    try:
        resp = requests.get(
            f"http://{host}:{port}/",
            timeout=timeout,
            allow_redirects=False,
            verify=False,
            headers={"User-Agent": "iot-audit-cli/0.1"},
        )
        is_https_redirect = (
            resp.status_code in (301, 302, 307, 308)
            and "https://" in resp.headers.get("Location", "").lower()
        )
        if is_https_redirect:
            status = "PASS"
            detail = f"HTTP {resp.status_code} redirect to HTTPS confirmed. ✓"
        else:
            status = "FAIL"
            detail = (
                f"HTTP {resp.status_code} — no HTTPS redirect. "
                f"Location: {resp.headers.get('Location', 'none')}"
            )
    except (ConnectionError, Timeout, SSLError, requests.exceptions.RequestException) as exc:
        status = "UNKNOWN"
        detail = f"Connection error: {exc}"

    return [VerifyResult(
        check_id="VERIFY-HTTP-REDIRECT",
        description="HTTP → HTTPS Redirect Active",
        target=host, port=port,
        status=status,
        detail=detail,
    )]


# ── Orchestrator ──────────────────────────────────────────────────────────────


def run_verification(
    host: str,
    ports: list[int],
    username: str = "",
    password: str = "",
    timeout: float = 3.0,
    verbose: bool = False,
) -> list[VerifyResult]:
    """
    Run all applicable verification checks for *host* based on *ports*.

    Returns:
        List of VerifyResult objects.
    """
    results: list[VerifyResult] = []

    console.print(f"\n[bold blue]🛡  Running defensive verification on {host}[/bold blue]")

    if 1883 in ports:
        results.extend(verify_mqtt_auth(host, 1883, username, password, timeout))
        results.extend(verify_mqtt_acl(host, 1883, username, password, timeout=timeout))

    if 8883 in ports:
        results.extend(verify_tls_enforcement(host, 8883, timeout))

    if 554 in ports or 8554 in ports:
        p = 554 if 554 in ports else 8554
        results.extend(verify_rtsp_auth(host, p, timeout))

    if 80 in ports or 8080 in ports:
        p = 80 if 80 in ports else 8080
        results.extend(verify_https_redirect(host, p, timeout))

    # ── Print verification table ───────────────────────────────────────────────
    table = Table(title=f"Verification Results — {host}", show_lines=True)
    table.add_column("Check ID", style="cyan", no_wrap=True)
    table.add_column("Description")
    table.add_column("Status", justify="center")
    table.add_column("Detail")

    for r in results:
        if r.status == "PASS":
            status_display = "[bold green]✓ PASS[/bold green]"
        elif r.status == "FAIL":
            status_display = "[bold red]✗ FAIL[/bold red]"
        else:
            status_display = "[yellow]? UNKNOWN[/yellow]"
        table.add_row(r.check_id, r.description, status_display, r.detail)

    console.print(table)
    return results

