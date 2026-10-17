"""
mqtt_probe.py — MQTT Protocol Vulnerability Probes

Probes:
  AUDIT-MQTT-01 : Anonymous authentication bypass
    Method: Send a minimal MQTT CONNECT packet; inspect CONNACK return code.
    Safe:   No topics are published; connection is immediately closed.
    Result: CONNACK 0x00 = anonymous access granted (VULNERABLE)
            CONNACK 0x05 = authentication required (PROTECTED)

  AUDIT-MQTT-02 : Wildcard topic namespace enumeration
    Method: Subscribe with '#' for 2 seconds; record received topic names only.
    Safe:   No payloads are stored; subscription is read-only.
    Result: Any topic received = namespace exposed (VULNERABLE)

  AUDIT-MQTTS-01: TLS enforcement on port 8883
    Method: Attempt plaintext connection on 8883; if accepted → TLS not enforced.
    Safe:   No MQTT CONNECT is sent if TLS handshake is required.
"""

from __future__ import annotations

import socket
import struct
import threading
import time
from typing import Optional

from rich.console import Console

console = Console(stderr=True)

# Try to import paho-mqtt ≥ 2.0
try:
    import paho.mqtt.client as mqtt  # type: ignore

    PAHO_AVAILABLE = True
except ImportError:
    PAHO_AVAILABLE = False
    console.print("[yellow]⚠  paho-mqtt not installed — MQTT probes will use raw sockets only.[/yellow]")


# ── Raw socket CONNACK reader ─────────────────────────────────────────────────


def _raw_mqtt_connack(host: str, port: int, timeout: float = 3.0) -> Optional[int]:
    """
    Send a minimal MQTT 3.1.1 CONNECT packet via raw TCP and return
    the CONNACK return code byte, or None on failure.

    Packet structure (20 bytes):
      Fixed header: 0x10 (CONNECT) + remaining length
      Variable header: protocol name, level, flags, keep-alive
      Payload: client ID "iot-audit"
    """
    client_id = b"iot-audit"
    # Variable header: "MQTT" name (6 bytes) + level(1) + flags(1) + keepalive(2)
    proto = b"\x00\x04MQTT\x04\x00\x00\x3c"
    payload = struct.pack("!H", len(client_id)) + client_id
    remaining = proto + payload
    fixed = bytes([0x10, len(remaining)])
    packet = fixed + remaining

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.sendall(packet)
        sock.settimeout(timeout)
        # CONNACK is always 4 bytes: 0x20 0x02 <session_present> <return_code>
        response = sock.recv(4)
        sock.close()
        if len(response) >= 4 and response[0] == 0x20:
            return response[3]  # return code
        return None
    except (OSError, socket.timeout):
        return None


# ── Wildcard subscription probe ───────────────────────────────────────────────


def _wildcard_subscribe(
    host: str,
    port: int,
    timeout: float = 3.0,
    listen_secs: float = 2.0,
) -> list[str]:
    """
    Attempt anonymous subscription to wildcard topic '#'.
    Returns a list of received topic names (payloads are discarded).
    Returns empty list if connection is refused or auth required.
    """
    if not PAHO_AVAILABLE:
        return []

    topics_seen: list[str] = []
    done_event = threading.Event()

    def on_connect(client, userdata, flags, rc, properties=None):
        if rc == 0:
            client.subscribe("#", qos=0)

    def on_message(client, userdata, msg):
        # Record topic name only — payload is deliberately ignored
        if msg.topic not in topics_seen:
            topics_seen.append(msg.topic)

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="iot-audit-wc")
    client.on_connect = on_connect
    client.on_message = on_message

    try:
        client.connect(host, port, keepalive=10)
        client.loop_start()
        time.sleep(listen_secs)
        client.loop_stop()
        client.disconnect()
    except Exception:
        pass

    return topics_seen


# ── TLS enforcement check ─────────────────────────────────────────────────────


def _check_tls_required(host: str, port: int = 8883, timeout: float = 3.0) -> bool:
    """
    Return True if the broker on *port* refuses a plaintext connection
    (i.e., TLS is enforced). Return False if plaintext is accepted.
    """
    code = _raw_mqtt_connack(host, port, timeout=timeout)
    # If we get any CONNACK back over plaintext → TLS not enforced
    return code is None


# ── Public probe functions ────────────────────────────────────────────────────

from iot_audit.models import Finding  # noqa: E402


def audit_mqtt(
    host: str,
    port: int = 1883,
    tls: bool = False,
    timeout: float = 3.0,
    verbose: bool = False,
) -> list[Finding]:
    """
    Run all MQTT audit probes on *host:port*.

    Returns:
        List of Finding objects.
    """
    findings: list[Finding] = []

    if tls:
        # AUDIT-MQTTS-01: verify TLS is actually enforced
        tls_enforced = _check_tls_required(host, port, timeout)
        if tls_enforced:
            verdict, evidence, severity = (
                "PROTECTED",
                "Plaintext connection rejected on port 8883 — TLS is enforced.",
                "INFO",
            )
        else:
            verdict, evidence, severity = (
                "VULNERABLE",
                "Plaintext MQTT CONNECT accepted on port 8883 — TLS is NOT enforced.",
                "HIGH",
            )
        findings.append(
            Finding(
                audit_id="AUDIT-MQTTS-01",
                host=host,
                port=port,
                protocol="MQTTS",
                verdict=verdict,
                title="TLS Enforcement on MQTT Secure Port (8883)",
                evidence=evidence,
                owasp="I7 – Insecure Data Transfer and Storage",
                cwe="CWE-319",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cvss_score=7.5 if verdict == "VULNERABLE" else 0.0,
                severity=severity,
                remediation=(
                    "In mosquitto.conf: set listener 8883 and configure "
                    "cafile, certfile, keyfile. Set require_certificate true for mTLS."
                ),
            )
        )
        return findings

    # ── AUDIT-MQTT-01: Anonymous authentication ───────────────────────────────
    console.print(f"    [dim]AUDIT-MQTT-01: Testing anonymous CONNECT on {host}:{port}…[/dim]")
    connack_code = _raw_mqtt_connack(host, port, timeout)

    if connack_code is None:
        verdict_01, evidence_01, severity_01 = (
            "UNKNOWN",
            "No CONNACK received — broker may be offline or filtered.",
            "INFO",
        )
        score_01 = 0.0
    elif connack_code == 0x00:
        verdict_01, evidence_01, severity_01 = (
            "VULNERABLE",
            f"CONNACK return code 0x00 (Connection Accepted) — anonymous access granted.",
            "CRITICAL",
        )
        score_01 = 9.8
    else:
        verdict_01, evidence_01, severity_01 = (
            "PROTECTED",
            f"CONNACK return code 0x{connack_code:02X} — connection refused (auth required).",
            "INFO",
        )
        score_01 = 0.0

    if verbose:
        console.print(f"      CONNACK code: {connack_code}")

    findings.append(
        Finding(
            audit_id="AUDIT-MQTT-01",
            host=host,
            port=port,
            protocol="MQTT",
            verdict=verdict_01,
            title="MQTT Broker Anonymous Authentication Bypass",
            evidence=evidence_01,
            owasp="I1 – Weak, Guessable, or Hardcoded Passwords",
            cwe="CWE-306",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_score=score_01,
            severity=severity_01,
            remediation=(
                "In mosquitto.conf:\n"
                "  allow_anonymous false\n"
                "  password_file /etc/mosquitto/passwd\n"
                "Then run: mosquitto_passwd -c /etc/mosquitto/passwd <username>"
            ),
        )
    )

    # ── AUDIT-MQTT-02: Wildcard topic namespace (only if broker is open) ──────
    if connack_code == 0x00 and PAHO_AVAILABLE:
        console.print(f"    [dim]AUDIT-MQTT-02: Wildcard subscription (#) for 2s on {host}:{port}…[/dim]")
        topics = _wildcard_subscribe(host, port, timeout=timeout, listen_secs=2.0)

        if topics:
            verdict_02, evidence_02, severity_02 = (
                "VULNERABLE",
                f"Wildcard '#' subscription succeeded. Topics exposed: {', '.join(topics[:10])}",
                "HIGH",
            )
            score_02 = 7.5
        else:
            verdict_02, evidence_02, severity_02 = (
                "UNKNOWN",
                "Broker accepted wildcard subscription but no messages received in 2s.",
                "INFO",
            )
            score_02 = 0.0

        if verbose:
            console.print(f"      Topics seen: {topics}")

        findings.append(
            Finding(
                audit_id="AUDIT-MQTT-02",
                host=host,
                port=port,
                protocol="MQTT",
                verdict=verdict_02,
                title="MQTT Wildcard Topic Namespace Exposure",
                evidence=evidence_02,
                owasp="I2 – Insecure Network Services",
                cwe="CWE-200",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cvss_score=score_02,
                severity=severity_02,
                remediation=(
                    "Implement MQTT ACLs in mosquitto.conf:\n"
                    "  acl_file /etc/mosquitto/acl\n"
                    "ACL file example:\n"
                    "  user sensor_node\n"
                    "  topic readwrite sensors/#\n"
                    "  topic deny #"
                ),
            )
        )

    return findings

