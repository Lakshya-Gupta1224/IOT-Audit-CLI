# IoT Security Assessment Report

**Target:** `192.168.1.0/24`
**Generated:** 2026-10-29T07:12:05.507568+00:00
**Tool:** iot-audit-cli v0.1.0

---

## Executive Summary

| Metric | Value |
|:---|:---|
| Total Probes Executed | 7 |
| Vulnerabilities Found | **5** |
| Highest CVSS Score | **9.8** |
| Risk Posture | **🔴 CRITICAL** |

---

## Vulnerability Findings


### AUDIT-MQTT-01 — MQTT Broker Anonymous Authentication Bypass

| Field | Detail |
|:---|:---|
| **Host** | `192.168.1.105:1883` |
| **Protocol** | MQTT |
| **Verdict** | VULNERABLE |
| **OWASP IoT** | I1 – Weak, Guessable, or Hardcoded Passwords |
| **CWE** | CWE-306 |
| **CVSS v3.1 Score** | 9.8 (CRITICAL) |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |

**Evidence:**
> CONNACK return code 0x00 (Connection Accepted) — anonymous access granted.

**Remediation:**
```
In mosquitto.conf:
  allow_anonymous false
  password_file /etc/mosquitto/passwd
Then run: mosquitto_passwd -c /etc/mosquitto/passwd <username>
```

---

### AUDIT-MQTT-02 — MQTT Wildcard Topic Namespace Exposure

| Field | Detail |
|:---|:---|
| **Host** | `192.168.1.105:1883` |
| **Protocol** | MQTT |
| **Verdict** | VULNERABLE |
| **OWASP IoT** | I2 – Insecure Network Services |
| **CWE** | CWE-200 |
| **CVSS v3.1 Score** | 7.5 (HIGH) |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |

**Evidence:**
> Wildcard '#' subscription succeeded. Topics exposed: telemetry/temp, sensors/node1/accel, status/health

**Remediation:**
```
Implement MQTT ACLs in mosquitto.conf:
  acl_file /etc/mosquitto/acl
ACL file example:
  user sensor_node
  topic readwrite sensors/#
  topic deny #
```

---

### AUDIT-HTTP-01 — Unencrypted Cleartext HTTP Admin Interface

| Field | Detail |
|:---|:---|
| **Host** | `192.168.1.112:8080` |
| **Protocol** | HTTP |
| **Verdict** | VULNERABLE |
| **OWASP IoT** | I7 – Insecure Data Transfer and Storage |
| **CWE** | CWE-319 |
| **CVSS v3.1 Score** | 7.4 (HIGH) |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` |

**Evidence:**
> HTTP 200 — web interface accessible over plaintext HTTP (no TLS redirect).

**Remediation:**
```
1. Enable HTTPS on the device web server.
2. Add HTTP -> HTTPS redirect (301) for all admin paths.
3. Enforce Strict-Transport-Security (HSTS) headers.
```

---

### AUDIT-HTTP-02 — Exposed Diagnostic / Telemetry Endpoints Without Authentication

| Field | Detail |
|:---|:---|
| **Host** | `192.168.1.112:8080` |
| **Protocol** | HTTP |
| **Verdict** | VULNERABLE |
| **OWASP IoT** | I3 – Insecure Ecosystem Interfaces |
| **CWE** | CWE-200 |
| **CVSS v3.1 Score** | 6.5 (MEDIUM) |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |

**Evidence:**
> 2 endpoint(s) returned HTTP 200 without authentication: /system/info, /api/device

**Remediation:**
```
1. Require Bearer token / Basic Auth over HTTPS on all API paths.
2. Disable diagnostic endpoints in production firmware.
```

---

### AUDIT-HTTP-03 — Default or Hardcoded Web Interface Credentials

| Field | Detail |
|:---|:---|
| **Host** | `192.168.1.112:8080` |
| **Protocol** | HTTP |
| **Verdict** | VULNERABLE |
| **OWASP IoT** | I1 – Weak, Guessable, or Hardcoded Passwords |
| **CWE** | CWE-521 |
| **CVSS v3.1 Score** | 9.8 (CRITICAL) |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |

**Evidence:**
> Default credentials accepted on /login: 'admin:admin'

**Remediation:**
```
1. Force administrator password rotation on initial boot.
2. Enforce minimum complexity requirements and rate limit login endpoints.
```

---

### AUDIT-COAP-01 — Unauthenticated CoAP Resource Discovery (.well-known/core)

| Field | Detail |
|:---|:---|
| **Host** | `192.168.1.130:5683` |
| **Protocol** | CoAP |
| **Verdict** | PROTECTED |
| **OWASP IoT** | I2 – Insecure Network Services |
| **CWE** | CWE-200 |
| **CVSS v3.1 Score** | 0.0 (INFO) |
| **CVSS Vector** | `` |

**Evidence:**
> CoAP response code 4.01 — Access denied / authentication enforced.

**Remediation:**
```
Maintain DTLS Pre-Shared Key (PSK) requirement for all CoAP queries.
```

---

### AUDIT-RTSP-01 — Unauthenticated RTSP Video Stream Access

| Field | Detail |
|:---|:---|
| **Host** | `192.168.1.140:554` |
| **Protocol** | RTSP |
| **Verdict** | PROTECTED |
| **OWASP IoT** | I1 – Weak, Guessable, or Hardcoded Passwords |
| **CWE** | CWE-306 |
| **CVSS v3.1 Score** | 0.0 (INFO) |
| **CVSS Vector** | `` |

**Evidence:**
> RTSP DESCRIBE returned 401/403 on all probed paths — authentication enforced.

**Remediation:**
```
Digest authentication verified.
```

---


## Defensive Verification Results


*No verification checks were run. Use `iot-audit verify` to confirm hardening.*


## OWASP IoT Top 10 Coverage

| Category | Title | Probes |
|:---|:---|:---|
| I1 | Weak, Guessable, or Hardcoded Passwords | AUDIT-MQTT-01, AUDIT-HTTP-03, AUDIT-RTSP-01 |
| I2 | Insecure Network Services | AUDIT-MQTT-02, AUDIT-COAP-01 |
| I7 | Insecure Data Transfer and Storage | AUDIT-HTTP-01 |
| I3 | Insecure Ecosystem Interfaces | AUDIT-HTTP-02 |


---
*Report generated by iot-audit-cli — Academic Research Tool*
*All probes are non-destructive and read-only.*