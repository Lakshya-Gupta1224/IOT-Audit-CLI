# iot-audit-cli

**Automated IoT Security Posture & Vulnerability Assessment Framework**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![OWASP IoT Top 10](https://img.shields.io/badge/OWASP-IoT%20Top%2010-orange)](https://owasp.org/www-project-internet-of-things/)
[![CVSS v3.1](https://img.shields.io/badge/Scoring-CVSS%20v3.1-red)](https://www.first.org/cvss/v3.1/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A non-destructive, research-grade CLI tool for evaluating IoT device security posture against the **OWASP IoT Top 10** and the **Penetration Testing Execution Standard (PTES)**. Designed for academic security research testbeds.

> ⚠️ **Academic & Research Use Only.** All probes are read-only and non-destructive. Only run this tool on networks and devices you own or have explicit written authorization to test.

---

## Features

| Module | Capability |
|:---|:---|
| **Discovery** | ARP sweep (Layer-2), UPnP/SSDP multicast, mDNS zero-config |
| **Fingerprinting** | IoT port suite (MQTT, RTSP, CoAP, HTTP, Telnet) with banner grabbing |
| **Auditing** | 7 OWASP-mapped vulnerability probes with CVSS v3.1 scoring |
| **Verification** | Post-hardening control validation (ACL, TLS, auth enforcement) |
| **Reporting** | Rich terminal tables, structured JSON, publication-ready Markdown |

### Audit Probes

| Probe ID | Protocol | Vulnerability | OWASP | CVSS |
|:---|:---|:---|:---|:---|
| `AUDIT-MQTT-01` | MQTT :1883 | Anonymous authentication bypass | I1 · CWE-306 | 9.8 Critical |
| `AUDIT-MQTT-02` | MQTT :1883 | Wildcard topic namespace exposure | I2 · CWE-200 | 7.5 High |
| `AUDIT-MQTTS-01` | MQTTS :8883 | TLS not enforced on secure port | I7 · CWE-319 | 7.5 High |
| `AUDIT-RTSP-01` | RTSP :554 | Unauthenticated video stream | I1 · CWE-306 | 9.1 Critical |
| `AUDIT-HTTP-01` | HTTP :80/8080 | Cleartext admin interface | I7 · CWE-319 | 7.4 High |
| `AUDIT-HTTP-02` | HTTP :80/8080 | Exposed diagnostic endpoints | I3 · CWE-200 | 6.5 Medium |
| `AUDIT-TELNET-01` | Telnet :23/2323 | Insecure legacy daemon active | I5 · CWE-319 | 9.1 Critical |

---

## Installation

### Prerequisites

- Python 3.10+
- **Windows:** [Npcap](https://npcap.com/) installed (for ARP sweep via Scapy)
- **Linux/macOS:** Run with `sudo` for raw socket access

### Install

```bash
# Clone the repository
git clone https://github.com/Lakshya-Gupta1224/IOT-Attack-Surface-Scanner.git
cd IOT-Attack-Surface-Scanner

# Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/macOS

# Install dependencies
pip install -r requirements.txt

# Install the CLI tool (editable mode)
pip install -e .
```

---

## Usage

### Discover devices on a subnet

```bash
iot-audit scan -t 192.168.1.0/24
```

### Run a full vulnerability audit

```bash
# Terminal table output (default)
iot-audit audit -t 192.168.1.101

# Export to JSON
iot-audit audit -t 192.168.1.101 -f json -o findings.json

# Export to Markdown report
iot-audit audit -t 192.168.1.101 -f markdown -o report.md

# Audit a full subnet
iot-audit audit -t 192.168.1.0/24 -f json -o findings.json
```

### Validate security hardening

```bash
# Verify ACLs, TLS, and auth controls after remediation
iot-audit verify -t 192.168.1.101 -u admin -P securepassword

# Verify specific ports only
iot-audit verify -t 192.168.1.101 --ports 1883,8883
```

### Regenerate a report from saved findings

```bash
iot-audit report -i findings.json -f markdown -o report.md
iot-audit report -i findings.json -f table
```

---

## CLI Reference

```
Usage: iot-audit [OPTIONS] COMMAND [ARGS]...

Commands:
  scan    Discover IoT devices on a subnet
  audit   Run full vulnerability audit against target(s)
  verify  Validate security hardening controls
  report  Regenerate a report from saved findings JSON

Options:
  -t, --target TEXT     Target CIDR or single IP          [required]
  -p, --ports TEXT      Comma-separated port list
  --timeout FLOAT       Socket timeout in seconds         [default: 0.5]
  -f, --format TEXT     table | json | markdown           [default: table]
  -o, --output TEXT     Output file path
  -u, --user TEXT       Username for verify testing
  -P, --pass TEXT       Password for verify testing
  -v, --verbose         Enable verbose debug logging
  -V, --version         Show version and exit
```

---

## Project Structure

```
iot-audit-cli/
├── pyproject.toml              # Build configuration
├── requirements.txt            # Dependencies
├── README.md
├── iot_audit/
│   ├── cli.py                  # CLI entrypoint (typer)
│   ├── core/
│   │   ├── discovery.py        # ARP + UPnP/SSDP + mDNS
│   │   ├── fingerprint.py      # TCP/UDP port scanner + banner grabber
│   │   ├── auditor.py          # Audit orchestrator
│   │   └── verify.py           # Hardening verification engine
│   ├── modules/
│   │   ├── mqtt_probe.py       # MQTT CONNACK + wildcard probes
│   │   ├── rtsp_probe.py       # RTSP DESCRIBE probe
│   │   └── http_probe.py       # HTTP cleartext + endpoint probes
│   └── utils/
│       ├── reporter.py         # JSON / Markdown / Rich table output
│       └── scoring.py          # CVSS v3.1 calculator + OWASP mapping
└── tests/
    ├── test_discovery.py
    └── test_auditor.py
```

---

## Running Tests

```bash
python -m pytest tests/ -v
```

---

## Ethical Use

This tool is designed strictly for:
- Academic security research in controlled lab environments
- Security posture assessment of **your own** IoT infrastructure
- Post-remediation hardening verification in authorized testbeds

**Never run this tool on networks or devices without explicit written authorization.**

---

## Standards & References

- [OWASP IoT Top 10 (2018)](https://owasp.org/www-project-internet-of-things/)
- [FIRST CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [PTES — Penetration Testing Execution Standard](http://www.pentest-standard.org/)
- [NIST NVD CWE Dictionary](https://nvd.nist.gov/vuln/categories)

---

## License

MIT License — see [LICENSE](LICENSE) for details.

