"""
models.py — Shared data models for iot_audit

Placing Finding and VerifyResult here breaks the circular import
between auditor.py ↔ probe modules.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Finding:
    """
    A single vulnerability finding produced by an audit probe.

    Attributes:
        audit_id    : Unique probe identifier (e.g. AUDIT-MQTT-01)
        host        : Target IP
        port        : Target port
        protocol    : e.g. "MQTT", "RTSP", "HTTP"
        verdict     : "VULNERABLE" | "PROTECTED" | "UNKNOWN"
        title       : Short human-readable description
        evidence    : Raw evidence string (e.g. CONNACK return code)
        owasp       : OWASP IoT category (e.g. "I1 – Weak Passwords")
        cwe         : CWE identifier (e.g. "CWE-306")
        cvss_vector : CVSS v3.1 vector string
        cvss_score  : Calculated base score (0.0–10.0)
        severity    : "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"INFO"
        remediation : Actionable remediation instructions
    """

    audit_id: str
    host: str
    port: int
    protocol: str
    verdict: str
    title: str
    evidence: str = ""
    owasp: str = ""
    cwe: str = ""
    cvss_vector: str = ""
    cvss_score: float = 0.0
    severity: str = "INFO"
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "audit_id": self.audit_id,
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "verdict": self.verdict,
            "title": self.title,
            "evidence": self.evidence,
            "owasp_category": self.owasp,
            "cwe": self.cwe,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "severity": self.severity,
            "remediation": self.remediation,
        }
