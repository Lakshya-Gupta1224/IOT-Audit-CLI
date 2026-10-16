"""
scoring.py — CVSS v3.1 Base Score Calculator & OWASP IoT Mapping

Implements the CVSS v3.1 base score formula as defined by FIRST.org.
Reference: https://www.first.org/cvss/v3.1/specification-document

Provides:
  - compute_cvss(vector_string) -> float
  - severity_label(score) -> str
  - OWASP_IOT_TOP10 mapping dict
"""

from __future__ import annotations

import math
import re

# ── OWASP IoT Top 10 (2018) reference table ───────────────────────────────────

OWASP_IOT_TOP10: dict[str, dict] = {
    "I1": {
        "title": "Weak, Guessable, or Hardcoded Passwords",
        "description": (
            "Use of easily brute forced, publicly available, or unchangeable credentials, "
            "including backdoors in firmware or client software that grants unauthorized "
            "access to deployed systems."
        ),
        "cwe": ["CWE-306", "CWE-521", "CWE-798"],
    },
    "I2": {
        "title": "Insecure Network Services",
        "description": (
            "Unneeded or insecure network services running on the device itself, "
            "especially those exposed to the internet, that compromise confidentiality, "
            "integrity/authenticity, or availability of information or allow unauthorized remote control."
        ),
        "cwe": ["CWE-200", "CWE-319"],
    },
    "I3": {
        "title": "Insecure Ecosystem Interfaces",
        "description": (
            "Insecure web, backend API, cloud, or mobile interfaces in the ecosystem "
            "outside of the device that allows compromise of the device or its related components. "
            "Common issues include a lack of authentication/authorization, lacking or weak encryption, "
            "and a lack of input and output filtering."
        ),
        "cwe": ["CWE-200", "CWE-284", "CWE-287"],
    },
    "I4": {
        "title": "Lack of Secure Update Mechanism",
        "description": (
            "Lack of ability to securely update the device. This includes lack of firmware "
            "validation on device, lack of secure delivery (un-encrypted in transit), "
            "lack of anti-rollback mechanisms, and lack of notifications of security changes due to updates."
        ),
        "cwe": ["CWE-494", "CWE-693"],
    },
    "I5": {
        "title": "Use of Insecure or Outdated Components",
        "description": (
            "Use of deprecated or insecure software components/libraries that could allow "
            "the device to be compromised. This includes insecure customization of operating system "
            "platforms, and the use of third-party software or hardware components from a compromised supply chain."
        ),
        "cwe": ["CWE-1035", "CWE-937"],
    },
    "I6": {
        "title": "Insufficient Privacy Protection",
        "description": (
            "User's personal information stored on the device or in the ecosystem that is "
            "used insecurely, improperly, or without permission."
        ),
        "cwe": ["CWE-359"],
    },
    "I7": {
        "title": "Insecure Data Transfer and Storage",
        "description": (
            "Lack of encryption or access control of sensitive data anywhere in the ecosystem, "
            "including at rest, in transit, or during processing."
        ),
        "cwe": ["CWE-319", "CWE-311"],
    },
    "I8": {
        "title": "Lack of Device Management",
        "description": (
            "Lack of security support on devices deployed in production, including asset management, "
            "update management, secure decommissioning, systems monitoring, and response capabilities."
        ),
        "cwe": ["CWE-693"],
    },
    "I9": {
        "title": "Insecure Default Settings",
        "description": (
            "Devices or systems shipped with insecure default settings or lack the ability "
            "to make the system more secure by restricting operators from modifying configurations."
        ),
        "cwe": ["CWE-1188", "CWE-276"],
    },
    "I10": {
        "title": "Lack of Physical Hardening",
        "description": (
            "Lack of physical hardening measures, allowing potential attackers to gain sensitive "
            "information that can be used in a future remote attack or take local control of the device."
        ),
        "cwe": ["CWE-1299"],
    },
}


# ── CVSS v3.1 metric weights ──────────────────────────────────────────────────

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # Scope Unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}  # Scope Changed
_UI = {"N": 0.85, "R": 0.62}
_C = {"N": 0.0, "L": 0.22, "H": 0.56}
_I = {"N": 0.0, "L": 0.22, "H": 0.56}
_A = {"N": 0.0, "L": 0.22, "H": 0.56}

_VECTOR_RE = re.compile(
    r"CVSS:3\.[01]/AV:([NALP])/AC:([LH])/PR:([NLH])/UI:([NR])/S:([UC])/C:([NLH])/I:([NLH])/A:([NLH])"
)


def compute_cvss(vector: str) -> float:
    """
    Parse a CVSS v3.1 vector string and return the base score (0.0–10.0).

    Args:
        vector: e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    Returns:
        Base score rounded to 1 decimal place, or 0.0 if vector is invalid.
    """
    m = _VECTOR_RE.match(vector.strip())
    if not m:
        return 0.0

    av_v, ac_v, pr_v, ui_v, s_v, c_v, i_v, a_v = m.groups()

    scope_changed = s_v == "C"
    pr_table = _PR_C if scope_changed else _PR_U

    av = _AV[av_v]
    ac = _AC[ac_v]
    pr = pr_table[pr_v]
    ui = _UI[ui_v]
    c = _C[c_v]
    i = _I[i_v]
    a = _A[a_v]

    # Exploitability sub-score
    iss = 1 - (1 - c) * (1 - i) * (1 - a)

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0

    if scope_changed:
        base = min(1.08 * (impact + exploitability), 10)
    else:
        base = min(impact + exploitability, 10)

    # Round up to nearest 0.1
    return math.ceil(base * 10) / 10


def severity_label(score: float) -> str:
    """Return CVSS v3.1 qualitative severity label for a numeric score."""
    if score == 0.0:
        return "INFO"
    elif score < 4.0:
        return "LOW"
    elif score < 7.0:
        return "MEDIUM"
    elif score < 9.0:
        return "HIGH"
    else:
        return "CRITICAL"


def severity_color(severity: str) -> str:
    """Return rich markup color for a severity label."""
    return {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "dim",
    }.get(severity.upper(), "white")

