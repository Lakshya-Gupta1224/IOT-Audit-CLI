"""
iot_audit — IoT Security Posture & Vulnerability Assessment Framework
OWASP IoT Top 10 · PTES-aligned · Non-destructive probes
"""

import sys

# Ensure UTF-8 output encoding across Windows terminals without charmap encoding crashes
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

__version__ = "0.1.0"
__author__ = "Lakshya Gupta"
