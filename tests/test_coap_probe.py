"""
test_coap_probe.py — Unit tests for the CoAP vulnerability audit probe

Tests AUDIT-COAP-01 under various server response conditions with mocked UDP sockets.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from iot_audit.modules.coap_probe import audit_coap, _send_coap_probe


class TestCoapProbe(unittest.TestCase):
    @patch("iot_audit.modules.coap_probe._send_coap_probe")
    def test_vulnerable_coap_resource_discovery(self, mock_probe):
        """2.05 Content response with link-format resources -> VULNERABLE."""
        mock_probe.return_value = (2, 5, "</sensors/temp>;rt=\"temperature\",</actuators/led>")

        findings = audit_coap("192.168.1.150", port=5683)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.audit_id, "AUDIT-COAP-01")
        self.assertEqual(f.verdict, "VULNERABLE")
        self.assertEqual(f.protocol, "CoAP")
        self.assertEqual(f.severity, "MEDIUM")
        self.assertGreater(f.cvss_score, 5.0)
        self.assertIn("/sensors/temp", f.evidence)

    @patch("iot_audit.modules.coap_probe._send_coap_probe")
    def test_protected_coap_unauthorized(self, mock_probe):
        """4.01 Unauthorized response -> PROTECTED."""
        mock_probe.return_value = (4, 1, "")

        findings = audit_coap("192.168.1.150", port=5683)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.audit_id, "AUDIT-COAP-01")
        self.assertEqual(f.verdict, "PROTECTED")
        self.assertEqual(f.cvss_score, 0.0)

    @patch("iot_audit.modules.coap_probe._send_coap_probe")
    def test_unknown_coap_no_response(self, mock_probe):
        """No response from target -> UNKNOWN."""
        mock_probe.return_value = None

        findings = audit_coap("192.168.1.150", port=5683)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.audit_id, "AUDIT-COAP-01")
        self.assertEqual(f.verdict, "UNKNOWN")
        self.assertEqual(f.cvss_score, 0.0)


if __name__ == "__main__":
    unittest.main()
