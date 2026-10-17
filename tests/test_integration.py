"""
test_integration.py — End-to-end pipeline integration tests

Simulates the complete scan -> fingerprint -> audit -> verify -> report workflow
with mocked network layer to ensure zero network dependency during automated test runs.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from iot_audit.core.auditor import run_audit
from iot_audit.core.fingerprint import ServiceInfo, ServiceMap
from iot_audit.core.verify import run_verification
from iot_audit.utils.reporter import generate_report


class TestPipelineIntegration(unittest.TestCase):
    def setUp(self):
        self.test_host = "192.168.1.100"
        self.smap = ServiceMap(host=self.test_host)
        self.smap.services = [
            ServiceInfo(host=self.test_host, port=1883, protocol="tcp", open=True, service_guess="MQTT"),
            ServiceInfo(host=self.test_host, port=80, protocol="tcp", open=True, service_guess="HTTP"),
            ServiceInfo(host=self.test_host, port=5683, protocol="udp", open=True, service_guess="CoAP"),
        ]

    @patch("iot_audit.modules.mqtt_probe._raw_mqtt_connack", return_value=0x00)
    @patch("iot_audit.modules.mqtt_probe._wildcard_subscribe", return_value=["telemetry/sensor1", "home/status"])
    @patch("iot_audit.modules.http_probe._http_get")
    @patch("iot_audit.modules.coap_probe._send_coap_probe", return_value=(2, 5, "</status>,</api/metrics>"))
    def test_full_audit_and_report_pipeline(
        self, mock_coap, mock_http_get, mock_mqtt_wc, mock_mqtt_connack
    ):
        """Verify entire flow from ServiceMap through vulnerability audit to report exports."""
        # Mock HTTP responses: HTTP 80 without redirect -> cleartext vulnerable
        http_resp = MagicMock()
        http_resp.status_code = 200
        http_resp.headers = {}
        http_resp.text = '{"device": "test-iot", "status": "online"}'
        mock_http_get.return_value = http_resp

        # 1. Run audit
        findings = run_audit(self.test_host, self.smap, timeout=1.0)
        self.assertGreater(len(findings), 0)

        finding_ids = [f.audit_id for f in findings]
        self.assertIn("AUDIT-MQTT-01", finding_ids)
        self.assertIn("AUDIT-HTTP-01", finding_ids)
        self.assertIn("AUDIT-COAP-01", finding_ids)

        # 2. Export JSON Report
        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = str(Path(tmpdir) / "test_findings.json")
            md_path = str(Path(tmpdir) / "test_report.md")

            out_json = generate_report(findings, target=self.test_host, fmt="json", output_path=json_path)
            self.assertEqual(out_json, json_path)
            self.assertTrue(Path(json_path).exists())

            # Validate JSON content schema
            data = json.loads(Path(json_path).read_text(encoding="utf-8"))
            self.assertIn("scan_metadata", data)
            self.assertEqual(data["scan_metadata"]["target"], self.test_host)
            self.assertIn("findings", data)
            self.assertGreaterEqual(len(data["findings"]), 3)
            self.assertIn("owasp_coverage", data)

            # 3. Export Markdown Report
            out_md = generate_report(findings, target=self.test_host, fmt="markdown", output_path=md_path)
            self.assertEqual(out_md, md_path)
            self.assertTrue(Path(md_path).exists())

            md_content = Path(md_path).read_text(encoding="utf-8")
            self.assertIn("# IoT Security Assessment Report", md_content)
            self.assertIn("AUDIT-MQTT-01", md_content)
            self.assertIn("Executive Summary", md_content)

    @patch("iot_audit.core.verify._raw_mqtt_connack", return_value=0x05)
    @patch("iot_audit.core.verify._rtsp_describe", return_value=(401, "RTSP/1.0 401 Unauthorized"))
    def test_verification_pipeline(self, mock_rtsp, mock_mqtt):
        """Verify the post-hardening defense validation engine."""
        results = run_verification(
            host=self.test_host,
            ports=[1883, 554],
            username="admin",
            password="securepassword123",
            timeout=1.0,
        )

        self.assertGreater(len(results), 0)
        anon_result = next(r for r in results if r.check_id == "VERIFY-MQTT-AUTH-ANON")
        self.assertEqual(anon_result.status, "PASS")

    def test_report_path_routing_to_dedicated_folder(self):
        """Ensure report paths default to the dedicated 'reports/' directory."""
        from iot_audit.utils.reporter import resolve_report_path, REPORTS_DIR

        # Case 1: None provided -> default inside reports/
        p1 = resolve_report_path(None, "audit_report.md")
        self.assertEqual(p1, str(REPORTS_DIR / "audit_report.md"))

        # Case 2: Bare filename provided -> routes inside reports/
        p2 = resolve_report_path("custom_report.json", "fallback.json")
        self.assertEqual(p2, str(REPORTS_DIR / "custom_report.json"))

        # Case 3: Explicit directory provided -> preserved as-is
        p3 = resolve_report_path(str(Path("custom_folder") / "report.md"), "fallback.md")
        self.assertEqual(p3, str(Path("custom_folder") / "report.md"))


if __name__ == "__main__":
    unittest.main()
