"""
test_auditor.py — Unit tests for vulnerability audit probes

Mock all network I/O so tests run offline, fast, and without admin rights.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from iot_audit.utils.scoring import compute_cvss, severity_label, OWASP_IOT_TOP10


# ── CVSS scoring tests ────────────────────────────────────────────────────────


class TestCvssScoring(unittest.TestCase):
    def test_critical_vector(self):
        """AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H should be 9.8 CRITICAL."""
        score = compute_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertAlmostEqual(score, 9.8, places=0)

    def test_high_vector(self):
        """AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N should be 7.5 HIGH."""
        score = compute_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        self.assertGreaterEqual(score, 7.0)
        self.assertLess(score, 9.0)

    def test_zero_impact(self):
        """All CIA:N should produce score 0.0."""
        score = compute_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        self.assertEqual(score, 0.0)

    def test_invalid_vector(self):
        """Garbage vector should return 0.0 without raising."""
        score = compute_cvss("not-a-vector")
        self.assertEqual(score, 0.0)

    def test_scope_changed_vector(self):
        """S:C should use scope-changed formula."""
        score = compute_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        self.assertGreater(score, 9.0)

    def test_severity_labels(self):
        self.assertEqual(severity_label(9.8), "CRITICAL")
        self.assertEqual(severity_label(7.5), "HIGH")
        self.assertEqual(severity_label(5.0), "MEDIUM")
        self.assertEqual(severity_label(2.0), "LOW")
        self.assertEqual(severity_label(0.0), "INFO")


class TestOwaspMapping(unittest.TestCase):
    def test_all_top10_present(self):
        for i in range(1, 11):
            key = f"I{i}"
            self.assertIn(key, OWASP_IOT_TOP10, f"OWASP {key} missing")

    def test_each_entry_has_title(self):
        for key, entry in OWASP_IOT_TOP10.items():
            self.assertIn("title", entry)
            self.assertIsInstance(entry["title"], str)

    def test_each_entry_has_cwe(self):
        for key, entry in OWASP_IOT_TOP10.items():
            self.assertIn("cwe", entry)
            self.assertIsInstance(entry["cwe"], list)
            self.assertGreater(len(entry["cwe"]), 0)


# ── MQTT probe tests ──────────────────────────────────────────────────────────


class TestMqttProbe(unittest.TestCase):
    @patch("iot_audit.modules.mqtt_probe._raw_mqtt_connack", return_value=0x00)
    @patch("iot_audit.modules.mqtt_probe._wildcard_subscribe", return_value=["sensor/temp", "home/light"])
    def test_vulnerable_broker_detection(self, mock_wc, mock_connack):
        """CONNACK 0x00 should produce AUDIT-MQTT-01 VULNERABLE finding."""
        from iot_audit.modules.mqtt_probe import audit_mqtt

        findings = audit_mqtt("192.168.1.101", port=1883, tls=False)
        mqtt01 = next(f for f in findings if f.audit_id == "AUDIT-MQTT-01")
        self.assertEqual(mqtt01.verdict, "VULNERABLE")
        self.assertGreater(mqtt01.cvss_score, 9.0)
        self.assertEqual(mqtt01.severity, "CRITICAL")

    @patch("iot_audit.modules.mqtt_probe._raw_mqtt_connack", return_value=0x05)
    def test_protected_broker(self, mock_connack):
        """CONNACK 0x05 should produce AUDIT-MQTT-01 PROTECTED finding."""
        from iot_audit.modules.mqtt_probe import audit_mqtt

        findings = audit_mqtt("192.168.1.101", port=1883, tls=False)
        mqtt01 = next(f for f in findings if f.audit_id == "AUDIT-MQTT-01")
        self.assertEqual(mqtt01.verdict, "PROTECTED")
        self.assertEqual(mqtt01.cvss_score, 0.0)

    @patch("iot_audit.modules.mqtt_probe._raw_mqtt_connack", return_value=None)
    def test_unreachable_broker(self, mock_connack):
        """No CONNACK should produce AUDIT-MQTT-01 UNKNOWN finding."""
        from iot_audit.modules.mqtt_probe import audit_mqtt

        findings = audit_mqtt("192.168.1.200", port=1883, tls=False)
        mqtt01 = next(f for f in findings if f.audit_id == "AUDIT-MQTT-01")
        self.assertEqual(mqtt01.verdict, "UNKNOWN")

    @patch("iot_audit.modules.mqtt_probe._raw_mqtt_connack", return_value=0x00)
    def test_tls_not_enforced(self, mock_connack):
        """Plaintext CONNACK on 8883 → TLS not enforced → VULNERABLE."""
        from iot_audit.modules.mqtt_probe import audit_mqtt

        findings = audit_mqtt("192.168.1.101", port=8883, tls=True)
        mqtts01 = next(f for f in findings if f.audit_id == "AUDIT-MQTTS-01")
        self.assertEqual(mqtts01.verdict, "VULNERABLE")

    @patch("iot_audit.modules.mqtt_probe._raw_mqtt_connack", return_value=None)
    def test_tls_enforced(self, mock_connack):
        """No plaintext CONNACK on 8883 → TLS enforced → PROTECTED."""
        from iot_audit.modules.mqtt_probe import audit_mqtt

        findings = audit_mqtt("192.168.1.101", port=8883, tls=True)
        mqtts01 = next(f for f in findings if f.audit_id == "AUDIT-MQTTS-01")
        self.assertEqual(mqtts01.verdict, "PROTECTED")


# ── RTSP probe tests ──────────────────────────────────────────────────────────


class TestRtspProbe(unittest.TestCase):
    @patch("iot_audit.modules.rtsp_probe._rtsp_describe", return_value=(200, "RTSP/1.0 200 OK"))
    def test_unauthenticated_stream(self, mock_describe):
        """200 OK on DESCRIBE → VULNERABLE."""
        from iot_audit.modules.rtsp_probe import audit_rtsp

        findings = audit_rtsp("192.168.1.104", port=554)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].verdict, "VULNERABLE")
        self.assertGreater(findings[0].cvss_score, 7.0)

    @patch("iot_audit.modules.rtsp_probe._rtsp_describe", return_value=(401, "RTSP/1.0 401 Unauthorized"))
    def test_authenticated_stream(self, mock_describe):
        """401 on DESCRIBE → PROTECTED."""
        from iot_audit.modules.rtsp_probe import audit_rtsp

        findings = audit_rtsp("192.168.1.104", port=554)
        self.assertEqual(findings[0].verdict, "PROTECTED")

    @patch("iot_audit.modules.rtsp_probe._rtsp_describe", return_value=None)
    def test_no_rtsp_response(self, mock_describe):
        """No response → UNKNOWN."""
        from iot_audit.modules.rtsp_probe import audit_rtsp

        findings = audit_rtsp("192.168.1.104", port=554)
        self.assertEqual(findings[0].verdict, "UNKNOWN")


# ── HTTP probe tests ──────────────────────────────────────────────────────────


class TestHttpProbe(unittest.TestCase):
    @patch("iot_audit.modules.http_probe._http_get")
    def test_cleartext_http_vulnerable(self, mock_get):
        """HTTP 200 without redirect → AUDIT-HTTP-01 VULNERABLE."""
        from iot_audit.modules.http_probe import audit_http

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.text = ""
        mock_get.return_value = mock_resp

        findings = audit_http("192.168.1.107", port=80)
        http01 = next(f for f in findings if f.audit_id == "AUDIT-HTTP-01")
        self.assertEqual(http01.verdict, "VULNERABLE")

    @patch("iot_audit.modules.http_probe._http_get")
    def test_https_redirect_protected(self, mock_get):
        """HTTP 301 → https → AUDIT-HTTP-01 PROTECTED."""
        from iot_audit.modules.http_probe import audit_http

        mock_resp = MagicMock()
        mock_resp.status_code = 301
        mock_resp.headers = {"Location": "https://192.168.1.107/"}
        mock_resp.text = ""
        mock_get.return_value = mock_resp

        findings = audit_http("192.168.1.107", port=80)
        http01 = next(f for f in findings if f.audit_id == "AUDIT-HTTP-01")
        self.assertEqual(http01.verdict, "PROTECTED")

    @patch("iot_audit.modules.http_probe._http_get")
    def test_exposed_endpoint_vulnerable(self, mock_get):
        """200 on /system/info → AUDIT-HTTP-02 VULNERABLE."""
        from iot_audit.modules.http_probe import audit_http

        def side_effect(url, **kwargs):
            resp = MagicMock()
            if "/system/info" in url or "/api/device" in url:
                resp.status_code = 200
                resp.text = '{"device": "camera", "firmware": "1.0.1"}'
            else:
                resp.status_code = 404
                resp.text = ""
            return resp

        mock_get.side_effect = side_effect

        findings = audit_http("192.168.1.107", port=80)
        http02 = next(f for f in findings if f.audit_id == "AUDIT-HTTP-02")
        self.assertEqual(http02.verdict, "VULNERABLE")

    @patch("iot_audit.modules.http_probe._http_post")
    @patch("iot_audit.modules.http_probe._http_get")
    def test_default_credentials_form_vulnerable(self, mock_get, mock_post):
        """Web login form accepts default admin/admin credentials -> AUDIT-HTTP-03 VULNERABLE."""
        from iot_audit.modules.http_probe import audit_http

        def get_side_effect(url, **kwargs):
            resp = MagicMock()
            if url.endswith("/login"):
                resp.status_code = 200
                resp.headers = {}
                resp.text = '<form method="post"><input name="user"><input type="password"></form>'
            else:
                resp.status_code = 404
                resp.headers = {}
                resp.text = ""
            return resp

        mock_get.side_effect = get_side_effect

        post_resp = MagicMock()
        post_resp.status_code = 302
        post_resp.headers = {"Location": "/dashboard"}
        mock_post.return_value = post_resp

        findings = audit_http("192.168.1.107", port=80)
        http03 = next(f for f in findings if f.audit_id == "AUDIT-HTTP-03")
        self.assertEqual(http03.verdict, "VULNERABLE")
        self.assertEqual(http03.severity, "CRITICAL")
        self.assertEqual(http03.cvss_score, 9.8)

    @patch("iot_audit.modules.http_probe._http_get")
    def test_default_credentials_basic_auth_vulnerable(self, mock_get):
        """HTTP Basic Auth challenge accepts admin/admin -> AUDIT-HTTP-03 VULNERABLE."""
        from iot_audit.modules.http_probe import audit_http

        def get_side_effect(url, auth=None, **kwargs):
            resp = MagicMock()
            if auth == ("admin", "admin"):
                resp.status_code = 200
                resp.headers = {}
                resp.text = "Welcome admin"
            elif url.endswith("/admin"):
                resp.status_code = 401
                resp.headers = {"WWW-Authenticate": 'Basic realm="IoT Admin"'}
                resp.text = "Unauthorized"
            else:
                resp.status_code = 404
                resp.headers = {}
                resp.text = ""
            return resp

        mock_get.side_effect = get_side_effect

        findings = audit_http("192.168.1.107", port=80)
        http03 = next(f for f in findings if f.audit_id == "AUDIT-HTTP-03")
        self.assertEqual(http03.verdict, "VULNERABLE")
        self.assertIn("admin:admin", http03.evidence)

    @patch("iot_audit.modules.http_probe._http_get")
    def test_default_credentials_digest_auth_vulnerable(self, mock_get):
        """HTTP Digest Auth challenge (common in IP Webcam) accepts admin/admin -> AUDIT-HTTP-03 VULNERABLE."""
        from requests.auth import HTTPDigestAuth
        from iot_audit.modules.http_probe import audit_http

        def get_side_effect(url, auth=None, **kwargs):
            resp = MagicMock()
            if isinstance(auth, HTTPDigestAuth) and auth.username == "admin" and auth.password == "admin":
                resp.status_code = 200
                resp.headers = {}
                resp.text = "IP Webcam stream OK"
            elif url.endswith("/"):
                resp.status_code = 401
                resp.headers = {"WWW-Authenticate": 'Digest realm="IP Webcam", nonce="12345"'}
                resp.text = "Unauthorized"
            else:
                resp.status_code = 404
                resp.headers = {}
                resp.text = ""
            return resp

        mock_get.side_effect = get_side_effect

        findings = audit_http("192.168.1.107", port=8080)
        http03 = next(f for f in findings if f.audit_id == "AUDIT-HTTP-03")
        self.assertEqual(http03.verdict, "VULNERABLE")
        self.assertEqual(http03.severity, "CRITICAL")
        self.assertEqual(http03.cvss_score, 9.8)
        self.assertIn("admin:admin", http03.evidence)


# ── Finding model tests ────────────────────────────────────────────────────────


class TestFindingModel(unittest.TestCase):
    def test_to_dict_has_all_keys(self):
        from iot_audit.models import Finding

        f = Finding(
            audit_id="AUDIT-TEST-01",
            host="127.0.0.1",
            port=1883,
            protocol="MQTT",
            verdict="VULNERABLE",
            title="Test Finding",
            cvss_score=9.8,
            severity="CRITICAL",
        )
        d = f.to_dict()
        for key in ("audit_id", "host", "port", "protocol", "verdict", "title", "cvss_score", "severity"):
            self.assertIn(key, d)

    def test_finding_defaults(self):
        from iot_audit.models import Finding

        f = Finding(
            audit_id="X", host="h", port=0, protocol="P",
            verdict="UNKNOWN", title="T"
        )
        self.assertEqual(f.evidence, "")
        self.assertEqual(f.cvss_score, 0.0)
        self.assertEqual(f.severity, "INFO")


if __name__ == "__main__":
    unittest.main()

