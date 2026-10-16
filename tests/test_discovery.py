"""
test_discovery.py — Unit tests for the network discovery engine

Uses mock sockets to avoid any real network traffic.
All tests pass without physical network access or admin privileges.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from iot_audit.core.discovery import (
    DiscoveredDevice,
    _parse_ssdp,
    _reverse_dns,
    lookup_vendor,
)


class TestDiscoveredDevice(unittest.TestCase):
    def test_basic_instantiation(self):
        dev = DiscoveredDevice(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:ff", vendor="Espressif Inc.")
        self.assertEqual(dev.ip, "192.168.1.1")
        self.assertEqual(dev.mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(dev.vendor, "Espressif Inc.")

    def test_default_fields(self):
        dev = DiscoveredDevice(ip="10.0.0.1")
        self.assertEqual(dev.mac, "unknown")
        self.assertEqual(dev.vendor, "unknown")
        self.assertEqual(dev.hostname, "")
        self.assertIsInstance(dev.services, list)

    def test_str_representation(self):
        dev = DiscoveredDevice(ip="192.168.1.5", mac="de:ad:be:ef:00:01")
        self.assertIn("192.168.1.5", str(dev))
        self.assertIn("de:ad:be:ef:00:01", str(dev))


class TestSSDPParser(unittest.TestCase):
    def test_parses_location_and_server(self):
        raw = (
            "HTTP/1.1 200 OK\r\n"
            "Location: http://192.168.1.1:1900/desc.xml\r\n"
            "Server: Linux/2.6 UPnP/1.0 MiniUPnPd/2.1\r\n"
            "ST: upnp:rootdevice\r\n"
            "\r\n"
        )
        result = _parse_ssdp(raw)
        self.assertIn("location", result)
        self.assertIn("http://192.168.1.1", result["location"])
        self.assertIn("server", result)

    def test_empty_response(self):
        result = _parse_ssdp("")
        self.assertIsInstance(result, dict)

    def test_malformed_header(self):
        # Should not raise — lines without ":" are silently skipped
        result = _parse_ssdp("HTTP/1.1 200 OK\r\nGarbage line no colon\r\n")
        self.assertIsInstance(result, dict)


class TestLookupVendor(unittest.TestCase):
    def test_unknown_mac_returns_string(self):
        # With manuf unavailable or unknown OUI, should still return a string
        result = lookup_vendor("ff:ff:ff:ff:ff:ff")
        self.assertIsInstance(result, str)

    def test_valid_mac_no_crash(self):
        # Should not raise regardless of manuf availability
        result = lookup_vendor("a4:c3:f0:11:22:33")
        self.assertIsInstance(result, str)


class TestReverseDns(unittest.TestCase):
    @patch("socket.gethostbyaddr", return_value=("router.local", [], ["192.168.1.1"]))
    def test_successful_reverse_dns(self, mock_gethostbyaddr):
        result = _reverse_dns("192.168.1.1")
        self.assertEqual(result, "router.local")

    @patch("socket.gethostbyaddr", side_effect=OSError("no host"))
    def test_failed_reverse_dns_returns_empty(self, mock_gethostbyaddr):
        result = _reverse_dns("192.168.1.99")
        self.assertEqual(result, "")


class TestPingSweepMocked(unittest.TestCase):
    """Test _ping_sweep logic with mocked socket connections."""

    @patch("socket.create_connection")
    def test_live_host_detected(self, mock_conn):
        """A host that accepts TCP 80 should appear in results."""
        from iot_audit.core.discovery import _ping_sweep

        mock_sock = MagicMock()
        mock_conn.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        with patch("iot_audit.core.discovery._reverse_dns", return_value=""):
            results = _ping_sweep("192.168.1.1/32")

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].ip, "192.168.1.1")

    @patch("socket.create_connection", side_effect=OSError("refused"))
    def test_dead_host_not_detected(self, mock_conn):
        """A host that refuses all connections should not appear."""
        from iot_audit.core.discovery import _ping_sweep

        results = _ping_sweep("192.168.1.1/32")
        self.assertEqual(len(results), 0)


if __name__ == "__main__":
    unittest.main()

