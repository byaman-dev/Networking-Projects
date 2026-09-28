"""
Tests for NetRisk Stage 1 — the scanning engine.

Run with:
    python -m unittest test_netrisk_scanner.py -v

These tests don't rely on any real network state except for one
integration test that opens a real local socket to confirm "open"
detection actually works end-to-end — everything else uses mocked
sockets so the tests are fast and don't depend on which ports
happen to be free on the machine running them.
"""

import socket
import threading
import time
import unittest
from unittest.mock import patch, MagicMock

import netrisk_scanner as nr


class SafetyCheckTests(unittest.TestCase):

    def test_localhost_is_safe(self):
        self.assertTrue(nr.is_safe_target("127.0.0.1"))

    def test_private_lan_address_is_safe(self):
        self.assertTrue(nr.is_safe_target("192.168.1.10"))
        self.assertTrue(nr.is_safe_target("10.0.0.5"))
        self.assertTrue(nr.is_safe_target("172.16.0.1"))

    def test_public_address_is_refused(self):
        self.assertFalse(nr.is_safe_target("8.8.8.8"))

    def test_garbage_input_is_refused_not_crashed(self):
        self.assertFalse(nr.is_safe_target("not-an-ip"))


class PortClassificationTests(unittest.TestCase):
    """
    These mock the socket itself so we can deterministically test
    each classification branch (open / closed / filtered / error)
    without depending on what's actually listening on the machine.
    """

    @patch("netrisk_scanner.socket.socket")
    def test_open_port_classified_correctly(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value = mock_sock

        result = nr.scan_port("127.0.0.1", 22, timeout=1.0)

        self.assertEqual(result["status"], "open")
        self.assertEqual(result["service_guess"], "SSH")
        self.assertIsNone(result["detail"])

    @patch("netrisk_scanner.socket.socket")
    def test_closed_port_classified_correctly(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111  # connection refused
        mock_socket_cls.return_value = mock_sock

        result = nr.scan_port("127.0.0.1", 21, timeout=1.0)

        self.assertEqual(result["status"], "closed")
        self.assertIn("refused", result["detail"].lower())

    @patch("netrisk_scanner.socket.socket")
    def test_timeout_classified_as_filtered(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = socket.timeout
        mock_socket_cls.return_value = mock_sock

        result = nr.scan_port("127.0.0.1", 443, timeout=1.0)

        self.assertEqual(result["status"], "filtered")
        self.assertIn("timed out", result["detail"].lower())

    @patch("netrisk_scanner.socket.socket")
    def test_unexpected_os_error_does_not_crash_the_scan(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = OSError("network unreachable")
        mock_socket_cls.return_value = mock_sock

        result = nr.scan_port("127.0.0.1", 80, timeout=1.0)

        self.assertEqual(result["status"], "error")
        self.assertIn("network unreachable", result["detail"])

    def test_unknown_port_gets_unknown_service_guess(self):
        with patch("netrisk_scanner.socket.socket") as mock_socket_cls:
            mock_sock = MagicMock()
            mock_sock.connect_ex.return_value = 111
            mock_socket_cls.return_value = mock_sock

            result = nr.scan_port("127.0.0.1", 54321, timeout=1.0)

        self.assertEqual(result["service_guess"], "Unknown")


class ScanHostTests(unittest.TestCase):

    @patch("netrisk_scanner.socket.socket")
    def test_scan_host_returns_results_in_port_order(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111
        mock_socket_cls.return_value = mock_sock

        results = nr.scan_host("127.0.0.1", [80, 22, 443], timeout=0.1)

        ports_in_order = [r["port"] for r in results]
        self.assertEqual(ports_in_order, [22, 80, 443])

    @patch("netrisk_scanner.socket.socket")
    def test_run_scan_includes_metadata(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111
        mock_socket_cls.return_value = mock_sock

        scan_data = nr.run_scan("127.0.0.1", [22, 80], timeout=0.1)

        self.assertEqual(scan_data["target"], "127.0.0.1")
        self.assertEqual(scan_data["ports_scanned"], 2)
        self.assertIn("scan_started", scan_data)
        self.assertIn("scan_finished", scan_data)
        self.assertEqual(len(scan_data["results"]), 2)


class RealSocketIntegrationTest(unittest.TestCase):
    """
    One real, non-mocked test: actually opens a local listening
    socket and confirms the scanner detects it as open. This is the
    one test that proves the whole thing works end-to-end, not just
    that the mocks were set up correctly.
    """

    def test_real_open_port_is_detected(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))  # 0 = let the OS pick a free port
        server.listen(1)
        port = server.getsockname()[1]

        def accept_loop():
            try:
                conn, _ = server.accept()
                conn.close()
            except OSError:
                pass

        thread = threading.Thread(target=accept_loop, daemon=True)
        thread.start()
        time.sleep(0.1)

        try:
            result = nr.scan_port("127.0.0.1", port, timeout=1.0)
            self.assertEqual(result["status"], "open")
        finally:
            server.close()

    def test_real_closed_port_is_detected(self):
        # Bind and immediately close, so nothing is listening —
        # freeing the port back up but keeping the number likely free.
        temp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        temp.bind(("127.0.0.1", 0))
        port = temp.getsockname()[1]
        temp.close()

        result = nr.scan_port("127.0.0.1", port, timeout=0.5)
        self.assertEqual(result["status"], "closed")


class PortRangeParsingTests(unittest.TestCase):

    def test_parses_single_port(self):
        self.assertEqual(nr.parse_port_range("80"), [80])

    def test_parses_range(self):
        self.assertEqual(nr.parse_port_range("20-23"), [20, 21, 22, 23])


if __name__ == "__main__":
    unittest.main()
