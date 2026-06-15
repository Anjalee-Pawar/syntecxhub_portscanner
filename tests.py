"""
Tests for Syntecxhub Port Scanner — Project 1
Run with: python -m pytest tests.py -v
"""

import socket
import threading
import time
import unittest
from unittest.mock import patch, MagicMock
from scanner import PortScanner, PortResult


# ─── Helpers ─────────────────────────────────────────────────────────────────

def start_echo_server(host="127.0.0.1", port=0):
    """Spin up a minimal TCP server on a random free port."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    server.settimeout(2)
    assigned_port = server.getsockname()[1]

    def _accept():
        try:
            while True:
                try:
                    conn, _ = server.accept()
                    conn.close()
                except socket.timeout:
                    break
        except Exception:
            pass
        finally:
            server.close()

    t = threading.Thread(target=_accept, daemon=True)
    t.start()
    return assigned_port, server, t


# ─── PortResult Tests ─────────────────────────────────────────────────────────

class TestPortResult(unittest.TestCase):

    def test_service_detection_ssh(self):
        r = PortResult("127.0.0.1", 22, "open")
        self.assertEqual(r.service, "SSH")

    def test_service_detection_http(self):
        r = PortResult("127.0.0.1", 80, "open")
        self.assertEqual(r.service, "HTTP")

    def test_service_unknown(self):
        r = PortResult("127.0.0.1", 12345, "open")
        self.assertEqual(r.service, "Unknown")

    def test_to_dict_keys(self):
        r = PortResult("10.0.0.1", 443, "open", "TLS", 12.5)
        d = r.to_dict()
        self.assertIn("host", d)
        self.assertIn("port", d)
        self.assertIn("status", d)
        self.assertIn("service", d)
        self.assertIn("banner", d)
        self.assertIn("latency_ms", d)
        self.assertIn("timestamp", d)

    def test_str_open(self):
        r = PortResult("127.0.0.1", 80, "open", "", 5.0)
        self.assertIn("OPEN", str(r))
        self.assertIn("✅", str(r))

    def test_str_closed(self):
        r = PortResult("127.0.0.1", 9999, "closed")
        self.assertIn("CLOSED", str(r))

    def test_str_timeout(self):
        r = PortResult("127.0.0.1", 1234, "timeout")
        self.assertIn("TIMEOUT", str(r))


# ─── PortScanner Unit Tests ───────────────────────────────────────────────────

class TestPortScannerUnit(unittest.TestCase):

    def setUp(self):
        self.scanner = PortScanner(timeout=0.5, max_threads=10)

    def test_scan_open_port(self):
        port, server, _ = start_echo_server()
        time.sleep(0.05)
        try:
            result = self.scanner.scan_port("127.0.0.1", port)
            self.assertEqual(result.status, "open")
            self.assertEqual(result.port, port)
        finally:
            server.close()

    def test_scan_closed_port(self):
        # Port 1 is almost certainly closed/refused on loopback
        result = self.scanner.scan_port("127.0.0.1", 1)
        self.assertIn(result.status, ("closed", "error", "timeout"))

    def test_scan_invalid_host(self):
        # The scanner must return a valid PortResult — in some environments
        # wildcard DNS resolves any hostname, so we accept any valid status.
        result = self.scanner.scan_port("invalid.host.that.does.not.exist.xyz", 80)
        self.assertIsInstance(result, PortResult)
        self.assertIn(result.status, ("open", "closed", "timeout", "error"))

    def test_latency_is_positive(self):
        port, server, _ = start_echo_server()
        time.sleep(0.05)
        try:
            result = self.scanner.scan_port("127.0.0.1", port)
            self.assertGreater(result.latency_ms, 0)
        finally:
            server.close()


# ─── PortScanner Integration Tests ───────────────────────────────────────────

class TestPortScannerIntegration(unittest.TestCase):

    def test_scan_multiple_ports_returns_all(self):
        scanner = PortScanner(timeout=0.5, max_threads=20)
        port, server, _ = start_echo_server()
        time.sleep(0.05)
        try:
            ports = [port, 1, 2, 3]
            results = scanner.scan_host("127.0.0.1", ports)
            self.assertEqual(len(results), 4)
            # The echo server port should be open
            open_results = [r for r in results if r.status == "open"]
            self.assertTrue(any(r.port == port for r in open_results))
        finally:
            server.close()

    def test_scan_range_returns_sorted(self):
        scanner = PortScanner(timeout=0.3, max_threads=50)
        results = scanner.scan_range("127.0.0.1", 1, 10)
        self.assertEqual(len(results), 10)
        ports = [r.port for r in results]
        self.assertEqual(ports, sorted(ports))

    def test_progress_callback_called(self):
        scanner = PortScanner(timeout=0.3, max_threads=10)
        calls = []
        scanner.scan_host("127.0.0.1", [1, 2, 3],
                          progress_callback=lambda c, t, r: calls.append(c))
        self.assertEqual(len(calls), 3)

    def test_get_summary_structure(self):
        scanner = PortScanner(timeout=0.3, max_threads=20)
        scanner.scan_range("127.0.0.1", 1, 5)
        s = scanner.get_summary()
        self.assertIn("total_scanned", s)
        self.assertIn("open", s)
        self.assertIn("closed", s)
        self.assertIn("timeout", s)
        self.assertIn("error", s)
        self.assertIn("open_ports", s)
        self.assertEqual(s["total_scanned"], 5)

    def test_save_results_creates_json(self):
        import os, json, tempfile
        scanner = PortScanner(timeout=0.3, max_threads=10)
        scanner.scan_range("127.0.0.1", 1, 3)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            scanner.save_results(path)
            with open(path) as f:
                data = json.load(f)
            self.assertIn("scan_summary", data)
            self.assertIn("results", data)
            self.assertEqual(len(data["results"]), 3)
        finally:
            os.unlink(path)

    def test_resolve_invalid_host(self):
        scanner = PortScanner()
        result = scanner._resolve("totally.invalid.host.xyz123")
        self.assertIsNone(result)

    def test_resolve_valid_ip(self):
        scanner = PortScanner()
        result = scanner._resolve("127.0.0.1")
        self.assertEqual(result, "127.0.0.1")


# ─── Thread Safety Tests ──────────────────────────────────────────────────────

class TestThreadSafety(unittest.TestCase):

    def test_concurrent_scans_no_race(self):
        """Verify internal results list is consistent under concurrency."""
        scanner = PortScanner(timeout=0.3, max_threads=50)
        # Scan 50 ports concurrently
        scanner.scan_range("127.0.0.1", 1, 50)
        s = scanner.get_summary()
        self.assertEqual(s["total_scanned"], 50)


if __name__ == "__main__":
    unittest.main(verbosity=2)
