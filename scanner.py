"""
Syntecxhub Port Scanner - Project 1
TCP Port Scanner with threading, logging, and result reporting.
"""

import socket
import threading
import logging
import json
import time
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

# ─── Logging Setup ──────────────────────────────────────────────────────────

def setup_logger(log_file: str = "scan_results.log") -> logging.Logger:
    logger = logging.getLogger("PortScanner")
    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")

    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


logger = setup_logger()


# ─── Port Result Dataclass ───────────────────────────────────────────────────

class PortResult:
    def __init__(self, host: str, port: int, status: str, banner: str = "", latency_ms: float = 0.0):
        self.host = host
        self.port = port
        self.status = status        # "open" | "closed" | "timeout" | "error"
        self.banner = banner
        self.latency_ms = latency_ms
        self.timestamp = datetime.now().isoformat()
        self.service = self._guess_service()

    def _guess_service(self) -> str:
        common = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
        }
        return common.get(self.port, "Unknown")

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "status": self.status,
            "service": self.service,
            "banner": self.banner,
            "latency_ms": round(self.latency_ms, 2),
            "timestamp": self.timestamp,
        }

    def __str__(self) -> str:
        icon = {"open": "✅", "closed": "❌", "timeout": "⏱️", "error": "⚠️"}.get(self.status, "?")
        svc = f"[{self.service}]" if self.service != "Unknown" else ""
        banner = f" | Banner: {self.banner[:50]}" if self.banner else ""
        return f"{icon} {self.host}:{self.port} {svc} → {self.status.upper()} ({self.latency_ms:.1f}ms){banner}"


# ─── Core Scanner ────────────────────────────────────────────────────────────

class PortScanner:
    def __init__(self, timeout: float = 1.0, max_threads: int = 100, grab_banner: bool = False):
        self.timeout = timeout
        self.max_threads = max_threads
        self.grab_banner = grab_banner
        self.results: list[PortResult] = []
        self._lock = threading.Lock()

    def scan_port(self, host: str, port: int) -> PortResult:
        """Scan a single TCP port and return a PortResult."""
        start = time.perf_counter()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                code = sock.connect_ex((host, port))
                latency = (time.perf_counter() - start) * 1000

                if code == 0:
                    banner = ""
                    if self.grab_banner:
                        try:
                            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                            banner = sock.recv(256).decode(errors="ignore").strip()
                        except Exception:
                            pass
                    result = PortResult(host, port, "open", banner, latency)
                    logger.info(f"OPEN   {host}:{port} ({result.service}) {latency:.1f}ms")
                else:
                    result = PortResult(host, port, "closed", "", latency)
                    logger.debug(f"CLOSED {host}:{port}")
                return result

        except socket.timeout:
            latency = (time.perf_counter() - start) * 1000
            logger.debug(f"TIMEOUT {host}:{port}")
            return PortResult(host, port, "timeout", "", latency)

        except socket.gaierror as e:
            latency = (time.perf_counter() - start) * 1000
            logger.error(f"DNS ERROR {host}:{port} → {e}")
            return PortResult(host, port, "error", str(e), latency)

        except OSError as e:
            latency = (time.perf_counter() - start) * 1000
            logger.error(f"OS ERROR {host}:{port} → {e}")
            return PortResult(host, port, "error", str(e), latency)

    def scan_host(self, host: str, ports: list[int], progress_callback=None) -> list[PortResult]:
        """Scan multiple ports on a single host using a thread pool."""
        resolved = self._resolve(host)
        if not resolved:
            logger.error(f"Cannot resolve host: {host}")
            return []

        logger.info(f"Starting scan on {host} ({resolved}) — {len(ports)} ports, {self.max_threads} threads")
        results = []
        completed = 0

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_map = {executor.submit(self.scan_port, resolved, p): p for p in ports}
            for future in as_completed(future_map):
                try:
                    result = future.result()
                    with self._lock:
                        results.append(result)
                        self.results.append(result)
                        completed += 1
                    if progress_callback:
                        progress_callback(completed, len(ports), result)
                except Exception as e:
                    port = future_map[future]
                    logger.error(f"Thread error for port {port}: {e}")

        results.sort(key=lambda r: r.port)
        return results

    def scan_range(self, host: str, start_port: int, end_port: int, progress_callback=None) -> list[PortResult]:
        """Scan a port range (inclusive)."""
        ports = list(range(start_port, end_port + 1))
        return self.scan_host(host, ports, progress_callback)

    def _resolve(self, host: str) -> Optional[str]:
        """Resolve hostname to IP."""
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            return None

    def save_results(self, filename: str = "scan_report.json"):
        """Save all results to a JSON file."""
        data = {
            "scan_summary": self.get_summary(),
            "results": [r.to_dict() for r in self.results],
        }
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
        logger.info(f"Results saved to {filename}")

    def get_summary(self) -> dict:
        """Return a summary of scan results."""
        open_ports = [r for r in self.results if r.status == "open"]
        return {
            "total_scanned": len(self.results),
            "open": len(open_ports),
            "closed": sum(1 for r in self.results if r.status == "closed"),
            "timeout": sum(1 for r in self.results if r.status == "timeout"),
            "error": sum(1 for r in self.results if r.status == "error"),
            "open_ports": [r.port for r in open_ports],
        }

    def print_summary(self):
        """Print a formatted summary to stdout."""
        s = self.get_summary()
        open_results = [r for r in self.results if r.status == "open"]
        print("\n" + "═" * 55)
        print("  SCAN SUMMARY")
        print("═" * 55)
        print(f"  Total Ports Scanned : {s['total_scanned']}")
        print(f"  ✅ Open             : {s['open']}")
        print(f"  ❌ Closed           : {s['closed']}")
        print(f"  ⏱️  Timeout          : {s['timeout']}")
        print(f"  ⚠️  Error            : {s['error']}")
        if open_results:
            print("\n  OPEN PORTS:")
            for r in sorted(open_results, key=lambda x: x.port):
                print(f"    • {r.port:>5}  {r.service:<15}  {r.latency_ms:.1f}ms")
        print("═" * 55 + "\n")
