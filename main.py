#!/usr/bin/env python3
"""
Syntecxhub Port Scanner — CLI Entry Point
Usage examples:
    python main.py -H scanme.nmap.org -p 22 80 443
    python main.py -H 192.168.1.1 -r 1 1024
    python main.py -H example.com -r 1 65535 --threads 200 --timeout 0.5 --banner
"""

import argparse
import sys
import time
from scanner import PortScanner


BANNER = r"""
 ____              _            _                   _     
/ ___| _   _ _ __ | |_ ___  ___| |__  _   _| |__   
\___ \| | | | '_ \| __/ _ \/ __| '_ \| | | | '_ \  
 ___) | |_| | | | | ||  __/ (__| | | | |_| | |_) | 
|____/ \__, |_| |_|\__\___|\___|_| |_|\__,_|_.__/  
       |___/                                          
  Port Scanner  •  Project 1  •  Syntecxhub          
"""


def progress_bar(completed: int, total: int, result, bar_width: int = 35):
    pct = completed / total
    filled = int(bar_width * pct)
    bar = "█" * filled + "░" * (bar_width - filled)
    status_icon = {"open": "✅", "closed": "·", "timeout": "⏱", "error": "⚠"}.get(result.status, "?")
    print(f"\r  [{bar}] {pct*100:5.1f}%  {status_icon} :{result.port:<6}", end="", flush=True)
    if completed == total:
        print()


def parse_args():
    parser = argparse.ArgumentParser(
        description="TCP Port Scanner — Syntecxhub Project 1",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Scan specific ports:
    python main.py -H scanme.nmap.org -p 22 80 443 8080

  Scan a port range:
    python main.py -H 192.168.1.1 -r 1 1024

  Full fast scan with banner grabbing:
    python main.py -H example.com -r 1 65535 --threads 300 --timeout 0.5 --banner

  Save results to JSON:
    python main.py -H 10.0.0.1 -r 1 500 --output report.json
        """,
    )
    parser.add_argument("-H", "--host", required=True, help="Target host (IP or hostname)")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--ports", nargs="+", type=int, metavar="PORT",
                       help="Specific ports to scan (e.g. -p 22 80 443)")
    group.add_argument("-r", "--range", nargs=2, type=int, metavar=("START", "END"),
                       help="Port range to scan (e.g. -r 1 1024)")

    parser.add_argument("--threads", type=int, default=100, help="Max concurrent threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("--banner", action="store_true", help="Attempt to grab service banners")
    parser.add_argument("--output", type=str, default="", help="Save results to JSON file")
    parser.add_argument("--no-progress", action="store_true", help="Disable the progress bar")
    return parser.parse_args()


def main():
    print(BANNER)
    args = parse_args()

    # Determine ports to scan
    if args.ports:
        ports = sorted(set(args.ports))
        label = f"ports {', '.join(map(str, ports))}"
    else:
        s, e = args.range
        if s < 1 or e > 65535 or s > e:
            print("❌ Invalid port range. Must be 1–65535 with start ≤ end.")
            sys.exit(1)
        ports = list(range(s, e + 1))
        label = f"port range {s}–{e} ({len(ports)} ports)"

    print(f"  Target  : {args.host}")
    print(f"  Scope   : {label}")
    print(f"  Threads : {args.threads}   Timeout: {args.timeout}s   Banner: {'yes' if args.banner else 'no'}")
    print("  " + "─" * 52)

    scanner = PortScanner(
        timeout=args.timeout,
        max_threads=args.threads,
        grab_banner=args.banner,
    )

    cb = None if args.no_progress else progress_bar
    t0 = time.time()

    if args.ports:
        scanner.scan_host(args.host, ports, progress_callback=cb)
    else:
        scanner.scan_range(args.host, args.range[0], args.range[1], progress_callback=cb)

    elapsed = time.time() - t0
    print(f"\n  ✔ Scan completed in {elapsed:.2f}s")

    scanner.print_summary()

    if args.output:
        scanner.save_results(args.output)
        print(f"  💾 Report saved → {args.output}\n")


if __name__ == "__main__":
    main()
