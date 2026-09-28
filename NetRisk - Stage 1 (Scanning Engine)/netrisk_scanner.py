"""
Project : NetRisk — Stage 1: Scanning Engine
Module  : Cybersecurity
Author  : Aman Kumar

Description:
This is the foundation stage of NetRisk, a network risk dashboard.
Stage 1 has no visuals and no risk scoring yet — it's just the
engine: a fast, threaded port scanner that produces clean,
structured JSON output instead of print statements.

Every later stage (risk explanations, the local dashboard, history
tracking) reads the JSON this stage produces, so getting this part
right and predictable matters more than making it flashy.

Safety:
This tool refuses to scan a target unless it's localhost or a
private-network address (something on your own LAN, like a home
router's subnet). Scanning a device you don't own or don't have
permission to scan is illegal in most places — this isn't a
formality, it's the actual boundary of what this tool is for.
"""

import argparse
import ipaddress
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone


# ----------------------------------------------------
# Known ports NetRisk understands
# ----------------------------------------------------
# A curated list, not the full 0-65535 range. NetRisk is meant to be
# explainable, not exhaustive — every port here is one Stage 2 will
# eventually attach a real risk explanation to. Scanning all 65535
# ports would be slower and mostly noise for a home-network tool.

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8008: "Chromecast / cast device",
    8009: "Chromecast / cast device",
    8080: "HTTP (alternate)",
    8443: "HTTPS (alternate)",
    9100: "Network printer (raw print)",
    27017: "MongoDB",
    62078: "Apple mobile device sync",
}


# ----------------------------------------------------
# Safety check
# ----------------------------------------------------

def is_safe_target(ip_str):
    """
    Only allow scanning localhost or a private (RFC 1918 / link-local)
    address — i.e. something on the user's own machine or own LAN.
    Refuses anything that looks like a public internet address.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    return ip.is_loopback or ip.is_private or ip.is_link_local


# ----------------------------------------------------
# Scanning
# ----------------------------------------------------

def scan_port(ip, port, timeout):
    """
    Attempt a TCP connection to a single port and classify the
    result. Returns a dict — never raises — so a scan of many ports
    can't be derailed by one unexpected error.
    """

    checked_at = datetime.now(timezone.utc).isoformat()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((ip, port))

        if result == 0:
            status = "open"
            error_detail = None
        else:
            status = "closed"
            error_detail = (
                f"Connection refused (errno {result}) — nothing is "
                f"listening on this port."
            )

    except socket.timeout:
        status = "filtered"
        error_detail = (
            "Connection timed out — the port didn't respond at all. "
            "This usually means a firewall is silently dropping the "
            "connection rather than actively refusing it."
        )

    except OSError as exc:
        status = "error"
        error_detail = f"Unexpected network error: {exc}"

    finally:
        sock.close()

    return {
        "port": port,
        "status": status,
        "service_guess": COMMON_PORTS.get(port, "Unknown"),
        "detail": error_detail,
        "checked_at": checked_at,
    }


def scan_host(ip, ports, timeout=1.0, max_workers=50):
    """
    Scan a list of ports on one host concurrently and return the
    results in port order (not completion order, so output stays
    predictable).
    """

    results = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_port, ip, port, timeout): port
            for port in ports
        }

        for future in as_completed(futures):
            port = futures[future]
            results[port] = future.result()

    return [results[port] for port in sorted(results)]


def run_scan(ip, ports, timeout=1.0, max_workers=50):
    """
    Run a full scan and wrap the results with metadata about the
    scan itself. This is the top-level function the CLI (and later,
    the dashboard) calls.
    """

    started = datetime.now(timezone.utc).isoformat()
    results = scan_host(ip, ports, timeout=timeout, max_workers=max_workers)
    finished = datetime.now(timezone.utc).isoformat()

    return {
        "target": ip,
        "scan_started": started,
        "scan_finished": finished,
        "ports_scanned": len(ports),
        "results": results,
    }


# ----------------------------------------------------
# CLI
# ----------------------------------------------------

def parse_port_range(range_str):
    """
    Parse a "start-end" string into a list of ports.
    """
    start_str, _, end_str = range_str.partition("-")
    start = int(start_str)
    end = int(end_str) if end_str else start
    return list(range(start, end + 1))


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description=(
            "NetRisk Stage 1 — a threaded port scanner that outputs "
            "structured JSON. Only scans localhost or your own "
            "private network."
        )
    )

    parser.add_argument(
        "target",
        nargs="?",
        default="127.0.0.1",
        help="IP address to scan (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--ports",
        help=(
            "Port range to scan, e.g. '1-1024'. "
            "Defaults to a curated list of common ports."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Per-port connection timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--output",
        default="scan_results.json",
        help="File to write JSON results to (default: scan_results.json)",
    )

    return parser


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    if not is_safe_target(args.target):
        print(
            f"❌ Refusing to scan '{args.target}'.\n"
            f"NetRisk only scans localhost or addresses on your own "
            f"private network (e.g. 127.0.0.1 or 192.168.x.x). "
            f"Scanning other networks without permission is illegal "
            f"in most places."
        )
        sys.exit(1)

    ports = parse_port_range(args.ports) if args.ports else list(COMMON_PORTS)

    print(f"Scanning {args.target} ({len(ports)} ports)...")

    scan_data = run_scan(
        args.target, ports, timeout=args.timeout
    )

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(scan_data, f, indent=2)

    open_ports = [r for r in scan_data["results"] if r["status"] == "open"]

    print(f"\nScan complete — {len(open_ports)} open port(s) found.")
    for r in open_ports:
        print(f"  {r['port']:<6} {r['service_guess']}")

    print(f"\nFull results written to {args.output}")


if __name__ == "__main__":
    main()
