"""
Lightweight TCP connect scanner for LOCAL mode only.

Only ever point this at hosts/networks you own or have explicit permission
to scan. This module deliberately does NOT do host discovery across an
arbitrary CIDR by default — it scans a single host you provide, to keep
the footprint small and intentional.
"""

import socket
import time

from config import config


def _grab_banner(ip, port, timeout):
    """Best-effort banner grab. Returns a short string or None."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                banner = sock.recv(128)
                return banner.decode(errors="ignore").strip() or None
            except socket.timeout:
                return None
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


PORT_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb",
    3306: "mysql", 3389: "rdp", 5900: "vnc", 8080: "http-alt",
}


def scan_host(target_ip, ports=None, timeout=None):
    """
    Scans a single host across a fixed list of common ports.
    Returns a device dict matching the shape used by demo_data.
    """
    ports = ports or config.SCAN_PORTS
    timeout = timeout or config.SCAN_TIMEOUT

    services = []
    for port in ports:
        try:
            with socket.create_connection((target_ip, port), timeout=timeout):
                banner = _grab_banner(target_ip, port, timeout)
                services.append({
                    "port": port,
                    "name": PORT_NAMES.get(port, "unknown"),
                    "product": banner,
                    "version": None,  # left for the user to confirm manually
                })
        except (socket.timeout, ConnectionRefusedError, OSError):
            continue

    try:
        hostname = socket.getfqdn(target_ip)
    except socket.herror:
        hostname = target_ip

    return {
        "ip": target_ip,
        "hostname": hostname,
        "services": services,
    }


def get_local_scan_result(target_ip):
    return {
        "mode": "local",
        "scanned_at": time.time(),
        "target": target_ip,
        "devices": [scan_host(target_ip)],
    }
