"""
Sample network data used in demo mode. Intentionally includes a mix of
clean and vulnerable-looking services so the dashboard has something
meaningful to show without ever touching a real network.
"""

import random
import time


def get_demo_scan_result():
    devices = [
        {
            "ip": "192.168.1.1",
            "hostname": "router.local",
            "services": [
                {"port": 23, "name": "telnet", "product": "BusyBox", "version": "1.31.1"},
                {"port": 80, "name": "http", "product": "lighttpd", "version": "1.4.45"},
            ],
        },
        {
            "ip": "192.168.1.14",
            "hostname": "nas.local",
            "services": [
                {"port": 22, "name": "ssh", "product": "OpenSSH", "version": "7.2"},
                {"port": 445, "name": "smb", "product": "Samba", "version": "4.5.9"},
            ],
        },
        {
            "ip": "192.168.1.22",
            "hostname": "workstation.local",
            "services": [
                {"port": 22, "name": "ssh", "product": "OpenSSH", "version": "9.6"},
                {"port": 3389, "name": "rdp", "product": "Microsoft Terminal Services", "version": None},
            ],
        },
        {
            "ip": "192.168.1.31",
            "hostname": "webserver.local",
            "services": [
                {"port": 80, "name": "http", "product": "Apache httpd", "version": "2.4.49"},
                {"port": 443, "name": "https", "product": "Apache httpd", "version": "2.4.49"},
            ],
        },
    ]

    return {
        "mode": "demo",
        "scanned_at": time.time(),
        "target": "192.168.1.0/24 (sample data)",
        "devices": devices,
    }
