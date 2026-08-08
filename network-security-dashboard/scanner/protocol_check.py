"""
Protocol-level verification for open ports.

A successful TCP handshake alone isn't proof of what's actually running —
ISP transparent proxies, captive portals, and middleboxes can make a port
look "open" even when nothing real is behind it (this is exactly what
happened scanning a CGNAT address: every port connected, none returned a
real banner). These checks send a small protocol-appropriate probe and
look for a real signature before calling a service "verified".

Each check returns (product_string_or_None, verified_bool).
"""

import socket
import ssl


def _read(sock, size=256):
    try:
        return sock.recv(size)
    except socket.timeout:
        return b""


def _check_banner_protocol(ip, port, timeout, expected_prefixes, send_probe=None):
    """
    Generic check for protocols that send a plaintext banner on connect
    (FTP, SSH, SMTP, POP3, IMAP) or reply to a simple probe (VNC).
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = _read(sock)
            if not data and send_probe:
                try:
                    sock.sendall(send_probe)
                    data = _read(sock)
                except OSError:
                    pass

            text = data.decode(errors="ignore").strip()
            if any(text.startswith(p) for p in expected_prefixes):
                return text[:120] or None, True
            return (text[:120] or None), False
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None, False


def check_ftp(ip, port, timeout):
    return _check_banner_protocol(ip, port, timeout, expected_prefixes=["220"])


def check_ssh(ip, port, timeout):
    return _check_banner_protocol(ip, port, timeout, expected_prefixes=["SSH-"])


def check_smtp(ip, port, timeout):
    return _check_banner_protocol(ip, port, timeout, expected_prefixes=["220"])


def check_pop3(ip, port, timeout):
    return _check_banner_protocol(ip, port, timeout, expected_prefixes=["+OK"])


def check_imap(ip, port, timeout):
    return _check_banner_protocol(ip, port, timeout, expected_prefixes=["* OK"])


def check_vnc(ip, port, timeout):
    # VNC servers send "RFB 00X.00Y\n" immediately on connect
    return _check_banner_protocol(ip, port, timeout, expected_prefixes=["RFB "])


def check_http(ip, port, timeout):
    """HTTP servers don't speak first — send a minimal request."""
    probe = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(probe)
            data = _read(sock, 512)
            text = data.decode(errors="ignore")
            if text.startswith("HTTP/"):
                first_line = text.splitlines()[0] if text.splitlines() else ""
                return first_line[:120] or None, True
            return (text[:120] or None), False
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None, False


def check_https(ip, port, timeout):
    """Verifies a real TLS handshake completes (doesn't validate the cert chain)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as tls_sock:
                cert = tls_sock.getpeercert(binary_form=False)
                subject = tls_sock.version() or "TLS"
                return subject, True
    except (socket.timeout, ConnectionRefusedError, ssl.SSLError, OSError):
        return None, False


def check_mysql(ip, port, timeout):
    """MySQL sends a binary greeting packet starting with a protocol version byte."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = _read(sock)
            # bytes 4 onward: protocol version (0x0A for modern MySQL) then a
            # null-terminated version string
            if len(data) > 5 and data[4] == 0x0A:
                version = data[5:].split(b"\x00", 1)[0].decode(errors="ignore")
                return f"MySQL {version}"[:60] or None, True
            return None, False
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None, False


# Protocols without a lightweight, dependency-free way to verify here
# (RDP and SMB use binary handshakes that need more than a raw probe to
# confirm safely). These stay "open but unverified" rather than guessing.
UNVERIFIABLE_PORTS = {445, 3389}

VERIFIERS = {
    21: check_ftp,
    22: check_ssh,
    23: None,  # telnet has no fixed signature; left unverified deliberately
    25: check_smtp,
    80: check_http,
    110: check_pop3,
    143: check_imap,
    443: check_https,
    3306: check_mysql,
    5900: check_vnc,
    8080: check_http,
}


def verify_port(ip, port, timeout):
    """
    Returns (product, verified). If no verifier exists for this port,
    verified is always False — the caller should surface that as
    "open, unconfirmed" rather than naming a specific service.
    """
    verifier = VERIFIERS.get(port)
    if verifier is None:
        return None, False
    return verifier(ip, port, timeout)
