"""
Simple rule-based checks for risky configurations, independent of CVE data.
These catch things a CVE database won't (like an inherently insecure
protocol being used at all, regardless of version).
"""

INSECURE_SERVICES = {
    "telnet": ("critical", "Telnet transmits credentials in plaintext. Use SSH instead."),
    "ftp": ("high", "FTP transmits credentials in plaintext. Use SFTP/FTPS instead."),
    "rdp": ("medium", "RDP exposed to the network increases brute-force and exploit risk. Restrict access or use a VPN."),
    "vnc": ("medium", "VNC is often unencrypted and a common brute-force target."),
    "smb": ("medium", "SMB has a history of high-severity remote exploits (e.g. EternalBlue). Keep patched and firewalled."),
}

SEVERITY_WEIGHT = {"critical": 40, "high": 25, "medium": 12, "low": 5}


def check_service(service):
    """Returns a list of rule-based findings for a single service."""
    findings = []
    name = (service.get("name") or "").lower()
    if name in INSECURE_SERVICES:
        severity, reason = INSECURE_SERVICES[name]
        findings.append({
            "type": "config",
            "severity": severity,
            "message": reason,
            "port": service.get("port"),
        })
    return findings


def score_device(services, cve_findings_by_service, config_findings_by_service):
    """
    Produces a 0-100 risk score for a device (100 = worst).
    Weighted sum of CVE severities + config findings, capped at 100.
    """
    total = 0
    for service in services:
        for cve in cve_findings_by_service.get(id(service), []):
            sev = (cve.get("severity") or "UNKNOWN").lower()
            total += SEVERITY_WEIGHT.get(sev, 8)
        for finding in config_findings_by_service.get(id(service), []):
            total += SEVERITY_WEIGHT.get(finding["severity"], 8)

    return min(total, 100)


def score_label(score):
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 15:
        return "medium"
    if score > 0:
        return "low"
    return "clean"
