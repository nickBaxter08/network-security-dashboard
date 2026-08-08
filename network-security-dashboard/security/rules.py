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

# Weights used for display/ordering; SEVERITY_IMPACT (below) drives scoring
SEVERITY_WEIGHT = {"critical": 40, "high": 25, "medium": 12, "low": 5}

# Each finding's "impact" is treated as an independent probability that it
# meaningfully raises risk. Combining them as 1 - product(1 - impact) gives
# diminishing returns — five medium findings on one box won't auto-saturate
# to 100 the way plain addition does, but a single critical still dominates.
SEVERITY_IMPACT = {"critical": 0.55, "high": 0.35, "medium": 0.18, "low": 0.08}


def check_service(service):
    """Returns a list of rule-based findings for a single service."""
    findings = []
    name = (service.get("name") or "").lower()
    verified = service.get("verified", False)
    if name in INSECURE_SERVICES:
        severity, reason = INSECURE_SERVICES[name]
        if not verified:
            reason += (" (protocol not independently verified on this scan — "
                       "could also be a false positive from a proxy/middlebox; "
                       "cross-check with another tool before acting on this.)")
        findings.append({
            "type": "config",
            "severity": severity,
            "message": reason,
            "port": service.get("port"),
            "verified": verified,
        })
    return findings


def score_device(services, cve_findings_by_service, config_findings_by_service):
    """
    Produces a 0-100 risk score for a device (100 = worst).

    Findings are combined with diminishing returns rather than summed
    directly: risk_remaining = product(1 - impact) across all findings,
    score = 100 * (1 - risk_remaining). One critical finding alone still
    lands high; several low/medium findings raise the score without
    automatically maxing it out the way plain addition does.
    """
    risk_remaining = 1.0
    for service in services:
        for cve in cve_findings_by_service.get(id(service), []):
            sev = (cve.get("severity") or "UNKNOWN").lower()
            risk_remaining *= (1 - SEVERITY_IMPACT.get(sev, 0.1))
        for finding in config_findings_by_service.get(id(service), []):
            impact = SEVERITY_IMPACT.get(finding["severity"], 0.1)
            if not finding.get("verified", True):
                impact *= 0.5  # lower confidence — reduce contribution, don't ignore
            risk_remaining *= (1 - impact)

    return round(100 * (1 - risk_remaining))


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
