from flask import Flask, jsonify, render_template, request

import ipaddress
import socket

from config import config
import db
from scanner.demo_data import get_demo_scan_result
from security.cve_lookup import lookup_cves
from security.rules import check_service, score_device, score_label

app = Flask(__name__)
db.init_db()


def _validate_target(target):
    """
    Accepts a valid IPv4/IPv6 address or a resolvable hostname.
    Returns None if valid, or an error message string if not.
    """
    if not target or not target.strip():
        return "Target is required."
    target = target.strip()

    try:
        ipaddress.ip_address(target)
        return None  # valid IP
    except ValueError:
        pass

    try:
        socket.getaddrinfo(target, None)
        return None  # resolvable hostname
    except socket.gaierror:
        return f"'{target}' isn't a valid IP address or a resolvable hostname."


def enrich_scan_result(scan_result):
    """Adds CVE + config-rule findings and a risk score to each device."""
    for device in scan_result["devices"]:
        cve_by_service = {}
        config_by_service = {}
        device_findings = []

        for service in device["services"]:
            cves = lookup_cves(service.get("product"), service.get("version"))
            cve_by_service[id(service)] = cves
            config_findings = check_service(service)
            config_by_service[id(service)] = config_findings

            service["cves"] = cves
            service["config_findings"] = config_findings
            device_findings.extend(cves)
            device_findings.extend(config_findings)

        score = score_device(device["services"], cve_by_service, config_by_service)
        device["risk_score"] = score
        device["risk_label"] = score_label(score)
        device["finding_count"] = len(device_findings)

    return scan_result


@app.route("/")
def index():
    return render_template("index.html", mode=config.APP_MODE)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    if config.is_local_mode:
        from scanner.network_scan import get_local_scan_result
        target = request.json.get("target") if request.is_json else None
        error = _validate_target(target)
        if error:
            return jsonify({"error": error}), 400
        result = get_local_scan_result(target.strip())
    else:
        result = get_demo_scan_result()

    result = enrich_scan_result(result)

    if result["mode"] == "local" and not result["devices"][0]["services"]:
        result["devices"][0]["unreachable_note"] = (
            "No open ports found on the common list. The host may be "
            "reachable but not running any scanned services, or it may "
            "not be responding at all — double-check the IP and that "
            "you're on the same network."
        )

    db.save_scan(result)
    return jsonify(result)


@app.route("/api/history")
def api_history():
    limit = request.args.get("limit", default=20, type=int)
    return jsonify(db.get_history(limit=limit))


@app.route("/api/history/<int:scan_id>")
def api_history_detail(scan_id):
    detail = db.get_scan_detail(scan_id)
    if detail is None:
        return jsonify({"error": "scan not found"}), 404
    return jsonify(detail)


@app.route("/api/mode")
def api_mode():
    return jsonify({"mode": config.APP_MODE})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
