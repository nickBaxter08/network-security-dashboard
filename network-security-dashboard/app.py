from flask import Flask, jsonify, render_template, request

from config import config
from scanner.demo_data import get_demo_scan_result
from security.cve_lookup import lookup_cves
from security.rules import check_service, score_device, score_label

app = Flask(__name__)


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
        if not target:
            return jsonify({"error": "target IP is required in local mode"}), 400
        result = get_local_scan_result(target)
    else:
        result = get_demo_scan_result()

    result = enrich_scan_result(result)
    return jsonify(result)


@app.route("/api/mode")
def api_mode():
    return jsonify({"mode": config.APP_MODE})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
