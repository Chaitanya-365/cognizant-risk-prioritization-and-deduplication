import json
import os
import subprocess
import sys
import threading
import time
import uuid

from flask import Flask, jsonify, request, send_from_directory

# Ensure repository root is on sys.path for normalization imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from zapv2 import ZAPv2
except ImportError:
    ZAPv2 = None

from deduplication import deduplicate_findings
from normalization import CanonicalFinding, NucleiNormalizer, OpenVASNormalizer, ZAPNormalizer, normalize_findings
from prioritization import prioritize_findings
from threat_intel import enrich_findings


app = Flask(__name__)
DASHBOARD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dashboard")
FIXTURES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures")


# ============================================================
# Dashboard Web UI Routes
# ============================================================

@app.get("/")
def dashboard_home():
    """Serve the SOC Vulnerability Management Dashboard."""
    return send_from_directory(DASHBOARD_DIR, "index.html")


@app.get("/static/<path:filename>")
def dashboard_static(filename):
    """Serve static dashboard assets (CSS, JS)."""
    return send_from_directory(DASHBOARD_DIR, filename)


@app.get("/api/dashboard/findings")
def api_dashboard_findings():
    """Return prioritized, deduplicated canonical findings with threat intel."""
    all_raw: list = []

    # Ingest completed scan findings from memory
    for scan in scans.values():
        if scan.get("status") == "completed" and scan.get("findings"):
            all_raw.extend(scan["findings"])

    # If no scans run yet, load realistic Juice Shop scan fixtures
    if not all_raw:
        zap_file = os.path.join(FIXTURES_DIR, "juice_shop_zap_raw.json")
        nuclei_file = os.path.join(FIXTURES_DIR, "juice_shop_nuclei_raw.json")

        if os.path.exists(zap_file):
            with open(zap_file, "r", encoding="utf-8") as f:
                all_raw.extend(json.load(f))
        if os.path.exists(nuclei_file):
            with open(nuclei_file, "r", encoding="utf-8") as f:
                all_raw.extend(json.load(f))

    # 1. Normalize
    canonical_list = normalize_findings(all_raw)

    # 2. Deduplicate
    dedup_res = deduplicate_findings(canonical_list)

    # 3. Enrich Threat Intel
    enrich_findings(dedup_res.unique_findings)

    # 4. Prioritize and Score
    prioritized = prioritize_findings(dedup_res.unique_findings)

    return jsonify({
        "status": "success",
        "total_raw": dedup_res.total_raw_count,
        "unique_count": dedup_res.unique_count,
        "duplicates_removed": dedup_res.duplicates_removed,
        "reduction_percentage": dedup_res.reduction_percentage,
        "findings": [p.to_dict() for p in prioritized]
    })


@app.get("/api/dashboard/stats")
def api_dashboard_stats():
    """Return dashboard summary metrics."""
    res = api_dashboard_findings()
    data = res.get_json() if hasattr(res, "get_json") else {}
    return jsonify(data)


# ============================================================
# Configuration
# ============================================================

ZAP_HOST = os.getenv("ZAP_HOST", "127.0.0.1")
ZAP_PORT = int(os.getenv("ZAP_PORT", "8080")) if os.getenv("ZAP_PORT") else 8080
ZAP_API_KEY = os.getenv("ZAP_API_KEY")


# In-memory scan storage
scans = {}


# ============================================================
# Health Check
# ============================================================

@app.get("/health")
def health():

    return jsonify({
        "service": "scanner-api",
        "status": "ok"
    })


# ============================================================
# Start Scan
# ============================================================

@app.post("/scan")
def start_scan():

    data = request.get_json(silent=True) or {}

    scanner = data.get("scanner")
    target = data.get("target")

    if scanner not in ["nuclei", "zap"]:

        return jsonify({
            "error": "Unsupported scanner",
            "supported_scanners": [
                "nuclei",
                "zap"
            ]
        }), 400

    if not target:

        return jsonify({
            "error": "target is required"
        }), 400

    scan_id = str(uuid.uuid4())

    scans[scan_id] = {
        "scan_id": scan_id,
        "scanner": scanner,
        "target": target,
        "status": "queued",
        "progress": 0,
        "stage": "queued",
        "findings": [],
        "total_findings": 0,
        "error": None
    }

    thread = threading.Thread(
        target=run_scan,
        args=(scan_id, scanner, target),
        daemon=True
    )

    thread.start()

    return jsonify({
        "scan_id": scan_id,
        "scanner": scanner,
        "target": target,
        "status": "started"
    }), 202


# ============================================================
# Get Scan Status
# ============================================================

@app.get("/scan/<scan_id>/status")
def scan_status(scan_id):

    scan = scans.get(scan_id)

    if not scan:

        return jsonify({
            "error": "scan not found"
        }), 404

    return jsonify({
        "scan_id": scan["scan_id"],
        "scanner": scan["scanner"],
        "target": scan["target"],
        "status": scan["status"],
        "stage": scan["stage"],
        "progress": scan["progress"],
        "total_findings": scan["total_findings"],
        "error": scan["error"]
    })


# ============================================================
# Get Scan Results
# ============================================================

@app.get("/scan/<scan_id>/results")
def scan_results(scan_id):

    scan = scans.get(scan_id)

    if not scan:

        return jsonify({
            "error": "scan not found"
        }), 404

    if scan["status"] != "completed":

        return jsonify({
            "scan_id": scan_id,
            "status": scan["status"],
            "stage": scan["stage"],
            "progress": scan["progress"]
        }), 202

    return jsonify({
        "scan_id": scan["scan_id"],
        "scanner": scan["scanner"],
        "target": scan["target"],
        "status": "completed",
        "total_findings": scan["total_findings"],
        "findings": scan["findings"]
    })


# ============================================================
# Run Selected Scanner
# ============================================================

def run_scan(scan_id, scanner, target):

    try:

        scans[scan_id]["status"] = "running"
        scans[scan_id]["stage"] = "starting"
        scans[scan_id]["progress"] = 5

        if scanner == "nuclei":

            findings = run_nuclei(
                scan_id,
                target
            )

        else:

            findings = run_zap(
                scan_id,
                target
            )

        scans[scan_id]["findings"] = findings
        scans[scan_id]["total_findings"] = len(findings)
        scans[scan_id]["status"] = "completed"
        scans[scan_id]["stage"] = "completed"
        scans[scan_id]["progress"] = 100

        print(
            f"[{scan_id}] Scan completed: "
            f"{len(findings)} findings"
        )

    except Exception as e:

        print(
            f"[{scan_id}] Scan failed: {e}"
        )

        scans[scan_id]["status"] = "failed"
        scans[scan_id]["stage"] = "failed"
        scans[scan_id]["error"] = str(e)


# ============================================================
# Nuclei Scanner
# ============================================================

def run_nuclei(scan_id, target):

    scans[scan_id]["stage"] = "nuclei_scan"
    scans[scan_id]["progress"] = 10

    print(
        f"[{scan_id}] Starting Nuclei scan: {target}"
    )

    command = [
        "nuclei",
        "-u",
        target,
        "-tags",
        "tech",
        "-jsonl"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=300
    )

    if result.returncode != 0:

        raise RuntimeError(
            result.stderr or
            "Nuclei execution failed"
        )

    scans[scan_id]["progress"] = 90
    scans[scan_id]["stage"] = "processing_results"

    findings = []

    for line in result.stdout.splitlines():

        line = line.strip()

        if not line.startswith("{"):
            continue

        try:

            raw = json.loads(line)
            canonical = NucleiNormalizer.normalize(raw)
            findings.append(canonical.to_dict())

        except Exception as err:

            print(
                f"[{scan_id}] Failed to parse/normalize Nuclei line: {err}"
            )
            continue

    print(
        f"[{scan_id}] Normalized Nuclei findings: {len(findings)}"
    )

    return findings


# ============================================================
# OWASP ZAP Scanner
# ============================================================

def run_zap(scan_id, target):

    if not ZAP_API_KEY:

        raise RuntimeError(
            "ZAP_API_KEY environment variable "
            "is not set"
        )

    if ZAPv2 is None:

        raise RuntimeError(
            "zapv2 library is not installed"
        )

    print(
        f"[{scan_id}] Starting ZAP scan: {target}"
    )

    # --------------------------------------------------------
    # Connect to ZAP
    # --------------------------------------------------------

    scans[scan_id]["stage"] = "connecting_to_zap"
    scans[scan_id]["progress"] = 5

    zap = ZAPv2(
        apikey=ZAP_API_KEY,
        proxies={
            "http": (
                f"http://{ZAP_HOST}:{ZAP_PORT}"
            ),
            "https": (
                f"http://{ZAP_HOST}:{ZAP_PORT}"
            )
        }
    )

    print(
        f"[{scan_id}] ZAP version: "
        f"{zap.core.version}"
    )

    # --------------------------------------------------------
    # Configure Spider
    # --------------------------------------------------------

    scans[scan_id]["stage"] = "configuring_spider"
    scans[scan_id]["progress"] = 10

    zap.spider.set_option_max_depth(2)
    zap.spider.set_option_max_children(20)
    zap.spider.set_option_max_duration(1)

    # --------------------------------------------------------
    # Start Spider
    # --------------------------------------------------------

    scans[scan_id]["stage"] = "spider"
    scans[scan_id]["progress"] = 15

    spider_id = zap.spider.scan(
        url=target,
        recurse=True
    )

    print(
        f"[{scan_id}] Spider ID: {spider_id}"
    )

    while True:

        progress = int(
            zap.spider.status(spider_id)
        )

        scans[scan_id]["progress"] = (
            15 + int(progress * 0.25)
        )

        if progress >= 100:
            break

        time.sleep(2)

    print(
        f"[{scan_id}] Spider completed"
    )

    # --------------------------------------------------------
    # Active Scan
    # --------------------------------------------------------

    scans[scan_id]["stage"] = "active_scan"
    scans[scan_id]["progress"] = 40

    active_scan_id = zap.ascan.scan(
        url=target,
        recurse=False
    )

    print(
        f"[{scan_id}] Active Scan ID: "
        f"{active_scan_id}"
    )

    while True:

        progress = int(
            zap.ascan.status(active_scan_id)
        )

        scans[scan_id]["progress"] = (
            40 + int(progress * 0.50)
        )

        if progress >= 100:
            break

        time.sleep(5)

    print(
        f"[{scan_id}] Active Scan completed"
    )

    # --------------------------------------------------------
    # Retrieve Alerts
    # --------------------------------------------------------

    scans[scan_id]["stage"] = "retrieving_findings"
    scans[scan_id]["progress"] = 92

    alerts = zap.core.alerts(
        baseurl=target,
        start=0,
        count=5000
    )

    # --------------------------------------------------------
    # Group & Normalize ZAP Alerts
    # --------------------------------------------------------

    scans[scan_id]["stage"] = "processing_results"
    scans[scan_id]["progress"] = 95

    grouped = {}

    for alert in alerts:

        key = (
            alert.get("pluginId"),
            alert.get("param") or ""
        )

        if key not in grouped:

            grouped[key] = {
                "scanner": "zap",
                "pluginId": alert.get("pluginId"),
                "alert_id": alert.get("pluginId"),
                "alert": alert.get("alert"),
                "name": alert.get("alert"),
                "risk": alert.get("risk"),
                "severity": alert.get("risk"),
                "confidence": alert.get("confidence"),
                "param": alert.get("param") or "",
                "parameter": alert.get("param") or "",
                "cweid": alert.get("cweid"),
                "cwe": alert.get("cweid"),
                "description": alert.get("description"),
                "solution": alert.get("solution"),
                "reference": alert.get("reference"),
                "evidence": alert.get("evidence"),
                "attack": alert.get("attack"),
                "method": alert.get("method"),
                "wascid": alert.get("wascid"),
                "other": alert.get("other"),
                "affected_urls": []
            }

        url = alert.get("url")

        if (
            url and
            url not in grouped[key]["affected_urls"]
        ):

            grouped[key]["affected_urls"].append(
                url
            )

    findings = []

    for alert_data in grouped.values():

        alert_data["affected_url_count"] = len(
            alert_data["affected_urls"]
        )

        canonical = ZAPNormalizer.normalize(alert_data)
        findings.append(canonical.to_dict())

    print(
        f"[{scan_id}] Raw alerts: "
        f"{len(alerts)}"
    )

    print(
        f"[{scan_id}] Normalized findings: "
        f"{len(findings)}"
    )

    return findings


# ============================================================
# Start Scanner API
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        threaded=True
    )