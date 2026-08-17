"""
End-to-end integration tests for scanner_api and normalization pipeline.
"""

import json
from unittest.mock import MagicMock, patch
import pytest

from scanners.scanner_api import app, scans


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["service"] == "scanner-api"
    assert data["status"] == "ok"


def test_dashboard_home_route(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Aegis SOC" in response.data or b"Vulnerability Management" in response.data


def test_dashboard_api_findings(client):
    response = client.get("/api/dashboard/findings")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    assert "findings" in data
    assert len(data["findings"]) > 0
    first = data["findings"][0]
    assert "risk_score" in first
    assert "why_prioritized" in first
    assert "recommended_action" in first


def test_start_scan_validation(client):
    # Missing target
    res1 = client.post("/scan", json={"scanner": "nuclei"})
    assert res1.status_code == 400

    # Unsupported scanner
    res2 = client.post("/scan", json={"scanner": "nessus", "target": "http://example.com"})
    assert res2.status_code == 400


def test_get_scan_results_normalized(client):
    # Simulate a completed scan with normalized findings in storage
    scan_id = "test-scan-123"
    scans[scan_id] = {
        "scan_id": scan_id,
        "scanner": "nuclei",
        "target": "http://localhost:3000",
        "status": "completed",
        "stage": "completed",
        "progress": 100,
        "total_findings": 1,
        "error": None,
        "findings": [
            {
                "finding_id": "find_abc123",
                "scanner": "nuclei",
                "title": "Apache Log4j RCE",
                "severity": "CRITICAL",
                "confidence": None,
                "cve": "CVE-2021-44228",
                "cvss": 10.0,
                "cwe": "CWE-502",
                "cwe_list": ["CWE-502"],
                "asset": "localhost:3000",
                "url": "http://localhost:3000/login",
                "method": "POST",
                "parameter": "user",
                "description": "Log4j vulnerability",
                "solution": "Patch immediately",
                "evidence": "Matcher: interactsh",
                "timestamp": "2026-08-18T00:00:00Z",
                "tags": ["cve", "rce"],
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
                "fingerprint": "1234567890abcdef",
                "raw_finding": {"template-id": "cve-2021-44228"}
            }
        ]
    }

    response = client.get(f"/scan/{scan_id}/results")
    assert response.status_code == 200
    data = response.get_json()

    assert data["scan_id"] == scan_id
    assert data["status"] == "completed"
    assert data["total_findings"] == 1
    finding = data["findings"][0]
    assert finding["severity"] == "CRITICAL"
    assert finding["cve"] == "CVE-2021-44228"
    assert finding["asset"] == "localhost:3000"
    assert finding["url"] == "http://localhost:3000/login"
