"""
Unit tests for OWASP ZAP normalizer.
"""

from normalization.schema import ConfidenceLevel, SeverityLevel
from normalization.zap_normalizer import ZAPNormalizer


def test_normalize_raw_zap_alert():
    raw_alert = {
        "pluginId": "40018",
        "alert": "SQL Injection",
        "risk": "High",
        "confidence": "Medium",
        "url": "http://localhost:3000/api/users?id=1",
        "param": "id",
        "attack": "' OR 1=1 --",
        "evidence": "syntax error near",
        "cweid": "89",
        "wascid": "19",
        "description": "SQL injection may allow an attacker to view unauthorized data.",
        "solution": "Use parameterized prepared statements.",
        "reference": "https://owasp.org/www-community/attacks/SQL_Injection",
        "method": "GET",
        "other": "db: postgresql"
    }

    canonical = ZAPNormalizer.normalize(raw_alert)

    assert canonical.scanner == "zap"
    assert canonical.title == "SQL Injection"
    assert canonical.severity == SeverityLevel.HIGH
    assert canonical.confidence == ConfidenceLevel.MEDIUM
    assert canonical.asset == "localhost:3000"
    assert canonical.url == "http://localhost:3000/api/users?id=1"
    assert canonical.method == "GET"
    assert canonical.parameter == "id"
    assert canonical.cwe == "CWE-89"
    assert canonical.cwe_list == ["CWE-89"]
    assert canonical.cve is None  # No CVE in this finding
    assert canonical.cvss is None
    assert canonical.solution == "Use parameterized prepared statements."
    assert "syntax error near" in (canonical.evidence or "")
    assert "wasc-19" in canonical.tags
    assert "https://owasp.org/www-community/attacks/SQL_Injection" in canonical.references
    assert canonical.raw_finding == raw_alert
    assert canonical.finding_id.startswith("find_")
    assert canonical.fingerprint is not None


def test_normalize_grouped_zap_finding():
    grouped_finding = {
        "scanner": "zap",
        "alert_id": "10020",
        "name": "X-Frame-Options Header Not Set",
        "severity": "Medium",
        "confidence": "Low",
        "parameter": "",
        "cwe": "693",
        "description": "Clickjacking protection is missing.",
        "solution": "Set X-Frame-Options: DENY",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
        "affected_urls": [
            "http://example.com/home",
            "http://example.com/about"
        ],
        "affected_url_count": 2
    }

    canonical = ZAPNormalizer.normalize(grouped_finding)

    assert canonical.scanner == "zap"
    assert canonical.title == "X-Frame-Options Header Not Set"
    assert canonical.severity == SeverityLevel.MEDIUM
    assert canonical.confidence == ConfidenceLevel.LOW
    assert canonical.parameter is None  # empty string converted to None
    assert canonical.cwe == "CWE-693"
    assert canonical.asset == "example.com"
    assert canonical.url == "http://example.com/home"


def test_normalize_zap_informational_severity():
    informational_alert = {
        "pluginId": "10049",
        "alert": "Content-Security-Policy (CSP) Header Not Set",
        "risk": "Informational",
        "confidence": "High",
        "url": "http://example.com/",
        "cweid": "16"
    }

    canonical = ZAPNormalizer.normalize(informational_alert)
    assert canonical.severity == SeverityLevel.INFO
    assert canonical.confidence == ConfidenceLevel.HIGH
    assert canonical.cwe == "CWE-16"


def test_normalize_zap_missing_optional_fields():
    minimal_alert = {
        "pluginId": "99999",
        "alert": "Unknown Issue",
        "risk": "Low",
    }

    canonical = ZAPNormalizer.normalize(minimal_alert)
    assert canonical.scanner == "zap"
    assert canonical.title == "Unknown Issue"
    assert canonical.severity == SeverityLevel.LOW
    assert canonical.confidence is None
    assert canonical.cve is None
    assert canonical.cwe is None
    assert canonical.asset is None
    assert canonical.url is None
    assert canonical.parameter is None
    assert canonical.evidence is None


def test_normalize_zap_batch():
    alerts = [
        {"pluginId": "1", "alert": "A1", "risk": "High"},
        {"pluginId": "2", "alert": "A2", "risk": "Low"}
    ]
    batch = ZAPNormalizer.normalize_batch(alerts)
    assert len(batch) == 2
    assert batch[0].severity == SeverityLevel.HIGH
    assert batch[1].severity == SeverityLevel.LOW
