"""
Integration tests for unified normalization and pipeline compatibility.
"""

from normalization import (
    CanonicalFinding,
    Normalizer,
    SeverityLevel,
    normalize_finding,
    normalize_findings,
    validate_finding,
)


def test_unified_dispatcher_auto_detection():
    zap_raw = {
        "pluginId": "40018",
        "alert": "SQL Injection",
        "risk": "High",
        "url": "http://example.com/api"
    }

    nuclei_raw = {
        "template-id": "cve-2021-44228-log4j",
        "info": {
            "name": "Log4j RCE",
            "severity": "critical"
        },
        "matched-at": "http://example.com/login"
    }

    norm_zap = normalize_finding(zap_raw)
    norm_nuclei = normalize_finding(nuclei_raw)

    assert norm_zap.scanner == "zap"
    assert norm_zap.severity == SeverityLevel.HIGH

    assert norm_nuclei.scanner == "nuclei"
    assert norm_nuclei.severity == SeverityLevel.CRITICAL


def test_mixed_findings_batch_normalization():
    mixed_raw = [
        {
            "scanner": "zap",
            "pluginId": "10020",
            "alert": "X-Frame-Options Header Not Set",
            "risk": "Medium",
            "url": "http://example.com/page1"
        },
        {
            "template-id": "cve-2022-1234",
            "info": {
                "name": "Sample Vulnerability",
                "severity": "low"
            },
            "matched-at": "http://example.com/page2"
        },
        {
            "scanner": "zap",
            "alert_id": "40012",
            "name": "Cross Site Scripting (Reflected)",
            "severity": "High",
            "affected_urls": ["http://example.com/search?q=test"]
        }
    ]

    canonical_list = normalize_findings(mixed_raw)

    assert len(canonical_list) == 3

    # Ensure all items validate cleanly against the canonical schema
    for finding in canonical_list:
        assert isinstance(finding, CanonicalFinding)
        errors = validate_finding(finding)
        assert errors == [], f"Validation errors found: {errors}"

    # Verify dictionary serialization consistency
    dict_list = [f.to_dict() for f in canonical_list]
    for d in dict_list:
        assert "finding_id" in d
        assert "scanner" in d
        assert "title" in d
        assert "severity" in d
        assert "cve" in d
        assert "cwe" in d
        assert "asset" in d
        assert "url" in d
        assert "fingerprint" in d


def test_schema_compatibility_between_scanners():
    zap_canonical = normalize_finding({
        "pluginId": "1",
        "alert": "ZAP Alert",
        "risk": "High",
        "url": "http://example.com/a"
    })

    nuclei_canonical = normalize_finding({
        "template-id": "t1",
        "info": {"name": "Nuclei Finding", "severity": "high"},
        "matched-at": "http://example.com/b"
    })

    zap_dict = zap_canonical.to_dict()
    nuclei_dict = nuclei_canonical.to_dict()

    # Verify both dictionaries share the exact same canonical keys
    assert set(zap_dict.keys()) == set(nuclei_dict.keys())


def test_deduplication_preparation():
    # Both scanners detecting same issue on same target
    f1 = normalize_finding({
        "scanner": "zap",
        "alert": "SQL Injection",
        "risk": "High",
        "url": "http://example.com/api",
        "param": "user_id",
        "cweid": "89"
    })

    f2 = normalize_finding({
        "scanner": "nuclei",
        "template-id": "sqli-error",
        "info": {
            "name": "SQL Injection",
            "severity": "high",
            "classification": {"cwe-id": "CWE-89"}
        },
        "matched-at": "http://example.com/api",
        "parameter": "user_id"
    })

    # Both findings should have normalized CWE-89, asset "example.com", same parameter
    assert f1.cwe == "CWE-89"
    assert f2.cwe == "CWE-89"
    assert f1.asset == "example.com"
    assert f2.asset == "example.com"
    assert f1.parameter == "user_id"
    assert f2.parameter == "user_id"
    assert f1.category == "Injection"
    assert f2.category == "Injection"


def test_canonical_scan_result_wrapper():
    from normalization import normalize_scan_result

    raw_list = [
        {
            "scanner": "zap",
            "pluginId": "40018",
            "alert": "SQL Injection",
            "risk": "High",
            "url": "http://localhost:3000/api/users?id=1",
            "param": "id",
            "cweid": "89"
        }
    ]

    scan_result = normalize_scan_result("http://localhost:3000", raw_list)
    res_dict = scan_result.to_dict()

    assert res_dict["target"] == "http://localhost:3000"
    assert len(res_dict["findings"]) == 1
    finding = res_dict["findings"][0]

    # Verify exact schema from hackathon format specification:
    assert finding["scanner"] == "zap"
    assert finding["title"] == "SQL Injection"
    assert finding["severity"] == "HIGH"
    assert isinstance(finding["urls"], list)
    assert "http://localhost:3000/api/users?id=1" in finding["urls"]
    assert finding["cwe"] == "CWE-89"
    assert finding["cve"] is None
    assert finding["category"] == "Injection"

