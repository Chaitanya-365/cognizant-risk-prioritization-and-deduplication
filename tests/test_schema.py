"""
Tests for CanonicalFinding schema and enum models.
"""

import json
import pytest
from pydantic import ValidationError

from normalization.schema import CanonicalFinding, ConfidenceLevel, SeverityLevel


def test_canonical_finding_instantiation_minimal():
    finding = CanonicalFinding(
        finding_id="find_12345",
        scanner="zap",
        title="SQL Injection",
        severity=SeverityLevel.HIGH
    )
    assert finding.finding_id == "find_12345"
    assert finding.scanner == "zap"
    assert finding.title == "SQL Injection"
    assert finding.severity == SeverityLevel.HIGH
    assert finding.confidence is None
    assert finding.cve is None
    assert finding.cvss is None
    assert finding.cwe is None
    assert finding.cwe_list == []
    assert finding.asset is None
    assert finding.url is None
    assert finding.method is None
    assert finding.parameter is None
    assert finding.description is None
    assert finding.solution is None
    assert finding.evidence is None
    assert finding.tags == []
    assert finding.references == []
    assert finding.fingerprint is None
    assert finding.raw_finding is None
    assert finding.timestamp is not None


def test_canonical_finding_full_fields():
    finding = CanonicalFinding(
        finding_id="find_abcdef123456",
        scanner="nuclei",
        title="Apache Log4j RCE",
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.CONFIRMED,
        cve="CVE-2021-44228",
        cvss=10.0,
        cwe="CWE-502",
        cwe_list=["CWE-502", "CWE-20"],
        asset="example.com:8080",
        url="http://example.com:8080/login",
        method="POST",
        parameter="username",
        description="Log4j JNDI injection vulnerability",
        solution="Upgrade to Log4j 2.15.0 or later",
        evidence="Matcher: interactsh-matcher",
        tags=["cve", "rce", "log4j"],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        fingerprint="abcd1234efgh5678",
        raw_finding={"template-id": "cve-2021-44228"}
    )
    assert finding.severity == SeverityLevel.CRITICAL
    assert finding.confidence == ConfidenceLevel.CONFIRMED
    assert finding.cvss == 10.0
    assert finding.cve == "CVE-2021-44228"
    assert finding.cwe == "CWE-502"


def test_to_dict_and_to_json():
    finding = CanonicalFinding(
        finding_id="find_test",
        scanner="zap",
        title="XSS",
        severity=SeverityLevel.MEDIUM
    )
    data = finding.to_dict()
    assert isinstance(data, dict)
    assert data["severity"] == "MEDIUM"
    assert data["title"] == "XSS"

    json_str = finding.to_json()
    assert isinstance(json_str, str)
    parsed = json.loads(json_str)
    assert parsed["finding_id"] == "find_test"


def test_from_dict():
    data = {
        "finding_id": "find_999",
        "scanner": "zap",
        "title": "Cross-Site Scripting",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "cwe": "CWE-79"
    }
    finding = CanonicalFinding.from_dict(data)
    assert finding.finding_id == "find_999"
    assert finding.severity == SeverityLevel.HIGH
    assert finding.confidence == ConfidenceLevel.MEDIUM
    assert finding.cwe == "CWE-79"


def test_validation_rejects_empty_title():
    with pytest.raises(ValidationError):
        CanonicalFinding(
            finding_id="find_1",
            scanner="zap",
            title="   ",
            severity=SeverityLevel.HIGH
        )


def test_validation_rejects_empty_scanner():
    with pytest.raises(ValidationError):
        CanonicalFinding(
            finding_id="find_1",
            scanner="",
            title="Valid Title",
            severity=SeverityLevel.HIGH
        )


def test_validation_rejects_invalid_severity():
    with pytest.raises(ValidationError):
        CanonicalFinding(
            finding_id="find_1",
            scanner="zap",
            title="Valid Title",
            severity="SUPER_CRITICAL"  # type: ignore
        )


def test_validation_rejects_out_of_bounds_cvss():
    with pytest.raises(ValidationError):
        CanonicalFinding(
            finding_id="find_1",
            scanner="zap",
            title="Valid Title",
            severity=SeverityLevel.HIGH,
            cvss=12.5
        )
