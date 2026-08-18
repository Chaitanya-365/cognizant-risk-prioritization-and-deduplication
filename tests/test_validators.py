"""
Tests for finding validators.
"""

from normalization.schema import CanonicalFinding, ConfidenceLevel, SeverityLevel
from normalization.validators import (
    validate_confidence,
    validate_cve,
    validate_cvss,
    validate_cwe,
    validate_finding,
    validate_severity,
)


def test_validate_severity():
    assert validate_severity("HIGH") is True
    assert validate_severity(SeverityLevel.CRITICAL) is True
    assert validate_severity("UNKNOWN") is False
    assert validate_severity(None) is False


def test_validate_confidence():
    assert validate_confidence(None) is True
    assert validate_confidence("HIGH") is True
    assert validate_confidence(ConfidenceLevel.CONFIRMED) is True
    assert validate_confidence("UNKNOWN") is False


def test_validate_cve():
    assert validate_cve(None) is True
    assert validate_cve("CVE-2021-44228") is True
    assert validate_cve("CVE-2023-123456") is True
    assert validate_cve("cve-2021-44228") is False  # Must be uppercase canonical
    assert validate_cve("invalid-cve") is False


def test_validate_cwe():
    assert validate_cwe(None) is True
    assert validate_cwe("CWE-79") is True
    assert validate_cwe("CWE-502") is True
    assert validate_cwe("79") is False  # Must be canonical format CWE-XXX
    assert validate_cwe("invalid") is False


def test_validate_cvss():
    assert validate_cvss(None) is True
    assert validate_cvss(0.0) is True
    assert validate_cvss(7.5) is True
    assert validate_cvss(10.0) is True
    assert validate_cvss(-0.1) is False
    assert validate_cvss(10.1) is False


def test_validate_finding_valid_instance():
    finding = CanonicalFinding(
        finding_id="find_test",
        scanner="zap",
        title="SQL Injection",
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        cve="CVE-2023-1234",
        cwe="CWE-89",
        cwe_list=["CWE-89"],
        cvss=8.5
    )
    errors = validate_finding(finding)
    assert errors == []


def test_validate_finding_dict_errors():
    invalid_dict = {
        "finding_id": "find_1",
        "scanner": "zap",
        "title": "SQL Injection",
        "severity": "INVALID_SEV",
    }
    errors = validate_finding(invalid_dict)
    assert len(errors) > 0
