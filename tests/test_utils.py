"""
Tests for normalization utilities (severity, CVE, CWE, URL, strings).
"""

import pytest

from normalization.schema import ConfidenceLevel, SeverityLevel
from normalization.utils import (
    clean_string,
    extract_asset_from_url,
    generate_dedup_fingerprint,
    generate_finding_id,
    normalize_confidence,
    normalize_cve,
    normalize_cwe,
    normalize_cwe_list,
    normalize_cvss,
    normalize_http_method,
    normalize_severity,
    normalize_string_list,
    normalize_url,
)


# ============================================================
# Severity Normalization Tests
# ============================================================

@pytest.mark.parametrize(
    "input_val,expected",
    [
        ("critical", SeverityLevel.CRITICAL),
        ("Critical", SeverityLevel.CRITICAL),
        ("CRITICAL", SeverityLevel.CRITICAL),
        ("crit", SeverityLevel.CRITICAL),
        ("4", SeverityLevel.CRITICAL),
        ("high", SeverityLevel.HIGH),
        ("High", SeverityLevel.HIGH),
        ("HIGH", SeverityLevel.HIGH),
        ("3", SeverityLevel.HIGH),
        ("medium", SeverityLevel.MEDIUM),
        ("Medium", SeverityLevel.MEDIUM),
        ("MEDIUM", SeverityLevel.MEDIUM),
        ("moderate", SeverityLevel.MEDIUM),
        ("warn", SeverityLevel.MEDIUM),
        ("warning", SeverityLevel.MEDIUM),
        ("2", SeverityLevel.MEDIUM),
        ("low", SeverityLevel.LOW),
        ("Low", SeverityLevel.LOW),
        ("LOW", SeverityLevel.LOW),
        ("1", SeverityLevel.LOW),
        ("info", SeverityLevel.INFO),
        ("Info", SeverityLevel.INFO),
        ("INFO", SeverityLevel.INFO),
        ("informational", SeverityLevel.INFO),
        ("Informational", SeverityLevel.INFO),
        ("0", SeverityLevel.INFO),
    ]
)
def test_normalize_severity_valid(input_val, expected):
    assert normalize_severity(input_val) == expected


def test_normalize_severity_invalid():
    with pytest.raises(ValueError):
        normalize_severity("unknown_severity")

    with pytest.raises(ValueError):
        normalize_severity("")

    with pytest.raises(ValueError):
        normalize_severity(None)


# ============================================================
# Confidence Normalization Tests
# ============================================================

@pytest.mark.parametrize(
    "input_val,expected",
    [
        ("high", ConfidenceLevel.HIGH),
        ("High", ConfidenceLevel.HIGH),
        ("medium", ConfidenceLevel.MEDIUM),
        ("low", ConfidenceLevel.LOW),
        ("confirmed", ConfidenceLevel.CONFIRMED),
        ("certain", ConfidenceLevel.CONFIRMED),
        ("false positive", ConfidenceLevel.FALSE_POSITIVE),
        ("false_positive", ConfidenceLevel.FALSE_POSITIVE),
        ("fp", ConfidenceLevel.FALSE_POSITIVE),
        (None, None),
        ("", None),
        ("unknown_confidence", None),
    ]
)
def test_normalize_confidence(input_val, expected):
    assert normalize_confidence(input_val) == expected


# ============================================================
# CVE Normalization Tests
# ============================================================

@pytest.mark.parametrize(
    "input_val,expected",
    [
        ("CVE-2021-44228", "CVE-2021-44228"),
        ("cve-2021-44228", "CVE-2021-44228"),
        ("cve-2023-12345", "CVE-2023-12345"),
        ("CVE-2026-99999", "CVE-2026-99999"),
        ("Found CVE-2020-1234 in response", "CVE-2020-1234"),
        (["CVE-2022-1111", "CVE-2022-2222"], "CVE-2022-1111"),
        ("", None),
        ("none", None),
        ("N/A", None),
        ("NOT-A-CVE", None),
        (None, None),
    ]
)
def test_normalize_cve(input_val, expected):
    assert normalize_cve(input_val) == expected


# ============================================================
# CWE Normalization Tests
# ============================================================

@pytest.mark.parametrize(
    "input_val,expected",
    [
        ("89", "CWE-89"),
        (89, "CWE-89"),
        ("cwe-89", "CWE-89"),
        ("CWE-89", "CWE-89"),
        ("CWE89", "CWE-89"),
        ("cwe_79", "CWE-79"),
        ("0", None),
        ("-1", None),
        ("", None),
        (None, None),
    ]
)
def test_normalize_cwe(input_val, expected):
    assert normalize_cwe(input_val) == expected


def test_normalize_cwe_list():
    assert normalize_cwe_list(["89", "cwe-79", "CWE-20"]) == ["CWE-89", "CWE-79", "CWE-20"]
    assert normalize_cwe_list("89, 79") == ["CWE-89", "CWE-79"]
    assert normalize_cwe_list(["0", "-1", None]) == []
    assert normalize_cwe_list(None) == []


# ============================================================
# CVSS Normalization Tests
# ============================================================

def test_normalize_cvss():
    assert normalize_cvss(7.5) == 7.5
    assert normalize_cvss("9.8") == 9.8
    assert normalize_cvss(10.0) == 10.0
    assert normalize_cvss(0.0) == 0.0
    assert normalize_cvss(12.0) is None
    assert normalize_cvss(-1.0) is None
    assert normalize_cvss("invalid") is None
    assert normalize_cvss(None) is None


# ============================================================
# URL and Asset Tests
# ============================================================

def test_extract_asset_from_url():
    assert extract_asset_from_url("http://example.com/api/v1") == "example.com"
    assert extract_asset_from_url("https://example.com:8080/login?user=admin") == "example.com:8080"
    assert extract_asset_from_url("http://192.168.1.5:3000/test") == "192.168.1.5:3000"
    assert extract_asset_from_url("localhost:5000/health") == "localhost:5000"
    assert extract_asset_from_url(None) is None


def test_normalize_url():
    assert normalize_url("  http://example.com/test?a=1  ") == "http://example.com/test?a=1"
    assert normalize_url("") is None
    assert normalize_url(None) is None


def test_normalize_http_method():
    assert normalize_http_method("get") == "GET"
    assert normalize_http_method("POST") == "POST"
    assert normalize_http_method("patch") == "PATCH"
    assert normalize_http_method("invalid_method") is None
    assert normalize_http_method(None) is None


# ============================================================
# String and List Cleaning Tests
# ============================================================

def test_clean_string():
    assert clean_string("  hello world  ") == "hello world"
    assert clean_string("") is None
    assert clean_string("   ") is None
    assert clean_string("none") is None
    assert clean_string("null") is None
    assert clean_string("N/A") is None
    assert clean_string(None) is None


def test_normalize_string_list():
    assert normalize_string_list(["a", "b, c", "d\ne", None, ""]) == ["a", "b", "c", "d", "e"]
    assert normalize_string_list("item1, item2, item3") == ["item1", "item2", "item3"]
    assert normalize_string_list(None) == []


# ============================================================
# ID and Fingerprint Generation Tests
# ============================================================

def test_generate_finding_id_deterministic():
    id1 = generate_finding_id("zap", "40018", "example.com", "http://example.com/api", "id")
    id2 = generate_finding_id("zap", "40018", "example.com", "http://example.com/api", "id")
    id3 = generate_finding_id("zap", "40019", "example.com", "http://example.com/api", "id")

    assert id1 == id2
    assert id1.startswith("find_")
    assert id1 != id3


def test_generate_dedup_fingerprint():
    fp1 = generate_dedup_fingerprint("CVE-2021-44228", "CWE-502", "example.com", "POST", "id", "RCE")
    fp2 = generate_dedup_fingerprint("cve-2021-44228", "cwe-502", "EXAMPLE.COM", "post", "ID", "rce")
    fp3 = generate_dedup_fingerprint(None, "CWE-79", "example.com", "GET", "q", "XSS")

    assert fp1 == fp2
    assert len(fp1) == 64
    assert fp1 != fp3
