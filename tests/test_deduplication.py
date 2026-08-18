"""
Unit tests for Deduplication Engine.
"""

from deduplication import DeduplicationEngine, deduplicate_findings
from normalization import CanonicalFinding, SeverityLevel


def test_deduplication_merges_identical_cve():
    f1 = CanonicalFinding(
        finding_id="find_1",
        scanner="nuclei",
        title="Apache Log4j RCE",
        severity=SeverityLevel.CRITICAL,
        cve="CVE-2021-44228",
        asset="localhost:3000",
        url="http://localhost:3000/login",
        urls=["http://localhost:3000/login"]
    )
    f2 = CanonicalFinding(
        finding_id="find_2",
        scanner="zap",
        title="Log4j JNDI Vulnerability",
        severity=SeverityLevel.HIGH,
        cve="CVE-2021-44228",
        asset="localhost:3000",
        url="http://localhost:3000/api",
        urls=["http://localhost:3000/api"]
    )

    result = deduplicate_findings([f1, f2])

    assert result.total_raw_count == 2
    assert result.unique_count == 1
    assert result.duplicates_removed == 1
    assert result.reduction_percentage == 50.0

    merged = result.unique_findings[0]
    assert "nuclei" in merged.scanner
    assert "zap" in merged.scanner
    assert merged.severity == SeverityLevel.CRITICAL  # Highest severity preserved
    assert len(merged.urls) == 2


def test_deduplication_distinct_findings():
    f1 = CanonicalFinding(
        finding_id="find_1",
        scanner="zap",
        title="SQL Injection",
        severity=SeverityLevel.HIGH,
        cwe="CWE-89",
        asset="localhost:3000",
        parameter="id"
    )
    f2 = CanonicalFinding(
        finding_id="find_2",
        scanner="zap",
        title="XSS",
        severity=SeverityLevel.MEDIUM,
        cwe="CWE-79",
        asset="localhost:3000",
        parameter="search"
    )

    result = deduplicate_findings([f1, f2])
    assert result.total_raw_count == 2
    assert result.unique_count == 2
    assert result.duplicates_removed == 0
    assert result.reduction_percentage == 0.0
