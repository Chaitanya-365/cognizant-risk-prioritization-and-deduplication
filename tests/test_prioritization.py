"""
Unit tests for Threat Intelligence Enrichment and Risk Prioritization.
"""

from normalization import CanonicalFinding, ConfidenceLevel, SeverityLevel
from prioritization import RiskScoringEngine, prioritize_findings
from threat_intel import ThreatIntelEnricher, enrich_finding


def test_threat_intel_enrichment():
    f = CanonicalFinding(
        finding_id="find_log4j",
        scanner="nuclei",
        title="Apache Log4j",
        severity=SeverityLevel.CRITICAL,
        cve="CVE-2021-44228"
    )

    intel = enrich_finding(f)
    assert intel.in_cisa_kev is True
    assert intel.epss_score is not None and intel.epss_score > 0.90
    assert intel.ransomware_campaign_use is True
    assert f.cvss == 10.0


def test_risk_scoring_prioritizes_kev_and_epss():
    log4j_finding = CanonicalFinding(
        finding_id="find_log4j",
        scanner="nuclei",
        title="Apache Log4j RCE",
        severity=SeverityLevel.CRITICAL,
        cve="CVE-2021-44228",
        asset="production-server.local",
        url="http://production-server.local/login",
        confidence=ConfidenceLevel.CONFIRMED,
        evidence="OAST payload connected back"
    )

    low_finding = CanonicalFinding(
        finding_id="find_info",
        scanner="zap",
        title="Swagger UI Exposure",
        severity=SeverityLevel.LOW,
        asset="production-server.local"
    )

    prioritized = prioritize_findings([low_finding, log4j_finding])

    # Rank 1 should be Log4j with very high risk score (90+)
    assert prioritized[0].finding.cve == "CVE-2021-44228"
    assert prioritized[0].risk_score >= 90
    assert "CISA Known Exploited (KEV)" in prioritized[0].score_breakdown
    assert prioritized[0].sla == "24 Hours (Urgent)"
    assert "SECURITY TICKET" in prioritized[0].security_ticket_markdown

    # Rank 2 is low finding
    assert prioritized[1].finding.title == "Swagger UI Exposure"
    assert prioritized[1].risk_score < 50
