"""
Unit tests for Threat Intelligence Enrichment and 7-Factor Risk Prioritization.
"""

from normalization import CanonicalFinding, ConfidenceLevel, SeverityLevel
from prioritization import AssetCriticality, PriorityTier, RiskScoringEngine, prioritize_findings
from threat_intel import ThreatIntelData, ThreatIntelEnricher, enrich_finding


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


def test_seven_factor_risk_scoring_all_dimensions():
    """
    Verify that all 7 dimensions contribute to the 0-100 score:
    1. CVSS Base Severity
    2. EPSS Exploit Likelihood
    3. CISA KEV Status
    4. Exploit Availability
    5. Asset Criticality
    6. Internet Exposure
    7. Scanner Confidence & PoC Evidence
    """
    log4j_finding = CanonicalFinding(
        finding_id="find_log4j",
        scanner="nuclei",
        title="Apache Log4j RCE",
        severity=SeverityLevel.CRITICAL,
        cve="CVE-2021-44228",
        asset="auth.corp.production",
        url="https://auth.corp.production/oauth/login",
        confidence=ConfidenceLevel.CONFIRMED,
        evidence="Interactsh OAST DNS query received"
    )

    prioritized = RiskScoringEngine.calculate_risk(
        finding=log4j_finding,
        asset_criticality=AssetCriticality.CRITICAL,
        is_internet_exposed=True,
        exploit_available=True
    )

    assert prioritized.risk_score >= 90
    assert prioritized.risk_score <= 100
    assert prioritized.priority == PriorityTier.P0
    assert "24 Hours" in prioritized.sla

    # Verify all 7 dimensions are present in score breakdown
    breakdown = prioritized.score_breakdown
    assert "1. CVSS Base Severity" in breakdown
    assert "2. EPSS Exploit Likelihood" in breakdown
    assert "3. CISA KEV Status" in breakdown
    assert "4. Exploit Availability" in breakdown
    assert "5. Asset Criticality" in breakdown
    assert "6. Internet Exposure" in breakdown
    assert "7. Scanner Confidence" in breakdown

    assert breakdown["1. CVSS Base Severity"] == 25
    assert breakdown["2. EPSS Exploit Likelihood"] == 20
    assert breakdown["3. CISA KEV Status"] == 15
    assert breakdown["4. Exploit Availability"] == 10
    assert breakdown["5. Asset Criticality"] == 10
    assert breakdown["6. Internet Exposure"] == 10
    assert breakdown["7. Scanner Confidence"] == 10


def test_priority_tier_mapping_p0_to_p3():
    """
    Verify Priority Tier classifications:
    - P0 (Critical / Blocker - SLA: 24 Hours)
    - P1 (High Priority - SLA: 72 Hours)
    - P2 (Medium Priority - SLA: 7 Days)
    - P3 (Low / Informational - SLA: 30 Days)
    """
    # 1. P0 Finding (Log4j / CISA KEV)
    p0_finding = CanonicalFinding(
        finding_id="f_p0",
        scanner="nuclei",
        title="Apache Log4j RCE",
        severity=SeverityLevel.CRITICAL,
        cve="CVE-2021-44228",
        cvss=10.0
    )
    res_p0 = RiskScoringEngine.calculate_risk(p0_finding)
    assert res_p0.priority == PriorityTier.P0
    assert "24 Hours" in res_p0.sla

    # 2. P1 Finding (High CVSS, no KEV, but internet exposed)
    p1_finding = CanonicalFinding(
        finding_id="f_p1",
        scanner="zap",
        title="Blind SQL Injection",
        severity=SeverityLevel.HIGH,
        cvss=8.5,
        confidence=ConfidenceLevel.HIGH,
        evidence="Time delay sleep payload verified"
    )
    intel_p1 = ThreatIntelData(epss_score=0.45, in_cisa_kev=False)
    res_p1 = RiskScoringEngine.calculate_risk(p1_finding, intel=intel_p1)
    assert res_p1.priority == PriorityTier.P1
    assert res_p1.risk_score >= 50

    # 3. P2 Finding (Medium Severity Misconfiguration)
    p2_finding = CanonicalFinding(
        finding_id="f_p2",
        scanner="zap",
        title="Missing Anti-Clickjacking Header",
        severity=SeverityLevel.MEDIUM,
        cvss=5.0,
        confidence=ConfidenceLevel.MEDIUM
    )
    intel_p2 = ThreatIntelData(epss_score=0.05, in_cisa_kev=False)
    res_p2 = RiskScoringEngine.calculate_risk(p2_finding, intel=intel_p2, is_internet_exposed=False)
    assert res_p2.priority == PriorityTier.P2
    assert "7 Days" in res_p2.sla

    # 4. P3 Finding (Info / Low Severity)
    p3_finding = CanonicalFinding(
        finding_id="f_p3",
        scanner="openvas",
        title="X-Content-Type-Options Header Missing",
        severity=SeverityLevel.LOW,
        cvss=2.0,
        confidence=ConfidenceLevel.LOW
    )
    intel_p3 = ThreatIntelData(epss_score=0.01, in_cisa_kev=False)
    res_p3 = RiskScoringEngine.calculate_risk(p3_finding, intel=intel_p3, is_internet_exposed=False)
    assert res_p3.priority == PriorityTier.P3
    assert "30 Days" in res_p3.sla


def test_batch_prioritize_findings_ranking():
    """Verify batch sorting ranks highest risk scores first."""
    crit = CanonicalFinding(
        finding_id="f1",
        scanner="nuclei",
        title="Log4j RCE",
        severity=SeverityLevel.CRITICAL,
        cve="CVE-2021-44228"
    )
    low = CanonicalFinding(
        finding_id="f2",
        scanner="zap",
        title="Info Disclosure",
        severity=SeverityLevel.LOW
    )

    ranked = prioritize_findings([low, crit])
    assert ranked[0].finding.finding_id == "f1"
    assert ranked[0].rank == 1
    assert ranked[0].priority == PriorityTier.P0

    assert ranked[1].finding.finding_id == "f2"
    assert ranked[1].rank == 2
    assert ranked[1].priority == PriorityTier.P3


def test_security_ticket_markdown_format():
    """Verify ticket generation includes Priority, Score breakdown, and SLA."""
    finding = CanonicalFinding(
        finding_id="f_ticket",
        scanner="nuclei",
        title="Struts RCE",
        severity=SeverityLevel.CRITICAL,
        cve="CVE-2017-5638",
        asset="payment-gateway.prod"
    )
    prioritized = RiskScoringEngine.calculate_risk(finding)
    ticket = prioritized.security_ticket_markdown

    assert "SECURITY TICKET [PRIORITY: P0]" in ticket
    assert "Priority Tier: P0" in ticket
    assert "Risk Score:" in ticket
    assert "Multi-Factor Risk Breakdown:" in ticket
    assert "1. CVSS Base Severity" in ticket
    assert "SLA:" in ticket
