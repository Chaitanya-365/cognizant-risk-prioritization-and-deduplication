"""
Explainable Risk Prioritization and Ticket Generation Engine.

Computes multi-factor risk scores (0-100) based on:
1. CVSS Base Severity (up to 30 pts)
2. EPSS Exploitation Likelihood (up to 25 pts)
3. CISA Known Exploited Vulnerabilities (KEV) status (+20 pts)
4. Internet Exposure & Asset Criticality (up to 15 pts)
5. Scanner Confidence & PoC Evidence (up to 10 pts)

Produces explainable scoring breakdowns and ticket-ready security actions.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from normalization.schema import CanonicalFinding, ConfidenceLevel, SeverityLevel
from threat_intel.enricher import ThreatIntelData, ThreatIntelEnricher


class PrioritizedFinding(BaseModel):
    """Vulnerability finding enriched with explainable risk score and security ticket."""
    rank: int = 1
    finding: CanonicalFinding
    threat_intel: ThreatIntelData
    risk_score: int = Field(ge=0, le=100)
    score_breakdown: Dict[str, int] = Field(default_factory=dict)
    why_prioritized: List[str] = Field(default_factory=list)
    recommended_action: str = ""
    sla: str = ""
    security_ticket_markdown: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class RiskScoringEngine:
    """Calculates explainable risk scores and generates ticket-ready action plans."""

    @classmethod
    def calculate_risk(
        cls,
        finding: CanonicalFinding,
        intel: Optional[ThreatIntelData] = None,
        is_internet_exposed: bool = True,
        is_critical_asset: bool = True
    ) -> PrioritizedFinding:
        """
        Calculate an explainable multi-factor risk score for a canonical finding.
        """
        if intel is None:
            intel = ThreatIntelEnricher.enrich_finding(finding)

        breakdown: Dict[str, int] = {}
        why: List[str] = []

        # 1. CVSS Score Contribution (Max 30 pts)
        if finding.cvss is not None:
            cvss_pts = int(round((finding.cvss / 10.0) * 30))
            breakdown["CVSS Severity Score"] = cvss_pts
            if finding.cvss >= 9.0:
                why.append(f"Critical CVSS v3 score ({finding.cvss}/10.0)")
            elif finding.cvss >= 7.0:
                why.append(f"High CVSS v3 score ({finding.cvss}/10.0)")
        else:
            # Fallback by severity level
            sev_map = {
                SeverityLevel.CRITICAL: 28,
                SeverityLevel.HIGH: 22,
                SeverityLevel.MEDIUM: 14,
                SeverityLevel.LOW: 6,
                SeverityLevel.INFO: 0
            }
            cvss_pts = sev_map.get(finding.severity, 10)
            breakdown["Scanner Severity Baseline"] = cvss_pts
            if finding.severity in {SeverityLevel.CRITICAL, SeverityLevel.HIGH}:
                why.append(f"Identified as {finding.severity.value} severity issue")

        # 2. EPSS Contribution (Max 25 pts)
        if intel.epss_score is not None and intel.epss_score > 0:
            epss_pts = int(round(min(25, intel.epss_score * 25)))
            # Boost high EPSS percentiles
            if intel.epss_percentile and intel.epss_percentile >= 0.90:
                epss_pts = max(epss_pts, 20)
            breakdown["EPSS Exploitation Probability"] = epss_pts
            epss_pct = int(round(intel.epss_score * 100))
            if epss_pct >= 50:
                why.append(f"High exploitation probability (EPSS = {epss_pct}%)")
            elif epss_pct >= 10:
                why.append(f"Elevated exploitation likelihood (EPSS = {epss_pct}%)")

        # 3. CISA KEV Status (+20 pts)
        if intel.in_cisa_kev:
            breakdown["CISA Known Exploited (KEV)"] = 20
            why.append("Actively weaponized in the wild (Listed in CISA KEV catalog)")
            if intel.ransomware_campaign_use:
                why.append("Documented use in ransomware campaigns")

        # 4. Asset Criticality & Internet Exposure (Max 15 pts)
        asset_pts = 0
        if is_internet_exposed:
            asset_pts += 9
            why.append("Target endpoint is internet-accessible")
        if is_critical_asset:
            asset_pts += 6
            why.append("Identified on high-value asset / target")
        breakdown["Asset Exposure & Criticality"] = asset_pts

        # 5. Scanner Confidence & PoC Evidence (Max 10 pts)
        conf_pts = 0
        if finding.confidence == ConfidenceLevel.CONFIRMED:
            conf_pts += 6
            why.append("Vulnerability confirmed with direct verification")
        elif finding.confidence == ConfidenceLevel.HIGH:
            conf_pts += 5
        elif finding.confidence == ConfidenceLevel.MEDIUM:
            conf_pts += 3

        if finding.evidence:
            conf_pts += 4
            why.append("Scanner verified functional proof-of-concept / payload")

        conf_pts = min(10, conf_pts)
        if conf_pts > 0:
            breakdown["Confidence & Verifiable Proof"] = conf_pts

        # Total Calculation
        total_risk = min(100, sum(breakdown.values()))

        # SLA & Recommended Action
        if total_risk >= 85 or intel.in_cisa_kev:
            sla = "24 Hours (Urgent)"
            action = f"Apply vendor security patch immediately for {finding.title}. Isolate affected endpoint if unpatched."
        elif total_risk >= 70:
            sla = "72 Hours (High)"
            action = f"Remediate {finding.title} in the next maintenance window or apply WAF virtual patch."
        elif total_risk >= 40:
            sla = "7 Days (Medium)"
            action = f"Schedule code fix and configuration update for {finding.title}."
        else:
            sla = "30 Days (Standard)"
            action = f"Review security configuration and update documentation for {finding.title}."

        if finding.solution:
            action = f"{action} Fix: {finding.solution}"

        # Markdown Ticket Template
        ticket_md = cls.generate_ticket_markdown(finding, intel, total_risk, why, action, sla, breakdown)

        return PrioritizedFinding(
            finding=finding,
            threat_intel=intel,
            risk_score=total_risk,
            score_breakdown=breakdown,
            why_prioritized=why,
            recommended_action=action,
            sla=sla,
            security_ticket_markdown=ticket_md
        )

    @classmethod
    def generate_ticket_markdown(
        cls,
        finding: CanonicalFinding,
        intel: ThreatIntelData,
        risk_score: int,
        why: List[str],
        action: str,
        sla: str,
        breakdown: Dict[str, int]
    ) -> str:
        """Format ticket into standard Security Ticket / Jira task."""
        lines = [
            "--------------------------------------------------",
            "SECURITY TICKET",
            "--------------------------------------------------",
            f"Title: Fix {finding.cve or finding.title} on {finding.asset or 'Production System'}",
            f"Severity: {finding.severity.value}",
            f"Risk Score: {risk_score}/100",
            "",
            "Why:"
        ]
        for w in why:
            lines.append(f"- {w}")

        lines.extend([
            "",
            f"Recommended Action:",
            action,
            "",
            f"SLA:",
            sla,
            "--------------------------------------------------"
        ])
        return "\n".join(lines)

    @classmethod
    def prioritize_findings(
        cls,
        findings: List[CanonicalFinding],
        threat_intel_list: Optional[List[ThreatIntelData]] = None
    ) -> List[PrioritizedFinding]:
        """
        Prioritize a list of canonical findings and rank them by Risk Score.
        """
        prioritized: List[PrioritizedFinding] = []

        for i, f in enumerate(findings):
            intel = threat_intel_list[i] if threat_intel_list and i < len(threat_intel_list) else None
            pf = cls.calculate_risk(f, intel=intel)
            prioritized.append(pf)

        # Sort descending by risk score
        prioritized.sort(key=lambda item: (item.risk_score, item.finding.severity.value), reverse=True)

        # Assign ranks
        for rank, item in enumerate(prioritized, start=1):
            item.rank = rank

        return prioritized


def prioritize_findings(
    findings: List[CanonicalFinding],
    threat_intel_list: Optional[List[ThreatIntelData]] = None
) -> List[PrioritizedFinding]:
    """Functional convenience interface for risk prioritization."""
    return RiskScoringEngine.prioritize_findings(findings, threat_intel_list=threat_intel_list)
