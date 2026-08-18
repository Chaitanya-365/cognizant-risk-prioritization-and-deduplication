"""
Explainable Risk Prioritization and Ticket Generation Engine.

Computes multi-factor risk scores (0-100) based on 7 core dimensions:
1. CVSS Base Severity (up to 25 pts)
2. EPSS Exploitation Likelihood (up to 20 pts)
3. CISA Known Exploited Vulnerabilities (KEV) Status (up to 15 pts)
4. Exploit Availability (up to 10 pts)
5. Asset Criticality (up to 10 pts)
6. Internet Exposure (up to 10 pts)
7. Scanner Confidence & PoC Evidence (up to 10 pts)
            ↓
    Risk Score 0–100
            ↓
    Priority Tiers: P0 / P1 / P2 / P3

Produces explainable scoring breakdowns and ticket-ready security actions with SLAs.
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field

from normalization.schema import CanonicalFinding, ConfidenceLevel, SeverityLevel
from threat_intel.enricher import ThreatIntelData, ThreatIntelEnricher


class PriorityTier(str, Enum):
    """Actionable security remediation priority tiers."""
    P0 = "P0"  # Critical / Blocker (SLA: 24h)
    P1 = "P1"  # High Priority (SLA: 72h)
    P2 = "P2"  # Medium Priority (SLA: 7 Days)
    P3 = "P3"  # Low / Informational (SLA: 30 Days)


class AssetCriticality(str, Enum):
    """Target asset criticality classification."""
    CRITICAL = "CRITICAL"  # Tier 1 (Database, Auth, Payment, Core API) -> 10 pts
    HIGH = "HIGH"          # Production Application / Gateway -> 7 pts
    MEDIUM = "MEDIUM"      # Internal Application / Staging -> 4 pts
    LOW = "LOW"            # Development / Isolated Sandbox -> 1 pt


class PrioritizedFinding(BaseModel):
    """Vulnerability finding enriched with explainable risk score and security ticket."""
    rank: int = 1
    finding: CanonicalFinding
    threat_intel: ThreatIntelData
    risk_score: int = Field(ge=0, le=100)
    priority: PriorityTier = PriorityTier.P3
    priority_label: str = "P3"
    score_breakdown: Dict[str, int] = Field(default_factory=dict)
    why_prioritized: List[str] = Field(default_factory=list)
    recommended_action: str = ""
    sla: str = ""
    security_ticket_markdown: str = ""

    def to_dict(self) -> Dict[str, Any]:
        data = self.model_dump(mode="json")
        data["priority"] = self.priority.value
        return data


class RiskScoringEngine:
    """Calculates explainable 7-factor risk scores and generates ticket-ready action plans."""

    @classmethod
    def calculate_risk(
        cls,
        finding: CanonicalFinding,
        intel: Optional[ThreatIntelData] = None,
        is_internet_exposed: bool = True,
        is_critical_asset: bool = True,
        asset_criticality: Optional[Union[AssetCriticality, str]] = None,
        exploit_available: Optional[bool] = None
    ) -> PrioritizedFinding:
        """
        Calculate an explainable 7-factor multi-dimensional risk score for a canonical finding.

        Formula Factors:
        1. CVSS Base Severity (Max 25 pts)
        2. EPSS Exploit Likelihood (Max 20 pts)
        3. CISA KEV Status (Max 15 pts)
        4. Exploit Availability (Max 10 pts)
        5. Asset Criticality (Max 10 pts)
        6. Internet Exposure (Max 10 pts)
        7. Scanner Confidence & Evidence (Max 10 pts)
        Total = min(100, sum(factors))
        """
        if intel is None:
            intel = ThreatIntelEnricher.enrich_finding(finding)

        breakdown: Dict[str, int] = {}
        why: List[str] = []

        # ----------------------------------------------------
        # 1. CVSS Base Severity Score (Max 25 pts)
        # ----------------------------------------------------
        if finding.cvss is not None:
            cvss_pts = int(round((finding.cvss / 10.0) * 25))
            breakdown["1. CVSS Base Severity"] = cvss_pts
            if finding.cvss >= 9.0:
                why.append(f"Critical CVSS v3 score ({finding.cvss}/10.0)")
            elif finding.cvss >= 7.0:
                why.append(f"High CVSS v3 score ({finding.cvss}/10.0)")
            elif finding.cvss >= 4.0:
                why.append(f"Medium CVSS v3 score ({finding.cvss}/10.0)")
        else:
            # Fallback by normalized severity level
            sev_map = {
                SeverityLevel.CRITICAL: 25,
                SeverityLevel.HIGH: 18,
                SeverityLevel.MEDIUM: 10,
                SeverityLevel.LOW: 4,
                SeverityLevel.INFO: 0
            }
            cvss_pts = sev_map.get(finding.severity, 8)
            breakdown["1. CVSS Base Severity"] = cvss_pts
            if finding.severity in {SeverityLevel.CRITICAL, SeverityLevel.HIGH}:
                why.append(f"Identified as {finding.severity.value} severity issue")

        # ----------------------------------------------------
        # 2. EPSS Exploitation Probability (Max 20 pts)
        # ----------------------------------------------------
        epss_pts = 0
        if intel.epss_score is not None and intel.epss_score > 0:
            epss_pts = int(round(min(20, intel.epss_score * 20)))
            if intel.epss_percentile and intel.epss_percentile >= 0.95:
                epss_pts = max(epss_pts, 20)
            elif intel.epss_percentile and intel.epss_percentile >= 0.90:
                epss_pts = max(epss_pts, 18)
            breakdown["2. EPSS Exploit Likelihood"] = epss_pts
            epss_pct = int(round(intel.epss_score * 100))
            if epss_pct >= 50:
                why.append(f"High exploitation probability (EPSS = {epss_pct}%)")
            elif epss_pct >= 10:
                why.append(f"Elevated exploitation likelihood (EPSS = {epss_pct}%)")
        else:
            breakdown["2. EPSS Exploit Likelihood"] = 0

        # ----------------------------------------------------
        # 3. CISA KEV Status (Max 15 pts)
        # ----------------------------------------------------
        kev_pts = 0
        if intel.in_cisa_kev:
            kev_pts = 15
            why.append("Actively weaponized in the wild (Listed in CISA KEV catalog)")
            if intel.ransomware_campaign_use:
                why.append("Documented use in active ransomware campaigns")
        breakdown["3. CISA KEV Status"] = kev_pts

        # ----------------------------------------------------
        # 4. Exploit Availability (Max 10 pts)
        # ----------------------------------------------------
        has_exploit = exploit_available if exploit_available is not None else intel.exploit_available
        exploit_pts = 0
        if has_exploit:
            weaponized_sources = {"metasploit", "exploitdb", "commercial exploit"}
            sources_lower = {s.lower() for s in intel.exploit_poc_sources}
            if sources_lower & weaponized_sources:
                exploit_pts = 10
                why.append(f"Public weaponized exploit available ({', '.join(intel.exploit_poc_sources)})")
            elif intel.exploit_poc_sources:
                exploit_pts = 7
                why.append(f"Public proof-of-concept available ({', '.join(intel.exploit_poc_sources)})")
            else:
                exploit_pts = 6
                why.append("Functional exploit code documented in public threat feeds")
        breakdown["4. Exploit Availability"] = exploit_pts

        # ----------------------------------------------------
        # 5. Asset Criticality (Max 10 pts)
        # ----------------------------------------------------
        if asset_criticality is not None:
            crit_str = str(asset_criticality).upper()
            if "CRITICAL" in crit_str:
                asset_pts = 10
                why.append("Identified on Tier-1 Critical Crown Jewel asset (Auth/Database/Payment)")
            elif "HIGH" in crit_str:
                asset_pts = 7
                why.append("Identified on High-Value Production asset")
            elif "MEDIUM" in crit_str:
                asset_pts = 4
                why.append("Identified on Medium-tier internal/staging asset")
            else:
                asset_pts = 1
        elif is_critical_asset:
            asset_pts = 7
            why.append("Identified on high-value asset / target")
        else:
            asset_pts = 3
        breakdown["5. Asset Criticality"] = asset_pts

        # ----------------------------------------------------
        # 6. Internet Exposure (Max 10 pts)
        # ----------------------------------------------------
        if is_internet_exposed:
            exposure_pts = 10
            why.append("Target endpoint is directly internet-accessible / perimeter-facing")
        else:
            exposure_pts = 2
            why.append("Target endpoint is internally restricted / behind firewall")
        breakdown["6. Internet Exposure"] = exposure_pts

        # ----------------------------------------------------
        # 7. Scanner Confidence & PoC Evidence (Max 10 pts)
        # ----------------------------------------------------
        conf_pts = 0
        if finding.confidence == ConfidenceLevel.CONFIRMED:
            conf_pts += 6
            why.append("Vulnerability confirmed with direct verification")
        elif finding.confidence == ConfidenceLevel.HIGH:
            conf_pts += 5
        elif finding.confidence == ConfidenceLevel.MEDIUM:
            conf_pts += 3
        elif finding.confidence == ConfidenceLevel.LOW:
            conf_pts += 1

        if finding.evidence:
            conf_pts += 4
            why.append("Scanner verified functional proof-of-concept / payload")

        conf_pts = min(10, conf_pts)
        breakdown["7. Scanner Confidence"] = conf_pts

        # ----------------------------------------------------
        # Total Risk Score (0 - 100)
        # ----------------------------------------------------
        total_risk = min(100, max(0, sum(breakdown.values())))

        # ----------------------------------------------------
        # Priority Tier & SLA Classification: P0 / P1 / P2 / P3
        # ----------------------------------------------------
        if total_risk >= 75 or (intel.in_cisa_kev and is_internet_exposed):
            priority = PriorityTier.P0
            sla = "24 Hours (Urgent Containment & Patching)"
            action = f"Apply vendor security patch immediately for {finding.title}. Isolate affected endpoint if unpatched."
        elif total_risk >= 50:
            priority = PriorityTier.P1
            sla = "72 Hours (High Priority Fast-Track)"
            action = f"Remediate {finding.title} in the next maintenance window or apply WAF virtual patch."
        elif total_risk >= 25:
            priority = PriorityTier.P2
            sla = "7 Days (Standard Sprint Remediation)"
            action = f"Schedule code fix and configuration update for {finding.title}."
        else:
            priority = PriorityTier.P3
            sla = "30 Days (Routine Maintenance / Hardening)"
            action = f"Review security configuration and update documentation for {finding.title}."

        if finding.solution:
            action = f"{action} Fix: {finding.solution}"

        # Markdown Ticket Template
        ticket_md = cls.generate_ticket_markdown(
            finding=finding,
            intel=intel,
            risk_score=total_risk,
            priority=priority,
            why=why,
            action=action,
            sla=sla,
            breakdown=breakdown
        )

        return PrioritizedFinding(
            finding=finding,
            threat_intel=intel,
            risk_score=total_risk,
            priority=priority,
            priority_label=priority.value,
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
        priority: PriorityTier,
        why: List[str],
        action: str,
        sla: str,
        breakdown: Dict[str, int]
    ) -> str:
        """Format ticket into standard Security Ticket / Jira task."""
        lines = [
            "--------------------------------------------------",
            f"SECURITY TICKET [PRIORITY: {priority.value}]",
            "--------------------------------------------------",
            f"Title: Fix {finding.cve or finding.title} on {finding.asset or 'Production System'}",
            f"Priority Tier: {priority.value}",
            f"Risk Score: {risk_score}/100",
            f"Severity: {finding.severity.value}",
            f"SLA: {sla}",
            "",
            "Why Prioritized:"
        ]
        for w in why:
            lines.append(f"- {w}")

        lines.extend([
            "",
            "Multi-Factor Risk Breakdown:"
        ])
        for factor_name, pts in breakdown.items():
            lines.append(f"- {factor_name}: +{pts} pts")

        lines.extend([
            f"Total Calculated Risk: {risk_score}/100",
            "",
            "Recommended Action:",
            action,
            "",
            "SLA:",
            sla,
            "--------------------------------------------------"
        ])
        return "\n".join(lines)

    @classmethod
    def prioritize_findings(
        cls,
        findings: List[CanonicalFinding],
        threat_intel_list: Optional[List[ThreatIntelData]] = None,
        is_internet_exposed: bool = True,
        is_critical_asset: bool = True
    ) -> List[PrioritizedFinding]:
        """
        Prioritize a list of canonical findings and rank them by Risk Score.
        """
        prioritized: List[PrioritizedFinding] = []

        for i, f in enumerate(findings):
            intel = threat_intel_list[i] if threat_intel_list and i < len(threat_intel_list) else None
            pf = cls.calculate_risk(
                f,
                intel=intel,
                is_internet_exposed=is_internet_exposed,
                is_critical_asset=is_critical_asset
            )
            prioritized.append(pf)

        # Sort descending by risk score, then severity
        severity_order = {
            SeverityLevel.CRITICAL: 5,
            SeverityLevel.HIGH: 4,
            SeverityLevel.MEDIUM: 3,
            SeverityLevel.LOW: 2,
            SeverityLevel.INFO: 1
        }
        prioritized.sort(
            key=lambda item: (item.risk_score, severity_order.get(item.finding.severity, 0)),
            reverse=True
        )

        # Assign ranks
        for rank, item in enumerate(prioritized, start=1):
            item.rank = rank

        return prioritized


def prioritize_findings(
    findings: List[CanonicalFinding],
    threat_intel_list: Optional[List[ThreatIntelData]] = None,
    is_internet_exposed: bool = True,
    is_critical_asset: bool = True
) -> List[PrioritizedFinding]:
    """Functional convenience interface for risk prioritization."""
    return RiskScoringEngine.prioritize_findings(
        findings=findings,
        threat_intel_list=threat_intel_list,
        is_internet_exposed=is_internet_exposed,
        is_critical_asset=is_critical_asset
    )

