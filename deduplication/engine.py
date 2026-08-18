"""
Vulnerability Deduplication Engine.

Merges duplicate findings across multiple scanners (Nuclei, OWASP ZAP, OpenVAS)
and multiple endpoints into unified, deduplication-ready canonical records.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from normalization.schema import CanonicalFinding, ConfidenceLevel, SeverityLevel


class DuplicateGroup(BaseModel):
    """Represents a group of duplicate / overlapping scanner findings."""
    group_key: str
    primary_finding: CanonicalFinding
    duplicate_count: int = 1
    participating_scanners: List[str] = Field(default_factory=list)
    all_urls: List[str] = Field(default_factory=list)


class DeduplicationResult(BaseModel):
    """Result of the deduplication process containing metrics and unique findings."""
    unique_findings: List[CanonicalFinding] = Field(default_factory=list)
    total_raw_count: int = 0
    unique_count: int = 0
    duplicates_removed: int = 0
    reduction_percentage: float = 0.0
    duplicate_groups: List[DuplicateGroup] = Field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


SEVERITY_ORDER = {
    SeverityLevel.CRITICAL: 5,
    SeverityLevel.HIGH: 4,
    SeverityLevel.MEDIUM: 3,
    SeverityLevel.LOW: 2,
    SeverityLevel.INFO: 1,
}

CONFIDENCE_ORDER = {
    ConfidenceLevel.CONFIRMED: 5,
    ConfidenceLevel.HIGH: 4,
    ConfidenceLevel.MEDIUM: 3,
    ConfidenceLevel.LOW: 2,
    ConfidenceLevel.FALSE_POSITIVE: 1,
}


class DeduplicationEngine:
    """Consolidates duplicate vulnerability findings across scanners."""

    @classmethod
    def generate_dedup_key(cls, finding: CanonicalFinding) -> str:
        """
        Generate a multi-level deduplication clustering key.
        - Level 1: Match by CVE + Asset
        - Level 2: Match by CWE + Asset + Parameter/Path
        - Level 3: Match by Fingerprint
        """
        asset = (finding.asset or "default_asset").strip().lower()

        # 1. If CVE exists, cluster by CVE + Asset
        if finding.cve:
            return f"cve:{finding.cve.upper()}:{asset}"

        # 2. If CWE + parameter exists
        param = (finding.parameter or "").strip().lower()
        if finding.cwe and param:
            return f"cwe_param:{finding.cwe.upper()}:{asset}:{param}"

        # 3. If CWE + Category + Asset
        if finding.cwe:
            # Extract basic path from primary url
            url_path = ""
            if finding.url:
                try:
                    from urllib.parse import urlsplit
                    url_path = urlsplit(finding.url).path.lower().rstrip("/")
                except Exception:
                    pass
            return f"cwe_path:{finding.cwe.upper()}:{asset}:{url_path}"

        # 4. Fallback to title + asset
        clean_title = (finding.title or "").strip().lower()
        return f"title_asset:{clean_title}:{asset}"

    @classmethod
    def merge_findings(cls, findings: List[CanonicalFinding]) -> CanonicalFinding:
        """
        Merge multiple duplicate findings into a single authoritative finding.
        """
        if not findings:
            raise ValueError("Cannot merge empty findings list")
        if len(findings) == 1:
            return findings[0]

        # Select primary finding with highest severity / confidence
        sorted_findings = sorted(
            findings,
            key=lambda f: (
                SEVERITY_ORDER.get(f.severity, 0),
                CONFIDENCE_ORDER.get(f.confidence, 0) if f.confidence else 0,
                1 if f.solution else 0,
                1 if f.description else 0
            ),
            reverse=True
        )

        primary = sorted_findings[0].model_copy(deep=True)

        # Merge scanners
        scanners_set = {f.scanner.lower() for f in findings if f.scanner}
        primary.scanner = ", ".join(sorted(scanners_set))

        # Merge URLs
        all_urls: List[str] = []
        for f in findings:
            for u in f.urls:
                if u and u not in all_urls:
                    all_urls.append(u)
            if f.url and f.url not in all_urls:
                all_urls.append(f.url)
        primary.urls = all_urls
        if all_urls and not primary.url:
            primary.url = all_urls[0]

        # Merge References
        all_refs: List[str] = list(primary.references)
        for f in findings:
            for ref in f.references:
                if ref and ref not in all_refs:
                    all_refs.append(ref)
        primary.references = all_refs

        # Merge Tags
        all_tags: List[str] = list(primary.tags)
        for f in findings:
            for tag in f.tags:
                if tag and tag not in all_tags:
                    all_tags.append(tag)
        primary.tags = all_tags

        # Merge Evidence strings
        evidences = [f.evidence for f in findings if f.evidence]
        if evidences:
            primary.evidence = " || ".join(dict.fromkeys(evidences))

        # Merge CWE list
        all_cwes: List[str] = list(primary.cwe_list)
        for f in findings:
            for c in f.cwe_list:
                if c and c not in all_cwes:
                    all_cwes.append(c)
        primary.cwe_list = all_cwes

        return primary

    @classmethod
    def deduplicate(cls, findings: List[CanonicalFinding]) -> DeduplicationResult:
        """
        Deduplicate a list of canonical findings.

        Returns:
            DeduplicationResult containing unique findings and reduction metrics.
        """
        if not findings:
            return DeduplicationResult()

        total_raw = len(findings)
        grouped: Dict[str, List[CanonicalFinding]] = {}

        for f in findings:
            key = cls.generate_dedup_key(f)
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(f)

        unique_findings: List[CanonicalFinding] = []
        duplicate_groups: List[DuplicateGroup] = []

        for key, group_items in grouped.items():
            merged = cls.merge_findings(group_items)
            unique_findings.append(merged)

            scanners = list({item.scanner for item in group_items if item.scanner})
            all_urls: List[str] = []
            for item in group_items:
                for u in item.urls:
                    if u not in all_urls:
                        all_urls.append(u)

            duplicate_groups.append(
                DuplicateGroup(
                    group_key=key,
                    primary_finding=merged,
                    duplicate_count=len(group_items),
                    participating_scanners=scanners,
                    all_urls=all_urls
                )
            )

        unique_count = len(unique_findings)
        duplicates_removed = total_raw - unique_count
        reduction_percentage = round((duplicates_removed / total_raw) * 100, 1) if total_raw > 0 else 0.0

        return DeduplicationResult(
            unique_findings=unique_findings,
            total_raw_count=total_raw,
            unique_count=unique_count,
            duplicates_removed=duplicates_removed,
            reduction_percentage=reduction_percentage,
            duplicate_groups=duplicate_groups
        )


def deduplicate_findings(findings: List[CanonicalFinding]) -> DeduplicationResult:
    """Convenience functional interface for deduplication."""
    return DeduplicationEngine.deduplicate(findings)
