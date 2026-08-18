"""
OWASP ZAP Finding Normalizer.

Transforms raw and grouped OWASP ZAP alerts into CanonicalFinding objects.
"""

from typing import Any, Dict, List, Optional
from normalization.schema import CanonicalFinding
from normalization.utils import (
    clean_string,
    derive_category,
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


class ZAPNormalizer:
    """Normalizer for OWASP ZAP vulnerability scanner findings."""

    @classmethod
    def normalize(cls, data: Dict[str, Any]) -> CanonicalFinding:
        """
        Convert a single raw or grouped ZAP alert dictionary into a CanonicalFinding.

        Args:
            data: Raw ZAP alert dictionary from zap.core.alerts() or grouped ZAP alert.

        Returns:
            A validated CanonicalFinding instance.
        """
        if not isinstance(data, dict):
            raise TypeError(f"Expected dictionary for ZAP finding, got {type(data).__name__}")

        # 1. Scanner & Title
        scanner = "zap"
        title = clean_string(data.get("alert") or data.get("name") or data.get("title"))
        plugin_id = str(data.get("pluginId") or data.get("alert_id") or data.get("id") or "").strip()
        if not title:
            if plugin_id:
                title = f"ZAP Alert {plugin_id}"
            else:
                title = "OWASP ZAP Vulnerability"

        # 2. Severity
        raw_severity = data.get("risk") or data.get("severity") or "INFO"
        severity = normalize_severity(raw_severity)

        # 3. Confidence
        confidence = normalize_confidence(data.get("confidence"))

        # 4. URLs & Asset
        urls: List[str] = []
        raw_url = data.get("url")
        if raw_url:
            cleaned_u = normalize_url(raw_url)
            if cleaned_u and cleaned_u not in urls:
                urls.append(cleaned_u)

        if data.get("affected_urls") and isinstance(data["affected_urls"], list):
            for u in data["affected_urls"]:
                cleaned_u = normalize_url(u)
                if cleaned_u and cleaned_u not in urls:
                    urls.append(cleaned_u)

        if data.get("urls") and isinstance(data["urls"], list):
            for u in data["urls"]:
                cleaned_u = normalize_url(u)
                if cleaned_u and cleaned_u not in urls:
                    urls.append(cleaned_u)

        primary_url = urls[0] if urls else None
        asset = extract_asset_from_url(primary_url)

        # 5. Method & Parameter
        method = normalize_http_method(data.get("method"))
        parameter = clean_string(data.get("param") or data.get("parameter"))

        # 6. Description & Solution
        description = clean_string(data.get("description"))
        solution = clean_string(data.get("solution"))

        # 7. Evidence
        evidence_parts: List[str] = []
        raw_evidence = clean_string(data.get("evidence"))
        raw_attack = clean_string(data.get("attack"))
        raw_other = clean_string(data.get("other"))

        if raw_evidence:
            evidence_parts.append(f"Evidence: {raw_evidence}")
        if raw_attack:
            evidence_parts.append(f"Attack: {raw_attack}")
        if raw_other:
            evidence_parts.append(f"Other: {raw_other}")

        evidence = " | ".join(evidence_parts) if evidence_parts else None

        # 8. CWE & CVE & CVSS & Category
        raw_cwe = data.get("cweid") or data.get("cwe")
        cwe = normalize_cwe(raw_cwe)
        cwe_list = normalize_cwe_list(raw_cwe)

        # Look for CVE if present in explicit fields, reference, or description
        cve = normalize_cve(data.get("cve"))
        if not cve:
            cve = normalize_cve(data.get("reference"))
        if not cve:
            cve = normalize_cve(description)

        cvss = normalize_cvss(data.get("cvss"))

        # 9. References & Tags
        references = normalize_string_list(data.get("reference"))
        tags: List[str] = []
        wasc_id = clean_string(data.get("wascid"))
        if wasc_id and wasc_id not in {"0", "-1"}:
            tags.append(f"wasc-{wasc_id}")

        if data.get("tags"):
            tags.extend(normalize_string_list(data.get("tags")))

        category = derive_category(cwe, title, tags, data.get("category"))

        # 10. Finding ID & Deduplication Fingerprint
        unique_key = plugin_id or title
        finding_id = generate_finding_id(scanner, unique_key, asset, primary_url, parameter)
        fingerprint = generate_dedup_fingerprint(cve, cwe, asset, method, parameter, title)

        return CanonicalFinding(
            finding_id=finding_id,
            scanner=scanner,
            title=title,
            severity=severity,
            confidence=confidence,
            urls=urls,
            url=primary_url,
            cve=cve,
            cvss=cvss,
            cwe=cwe,
            cwe_list=cwe_list,
            category=category,
            asset=asset,
            method=method,
            parameter=parameter,
            description=description,
            solution=solution,
            evidence=evidence,
            tags=tags,
            references=references,
            fingerprint=fingerprint,
            raw_finding=data
        )

    @classmethod
    def normalize_batch(cls, findings: List[Dict[str, Any]]) -> List[CanonicalFinding]:
        """Normalize a list of ZAP findings."""
        if not isinstance(findings, list):
            raise TypeError(f"Expected list of findings, got {type(findings).__name__}")
        return [cls.normalize(f) for f in findings if isinstance(f, dict)]
