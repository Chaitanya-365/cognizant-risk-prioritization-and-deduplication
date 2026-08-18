"""
Nuclei Finding Normalizer.

Transforms raw Nuclei JSONL results and simplified Nuclei dictionaries into CanonicalFinding objects.
"""

import re
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


class NucleiNormalizer:
    """Normalizer for ProjectDiscovery Nuclei vulnerability scanner findings."""

    @classmethod
    def normalize(cls, data: Dict[str, Any]) -> CanonicalFinding:
        """
        Convert a raw Nuclei finding dictionary or JSONL record into a CanonicalFinding.

        Args:
            data: Raw Nuclei finding dictionary.

        Returns:
            A validated CanonicalFinding instance.
        """
        if not isinstance(data, dict):
            raise TypeError(f"Expected dictionary for Nuclei finding, got {type(data).__name__}")

        info = data.get("info") if isinstance(data.get("info"), dict) else {}
        classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}

        # 1. Scanner & Title
        scanner = "nuclei"
        template_id = clean_string(
            data.get("template-id") or data.get("template_id") or data.get("templateID")
        )
        name = clean_string(info.get("name") or data.get("name") or template_id)
        title = name or (f"Nuclei Template {template_id}" if template_id else "Nuclei Finding")

        # 2. Severity
        raw_severity = info.get("severity") or data.get("severity") or "INFO"
        severity = normalize_severity(raw_severity)

        # 3. Confidence (Nuclei does not natively emit confidence levels)
        confidence = normalize_confidence(data.get("confidence"))

        # 4. URLs & Asset
        urls: List[str] = []
        raw_matched = data.get("matched-at") or data.get("matched_at") or data.get("url")
        raw_host = data.get("host")

        if raw_matched:
            cleaned_m = normalize_url(raw_matched)
            if cleaned_m and cleaned_m not in urls:
                urls.append(cleaned_m)

        if raw_host:
            cleaned_h = normalize_url(raw_host)
            if cleaned_h and cleaned_h not in urls:
                urls.append(cleaned_h)

        if data.get("urls") and isinstance(data["urls"], list):
            for u in data["urls"]:
                cleaned_u = normalize_url(u)
                if cleaned_u and cleaned_u not in urls:
                    urls.append(cleaned_u)

        primary_url = urls[0] if urls else None
        asset = extract_asset_from_url(raw_host or primary_url)

        # 5. Method & Parameter
        raw_method = data.get("method")
        curl_cmd = clean_string(data.get("curl-command"))
        if not raw_method and curl_cmd:
            method_match = re.search(r"-X\s+([A-Z]+)", curl_cmd, re.IGNORECASE)
            if method_match:
                raw_method = method_match.group(1)

        method = normalize_http_method(raw_method)
        parameter = clean_string(data.get("parameter") or data.get("param"))

        # 6. Description & Solution / Remediation
        description = clean_string(info.get("description") or data.get("description"))
        solution = clean_string(info.get("remediation") or info.get("solution") or data.get("solution"))

        # 7. Evidence
        evidence_parts: List[str] = []
        matcher_name = clean_string(data.get("matcher-name") or data.get("matcher_name"))
        extracted_results = data.get("extracted-results") or data.get("extracted_results")

        if matcher_name:
            evidence_parts.append(f"Matcher: {matcher_name}")

        if extracted_results:
            if isinstance(extracted_results, list):
                clean_extracted = [str(r).strip() for r in extracted_results if str(r).strip()]
                if clean_extracted:
                    evidence_parts.append(f"Extracted: {', '.join(clean_extracted)}")
            else:
                clean_res = clean_string(extracted_results)
                if clean_res:
                    evidence_parts.append(f"Extracted: {clean_res}")

        if curl_cmd:
            evidence_parts.append(f"Command: {curl_cmd}")

        evidence = " | ".join(evidence_parts) if evidence_parts else None

        # 8. CVE, CWE & CVSS & Category
        # Check classification first, then template-id / tags / references
        raw_cve = classification.get("cve-id") or classification.get("cve_id") or data.get("cve")
        cve = normalize_cve(raw_cve)
        if not cve and template_id:
            cve = normalize_cve(template_id)
        if not cve and info.get("tags"):
            cve = normalize_cve(info.get("tags"))
        if not cve and info.get("reference"):
            cve = normalize_cve(info.get("reference"))

        raw_cwe = classification.get("cwe-id") or classification.get("cwe_id") or data.get("cwe")
        cwe = normalize_cwe(raw_cwe)
        cwe_list = normalize_cwe_list(raw_cwe)

        raw_cvss = classification.get("cvss-score") or classification.get("cvss_score") or data.get("cvss")
        cvss = normalize_cvss(raw_cvss)

        # 9. References & Tags
        references = normalize_string_list(info.get("reference") or data.get("reference"))
        tags = normalize_string_list(info.get("tags") or data.get("tags"))

        category = derive_category(cwe, title, tags, data.get("category"))

        # 10. Finding ID & Deduplication Fingerprint
        unique_key = template_id or title
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
        """Normalize a list of Nuclei findings."""
        if not isinstance(findings, list):
            raise TypeError(f"Expected list of findings, got {type(findings).__name__}")
        return [cls.normalize(f) for f in findings if isinstance(f, dict)]
