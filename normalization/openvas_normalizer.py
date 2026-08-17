"""
OpenVAS / Greenbone Vulnerability Scanner Normalizer.

Transforms OpenVAS / Greenbone report items and dictionaries into CanonicalFinding objects.
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
    normalize_severity,
    normalize_string_list,
    normalize_url,
)


class OpenVASNormalizer:
    """Normalizer for OpenVAS / Greenbone vulnerability scanner outputs."""

    @classmethod
    def normalize(cls, data: Dict[str, Any]) -> CanonicalFinding:
        """
        Convert an OpenVAS finding dictionary into a CanonicalFinding.

        Args:
            data: OpenVAS finding dictionary.

        Returns:
            A validated CanonicalFinding instance.
        """
        if not isinstance(data, dict):
            raise TypeError(f"Expected dictionary for OpenVAS finding, got {type(data).__name__}")

        nvt = data.get("nvt") if isinstance(data.get("nvt"), dict) else {}

        # 1. Scanner & Title
        scanner = "openvas"
        nvt_oid = clean_string(nvt.get("oid") or data.get("oid") or data.get("nvt_oid"))
        name = clean_string(nvt.get("name") or data.get("name") or data.get("title"))
        title = name or (f"OpenVAS NVT {nvt_oid}" if nvt_oid else "OpenVAS Vulnerability")

        # 2. Severity & CVSS
        cvss_score = normalize_cvss(
            nvt.get("cvss_base") or data.get("cvss_base") or data.get("cvss") or data.get("severity_score")
        )
        raw_severity = data.get("threat") or data.get("severity") or nvt.get("threat")
        if not raw_severity and cvss_score is not None:
            if cvss_score >= 9.0:
                raw_severity = "CRITICAL"
            elif cvss_score >= 7.0:
                raw_severity = "HIGH"
            elif cvss_score >= 4.0:
                raw_severity = "MEDIUM"
            elif cvss_score > 0.0:
                raw_severity = "LOW"
            else:
                raw_severity = "INFO"

        severity = normalize_severity(raw_severity or "INFO")

        # 3. Confidence / QOD (Quality of Detection)
        qod = data.get("qod") or data.get("confidence")
        confidence = normalize_confidence(qod)

        # 4. URLs & Asset
        host = clean_string(data.get("host") or data.get("target") or data.get("ip"))
        port = clean_string(data.get("port"))
        asset = f"{host}:{port}" if host and port and port not in {"general/tcp", "0"} else host

        urls: List[str] = []
        raw_url = data.get("url")
        if raw_url:
            cleaned_u = normalize_url(raw_url)
            if cleaned_u:
                urls.append(cleaned_u)
        elif asset:
            if "://" not in asset:
                candidate = f"http://{asset}"
            else:
                candidate = asset
            urls.append(candidate)

        primary_url = urls[0] if urls else None

        # 5. Method & Parameter
        method = None
        parameter = clean_string(data.get("parameter") or data.get("param"))

        # 6. Description & Solution
        description = clean_string(
            nvt.get("summary") or nvt.get("description") or data.get("description")
        )
        solution = clean_string(
            nvt.get("solution") or data.get("solution") or data.get("remediation")
        )

        # 7. Evidence
        evidence = clean_string(data.get("report") or data.get("result") or data.get("evidence"))

        # 8. CVE, CWE & CVSS & Category
        raw_cve = nvt.get("cve") or data.get("cve")
        cve = normalize_cve(raw_cve)

        raw_cwe = nvt.get("cwe") or data.get("cwe")
        cwe = normalize_cwe(raw_cwe)
        cwe_list = normalize_cwe_list(raw_cwe)

        # 9. References & Tags
        references = normalize_string_list(nvt.get("xref") or nvt.get("references") or data.get("reference"))
        tags = normalize_string_list(nvt.get("tags") or data.get("tags"))
        if nvt.get("category"):
            tags.append(str(nvt["category"]))

        category = derive_category(cwe, title, tags, data.get("category") or nvt.get("category"))

        # 10. Finding ID & Deduplication Fingerprint
        unique_key = nvt_oid or title
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
            cvss=cvss_score,
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
        """Normalize a list of OpenVAS findings."""
        if not isinstance(findings, list):
            raise TypeError(f"Expected list of findings, got {type(findings).__name__}")
        return [cls.normalize(f) for f in findings if isinstance(f, dict)]
