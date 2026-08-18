"""
Normalization Layer for Multi-Scanner Vulnerability Findings.

This package provides canonical models, utilities, and normalizers for
OWASP ZAP, ProjectDiscovery Nuclei, and OpenVAS security scanners.
"""

from normalization.nuclei_normalizer import NucleiNormalizer
from normalization.openvas_normalizer import OpenVASNormalizer
from normalization.normalizer import (
    Normalizer,
    normalize_finding,
    normalize_findings,
    normalize_nuclei_finding,
    normalize_nuclei_findings,
    normalize_openvas_finding,
    normalize_openvas_findings,
    normalize_scan_result,
    normalize_zap_finding,
    normalize_zap_findings,
)
from normalization.schema import (
    CanonicalFinding,
    CanonicalScanResult,
    ConfidenceLevel,
    SeverityLevel,
)
from normalization.validators import (
    FindingValidationError,
    validate_confidence,
    validate_cve,
    validate_cvss,
    validate_cwe,
    validate_finding,
    validate_severity,
)
from normalization.zap_normalizer import ZAPNormalizer

__all__ = [
    "CanonicalFinding",
    "CanonicalScanResult",
    "SeverityLevel",
    "ConfidenceLevel",
    "Normalizer",
    "ZAPNormalizer",
    "NucleiNormalizer",
    "OpenVASNormalizer",
    "normalize_finding",
    "normalize_findings",
    "normalize_scan_result",
    "normalize_zap_finding",
    "normalize_zap_findings",
    "normalize_nuclei_finding",
    "normalize_nuclei_findings",
    "normalize_openvas_finding",
    "normalize_openvas_findings",
    "validate_finding",
    "validate_severity",
    "validate_confidence",
    "validate_cve",
    "validate_cwe",
    "validate_cvss",
    "FindingValidationError",
]
