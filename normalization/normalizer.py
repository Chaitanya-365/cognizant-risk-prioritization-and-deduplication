"""
Unified Normalizer Dispatcher.

Provides auto-detection and batch normalization entrypoints for vulnerability findings.
"""

from typing import Any, Dict, List, Optional
from normalization.nuclei_normalizer import NucleiNormalizer
from normalization.openvas_normalizer import OpenVASNormalizer
from normalization.schema import CanonicalFinding, CanonicalScanResult
from normalization.zap_normalizer import ZAPNormalizer


class Normalizer:
    """Unified coordinator for scanner normalization."""

    @classmethod
    def detect_scanner(cls, finding: Dict[str, Any]) -> str:
        """
        Detect scanner type from finding structure and metadata.

        Returns:
            'zap', 'nuclei', or 'openvas'

        Raises:
            ValueError: If scanner type cannot be unambiguously determined.
        """
        if not isinstance(finding, dict):
            raise TypeError(f"Expected dictionary, got {type(finding).__name__}")

        scanner_field = str(finding.get("scanner") or "").strip().lower()
        if scanner_field in {"zap", "owasp_zap", "owasp-zap", "owasp zap"}:
            return "zap"
        if scanner_field in {"nuclei", "projectdiscovery"}:
            return "nuclei"
        if scanner_field in {"openvas", "gvm", "greenbone"}:
            return "openvas"

        # Check OpenVAS unique signatures
        if "nvt" in finding or "nvt_oid" in finding or "qod" in finding:
            return "openvas"

        # Check ZAP unique signatures
        zap_keys = {"pluginId", "alert_id", "alert", "cweid", "wascid", "affected_urls"}
        if any(k in finding for k in zap_keys):
            return "zap"

        # Check Nuclei unique signatures
        nuclei_keys = {"template-id", "template_id", "templateID", "matcher-name", "extracted-results", "curl-command"}
        if any(k in finding for k in nuclei_keys):
            return "nuclei"

        # Check nested info dictionary (Nuclei)
        if isinstance(finding.get("info"), dict) and "name" in finding["info"]:
            return "nuclei"

        raise ValueError(
            f"Unable to auto-detect scanner type for finding keys: {list(finding.keys())}"
        )

    @classmethod
    def normalize(cls, finding: Dict[str, Any], scanner: Optional[str] = None) -> CanonicalFinding:
        """
        Normalize a single raw or structured finding into a CanonicalFinding.

        Args:
            finding: Finding dictionary from a security scanner.
            scanner: Optional scanner identifier ('zap', 'nuclei', 'openvas'). Auto-detected if None.

        Returns:
            A standardized CanonicalFinding instance.
        """
        if not isinstance(finding, dict):
            raise TypeError(f"Expected dictionary, got {type(finding).__name__}")

        scanner_name = (scanner.strip().lower() if scanner else None) or cls.detect_scanner(finding)

        if scanner_name == "zap":
            return ZAPNormalizer.normalize(finding)
        elif scanner_name == "nuclei":
            return NucleiNormalizer.normalize(finding)
        elif scanner_name == "openvas":
            return OpenVASNormalizer.normalize(finding)
        else:
            raise ValueError(f"Unsupported scanner type: '{scanner_name}'")

    @classmethod
    def normalize_findings(
        cls, findings: List[Dict[str, Any]], scanner: Optional[str] = None
    ) -> List[CanonicalFinding]:
        """
        Normalize a list of findings into canonical findings.

        Args:
            findings: List of finding dictionaries.
            scanner: Optional scanner identifier ('zap', 'nuclei', 'openvas'). Auto-detected per finding if None.

        Returns:
            List of standardized CanonicalFinding instances.
        """
        if not isinstance(findings, list):
            raise TypeError(f"Expected list of findings, got {type(findings).__name__}")

        normalized_list: List[CanonicalFinding] = []
        for item in findings:
            if isinstance(item, dict):
                normalized_list.append(cls.normalize(item, scanner=scanner))

        return normalized_list

    @classmethod
    def normalize_scan_result(
        cls, target: str, findings: List[Dict[str, Any]], scanner: Optional[str] = None
    ) -> CanonicalScanResult:
        """
        Normalize a list of findings for a target into a CanonicalScanResult.
        """
        canonical_list = cls.normalize_findings(findings, scanner=scanner)
        return CanonicalScanResult(target=target, findings=canonical_list)


# ============================================================
# Functional Convenience API
# ============================================================

def normalize_finding(finding: Dict[str, Any], scanner: Optional[str] = None) -> CanonicalFinding:
    """Normalize a single finding dictionary into a CanonicalFinding."""
    return Normalizer.normalize(finding, scanner=scanner)


def normalize_findings(
    findings: List[Dict[str, Any]], scanner: Optional[str] = None
) -> List[CanonicalFinding]:
    """Normalize a list of finding dictionaries into CanonicalFinding instances."""
    return Normalizer.normalize_findings(findings, scanner=scanner)


def normalize_scan_result(
    target: str, findings: List[Dict[str, Any]], scanner: Optional[str] = None
) -> CanonicalScanResult:
    """Normalize findings for a target into a CanonicalScanResult."""
    return Normalizer.normalize_scan_result(target, findings, scanner=scanner)


def normalize_zap_finding(finding: Dict[str, Any]) -> CanonicalFinding:
    """Normalize a single OWASP ZAP finding dictionary."""
    return ZAPNormalizer.normalize(finding)


def normalize_zap_findings(findings: List[Dict[str, Any]]) -> List[CanonicalFinding]:
    """Normalize a list of OWASP ZAP finding dictionaries."""
    return ZAPNormalizer.normalize_batch(findings)


def normalize_nuclei_finding(finding: Dict[str, Any]) -> CanonicalFinding:
    """Normalize a single Nuclei finding dictionary."""
    return NucleiNormalizer.normalize(finding)


def normalize_nuclei_findings(findings: List[Dict[str, Any]]) -> List[CanonicalFinding]:
    """Normalize a list of Nuclei finding dictionaries."""
    return NucleiNormalizer.normalize_batch(findings)


def normalize_openvas_finding(finding: Dict[str, Any]) -> CanonicalFinding:
    """Normalize a single OpenVAS finding dictionary."""
    return OpenVASNormalizer.normalize(finding)


def normalize_openvas_findings(findings: List[Dict[str, Any]]) -> List[CanonicalFinding]:
    """Normalize a list of OpenVAS finding dictionaries."""
    return OpenVASNormalizer.normalize_batch(findings)
