"""
Validation helpers and rules for canonical findings.

Ensures schema integrity, valid enumerations, and proper formatting for CVEs, CWEs,
and URLs without corrupting or dropping optional scanner data.
"""

import re
from typing import Any, Dict, List, Optional, Union
from pydantic import ValidationError

from normalization.schema import CanonicalFinding, ConfidenceLevel, SeverityLevel

CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,}$")
CWE_REGEX = re.compile(r"^CWE-\d+$")


class FindingValidationError(Exception):
    """Raised when finding data violates canonical schema constraints."""
    def __init__(self, message: str, errors: Optional[List[str]] = None):
        super().__init__(message)
        self.errors = errors or [message]


def validate_severity(severity: Any) -> bool:
    """Check if severity is a recognized SeverityLevel value."""
    if isinstance(severity, SeverityLevel):
        return True
    if isinstance(severity, str):
        return severity.upper() in SeverityLevel.__members__
    return False


def validate_confidence(confidence: Any) -> bool:
    """Check if confidence is None or a recognized ConfidenceLevel value."""
    if confidence is None:
        return True
    if isinstance(confidence, ConfidenceLevel):
        return True
    if isinstance(confidence, str):
        return confidence.upper() in ConfidenceLevel.__members__
    return False


def validate_cve(cve: Optional[str]) -> bool:
    """Check if CVE is None or matches standard 'CVE-YYYY-NNNN+' format."""
    if cve is None:
        return True
    return bool(CVE_REGEX.match(cve))


def validate_cwe(cwe: Optional[str]) -> bool:
    """Check if CWE is None or matches standard 'CWE-N+' format."""
    if cwe is None:
        return True
    return bool(CWE_REGEX.match(cwe))


def validate_cvss(cvss: Optional[float]) -> bool:
    """Check if CVSS is None or within 0.0 to 10.0 range."""
    if cvss is None:
        return True
    return isinstance(cvss, (int, float)) and 0.0 <= cvss <= 10.0


def validate_finding(finding: Union[CanonicalFinding, Dict[str, Any]]) -> List[str]:
    """
    Validate a CanonicalFinding instance or finding dictionary.
    Returns a list of validation error descriptions (empty if valid).
    """
    errors: List[str] = []

    if isinstance(finding, dict):
        try:
            CanonicalFinding.model_validate(finding)
        except ValidationError as e:
            for err in e.errors():
                loc = ".".join(str(l) for l in err.get("loc", []))
                msg = err.get("msg", "Invalid field")
                errors.append(f"{loc}: {msg}")
            return errors
        finding_obj = CanonicalFinding.model_validate(finding)
    elif isinstance(finding, CanonicalFinding):
        finding_obj = finding
    else:
        return [f"Unsupported finding type: {type(finding).__name__}"]

    if not finding_obj.finding_id:
        errors.append("finding_id is required and cannot be empty")

    if not finding_obj.scanner:
        errors.append("scanner is required and cannot be empty")

    if not finding_obj.title:
        errors.append("title is required and cannot be empty")

    if not validate_severity(finding_obj.severity):
        errors.append(f"Invalid severity value: {finding_obj.severity}")

    if finding_obj.confidence and not validate_confidence(finding_obj.confidence):
        errors.append(f"Invalid confidence value: {finding_obj.confidence}")

    if finding_obj.cve and not validate_cve(finding_obj.cve):
        errors.append(f"Invalid CVE format: '{finding_obj.cve}'. Expected 'CVE-YYYY-NNNN+'")

    if finding_obj.cwe and not validate_cwe(finding_obj.cwe):
        errors.append(f"Invalid CWE format: '{finding_obj.cwe}'. Expected 'CWE-NNN'")

    for cwe_item in finding_obj.cwe_list:
        if not validate_cwe(cwe_item):
            errors.append(f"Invalid CWE list item format: '{cwe_item}'. Expected 'CWE-NNN'")

    if finding_obj.cvss is not None and not validate_cvss(finding_obj.cvss):
        errors.append(f"Invalid CVSS score: {finding_obj.cvss}. Must be between 0.0 and 10.0")

    return errors
