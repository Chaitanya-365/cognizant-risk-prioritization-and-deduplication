"""
Canonical Vulnerability Finding Schema.

Defines the common schema and enumerations for normalized vulnerability findings
produced by OWASP ZAP, Nuclei, OpenVAS, and future security scanners.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class SeverityLevel(str, Enum):
    """Standardized vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ConfidenceLevel(str, Enum):
    """Standardized finding confidence / certainty levels."""
    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class CanonicalFinding(BaseModel):
    """
    Canonical vulnerability finding model.

    Represents a unified, standardized security finding across multiple scanner tools.
    """
    finding_id: str = Field(
        ...,
        description="Stable deterministic unique identifier for the finding record."
    )
    scanner: str = Field(
        ...,
        description="Scanner source name in lowercase (e.g. 'zap', 'nuclei', 'openvas')."
    )
    title: str = Field(
        ...,
        description="Clean, human-readable vulnerability title / alert name."
    )
    severity: SeverityLevel = Field(
        ...,
        description="Standardized severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)."
    )
    confidence: Optional[ConfidenceLevel] = Field(
        default=None,
        description="Standardized confidence level, or None if scanner does not report confidence."
    )
    urls: List[str] = Field(
        default_factory=list,
        description="List of all affected endpoint URLs."
    )
    url: Optional[str] = Field(
        default=None,
        description="Primary affected endpoint URL with scheme, path, and query parameters."
    )
    cve: Optional[str] = Field(
        default=None,
        description="Standardized CVE identifier (e.g. 'CVE-2021-44228'), or None if not applicable."
    )
    cvss: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description="CVSS base score (0.0 to 10.0), or None if not provided."
    )
    cwe: Optional[str] = Field(
        default=None,
        description="Standardized primary CWE identifier (e.g. 'CWE-89'), or None if not applicable."
    )
    cwe_list: List[str] = Field(
        default_factory=list,
        description="List of all associated standardized CWE identifiers."
    )
    category: Optional[str] = Field(
        default=None,
        description="Vulnerability category / classification (e.g. 'Injection', 'Cross-Site Scripting')."
    )
    asset: Optional[str] = Field(
        default=None,
        description="Target asset hostname / IP / netloc (e.g. 'example.com:8080')."
    )
    method: Optional[str] = Field(
        default=None,
        description="HTTP method in uppercase ('GET', 'POST', etc.), or None."
    )
    parameter: Optional[str] = Field(
        default=None,
        description="Affected parameter name, header, or input field, or None."
    )
    description: Optional[str] = Field(
        default=None,
        description="Detailed description of the vulnerability."
    )
    solution: Optional[str] = Field(
        default=None,
        description="Remediation guidance / solution recommendation."
    )
    evidence: Optional[str] = Field(
        default=None,
        description="Scanner evidence, matched pattern, attack payload, or PoC string."
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 UTC timestamp when the finding was created or normalized."
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Classification tags (e.g. ['cve', 'rce', 'owasp-top-10'])."
    )
    references: List[str] = Field(
        default_factory=list,
        description="List of external advisory / documentation URLs."
    )
    fingerprint: Optional[str] = Field(
        default=None,
        description="Deterministic hash for downstream deduplication assistance."
    )
    raw_finding: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Preserved raw scanner output for auditability and traceability."
    )

    @field_validator("title")
    @classmethod
    def validate_title_non_empty(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("title cannot be empty or whitespace only")
        return cleaned

    @field_validator("scanner")
    @classmethod
    def validate_scanner_lowercase(cls, v: str) -> str:
        cleaned = v.strip().lower()
        if not cleaned:
            raise ValueError("scanner cannot be empty")
        return cleaned

    def to_dict(self) -> Dict[str, Any]:
        """Convert the canonical finding to a plain JSON-serializable dictionary."""
        return self.model_dump(mode="json")

    def to_json(self, indent: Optional[int] = None) -> str:
        """Convert the canonical finding to a JSON string."""
        return self.model_dump_json(indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CanonicalFinding":
        """Construct a CanonicalFinding from a dictionary."""
        return cls.model_validate(data)


class CanonicalScanResult(BaseModel):
    """
    Canonical scan result wrapper representing findings for a given target.
    """
    target: str = Field(..., description="Target URL, hostname, or IP address.")
    findings: List[CanonicalFinding] = Field(
        default_factory=list,
        description="List of canonical vulnerability findings."
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return self.model_dump(mode="json")
