"""
Normalization utility functions.

Provides helper functions for string cleaning, severity/confidence normalization,
CVE/CWE standardization, category derivation, URL and asset extraction, and deterministic ID generation.
"""

import hashlib
import re
from typing import Any, List, Optional, Tuple, Union
from urllib.parse import urlsplit, urlunsplit

from normalization.schema import ConfidenceLevel, SeverityLevel

# Regex patterns
CVE_PATTERN = re.compile(r"\b(CVE-\d{4}-\d{4,})\b", re.IGNORECASE)
CWE_PATTERN = re.compile(r"(?:CWE[-_]?)?(\d+)", re.IGNORECASE)

SEVERITY_MAP = {
    "critical": SeverityLevel.CRITICAL,
    "crit": SeverityLevel.CRITICAL,
    "4": SeverityLevel.CRITICAL,
    "high": SeverityLevel.HIGH,
    "3": SeverityLevel.HIGH,
    "medium": SeverityLevel.MEDIUM,
    "med": SeverityLevel.MEDIUM,
    "moderate": SeverityLevel.MEDIUM,
    "warn": SeverityLevel.MEDIUM,
    "warning": SeverityLevel.MEDIUM,
    "2": SeverityLevel.MEDIUM,
    "low": SeverityLevel.LOW,
    "1": SeverityLevel.LOW,
    "info": SeverityLevel.INFO,
    "informational": SeverityLevel.INFO,
    "information": SeverityLevel.INFO,
    "note": SeverityLevel.INFO,
    "none": SeverityLevel.INFO,
    "debug": SeverityLevel.INFO,
    "0": SeverityLevel.INFO,
}

CONFIDENCE_MAP = {
    "confirmed": ConfidenceLevel.CONFIRMED,
    "certain": ConfidenceLevel.CONFIRMED,
    "user confirmed": ConfidenceLevel.CONFIRMED,
    "high": ConfidenceLevel.HIGH,
    "3": ConfidenceLevel.HIGH,
    "medium": ConfidenceLevel.MEDIUM,
    "2": ConfidenceLevel.MEDIUM,
    "low": ConfidenceLevel.LOW,
    "1": ConfidenceLevel.LOW,
    "tentative": ConfidenceLevel.LOW,
    "suspicious": ConfidenceLevel.LOW,
    "false positive": ConfidenceLevel.FALSE_POSITIVE,
    "false_positive": ConfidenceLevel.FALSE_POSITIVE,
    "fp": ConfidenceLevel.FALSE_POSITIVE,
    "0": ConfidenceLevel.FALSE_POSITIVE,
}

# CWE to Standard Category Mapping
CWE_CATEGORY_MAP = {
    "CWE-89": "Injection",
    "CWE-77": "Injection",
    "CWE-78": "Injection",
    "CWE-94": "Injection",
    "CWE-502": "Insecure Deserialization",
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-80": "Cross-Site Scripting (XSS)",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-22": "Broken Access Control",
    "CWE-23": "Broken Access Control",
    "CWE-284": "Broken Access Control",
    "CWE-285": "Broken Access Control",
    "CWE-287": "Identification and Authentication Failures",
    "CWE-384": "Identification and Authentication Failures",
    "CWE-613": "Identification and Authentication Failures",
    "CWE-16": "Security Misconfiguration",
    "CWE-693": "Security Misconfiguration",
    "CWE-1004": "Security Misconfiguration",
    "CWE-1021": "Security Misconfiguration",
    "CWE-200": "Information Disclosure",
    "CWE-209": "Information Disclosure",
    "CWE-548": "Information Disclosure",
    "CWE-310": "Cryptographic Failures",
    "CWE-327": "Cryptographic Failures",
    "CWE-328": "Cryptographic Failures",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-400": "Denial of Service",
    "CWE-434": "Unrestricted File Upload",
}


def clean_string(val: Any) -> Optional[str]:
    """
    Clean a string by stripping leading/trailing whitespace and converting empty/null placeholders to None.
    """
    if val is None:
        return None
    s = str(val).strip()
    if not s:
        return None
    if s.lower() in {"none", "null", "n/a", "undefined", "unknown"}:
        return None
    return s


def normalize_severity(val: Any) -> SeverityLevel:
    """
    Standardize severity strings/numbers to a SeverityLevel enum.

    Raises:
        ValueError: If severity value is unknown, invalid, or missing.
    """
    if val is None:
        raise ValueError("Severity cannot be None")

    if isinstance(val, SeverityLevel):
        return val

    key = str(val).strip().lower()
    if not key:
        raise ValueError("Severity cannot be empty")

    if key in SEVERITY_MAP:
        return SEVERITY_MAP[key]

    raise ValueError(f"Unknown or unsupported severity value: '{val}'")


def normalize_confidence(val: Any) -> Optional[ConfidenceLevel]:
    """
    Standardize confidence strings/numbers to a ConfidenceLevel enum.
    Returns None if missing or not recognized.
    """
    if val is None:
        return None

    if isinstance(val, ConfidenceLevel):
        return val

    key = str(val).strip().lower()
    if not key:
        return None

    return CONFIDENCE_MAP.get(key, None)


def normalize_cve(val: Any) -> Optional[str]:
    """
    Standardize and validate a CVE identifier (e.g. 'cve-2021-44228' -> 'CVE-2021-44228').
    Returns None if absent or not a valid CVE pattern.
    """
    if val is None:
        return None

    if isinstance(val, list):
        for item in val:
            norm = normalize_cve(item)
            if norm:
                return norm
        return None

    s = str(val).strip()
    match = CVE_PATTERN.search(s)
    if match:
        return match.group(1).upper()
    return None


def normalize_cwe(val: Any) -> Optional[str]:
    """
    Standardize and validate a CWE identifier (e.g. '89', 'cwe-89', 'CWE-89' -> 'CWE-89').
    Returns None if absent, zero, or invalid.
    """
    if val is None:
        return None

    if isinstance(val, list):
        for item in val:
            norm = normalize_cwe(item)
            if norm:
                return norm
        return None

    s = str(val).strip()
    if not s or s in {"0", "-1"}:
        return None

    match = CWE_PATTERN.search(s)
    if match:
        cwe_num = int(match.group(1))
        if cwe_num > 0:
            return f"CWE-{cwe_num}"
    return None


def normalize_cwe_list(val: Any) -> List[str]:
    """
    Extract and normalize a list of CWE identifiers.
    """
    if val is None:
        return []

    cwes: List[str] = []
    items: List[Any] = val if isinstance(val, (list, tuple, set)) else [val]

    for item in items:
        if isinstance(item, str) and ("," in item or ";" in item):
            parts = re.split(r"[,;]+", item)
            for part in parts:
                norm = normalize_cwe(part)
                if norm and norm not in cwes:
                    cwes.append(norm)
        else:
            norm = normalize_cwe(item)
            if norm and norm not in cwes:
                cwes.append(norm)

    return cwes


def normalize_cvss(val: Any) -> Optional[float]:
    """
    Extract and validate a numeric CVSS score between 0.0 and 10.0.
    """
    if val is None:
        return None
    try:
        score = float(val)
        if 0.0 <= score <= 10.0:
            return round(score, 1)
        return None
    except (ValueError, TypeError):
        return None


def derive_category(
    cwe: Optional[str] = None,
    title: Optional[str] = None,
    tags: Optional[List[str]] = None,
    explicit_category: Optional[str] = None
) -> Optional[str]:
    """
    Derive or standardize vulnerability category based on CWE, title, tags, or explicit value.
    """
    if explicit_category:
        cleaned = clean_string(explicit_category)
        if cleaned:
            return cleaned

    if cwe and cwe in CWE_CATEGORY_MAP:
        return CWE_CATEGORY_MAP[cwe]

    t_lower = (title or "").lower()

    if "sql" in t_lower or "command injection" in t_lower or "code execution" in t_lower or "rce" in t_lower:
        return "Injection"
    if "xss" in t_lower or "cross-site scripting" in t_lower or "cross site scripting" in t_lower:
        return "Cross-Site Scripting (XSS)"
    if "csrf" in t_lower or "cross-site request forgery" in t_lower:
        return "Cross-Site Request Forgery (CSRF)"
    if "ssrf" in t_lower or "server-side request forgery" in t_lower:
        return "Server-Side Request Forgery (SSRF)"
    if "header" in t_lower or "cookie" in t_lower or "misconfiguration" in t_lower or "csp" in t_lower or "cors" in t_lower:
        return "Security Misconfiguration"
    if "disclosure" in t_lower or "leak" in t_lower or "directory browsing" in t_lower or "information" in t_lower:
        return "Information Disclosure"
    if "auth" in t_lower or "login" in t_lower or "session" in t_lower or "password" in t_lower:
        return "Identification and Authentication Failures"
    if "traversal" in t_lower or "lfi" in t_lower or "rfi" in t_lower or "access control" in t_lower:
        return "Broken Access Control"
    if "deserialization" in t_lower:
        return "Insecure Deserialization"
    if "ssl" in t_lower or "tls" in t_lower or "crypto" in t_lower:
        return "Cryptographic Failures"

    if tags:
        for tag in tags:
            tag_lower = str(tag).lower()
            if "rce" in tag_lower or "sqli" in tag_lower:
                return "Injection"
            if "xss" in tag_lower:
                return "Cross-Site Scripting (XSS)"
            if "ssrf" in tag_lower:
                return "Server-Side Request Forgery (SSRF)"
            if "misconfig" in tag_lower or "config" in tag_lower:
                return "Security Misconfiguration"

    return "Vulnerability"


def extract_asset_from_url(url: Optional[str]) -> Optional[str]:
    """
    Extract the asset / hostname / netloc from a URL.
    Examples:
        'http://example.com:8080/path' -> 'example.com:8080'
        'https://app.local/login' -> 'app.local'
        '192.168.1.5' -> '192.168.1.5'
    """
    if not url:
        return None

    cleaned = str(url).strip()
    if not cleaned:
        return None

    if "://" not in cleaned:
        candidate = f"http://{cleaned}"
    else:
        candidate = cleaned

    try:
        parsed = urlsplit(candidate)
        if parsed.netloc:
            return parsed.netloc
        if parsed.path and "/" not in parsed.path:
            return parsed.path
    except Exception:
        pass

    match = re.search(r"^(?:https?://)?([^/:\s]+(?::\d+)?)", cleaned)
    if match:
        return match.group(1)

    return cleaned


def normalize_url(url: Optional[str]) -> Optional[str]:
    """
    Conservative URL normalization.
    Strips leading/trailing whitespace without altering scheme, port, path, or query params.
    """
    if not url:
        return None
    cleaned = str(url).strip()
    return cleaned if cleaned else None


def normalize_http_method(method: Optional[str]) -> Optional[str]:
    """
    Normalize HTTP method name to uppercase (e.g. 'get' -> 'GET').
    """
    if not method:
        return None
    cleaned = str(method).strip().upper()
    valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
    return cleaned if cleaned in valid_methods else None


def normalize_string_list(val: Any) -> List[str]:
    """
    Normalize string list or comma-separated strings into a clean list of strings.
    """
    if val is None:
        return []

    results: List[str] = []
    items: List[Any] = val if isinstance(val, (list, tuple, set)) else [val]

    for item in items:
        if item is None:
            continue
        if isinstance(item, str):
            for part in re.split(r"[\r\n,]+", item):
                cleaned = clean_string(part)
                if cleaned and cleaned not in results:
                    results.append(cleaned)
        else:
            cleaned = clean_string(item)
            if cleaned and cleaned not in results:
                results.append(cleaned)

    return results


def generate_finding_id(
    scanner: str,
    unique_key: str,
    asset: Optional[str] = None,
    url: Optional[str] = None,
    parameter: Optional[str] = None
) -> str:
    """
    Generate a stable, deterministic finding ID.
    Uses SHA-256 over key attributes to guarantee repeatable finding IDs.
    """
    components = [
        str(scanner or "").strip().lower(),
        str(unique_key or "").strip(),
        str(asset or "").strip().lower(),
        str(url or "").strip(),
        str(parameter or "").strip()
    ]
    raw_key = ":".join(components)
    digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:16]
    return f"find_{digest}"


def generate_dedup_fingerprint(
    cve: Optional[str] = None,
    cwe: Optional[str] = None,
    asset: Optional[str] = None,
    method: Optional[str] = None,
    parameter: Optional[str] = None,
    title: Optional[str] = None
) -> str:
    """
    Generate a deterministic fingerprint hash to assist downstream deduplication modules.
    """
    components = [
        str(cve or "").strip().upper(),
        str(cwe or "").strip().upper(),
        str(asset or "").strip().lower(),
        str(method or "").strip().upper(),
        str(parameter or "").strip().lower(),
        str(title or "").strip().lower()
    ]
    raw_key = "|".join(components)
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
