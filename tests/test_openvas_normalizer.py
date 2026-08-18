"""
Unit tests for OpenVAS normalizer.
"""

from normalization.openvas_normalizer import OpenVASNormalizer
from normalization.schema import SeverityLevel


def test_normalize_openvas_finding():
    openvas_data = {
        "scanner": "openvas",
        "nvt": {
            "oid": "1.3.6.1.4.1.25623.1.0.100001",
            "name": "Apache Log4j Remote Code Execution Vulnerability",
            "cve": "CVE-2021-44228",
            "cwe": "502",
            "cvss_base": "10.0",
            "threat": "High",
            "summary": "Apache Log4j is prone to a remote code execution vulnerability.",
            "solution": "Update to version 2.15.0 or later.",
            "xref": "URL:https://logging.apache.org/log4j/2.x/security.html"
        },
        "host": "192.168.1.100",
        "port": "8080/tcp",
        "qod": "High",
        "report": "Detected vulnerable Log4j jar in classpath."
    }

    canonical = OpenVASNormalizer.normalize(openvas_data)

    assert canonical.scanner == "openvas"
    assert canonical.title == "Apache Log4j Remote Code Execution Vulnerability"
    assert canonical.severity == SeverityLevel.HIGH
    assert canonical.cve == "CVE-2021-44228"
    assert canonical.cvss == 10.0
    assert canonical.cwe == "CWE-502"
    assert canonical.asset == "192.168.1.100:8080/tcp"
    assert "192.168.1.100" in canonical.urls[0]
    assert canonical.solution == "Update to version 2.15.0 or later."
    assert canonical.category == "Insecure Deserialization"
    assert canonical.finding_id.startswith("find_")
