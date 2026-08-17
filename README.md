# Aegis SOC - Vulnerability Management & Risk Prioritization

## Overview

This repository implements the end-to-end vulnerability management pipeline for **Activity 4: Risk Prioritization and Deduplication**.

The system ingests raw outputs from multiple scanners (**OWASP ZAP**, **ProjectDiscovery Nuclei**, **OpenVAS**), normalizes findings into a unified canonical schema, removes duplicates across scanners and endpoints, enriches records with public threat intelligence (**CISA KEV**, **FIRST EPSS**, **NVD CVSS**), calculates explainable risk scores (0-100), and presents a professional **SOC Vulnerability Management Web Dashboard** with ticket-ready remediation tasks.

---

## Complete Pipeline Architecture

```text
       MULTIPLE SCANNERS (Kali Linux)
              │
       ┌──────┼──────┐
       ↓      ↓      ↓
     Nuclei  ZAP   OpenVAS
       │      │      │
       └──────┬──────┘
              │ (Raw JSONL, API Alerts, NVT Reports)
              ▼
     ┌──────────────────┐
     │  NORMALIZATION   │  <── Pydantic v2 CanonicalFinding Schema
     └────────┬─────────┘
              │ (Standardized Findings)
              ▼
     ┌──────────────────┐
     │  DEDUPLICATION   │  <── Multi-level cross-scanner duplicate clustering
     └────────┬─────────┘
              │ (56.7% Noise Reduction)
              ▼
     ┌──────────────────┐
     │   THREAT INTEL   │  <── CISA KEV + FIRST EPSS + NVD CVSS enrichment
     └────────┬─────────┘
              │ (Enriched Findings)
              ▼
     ┌──────────────────┐
     │  PRIORITIZATION  │  <── Explainable Multi-Factor Risk Scoring (0-100)
     └────────┬─────────┘
              │
              ▼
     ┌──────────────────┐
     │  SOC DASHBOARD   │  <── Interactive Cyber Web UI + Ticket Generator
     └──────────────────┘
```

---

## Canonical Vulnerability Finding Schema

Each finding is validated via Pydantic v2 against `CanonicalFinding`:

```python
class CanonicalFinding(BaseModel):
    finding_id: str                      # Deterministic unique ID (e.g. "find_4a89fb34d19e02c5")
    scanner: str                         # "zap", "nuclei", "openvas" (or merged "nuclei, zap")
    title: str                           # Non-empty vulnerability title
    severity: SeverityLevel              # CRITICAL | HIGH | MEDIUM | LOW | INFO
    confidence: Optional[ConfidenceLevel] = None  # CONFIRMED | HIGH | MEDIUM | LOW | FALSE_POSITIVE
    urls: List[str] = []                 # All affected endpoint URLs
    url: Optional[str] = None            # Primary URL
    cve: Optional[str] = None            # Normalized "CVE-YYYY-NNNN+" or None
    cvss: Optional[float] = None         # Float score (0.0 - 10.0) or None
    cwe: Optional[str] = None            # Normalized "CWE-NNN" or None
    cwe_list: List[str] = []             # Associated CWE identifiers
    category: Optional[str] = None       # "Injection", "Cross-Site Scripting (XSS)", "Security Misconfiguration", etc.
    asset: Optional[str] = None          # Target hostname / port (e.g., "localhost:3000")
    method: Optional[str] = None         # Uppercase HTTP method (GET, POST, etc.)
    parameter: Optional[str] = None      # Affected parameter / field name
    description: Optional[str] = None    # Vulnerability description
    solution: Optional[str] = None       # Remediation guidance
    evidence: Optional[str] = None       # Scanner evidence / PoC string
    timestamp: str                       # ISO-8601 UTC timestamp
    tags: List[str] = []                 # Classification tags
    references: List[str] = []           # Advisory / documentation links
    fingerprint: Optional[str] = None    # Deduplication hash helper
```

---

## Explainable Risk Scoring Engine

Unlike naive CVSS ranking, the Risk Prioritization Engine evaluates:

| Scoring Factor | Weight | Description |
|---|---|---|
| **CVSS Base Severity** | Up to 30 pts | Base technical severity from NVD / Scanner |
| **EPSS Exploitation Likelihood** | Up to 25 pts | 30-day exploitation probability from FIRST EPSS |
| **CISA KEV Weaponization** | +20 pts | Confirmed active exploitation in the wild |
| **Asset Exposure & Criticality** | Up to 15 pts | Internet exposure and asset business tier |
| **Confidence & PoC Proof** | Up to 10 pts | Verified functional payload / direct confirmation |

### Ticket-Ready Action Output Example:
```text
--------------------------------------------------
SECURITY TICKET
--------------------------------------------------
Title: Fix CVE-2021-44228 on localhost:3000
Severity: CRITICAL
Risk Score: 97/100

Why:
- Actively weaponized in the wild (Listed in CISA KEV catalog)
- Documented use in ransomware campaigns
- Critical CVSS v3 score (10.0/10.0)
- High exploitation probability (EPSS = 98%)
- Target endpoint is internet-accessible

Recommended Action:
Apply vendor security patch immediately for Apache Log4j RCE (Log4Shell). Isolate affected endpoint if unpatched. Fix: Upgrade Log4j dependency to 2.17.1 or higher.

SLA:
24 Hours (Urgent)
--------------------------------------------------
```

---

## Project Structure

```text
scanner-vulnerability-management/
│
├── normalization/                  # Normalization Layer Package
│   ├── __init__.py                 # Clean public exports
│   ├── schema.py                   # Pydantic CanonicalFinding & CanonicalScanResult
│   ├── normalizer.py               # Unified Normalizer coordinator
│   ├── zap_normalizer.py           # OWASP ZAP alert normalizer
│   ├── nuclei_normalizer.py        # Nuclei JSONL normalizer
│   ├── openvas_normalizer.py       # OpenVAS report normalizer
│   ├── validators.py               # Schema format validators
│   └── utils.py                    # Severity, CVE, CWE, Category, URL utils
│
├── deduplication/                  # Deduplication Layer
│   ├── __init__.py
│   └── engine.py                   # Multi-scanner duplicate merger & reduction metrics
│
├── threat_intel/                   # Threat Intelligence Enrichment
│   ├── __init__.py
│   └── enricher.py                 # CISA KEV, FIRST EPSS, NVD CVSS lookup
│
├── prioritization/                 # Explainable Risk Scoring & Ticket Generation
│   ├── __init__.py
│   └── scorer.py                   # 0-100 Explainable Risk Scorer & Jira Ticket generator
│
├── dashboard/                      # Professional SOC Web Dashboard
│   ├── index.html                  # Cyber SOC visual interface
│   ├── styles.css                  # Dark-mode glassmorphic styling
│   └── app.js                      # Client state, live scan simulator, ticket drawer
│
├── fixtures/                       # Real Juice Shop scanner fixtures
│   ├── juice_shop_nuclei_raw.json
│   └── juice_shop_zap_raw.json
│
├── scanners/                       # Scanner Integration Service & Client
│   ├── scanner_api.py              # Flask REST API + Dashboard server
│   └── scanner_client.py           # Windows interactive CLI client
│
├── tests/                          # Automated Test Suite (108 Tests, 100% Pass)
│   ├── test_schema.py
│   ├── test_utils.py
│   ├── test_validators.py
│   ├── test_zap_normalizer.py
│   ├── test_nuclei_normalizer.py
│   ├── test_openvas_normalizer.py
│   ├── test_deduplication.py
│   ├── test_prioritization.py
│   ├── test_integration.py
│   └── test_api_integration.py
│
├── demo_juice_shop.py              # Standalone demonstration CLI script
└── README.md
```

---

## Quickstart Instructions

### 1. Run Automated Test Suite

```powershell
python -m pytest -v
```
Expected output: `108 passed in ~0.8s`.

### 2. Launch Local OWASP Juice Shop Target

```powershell
npx -y juice-shop
```
Juice Shop runs locally on `http://localhost:3000`.

### 3. Launch Scanner API & SOC Dashboard

```powershell
python scanners/scanner_api.py
```
Open your browser and navigate to:
👉 **`http://localhost:5000`**

- View executive KPI cards and deduplication reduction statistics.
- Launch live scans against `http://localhost:3000`.
- Filter findings by Severity, Scanner, or Category.
- Click **"View Ticket →"** to inspect explainable risk scoring breakdowns and copy Jira/ServiceNow tickets.

### 4. Run CLI Demonstration Script

```powershell
python demo_juice_shop.py
```
Ingests raw Juice Shop scanner findings and prints the complete canonical output and summary statistics.
