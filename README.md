# VULNEX — Vulnerability Risk Management & SOC Prioritization Platform

> **Hackathon Activity 4: Risk Prioritization and Deduplication**  
> Ingests multi-scanner security telemetry, normalizes findings into a unified canonical schema, removes cross-scanner duplicates, enriches records with real-time threat intelligence (CISA KEV, FIRST EPSS, NVD CVSS), and computes explainable 7-factor risk scores with actionable P0–P3 remediation SLAs.

---

## Complete Pipeline Architecture

```text
       MULTIPLE SCANNERS (Kali Linux / Localhost)
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
     │   THREAT INTEL   │  <── CISA KEV + FIRST EPSS v3 + NVD CVSS enrichment
     └────────┬─────────┘
              │ (Enriched Findings)
              ▼
     ┌──────────────────┐
     │  PRIORITIZATION  │  <── Explainable 7-Factor Risk Scoring (0–100)
     └────────┬─────────┘
              │
              ▼
     ┌──────────────────┐
     │ VULNEX DASHBOARD │  <── React + Tailwind Enterprise SOC Dashboard & Jira Tickets
     └──────────────────┘
```

---

## Explainable 7-Factor Risk Scoring Engine

The prioritization engine answers the primary SOC question: **"What should the security team fix first?"**

```text
CVSS Base Severity           (0 – 25 pts)
+ EPSS Exploit Likelihood    (0 – 20 pts)
+ CISA KEV Status            (0 – 15 pts)
+ Exploit Availability       (0 – 10 pts)
+ Asset Criticality          (0 – 10 pts)
+ Internet Exposure          (0 – 10 pts)
+ Scanner Confidence & PoC   (0 – 10 pts)
        ↓
Risk Score 0–100 (Explainable Sum)
        ↓
P0 / P1 / P2 / P3 Action Tiers
```

### Multi-Dimensional Scoring Breakdown

| Dimension | Max Points | Evaluation Rules & Logic |
|---|:---:|---|
| **1. CVSS Base Severity** | **25 pts** | Scaled technical severity: `(cvss / 10.0) * 25` (or fallback: Critical=25, High=18, Medium=10, Low=4, Info=0) |
| **2. EPSS Exploit Likelihood** | **20 pts** | 30-day empirical exploitation probability from FIRST EPSS v3 & percentile rank |
| **3. CISA KEV Status** | **15 pts** | Flagged in CISA Known Exploited Vulnerabilities catalog (+ active ransomware use) |
| **4. Exploit Availability** | **10 pts** | Public weaponized exploit in Metasploit, Exploit-DB, or verified PoC |
| **5. Asset Criticality** | **10 pts** | Tier-1 Crown Jewel (Database / Auth / Payment) vs Production vs Staging vs Dev |
| **6. Internet Exposure** | **10 pts** | Directly internet-accessible / perimeter facing vs internal / behind firewall |
| **7. Scanner Confidence** | **10 pts** | Confirmed certainty rating + verified functional PoC / payload evidence |
| **Total Risk Score** | **100 pts** | Explainable sum clamped to `[0, 100]` |

---

### Priority Tier & Remediation SLA Matrix

| Priority Tier | Score Threshold | Criteria | Remediation SLA | Recommended Action |
|:---:|:---:|---|:---:|---|
| **`P0` (Emergency)** | **75 – 100** | Active CISA KEV + Internet Exposed, or Critical CVSS with Weaponized Exploit | **24 Hours** | Immediate emergency patch / isolate affected host |
| **`P1` (Critical)** | **50 – 74** | High CVSS, elevated EPSS, or confirmed RCE / SQLi on perimeter assets | **72 Hours** | Fast-track remediation in next maintenance cycle / WAF rule |
| **`P2` (High)** | **25 – 49** | Moderate severity misconfigurations, missing security headers, internal issues | **7 Days** | Standard sprint/backlog remediation |
| **`P3` (Medium)** | **0 – 24** | Informational disclosure, low impact findings, routine hardening | **30 Days** | Review configuration and documentation |

---

## Quickstart & Setup Guide for Kali Linux

Kali Linux is the recommended operating system for running live scans, as all required security tools (**Nuclei**, **OWASP ZAP**, **Python 3**) are natively supported.

### Step 1: Install System Dependencies & Tools on Kali Linux
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv nuclei zaproxy nodejs npm
nuclei -update-templates
```

### Step 2: Clone the Repository & Set Up Python Environment
```bash
git clone https://github.com/Chaitanya-365/cognizant-risk-prioritization-and-deduplication.git
cd cognizant-risk-prioritization-and-deduplication

# Create and activate Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python requirements
pip install -r requirements.txt
```

### Step 3: Run the Test Suite
Verify that all 111 unit, integration, and normalization tests pass:
```bash
pytest -v
```

### Step 4: Start the Target Application (OWASP Juice Shop)
Run Juice Shop locally on port `3000`:
```bash
# Option A: Run via Docker (Recommended on Kali)
sudo docker run --rm -p 3000:3000 bkimminich/juice-shop

# Option B: Run via npx
npx -y juice-shop
```
Juice Shop will now be available at `http://localhost:3000`.

### Step 5: Launch the VULNEX Backend & SOC Dashboard
```bash
python scanners/scanner_api.py
```
Open your browser on Kali Linux and navigate to:
👉 **`http://localhost:5000`**

---

### Step 6 (Optional): Running with Live OWASP ZAP Daemon
To enable active and passive OWASP ZAP scanning alongside Nuclei:

1. **Start ZAP in Headless/Daemon Mode** (in a separate terminal):
   ```bash
   zaproxy -daemon -port 8080 -config api.key=mysecretkey
   ```

2. **Export ZAP Environment Variables** in your app terminal:
   ```bash
   export ZAP_API_KEY="mysecretkey"
   export ZAP_HOST="127.0.0.1"
   export ZAP_PORT=8080
   
   python scanners/scanner_api.py
   ```

---

### Step 7 (Optional): Frontend Development Mode (Vite Dev Server)
If you want to edit and develop the React frontend with Live Hot Module Replacement (HMR):
```bash
cd frontend
npm install
npm run dev
```
Open **`http://localhost:3000`** in your browser. (API calls are automatically proxied to the Flask server at port `5000`).

To rebuild the production bundle:
```bash
cd frontend
npm run build
```
*(The Flask backend automatically serves the compiled React application from `frontend/dist`)*.

---

## Windows Quickstart Instructions

### 1. Set Up Python Environment
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Run Test Suite
```powershell
pytest
```

### 3. Start Backend & Dashboard
```powershell
python scanners/scanner_api.py
```
Navigate to **`http://localhost:5000`** in your browser.

---

## 8 Enterprise Dashboard Pages

| Page | Title & Route | Capabilities & Features |
| :--- | :--- | :--- |
| **Page 1** | **Dashboard** (`/`) | Executive overview, 6 KPI cards, Scanner Comparison Bar Chart, Severity Distribution Donut, Top Priority table |
| **Page 2** | **Scan Center** (`/scan-center`) | Target selector (`http://localhost:3000`), scanner chooser (Nuclei / ZAP / Both), live 6-stage pipeline progress tracker (`SCAN → NORMALIZE → DEDUPLICATE → ENRICH → PRIORITIZE → COMPLETE`), interactive terminal console |
| **Page 3** | **Findings Grid** (`/findings`) | Complete canonical vulnerability table with full-text search, multi-filters (Severity, Priority, Scanner, CISA KEV), sort by risk score, pagination |
| **Page 4** | **Finding Details** (`/finding-details`) | Technical deep-dive, 7-factor explainable score matrix with exact point contributions from the backend, "Why?" checklist, evidence string, Jira ticket generator |
| **Page 5** | **Deduplication** (`/deduplication`) | **56.7% noise reduction metrics**, visual multi-scanner merging architecture diagram (Nuclei + ZAP → Clustering → Canonical Finding), duplicate groups table |
| **Page 6** | **Priorities & SLAs** (`/priorities`) | **Answers "What should the team fix first?"** Ranked action plan categorized by Priority Tier (`P0 Emergency 24h`, `P1 Critical 72h`, `P2 High 7d`, `P3 Medium 30d`) with 1-click Jira ticket copying |
| **Page 7** | **Threat Intelligence** (`/threat-intel`) | CISA KEV catalog table, FIRST.org EPSS v3 probability scores & percentiles, Metasploit/Exploit-DB weaponization tags, NVD direct links |
| **Page 8** | **Reports & Exports** (`/reports`) | 1-Click **Export CSV**, **Export JSON**, and **Print / PDF Executive Briefing Summary** for leadership presentation |
| **Page 9** | **Settings** (`/settings`) | Scanner daemon parameters (`ZAP_HOST`, `ZAP_PORT`, `ZAP_API_KEY`), SLA thresholds, live/demo mode toggle |

---

## Repository Structure

```text
cognizant-risk-prioritization-and-deduplication/
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
├── deduplication/                  # Deduplication Engine
│   ├── __init__.py
│   └── engine.py                   # Multi-scanner duplicate merger & reduction metrics (56.7%)
│
├── threat_intel/                   # Threat Intelligence Enrichment
│   ├── __init__.py
│   └── enricher.py                 # CISA KEV, FIRST EPSS, NVD CVSS lookup
│
├── prioritization/                 # Explainable Risk Scoring & Ticket Generation
│   ├── __init__.py
│   └── scorer.py                   # 0-100 Explainable 7-Factor Risk Scorer & Jira Ticket generator
│
├── frontend/                       # Enterprise React + Vite + Tailwind CSS UI
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   ├── tailwind.config.js
│   ├── src/
│   │   ├── components/             # Reusable UI components (KPIs, Badges, Meters, Drawer)
│   │   ├── pages/                  # 8 Enterprise SOC Pages
│   │   └── services/api.js         # REST Client with Juice Shop demo fallback
│   └── dist/                       # Pre-compiled production React distribution
│
├── fixtures/                       # Real Juice Shop scanner fixtures
│   ├── juice_shop_nuclei_raw.json
│   └── juice_shop_zap_raw.json
│
├── scanners/                       # Scanner Integration Service & Client
│   ├── scanner_api.py              # Flask REST API + Dashboard server
│   └── scanner_client.py           # Interactive CLI client
│
├── tests/                          # Automated Test Suite (111 Tests, 100% Pass)
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
├── requirements.txt                # Python dependencies
└── README.md                       # Documentation & Setup Guide
```

---

## License & Acknowledgements
Built for the Cyber Security Hackathon — Activity 4: Risk Prioritization & Deduplication.
Integrates with open-source security intelligence feeds from [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [FIRST.org EPSS](https://www.first.org/epss/), [OWASP ZAP](https://www.zaproxy.org/), and [ProjectDiscovery Nuclei](https://nuclei.projectdiscovery.io/).
