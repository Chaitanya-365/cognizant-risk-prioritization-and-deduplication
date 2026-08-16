# Scanner Vulnerability Management

A modular vulnerability-management system being developed for the Cognizant placement project.

The goal of this project is to integrate multiple security scanners, automatically collect their findings, normalize the results into a common format, remove duplicate findings, store them, and present them through a centralized dashboard.

---

# Project Architecture

```text
                    Security Scanners
                    /               \
                   /                 \
                OWASP ZAP          Nuclei
                   |                  |
                   |                  |
                   v                  v
              Scanner Findings
                    \                /
                     \              /
                      v            v
                    Normalization
                         |
                         v
                    Deduplication
                         |
                         v
                      Database
                         |
                         v
                    Backend API
                         |
                         v
                     Dashboard
```

---

# Current Development Status

## OWASP ZAP Integration

**Status: Completed PoC**

The OWASP ZAP integration has been successfully implemented and tested using OWASP Juice Shop as the authorized local target.

Current pipeline:

```text
Windows Python Client
        |
        v
      ZAP API
        |
        v
      Spider
        |
        v
    Active Scan
        |
        v
    ZAP Alerts
        |
        v
 Python Alert Retrieval
```

The current implementation automatically:

1. Connects to ZAP running in Kali Linux.
2. Verifies the ZAP API connection.
3. Starts the Spider.
4. Monitors Spider progress.
5. Uses controlled Spider limits.
6. Starts the Active Scanner.
7. Monitors Active Scan progress.
8. Retrieves vulnerability alerts through the ZAP API.
9. Prints the retrieved security findings.

The ZAP integration has successfully retrieved real findings from the local Juice Shop test environment.

The ZAP Python client uses environment variables for the ZAP host, port, target URL, and API key instead of hard-coded environment-specific values.

---

# Development Environment

## Windows

Windows is used for:

* Python development
* Scanner automation
* Backend development
* Frontend development
* Git/GitHub

Requirements:

* Python 3.13+
* Git
* VS Code

## Kali Linux

Kali Linux is used for:

* OWASP ZAP
* OWASP Juice Shop
* Nuclei
* Docker

Current lab architecture:

```text
Windows
   |
   | HTTP + ZAP API + SSH
   |
   v
Kali Linux
<KALI_VM_IP>
   |
   +---- ZAP :8080
   |
   +---- Juice Shop :3000
   |
   +---- Nuclei
```

The Windows Python scanner connects to Kali using the Kali VM IP.

For the local development environment, the Juice Shop target is reachable from Windows as:

```text
http://192.168.56.101:3000
```

Inside Kali Linux, the same Juice Shop instance is available at:

```text
http://localhost:3000
```

---

# OWASP Juice Shop

OWASP Juice Shop is used as the intentionally vulnerable local test application.

It runs inside Kali Linux using Docker.

Start Juice Shop:

```bash
sudo docker run --rm -p 3000:3000 bkimminich/juice-shop
```

The application is then available inside Kali at:

```text
http://localhost:3000
```

From the Windows machine, the target is:

```text
http://192.168.56.101:3000
```

This project should only be used against systems that are owned by the team or where explicit authorization has been provided to test them.

---

# OWASP ZAP Setup

ZAP runs inside Kali Linux as a daemon.

For the current Windows ↔ Kali VM development setup, ZAP must be reachable from the Windows host.

Start ZAP in Kali:

```bash
zaproxy -daemon -host 0.0.0.0 -port 8080 \
-config api.disablekey=false \
-config api.addrs.addr.name=.* \
-config api.addrs.addr.regex=true
```

ZAP should listen on:

```text
0.0.0.0:8080
```
## Security Note

The ZAP API is exposed on the Kali VM network interface so that the Windows scanner client can communicate with it.

This configuration is intended only for the isolated development/lab environment.

Do not:

- Port-forward ZAP port `8080` to the public Internet.
- Expose the ZAP API to untrusted networks.
- Share the ZAP API key.
- Hard-code the ZAP API key in source code.

The ZAP API key should be supplied through the `ZAP_API_KEY` environment variable.

For environments where the scanner and ZAP run on the same machine, prefer binding ZAP to localhost instead of exposing it on all interfaces.

The Windows machine connects to the ZAP API through the Kali VM IP:

```text
<KALI_VM_IP>
```

---

# Verify ZAP API

From Kali:

```bash
curl "http://127.0.0.1:8080/JSON/core/view/version/?apikey=YOUR_ZAP_API_KEY"
```

Expected response:

```json
{
    "version": "2.17.0"
}
```

From Windows PowerShell:

```powershell
curl.exe "http://<KALI_VM_IP>:8080/JSON/core/view/version/?apikey=YOUR_ZAP_API_KEY"

Expected:

```json
{
    "version": "2.17.0"
}
```

Do not commit or share the actual API key.

---

# ZAP API Key

The ZAP API key must not be hard-coded into the Python source code.

Set the API key as an environment variable in Windows PowerShell:

```powershell
$env:ZAP_API_KEY="YOUR_ZAP_API_KEY"
```

Verify:

```powershell
if ($env:ZAP_API_KEY) { "ZAP API key is set" } else { "ZAP API key is missing" }
```

Expected:

```text
ZAP API key is set
```

The Python application reads the key using:

```python
os.getenv("ZAP_API_KEY")
```

Never commit the actual API key to GitHub.

---

# Nuclei Setup

Nuclei is installed and configured in Kali Linux.

Verify the installation:

```bash
nuclei -version
```

Expected:

```text
[INF] Nuclei Engine Version: v3.11.0
```

Update Nuclei templates:

```bash
nuclei -update-templates
```

Nuclei templates are maintained separately from the Nuclei engine.

The current integration invokes Nuclei from the Windows Python application through SSH.

---

# Nuclei Python Integration

The Nuclei scanner is integrated through:

```text
scanners/
└── nuclei/
    └── nuclei_client.py
```

The Windows Python client connects to Kali through SSH and executes Nuclei on the Kali machine.

Current workflow:

```text
Windows Python Client
        |
        | SSH
        v
Kali Linux
        |
        v
     Nuclei
        |
        v
   JSONL Output
        |
        v
Windows Python Client
        |
        v
 Parse JSON Findings
```

The Nuclei client uses environment variables for environment-specific configuration:

```text
KALI_HOST
KALI_USER
TARGET_URL
```

Example:

```powershell
$env:KALI_HOST="192.168.56.101"
$env:KALI_USER="darshan"
$env:TARGET_URL="http://192.168.56.101:3000"
```

The values can be verified using:

```powershell
echo $env:KALI_HOST
echo $env:KALI_USER
echo $env:TARGET_URL
```

The Nuclei client invokes Nuclei remotely using:

```text
ssh <KALI_USER>@<KALI_HOST>
```

and requests machine-readable JSONL output.

Current Nuclei command:

```text
nuclei -u <TARGET_URL> -tags tech -jsonl
```

The current implementation performs a technology-focused Nuclei scan using the `tech` tag.

The Python client captures the JSONL output and parses each JSON finding.

---

# Nuclei SSH Configuration

The Windows machine uses SSH to execute Nuclei on Kali Linux.

Verify SSH connectivity:

```powershell
ssh darshan@192.168.56.101 "nuclei -version"
```

SSH key-based authentication is configured so that the Python scanner can execute the command without requiring an interactive password.

The private SSH key is stored locally on the Windows machine and must not be committed to GitHub.

The project should not contain private SSH keys or credentials.

---

# Running the Nuclei Scanner

Before running the Python Nuclei scanner, make sure:

1. Kali Linux is running.
2. Nuclei is installed in Kali.
3. Nuclei templates are available.
4. Juice Shop is running in Kali.
5. Windows can communicate with Kali.
6. SSH access from Windows to Kali is working.
7. SSH key-based authentication is configured.
8. `KALI_HOST` is set.
9. `KALI_USER` is set.
10. `TARGET_URL` is set.

Set the required environment variables in PowerShell:

```powershell
$env:KALI_HOST="192.168.56.101"
$env:KALI_USER="darshan"
$env:TARGET_URL="http://192.168.56.101:3000"
```

Test Nuclei through SSH:

```powershell
ssh darshan@192.168.56.101 "nuclei -version"
```

Run the Python client:

```powershell
python scanners/nuclei/nuclei_client.py
```

Expected workflow:

```text
Starting Nuclei scan...
Target: http://192.168.56.101:3000

Nuclei scan completed.
Total findings: ...
```

The scanner parses the JSONL output and displays the findings.

---

# Nuclei Findings

Nuclei returns machine-readable JSONL findings.

The Python client currently extracts information including:

```text
Template ID
Name
Severity
Matched At
```

Example technology findings from the local Juice Shop environment may include:

```text
Template ID:
fingerprinthub-web-fingerprints

Name:
FingerprintHub Technology Fingerprint

Severity:
info

Matched At:
http://192.168.56.101:3000
```

Other technology detection templates may also identify the application and its technologies.

The raw Nuclei findings will later be converted into the project's common vulnerability schema by the normalization layer.

---

# Python Environment

Go to the project root:

```powershell
cd scanner-vulnerability-management
```

Create the virtual environment:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

The terminal should show:

```text
(.venv)
```

Verify Python:

```powershell
python --version
```

Install the ZAP Python client:

```powershell
python -m pip install --upgrade pip
pip install python-owasp-zap-v2.4
```

The Nuclei Python client currently uses Python standard-library modules such as:

```python
json
os
subprocess
```

No additional Python Nuclei SDK is required because Nuclei is executed as a command-line tool on Kali through SSH.

---

# Project Structure

Current structure:

```text
scanner-vulnerability-management/
│
├── scanners/
│   ├── zap/
│   │   └── zap_client.py
│   │
│   └── nuclei/
│       └── nuclei_client.py
│
├── .gitignore
├── README.md
│
└── .venv/                  # Local only - not committed
```

Planned project structure:

```text
scanner-vulnerability-management/
│
├── scanners/
│   │
│   ├── zap/
│   │   └── zap_client.py
│   │
│   └── nuclei/
│       └── nuclei_client.py
│
├── normalizer/
│   └── normalizer.py
│
├── deduplication/
│   └── deduplicator.py
│
├── database/
│   └── ...
│
├── backend/
│   └── ...
│
├── frontend/
│   └── ...
│
├── .gitignore
├── README.md
└── requirements.txt
```

The planned folders will be added as the corresponding modules are developed.

---

# Running the ZAP Scanner

Before running the Python scanner, make sure:

1. Juice Shop is running in Kali.
2. ZAP is running in daemon mode.
3. ZAP is listening on port `8080`.
4. Windows can communicate with Kali.
5. The `ZAP_API_KEY` environment variable is set.
6. The Python virtual environment is activated.
7. `ZAP_HOST`, `ZAP_PORT`, and `TARGET_URL` are configured.

Example:

```powershell
$env:ZAP_HOST="192.168.56.101"
$env:ZAP_PORT="8080"
$env:TARGET_URL="http://192.168.56.101:3000"
$env:ZAP_API_KEY="YOUR_ZAP_API_KEY"
```

From the project root:

```powershell
python scanners/zap/zap_client.py
```

---

# ZAP Scanner Workflow

The current Python client performs the following workflow:

```text
1. Connect to ZAP
        |
        v
2. Verify ZAP version
        |
        v
3. Configure Spider
        |
        v
4. Start Spider
        |
        v
5. Monitor Spider progress
        |
        v
6. Wait for Spider completion
        |
        v
7. Start Active Scan
        |
        v
8. Monitor Active Scan progress
        |
        v
9. Wait for Active Scan completion
        |
        v
10. Retrieve ZAP alerts
        |
        v
11. Print findings
```

---

# Spider Configuration

The current development configuration uses controlled Spider limits:

```text
Maximum depth:      5
Maximum children:   100
Maximum duration:   5 minutes
```

These limits are used to prevent uncontrolled crawling during development.

The limits are especially useful with Juice Shop because the application can expose a very large URL space during crawling.

---

# Current Target

The current authorized development target is:

```text
http://192.168.56.101:3000
```

Inside Kali Linux, this same local Juice Shop instance is available at:

```text
http://localhost:3000
```

Do not replace the target with systems that the team does not own or have explicit authorization to test.

---

# ZAP Findings

The ZAP API returns information including:

```text
Alert name
Risk
Confidence
URL
HTTP method
Parameter
CWE ID
Description
Solution
Reference
```

Example:

```text
Alert:
Content Security Policy (CSP) Header Not Set

Risk:
Medium

Confidence:
High

URL:
http://localhost:3000/...

Method:
GET

CWE:
693
```

The raw scanner output will later be converted into the project's common vulnerability schema.

---

# Planned Common Finding Schema

Different scanners produce different output formats.

For example:

* ZAP produces ZAP-specific alert fields.
* Nuclei produces template-based findings.

The project will convert these scanner-specific findings into a common structure.

Example:

```json
{
    "scanner": "ZAP",
    "title": "Content Security Policy (CSP) Header Not Set",
    "severity": "Medium",
    "confidence": "High",
    "url": "http://localhost:3000/example",
    "method": "GET",
    "parameter": "",
    "cwe": "693",
    "description": "Content Security Policy header is not set.",
    "solution": "Configure an appropriate Content Security Policy."
}
```

The final common schema will be agreed upon by the team before database implementation.

---

# Nuclei Integration

**Status: Completed PoC**

Nuclei has been integrated as another automated scanner.

The current Nuclei module:

1. Runs Nuclei against an authorized target.
2. Executes Nuclei remotely on Kali Linux through SSH.
3. Generates machine-readable JSONL output.
4. Automatically retrieves the findings through the Python subprocess.
5. Parses the JSONL findings.
6. Displays the parsed Nuclei findings.

The current implementation performs a technology-focused scan using:

```text
nuclei -tags tech -jsonl
```

The Nuclei module currently does **not** perform normalization or deduplication. Those responsibilities belong to the planned downstream processing layers.

The Nuclei module remains independent from:

* Database
* Dashboard
* Frontend

The scanner focuses only on scanning and producing structured findings.

---

# Normalization

**Status: Planned**

The normalization layer will convert scanner-specific results into the common project format.

Example:

```text
                 ZAP
                  |
                  v
             ZAP Finding
                  |
                  |
                  v
             Normalizer
                  ^
                  |
                  |
             Nuclei Finding
                  ^
                  |
                Nuclei
```

After normalization:

```text
ZAP Finding
     |
     v
Common Finding Schema
     ^
     |
Nuclei Finding
```

This allows the rest of the system to work independently of the scanner that generated the finding.

---

# Deduplication

**Status: Planned**

Different scanners may identify the same underlying vulnerability.

Example:

```text
ZAP
CSP Header Not Set
URL: /login

Nuclei
CSP Header Missing
URL: /login
```

These findings may represent the same underlying issue.

The deduplication layer will identify related findings using fields such as:

* Target
* URL
* Finding type
* CWE
* Parameter
* Template ID
* Evidence
* Scanner information

The exact deduplication algorithm will be finalized after the common finding schema is finalized.

---

# Database

**Status: Planned**

The database will eventually store:

### Targets

```text
Target ID
Target URL
Name
Environment
Created time
```

### Scans

```text
Scan ID
Target ID
Scanner
Start time
End time
Status
```

### Findings

```text
Finding ID
Scan ID
Title
Severity
Confidence
CWE
Description
Solution
```

### Occurrences

```text
Occurrence ID
Finding ID
URL
Method
Parameter
Evidence
First detected
Last detected
```

This structure will allow the project to track findings across multiple scans.

---

# Dashboard

**Status: Planned**

The dashboard will eventually display:

* Total vulnerabilities
* Critical vulnerabilities
* High vulnerabilities
* Medium vulnerabilities
* Low vulnerabilities
* Informational findings
* Scanner-wise findings
* Affected URLs
* Finding details
* Scan history
* New findings
* Resolved findings
* Duplicate findings

Example planned dashboard:

```text
-----------------------------------------------------
             Vulnerability Dashboard
-----------------------------------------------------

Total Findings        284

Critical                0
High                    5
Medium                 32
Low                    97
Informational         150

-----------------------------------------------------

Scanner Distribution

ZAP                    284
Nuclei                  XX

-----------------------------------------------------

Recent Scans

Target          Scanner       Status
Juice Shop      ZAP            Completed
Juice Shop      Nuclei         Completed
-----------------------------------------------------
```

The actual dashboard design will be developed later.

---

# Automatic Ingestion

The final system is intended to support automatic scanner ingestion.

Planned workflow:

```text
                    Scheduler / User
                           |
                           v
                    Start Scan Job
                           |
             +-------------+-------------+
             |                           |
             v                           v
            ZAP                        Nuclei
             |                           |
             v                           v
        ZAP Alerts                 Nuclei JSON
             |                           |
             +-------------+-------------+
                           |
                           v
                     Normalization
                           |
                           v
                     Deduplication
                           |
                           v
                        Database
                           |
                           v
                       Dashboard
```

The goal is to avoid manually downloading scanner reports.

---

# Team Responsibilities

| Module        | Status        | Responsibility                               |
| ------------- | ------------- | -------------------------------------------- |
| OWASP ZAP     | Completed PoC | Automated ZAP scanning and alert retrieval   |
| Nuclei        | Completed PoC | Automated Nuclei scanning and JSON ingestion |
| Normalization | Planned       | Common finding format                        |
| Deduplication | Planned       | Identify duplicate findings                  |
| Database      | Planned       | Persistent vulnerability storage             |
| Backend       | Planned       | APIs and application logic                   |
| Dashboard     | Planned       | Visualization and vulnerability management   |

Team members should update this section as responsibilities are finalized.

---

# Development Guidelines

## 1. Do not commit secrets

Never commit:

```text
API keys
Passwords
Tokens
.env files
Private credentials
Private SSH keys
```

Use environment variables instead.

---

## 2. Do not commit the virtual environment

The `.venv` directory is local to each developer.

Install dependencies using:

```powershell
pip install -r requirements.txt
```

A shared `requirements.txt` will be added when the dependencies are finalized.

---

## 3. Keep scanner modules independent

Each scanner should have its own directory.

Example:

```text
scanners/
├── zap/
│   └── zap_client.py
│
└── nuclei/
    └── nuclei_client.py
```

Scanner-specific code should not directly depend on the database or dashboard.

---

## 4. Use the common finding schema

Once finalized, every scanner should produce the same normalized structure.

This allows ZAP and Nuclei findings to be processed by the same downstream components.

---

## 5. Test locally first

The development target should remain the local Juice Shop environment until the team has completed the scanner integrations.

---

## 6. Only perform authorized security testing

Do not scan systems without explicit permission.

---

# Git Setup

Clone the project repository:

```bash
git clone <TEAM_REPOSITORY_URL>
```

Enter the project:

```bash
cd scanner-vulnerability-management
```

Create a virtual environment:

```powershell
python -m venv .venv
```

Activate:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

Set scanner-specific environment variables as required.

For Nuclei:

```powershell
$env:KALI_HOST="192.168.56.101"
$env:KALI_USER="darshan"
$env:TARGET_URL="http://192.168.56.101:3000"
```

For ZAP:

```powershell
$env:ZAP_HOST="192.168.56.101"
$env:ZAP_PORT="8080"
$env:TARGET_URL="http://192.168.56.101:3000"
$env:ZAP_API_KEY="YOUR_ZAP_API_KEY"
```

---

# Current Milestones

## Milestone 1 — Scanner Integration

### OWASP ZAP

* [x] Install ZAP
* [x] Configure ZAP API
* [x] Run Juice Shop
* [x] Connect Windows Python to ZAP
* [x] Automate Spider
* [x] Configure Spider limits
* [x] Automate Active Scan
* [x] Monitor scan progress
* [x] Retrieve ZAP alerts

### Nuclei

* [x] Install/configure Nuclei
* [x] Automate scanning
* [x] Retrieve JSON findings
* [ ] Convert findings to common format

---

## Milestone 2 — Finding Processing

* [ ] Common finding schema
* [ ] Normalization
* [ ] Deduplication
* [ ] Severity handling
* [ ] Finding lifecycle/status

---

## Milestone 3 — Storage

* [ ] Database schema
* [ ] Scan storage
* [ ] Finding storage
* [ ] Finding history

---

## Milestone 4 — Application

* [ ] Backend API
* [ ] Dashboard
* [ ] Scan management
* [ ] Finding management
* [ ] Reporting

---

## Milestone 5 — Automation

* [ ] Scheduled scans
* [ ] Automatic ingestion
* [ ] Finding comparison between scans
* [ ] New/resolved finding detection

---

# Important

This project is intended for authorized security testing and educational purposes.

The current testing environment uses OWASP Juice Shop, an intentionally vulnerable application running locally in Kali Linux.
