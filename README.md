# Vulnerability Scanner Integration

## Overview

This module provides a scanner integration layer for running vulnerability scans using **Nuclei** and **OWASP ZAP**.

The Windows client communicates with a Scanner API hosted on a Kali Linux machine. Kali performs the actual security scans and returns normalized findings.

The Scanner API is accessed through the `KALI_SCANNER_API` environment variable, so the Windows client does not depend on a hard-coded server IP. This allows the same client to be used with the current Kali server and with a future centralized scanner server.

## Architecture

```text
                         WINDOWS
                    ┌─────────────────┐
                    │ scanner_client  │
                    │                 │
                    │ Scanner choice  │
                    │ Target input    │
                    │ Progress        │
                    │ Findings        │
                    └────────┬────────┘
                             │
                             │ HTTP
                             │
                 KALI_SCANNER_API
                             │
                             ▼
                    ┌─────────────────┐
                    │   KALI LINUX    │
                    │                 │
                    │ scanner_api.py  │
                    └────────┬────────┘
                             │
                    ┌────────┴────────┐
                    │                 │
                    ▼                 ▼
                ┌────────┐        ┌────────┐
                │ Nuclei │        │  ZAP   │
                └────┬───┘        └────┬───┘
                     │                 │
                     └────────┬────────┘
                              ▼
                         Findings
                              │
                              ▼
                         Windows Client
```

## Components

### `scanner_client.py` — Windows

Responsibilities:

- Scanner selection
- Target URL input
- Starting a scan
- Receiving a scan ID
- Polling scan progress
- Displaying scan stages
- Retrieving completed findings
- Displaying normalized results
- Returning to the scanner menu
- Allowing the user to exit voluntarily

Supported scanners:

- Nuclei
- OWASP ZAP

### `scanner_api.py` — Kali

Responsibilities:

- Receive scan requests
- Generate scan IDs
- Execute the selected scanner
- Track scan status
- Track scan progress
- Retrieve scanner findings
- Normalize scanner-specific output
- Return results through HTTP endpoints

## Centralized Server Configuration

The Windows client does not hard-code the scanner server address.

In `scanner_client.py`:

```python
KALI_SCANNER_API = os.getenv(
    "KALI_SCANNER_API"
)

if not KALI_SCANNER_API:
    raise RuntimeError(
        "KALI_SCANNER_API environment variable is not set"
    )

POLL_INTERVAL = 2
```

This separates server configuration from application code.

### Current development setup

On Windows PowerShell:

```powershell
$env:KALI_SCANNER_API="http://<SCANNER_SERVER_IP>:5000"
```

Then run:

```powershell
python .\scanners\scanner_client.py
```

### Future centralized deployment

The same client can point to a centralized scanner server without changing the Python source:

```powershell
$env:KALI_SCANNER_API="https://scanner.company.local"
```

The client therefore remains independent of the physical server IP.

> The current implementation uses Kali as the scanner host. A future centralized deployment can move the same API to a dedicated Linux server, VM, or cloud infrastructure.

## Project Structure

```text
scanner-vulnerability-management/
│
├── scanners/
│   ├── scanner_client.py       # Windows client
│   └── scanner_api.py          # Kali scanner service
│
├── README.md
├── .gitignore
└── .venv/                      # local only; do not commit
```

## Kali Scanner API Setup

### Requirements

The Kali machine requires:

- Python 3
- Flask
- Nuclei
- OWASP ZAP
- Python ZAP API library

Install Python dependencies:

```bash
pip install flask python-owasp-zap-v2.4
```

### Nuclei

Verify Nuclei:

```bash
nuclei -version
```

### OWASP ZAP

Start ZAP on Kali and verify its API:

```bash
curl "http://127.0.0.1:8080/JSON/core/view/version/?apikey=$ZAP_API_KEY"
```

Expected response:

```json
{
  "version": "2.17.0"
}
```

## Environment Variables

### Kali

Configure ZAP on Kali:

```bash
export ZAP_HOST="127.0.0.1"
export ZAP_PORT="8080"
export ZAP_API_KEY="YOUR_ZAP_API_KEY"
```

Verify the API key without displaying it:

```bash
if [ -n "$ZAP_API_KEY" ]; then
    echo "ZAP_API_KEY is set"
else
    echo "ZAP_API_KEY is NOT set"
fi
```

### Windows

Configure the Scanner API address:

```powershell
$env:KALI_SCANNER_API="http://<SCANNER_SERVER_IP>:5000"
```

For a future centralized deployment:

```powershell
$env:KALI_SCANNER_API="https://scanner.company.local"
```

**Never commit actual API keys, passwords, or private keys to Git.**

## Start the Scanner API

On Kali:

```bash
cd ~/scanner-api
source .venv/bin/activate
python scanner_api.py
```

The API listens on port `5000`.

Verify it:

```bash
curl http://127.0.0.1:5000/health
```

Expected:

```json
{
  "service": "scanner-api",
  "status": "ok"
}
```

## API Endpoints

### Health Check

```http
GET /health
```

### Start a Scan

```http
POST /scan
```

Nuclei:

```bash
curl -X POST http://127.0.0.1:5000/scan \
-H "Content-Type: application/json" \
-d '{"scanner":"nuclei","target":"http://localhost:3000"}'
```

ZAP:

```bash
curl -X POST http://127.0.0.1:5000/scan \
-H "Content-Type: application/json" \
-d '{"scanner":"zap","target":"http://localhost:3000"}'
```

The API returns a scan ID.

### Check Scan Status

```http
GET /scan/<scan_id>/status
```

The response contains:

- scan ID
- scanner
- target
- status
- stage
- progress
- total findings
- error

Example:

```bash
curl http://127.0.0.1:5000/scan/<scan_id>/status
```

### Retrieve Results

```http
GET /scan/<scan_id>/results
```

Returns the normalized findings after the scan completes.

## Windows Client Setup

Activate the Windows virtual environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install the HTTP client dependency:

```powershell
pip install requests
```

Configure the Scanner API:

```powershell
$env:KALI_SCANNER_API="http://<SCANNER_SERVER_IP>:5000"
```

Run the client:

```powershell
python .\scanners\scanner_client.py
```

The menu provides:

```text
1. Nuclei
2. OWASP ZAP
3. Exit
```

## Scan Flow

```text
1. User selects scanner
        ↓
2. User enters target
        ↓
3. Windows POST /scan
        ↓
4. Kali returns scan_id
        ↓
5. Kali runs selected scanner
        ↓
6. Windows polls /status
        ↓
7. Progress and stage are displayed
        ↓
8. Scan completes
        ↓
9. Windows GET /results
        ↓
10. Findings are displayed
        ↓
11. Menu appears again
```

The Windows client polls every **2 seconds**:

```python
POLL_INTERVAL = 2
```

## Centralization Roadmap

The current architecture already separates the client from the scanner execution layer:

```text
Windows Clients
      |
      | HTTP
      v
Central Scanner API
      |
   +--+--+
   |     |
 Nuclei ZAP
```

A future production architecture can extend this with:

- A dedicated Linux scanner server
- HTTPS/TLS
- Authentication and authorization
- PostgreSQL for persistent scan history
- A scan queue for multiple concurrent users
- Multiple scanner workers
- Centralized dashboard
- Vulnerability deduplication
- Reporting and remediation tracking

The Windows client can continue using the same API contract while the backend evolves.

## Security Notes

- Do not hard-code the ZAP API key.
- Do not commit passwords, SSH private keys, or API secrets.
- Keep `.venv/` out of Git.
- Do not expose the Scanner API directly to the public internet without authentication and TLS.
- The current implementation is intended for the project/lab environment.
- Production deployment should add authentication, HTTPS/TLS, target authorization, persistent job storage, and appropriate access controls.

## Current Scope

This component covers:

- Nuclei integration
- OWASP ZAP integration
- Windows-to-Kali HTTP communication
- Configurable Scanner API address
- Scan ID management
- Progress tracking
- Finding retrieval
- Finding normalization
- User-controlled scanner selection
- Foundation for centralized scanner deployment

Dashboard, database, authentication, reporting, and full production deployment can be implemented as separate components.
