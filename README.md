# Vulnerability Scanner Integration

## Overview

This module provides a scanner integration layer for running vulnerability scans using **Nuclei** and **OWASP ZAP**.

The Windows client communicates with a Scanner API hosted on Kali Linux. Kali performs the actual scans and returns normalized findings.

## Architecture

```text
WINDOWS
  scanner_client.py
        |
        | HTTP
        v
KALI LINUX
  scanner_api.py
        |
   +----+----+
   |         |
 Nuclei     ZAP
   |         |
   +----+----+
        |
    Findings
        |
        v
WINDOWS CLIENT
```

## Project Structure

```text
scanner-vulnerability-management/
|
+-- scanners/
|   +-- scanner_client.py   # Windows client
|   +-- scanner_api.py      # Kali scanner service
|
+-- README.md
+-- .gitignore
+-- .venv/                  # local only; do not commit
```

## Components

### `scanner_client.py` — Windows

- Lets the user choose Nuclei or OWASP ZAP.
- Accepts the target URL.
- Starts the remote scan.
- Receives the scan ID.
- Polls scan progress.
- Retrieves completed findings.
- Displays results.
- Returns to the menu until the user chooses Exit.

### `scanner_api.py` — Kali

- Receives scan requests.
- Generates scan IDs.
- Executes Nuclei or OWASP ZAP.
- Tracks scan status and progress.
- Retrieves and normalizes findings.
- Exposes HTTP endpoints for the Windows client.

## Kali Setup

### Requirements

- Python 3
- Flask
- Nuclei
- OWASP ZAP
- `python-owasp-zap-v2.4`

Install Python dependencies:

```bash
pip install flask python-owasp-zap-v2.4
```

Verify Nuclei:

```bash
nuclei -version
```

Verify ZAP:

```bash
curl "http://127.0.0.1:8080/JSON/core/view/version/?apikey=$ZAP_API_KEY"
```

## Environment Variables

On Kali:

```bash
export ZAP_HOST="127.0.0.1"
export ZAP_PORT="8080"
export ZAP_API_KEY="YOUR_ZAP_API_KEY"
```

Check the API key without printing it:

```bash
if [ -n "$ZAP_API_KEY" ]; then
    echo "ZAP_API_KEY is set"
else
    echo "ZAP_API_KEY is NOT set"
fi
```

**Never commit the ZAP API key, passwords, or SSH private keys.**

## Start the Kali Scanner API

```bash
cd ~/scanner-api
source .venv/bin/activate
python scanner_api.py
```

The API listens on port `5000`.

From Windows, the current Kali address is:

```text
http://192.168.93.129:5000
```

If the Kali IP changes, update the API address in `scanner_client.py`.

## API Endpoints

### Health

```http
GET /health
```

Example:

```bash
curl http://127.0.0.1:5000/health
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

The API returns a `scan_id`.

### Scan Status

```http
GET /scan/<scan_id>/status
```

Returns:

- scanner
- target
- status
- stage
- progress
- total findings
- error, if any

Example:

```bash
curl http://127.0.0.1:5000/scan/<scan_id>/status
```

### Scan Results

```http
GET /scan/<scan_id>/results
```

Returns the normalized findings after the scan completes.

## Windows Setup

Activate the Windows virtual environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install the HTTP client dependency:

```powershell
pip install requests
```

Run:

```powershell
python .\scanners\scanner_client.py
```

The menu provides:

```text
1. Nuclei
2. OWASP ZAP
3. Exit
```

The user can run either scanner independently and return to the menu after completion.

## Scan Flow

```text
1. User selects scanner
        |
2. User enters target
        |
3. Windows POST /scan
        |
4. Kali returns scan_id
        |
5. Kali runs selected scanner
        |
6. Windows polls /status
        |
7. Progress is displayed
        |
8. Scan completes
        |
9. Windows GET /results
        |
10. Findings are displayed
        |
11. Menu appears again
```

## Current Scope

This component covers:

- Nuclei integration
- OWASP ZAP integration
- Windows-to-Kali HTTP communication
- Scan ID management
- Progress tracking
- Finding retrieval
- Finding normalization
- User-controlled scanner selection

Dashboard, database, authentication, reporting, and centralized production deployment are outside this scanner-integration component.
