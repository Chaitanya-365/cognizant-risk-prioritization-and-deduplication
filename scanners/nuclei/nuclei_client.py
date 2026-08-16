import json
import os
import subprocess


# ============================================================
# Configuration
# ============================================================

KALI_HOST = os.getenv("KALI_HOST")
KALI_USER = os.getenv("KALI_USER")
TARGET = os.getenv("TARGET_URL")


# ============================================================
# Validate configuration
# ============================================================

if not KALI_HOST:
    raise RuntimeError("KALI_HOST environment variable is not set")

if not KALI_USER:
    raise RuntimeError("KALI_USER environment variable is not set")

if not TARGET:
    raise RuntimeError("TARGET_URL environment variable is not set")


# ============================================================
# Run Nuclei
# ============================================================

print("Starting Nuclei scan...")
print("Target:", TARGET)

command = [
    "ssh",
    f"{KALI_USER}@{KALI_HOST}",
    f"nuclei -u {TARGET} -tags tech -jsonl"
]

result = subprocess.run(
    command,
    capture_output=True,
    text=True
)


# ============================================================
# Check execution
# ============================================================

if result.returncode != 0:
    print("Nuclei execution failed.")
    print(result.stderr)
    raise SystemExit(1)


# ============================================================
# Parse and Normalize JSONL findings
# ============================================================

findings = []

for line in result.stdout.splitlines():

    line = line.strip()

    if not line.startswith("{"):
        continue

    try:
        raw_finding = json.loads(line)

        info = raw_finding.get("info", {})

        finding = {
            "scanner": "nuclei",
            "template_id": raw_finding.get("template-id"),
            "name": info.get("name"),
            "severity": info.get("severity"),
            "matched_at": raw_finding.get("matched-at"),
            "description": info.get("description"),
            "reference": info.get("reference"),
            "tags": info.get("tags"),
        }

        findings.append(finding)

    except json.JSONDecodeError:
        continue

# ============================================================
# Display results
# ============================================================

print("\nNuclei scan completed.")
print("Total findings:", len(findings))


for index, finding in enumerate(findings, start=1):

    print("\n" + "=" * 70)

    print(f"Finding #{index}")
    print("Scanner:", finding.get("scanner"))
    print("Template ID:", finding.get("template_id"))
    print("Name:", finding.get("name"))
    print("Severity:", finding.get("severity"))
    print("Matched At:", finding.get("matched_at"))