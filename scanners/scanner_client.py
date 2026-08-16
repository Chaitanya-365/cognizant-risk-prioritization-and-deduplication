import os
import time
import requests


# ============================================================
# Configuration
# ============================================================

KALI_SCANNER_API = os.getenv(
    "KALI_SCANNER_API",
    "http://192.168.93.129:5000"
)

POLL_INTERVAL = 2


# ============================================================
# Start Scan
# ============================================================

def start_scan(scanner, target):

    response = requests.post(
        f"{KALI_SCANNER_API}/scan",
        json={
            "scanner": scanner,
            "target": target
        },
        timeout=10
    )

    if response.status_code != 202:
        raise RuntimeError(
            f"Failed to start scan: "
            f"{response.status_code} - {response.text}"
        )

    return response.json()


# ============================================================
# Get Scan Status
# ============================================================

def get_status(scan_id):

    response = requests.get(
        f"{KALI_SCANNER_API}/scan/{scan_id}/status",
        timeout=10
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"Failed to get scan status: "
            f"{response.status_code} - {response.text}"
        )

    return response.json()


# ============================================================
# Get Scan Results
# ============================================================

def get_results(scan_id):

    response = requests.get(
        f"{KALI_SCANNER_API}/scan/{scan_id}/results",
        timeout=10
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"Failed to get scan results: "
            f"{response.status_code} - {response.text}"
        )

    return response.json()


# ============================================================
# Display Progress
# ============================================================

def display_progress(status):

    progress = status.get("progress", 0)
    stage = status.get("stage", "unknown")

    bar_length = 40

    filled = int(
        bar_length * progress / 100
    )

    bar = (
        "█" * filled +
        "-" * (bar_length - filled)
    )

    print(
        f"\r[{bar}] "
        f"{progress:3d}% | "
        f"{stage:<25}",
        end="",
        flush=True
    )


# ============================================================
# Run Scanner
# ============================================================

def run_scan(scanner, target):

    print("\n" + "=" * 70)
    print(f"Starting {scanner.upper()} scan")
    print("Target:", target)
    print("=" * 70)

    # --------------------------------------------------------
    # Start
    # --------------------------------------------------------

    try:

        scan = start_scan(
            scanner,
            target
        )

    except requests.exceptions.RequestException as e:

        print("\nUnable to connect to Kali Scanner API.")
        print("Error:", e)
        return

    except RuntimeError as e:

        print("\nScan could not be started.")
        print(e)
        return

    scan_id = scan["scan_id"]

    print("\nScan ID:", scan_id)
    print("\nProgress:")

    # --------------------------------------------------------
    # Poll Status
    # --------------------------------------------------------

    while True:

        try:

            status = get_status(
                scan_id
            )

        except requests.exceptions.RequestException as e:

            print("\n\nLost connection to Scanner API.")
            print("Error:", e)
            return

        except RuntimeError as e:

            print("\n\nUnable to retrieve scan status.")
            print(e)
            return

        display_progress(status)

        scan_status = status.get("status")

        if scan_status == "completed":
            break

        if scan_status == "failed":

            print("\n\nScan failed.")

            error = status.get("error")

            if error:
                print("Error:", error)

            return

        time.sleep(POLL_INTERVAL)

    print("\n\nScan completed successfully.")

    # --------------------------------------------------------
    # Retrieve Findings
    # --------------------------------------------------------

    try:

        results = get_results(
            scan_id
        )

    except requests.exceptions.RequestException as e:

        print("\nUnable to retrieve findings.")
        print("Error:", e)
        return

    except RuntimeError as e:

        print("\nUnable to retrieve findings.")
        print(e)
        return

    findings = results.get(
        "findings",
        []
    )

    print("\n" + "=" * 70)
    print("SCAN RESULTS")
    print("=" * 70)

    print("Scanner:",
          results.get("scanner"))

    print("Target:",
          results.get("target"))

    print("Total findings:",
          results.get("total_findings"))

    # --------------------------------------------------------
    # Display Findings
    # --------------------------------------------------------

    if not findings:

        print("\nNo findings returned.")

        return

    print("\nFindings:")

    for index, finding in enumerate(
        findings,
        start=1
    ):

        print("\n" + "-" * 70)

        print(f"Finding #{index}")

        print(
            "Name:",
            finding.get("name")
        )

        print(
            "Severity:",
            finding.get("severity")
        )

        # Nuclei
        if scanner == "nuclei":

            print(
                "Template ID:",
                finding.get("template_id")
            )

            print(
                "Matched At:",
                finding.get("matched_at")
            )

        # ZAP
        elif scanner == "zap":

            print(
                "Alert ID:",
                finding.get("alert_id")
            )

            print(
                "Affected URLs:",
                finding.get(
                    "affected_url_count"
                )
            )

            urls = finding.get(
                "affected_urls",
                []
            )

            for url in urls[:5]:

                print(
                    "  -",
                    url
                )

            if len(urls) > 5:

                print(
                    f"  ... and "
                    f"{len(urls) - 5} more"
                )

        print(
            "Description:",
            finding.get("description")
        )


# ============================================================
# Main Menu
# ============================================================

def main():

    while True:

        print("\n" + "=" * 70)
        print("              VULNERABILITY SCANNER")
        print("=" * 70)

        print("\nAvailable scanners:")

        print("1. Nuclei")
        print("2. OWASP ZAP")
        print("3. Exit")

        choice = input(
            "\nSelect scanner: "
        ).strip()

        # ----------------------------------------------------
        # Exit
        # ----------------------------------------------------

        if choice == "3":

            print("\nExiting scanner.")
            break

        # ----------------------------------------------------
        # Scanner selection
        # ----------------------------------------------------

        if choice == "1":

            scanner = "nuclei"

        elif choice == "2":

            scanner = "zap"

        else:

            print(
                "\nInvalid choice. "
                "Please select 1, 2, or 3."
            )

            continue

        # ----------------------------------------------------
        # Target
        # ----------------------------------------------------

        target = input(
            "\nEnter target URL: "
        ).strip()

        if not target:

            print(
                "\nTarget URL cannot be empty."
            )

            continue

        # ----------------------------------------------------
        # Run
        # ----------------------------------------------------

        run_scan(
            scanner,
            target
        )

        print(
            "\nReturning to scanner menu..."
        )


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":
    main()