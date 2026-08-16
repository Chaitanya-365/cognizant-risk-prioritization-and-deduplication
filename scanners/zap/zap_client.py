import os
import time

from zapv2 import ZAPv2


# ============================================================
# Configuration
# ============================================================

ZAP_HOST = os.getenv("ZAP_HOST", "192.168.93.129")
ZAP_PORT = int(os.getenv("ZAP_PORT", "8080"))
TARGET = os.getenv("TARGET_URL", "http://localhost:3000")

API_KEY = os.getenv("ZAP_API_KEY")


# ============================================================
# Validate configuration
# ============================================================
if not ZAP_HOST:
    raise RuntimeError("ZAP_HOST environment variable is not set")

if not ZAP_PORT:
    raise RuntimeError("ZAP_PORT environment variable is not set")

if not TARGET:
    raise RuntimeError("TARGET_URL environment variable is not set")

if not API_KEY:
    raise RuntimeError(
        "ZAP_API_KEY environment variable is not set."
    )


# ============================================================
# Connect to ZAP
# ============================================================

zap = ZAPv2(
    apikey=API_KEY,
    proxies={
        "http": f"http://{ZAP_HOST}:{ZAP_PORT}",
        "https": f"http://{ZAP_HOST}:{ZAP_PORT}",
    },
)


# ============================================================
# Test connection
# ============================================================

print("Connected to ZAP")
print("ZAP version:", zap.core.version)


# ============================================================
# Configure Spider
# ============================================================

print("\nConfiguring Spider...")

zap.spider.set_option_max_depth(5)
zap.spider.set_option_max_children(100)
zap.spider.set_option_max_duration(5)

print("Maximum depth: 5")
print("Maximum children: 100")
print("Maximum duration: 5 minutes")


# ============================================================
# Start Spider
# ============================================================

print("\nStarting Spider...")
print("Target:", TARGET)

spider_id = zap.spider.scan(
    url=TARGET,
    recurse=True
)

print("Spider started. Scan ID:", spider_id)


# ============================================================
# Monitor Spider
# ============================================================

while True:

    progress = int(
        zap.spider.status(spider_id)
    )

    print(f"Spider progress: {progress}%")

    if progress >= 100:
        break

    time.sleep(2)


print("\nSpider completed!")


# ============================================================
# Start Active Scan
# ============================================================

print("\nStarting Active Scan...")
print("Target:", TARGET)

active_scan_id = zap.ascan.scan(
    url=TARGET,
    recurse=True
)

print("Active Scan started. Scan ID:", active_scan_id)


# ============================================================
# Monitor Active Scan
# ============================================================

while True:

    progress = int(
        zap.ascan.status(active_scan_id)
    )

    print(f"Active Scan progress: {progress}%")

    if progress >= 100:
        break

    time.sleep(5)


print("\nActive Scan completed!")


# ============================================================
# Retrieve Alerts
# ============================================================

print("\nRetrieving security alerts...")

alerts = zap.core.alerts(
    baseurl=TARGET,
    start=0,
    count=5000
)


# ============================================================
# Display Alerts
# ============================================================

print(f"\nTotal alerts found: {len(alerts)}")


for index, alert in enumerate(alerts, start=1):

    print("\n" + "=" * 70)

    print(f"Alert #{index}")
    print("Name:", alert.get("alert"))
    print("Risk:", alert.get("risk"))
    print("Confidence:", alert.get("confidence"))
    print("URL:", alert.get("url"))
    print("Method:", alert.get("method"))
    print("Parameter:", alert.get("param"))
    print("CWE:", alert.get("cweid"))
    print("Description:", alert.get("description"))


print("\n" + "=" * 70)
print("Automatic ZAP scan completed successfully.")