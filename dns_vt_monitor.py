#!/usr/bin/env python3
"""
dns_vt_monitor.py (JSON storage version)

- Reads Windows DNS cache (ipconfig /displaydns)
- Parses domain -> A (host) records
- Stores sightings in dns_cache.json
- Checks new IPs against VirusTotal v3 API
- Alerts if malicious IP detected
- Supports simulation mode (--simulate) for offline testing
"""

import subprocess
import time
import os
import requests
import json
from datetime import datetime, timezone
from dotenv import load_dotenv
import argparse

# Optional Windows toast notifications
# from win10toast import ToastNotifier
# toast = ToastNotifier()

# ---------------- CONFIGURATION ----------------
JSON_PATH = "dns_cache.json"        # JSON file to store DNS + VT info
CHECK_INTERVAL_SEC = 60             # How often to read DNS cache (seconds)
VT_SECONDS_BETWEEN_REQS = 16        # Delay between VirusTotal requests to avoid rate-limits
MALICIOUS_THRESHOLD = 1             # Alert if VT malicious count >= this
IPCONFIG_TIMEOUT = 10               # Timeout for ipconfig subprocess
MAX_VT_CHECKS_PER_LOOP = 3          # Change to the number you want
# ------------------------------------------------

# Load VT API key from .env
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"
HEADERS = {"x-apikey": VT_API_KEY} if VT_API_KEY else {}

# ----------------- Utilities -----------------
def now_ts():
    return datetime.now(timezone.utc).isoformat()

# ----------------- JSON storage -----------------
def load_json():
    if os.path.exists(JSON_PATH):
        with open(JSON_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"records": []}

def save_json(data):
    with open(JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

def inject_demo_record():
    """
    Add or update a demo malicious record in dns_cache.json.
    Leaves vt_last_checked as None so the monitor will check it on next cycle.
    """
    domain = "test-malicious.example"
    ip = "1.2.3.4"

    data = load_json()
    now = now_ts()

    # If exists, update timestamps and clear vt_last_checked
    for r in data["records"]:
        if r.get("domain") == domain and r.get("ip") == ip:
            print("Demo record already present — updating timestamps and clearing vt_last_checked.")
            r["last_seen"] = now
            r["times_seen"] = (r.get("times_seen") or 1) + 1
            r["vt_last_checked"] = None
            r["vt_malicious_count"] = None
            r["vt_reputation"] = None
            r["vt_summary"] = None
            save_json(data)
            print(f"Updated existing demo record: {domain} -> {ip}")
            return

    # Otherwise create a new demo entry
    new_rec = {
        "domain": domain,
        "ip": ip,
        "first_seen": now,
        "last_seen": now,
        "times_seen": 1,
        "vt_last_checked": None,
        "vt_malicious_count": None,
        "vt_reputation": None,
        "vt_summary": None
    }
    data["records"].append(new_rec)
    save_json(data)
    print(f"Injected demo record: {domain} -> {ip} into {JSON_PATH}")

def store_record(domain, ip, vt_result=None):
    """
    Add or update a record in dns_cache.json.
    Stores a small VT summary instead of the full raw JSON to keep the file small.
    """
    data = load_json()
    now = now_ts()

    # Build a compact VT summary if vt_result supplied
    vt_summary = None
    if vt_result:
        raw = vt_result.get("raw", {}) or {}
        attrs = raw.get("data", {}).get("attributes", {}) if isinstance(raw, dict) else {}
        stats = attrs.get("last_analysis_stats", {}) if attrs else {}
        vt_summary = {
            "malicious": vt_result.get("malicious", stats.get("malicious", 0)),
            "harmless": stats.get("harmless"),
            "suspicious": stats.get("suspicious"),
            "undetected": stats.get("undetected"),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "reputation": vt_result.get("reputation", attrs.get("reputation"))
        }

    # Check if record exists
    for r in data["records"]:
        if r["domain"] == domain and r["ip"] == ip:
            r["last_seen"] = now
            r["times_seen"] = (r.get("times_seen") or 0) + 1
            if vt_summary is not None:
                r["vt_last_checked"] = now
                r["vt_malicious_count"] = vt_summary.get("malicious")
                r["vt_reputation"] = vt_summary.get("reputation")
                r["vt_summary"] = vt_summary
            save_json(data)
            return

    # New record
    new_rec = {
        "domain": domain,
        "ip": ip,
        "first_seen": now,
        "last_seen": now,
        "times_seen": 1,
        "vt_last_checked": now if vt_summary else None,
        "vt_malicious_count": vt_summary.get("malicious") if vt_summary else None,
        "vt_reputation": vt_summary.get("reputation") if vt_summary else None,
        "vt_summary": vt_summary
    }
    data["records"].append(new_rec)
    save_json(data)


def get_ips_to_check():
    """Return list of IPs that haven't been checked by VT yet."""
    data = load_json()
    to_check = []
    for r in data["records"]:
        if r.get("vt_last_checked") is None:
            to_check.append((r["domain"], r["ip"]))
    return to_check

# ----------------- DNS cache -----------------
def run_ipconfig_displaydns():
    try:
        proc = subprocess.run(["ipconfig", "/displaydns"],
                              capture_output=True, text=True, timeout=IPCONFIG_TIMEOUT)
        return proc.stdout
    except subprocess.TimeoutExpired:
        print("ipconfig timed out")
        return ""
    except Exception as e:
        print("Error running ipconfig:", e)
        return ""

def parse_dns_cache(output):
    records = []
    current_name = None

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line.lower().startswith("record name") or "record name" in line.lower():
            parts = line.split(":", 1)
            current_name = parts[1].strip() if len(parts) == 2 else None
            continue
        if "a (host)" in line.lower():
            parts = line.split(":", 1)
            if len(parts) == 2:
                ip_address = parts[1].strip()
                if current_name and ip_address:
                    records.append((current_name, ip_address))
                    current_name = None
            continue
    return records

# ----------------- VirusTotal -----------------
def vt_check_ip(ip, simulate=False):
    if simulate:
        if ip == "1.2.3.4":
            return {"malicious": 5, "reputation": -15, "raw": {"simulated": True}}
        return {"malicious": 0, "reputation": 0, "raw": {"simulated": True}}

    if not VT_API_KEY:
        print("No VT_API_KEY set. Cannot check VirusTotal.")
        return None

    url = VT_IP_URL.format(ip)
    try:
        r = requests.get(url, headers=HEADERS, timeout=20)
    except requests.RequestException as e:
        print("Network error during VT request for", ip, ":", e)
        return None

    if r.status_code == 200:
        j = r.json()
        attrs = j.get("data", {}).get("attributes", {})
        last_stats = attrs.get("last_analysis_stats", {})
        malicious_count = last_stats.get("malicious", 0)
        reputation = attrs.get("reputation", None)
        return {"malicious": malicious_count, "reputation": reputation, "raw": j}
    elif r.status_code == 429:
        return {"rate_limited": True}
    else:
        print(f"VirusTotal responded {r.status_code} for {ip}. Body: {r.text[:400]}")
        return None

# ----------------- Alerts -----------------
def alert_malicious(ip, malicious_count, reputation):
    print("\n" + "!"*60)
    print(f"ALERT [{now_ts()}]: Malicious IP detected: {ip}")
    print(f" - VirusTotal malicious detections: {malicious_count}")
    print(f" - VirusTotal reputation score: {reputation}")
    print("Check VirusTotal for full details.")
    print("!"*60 + "\n")
    # Optional toast notifications:
    # toast.show_toast("DNS Monitor Alert", f"Malicious IP: {ip} ({malicious_count} detections)", duration=8)

# ----------------- Main loop -----------------
def main_loop(simulate=False):
    print("Starting DNS cache monitor. (simulate={})".format(simulate))
    try:
        while True:
            txt = run_ipconfig_displaydns()
            records = parse_dns_cache(txt)
            if records:
                print(f"[{now_ts()}] Found {len(records)} record(s) in DNS cache.")
            else:
                print(f"[{now_ts()}] No DNS cache records found.")

            for domain, ip in records:
                store_record(domain, ip)

            to_check_ips = get_ips_to_check()
            if to_check_ips:
                print(f"[{now_ts()}] Need to check {len(to_check_ips)} IP(s) on VirusTotal.")

            checks_done = 0
            for domain, ip in to_check_ips:
                if checks_done >= MAX_VT_CHECKS_PER_LOOP:
                    print(f"[{now_ts()}] Reached MAX_VT_CHECKS_PER_LOOP ({MAX_VT_CHECKS_PER_LOOP}). Will continue next cycle.")
                    break

                vt_res = vt_check_ip(ip, simulate=simulate)
                if vt_res is None:
                    # network error or no key; skip this ip for now
                    continue

                if vt_res.get("rate_limited"):
                    # rate-limited — back off and break so we don't loop hitting VT again
                    print("VirusTotal rate limit hit. Backing off for 60s.")
                    time.sleep(60)
                    break

                # record VT results into JSON
                store_record(domain, ip, vt_result=vt_res)

                # alert if malicious
                if vt_res.get("malicious", 0) >= MALICIOUS_THRESHOLD:
                    alert_malicious(ip, vt_res.get("malicious"), vt_res.get("reputation"))

                checks_done += 1
                time.sleep(VT_SECONDS_BETWEEN_REQS)

            print(f"[{now_ts()}] Sleeping {CHECK_INTERVAL_SEC}s before next check.\n")
            time.sleep(CHECK_INTERVAL_SEC)

    except KeyboardInterrupt:
        print("Stopped by user.")

# ----------------- CLI -----------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS cache monitor + VirusTotal checks (JSON storage)")
    parser.add_argument("--simulate", action="store_true", help="simulate VirusTotal responses (no API key needed)")
    parser.add_argument("--inject-demo", action="store_true", help="inject a demo malicious record (test-malicious.example -> 1.2.3.4)")
    parser.add_argument("--remove-demo", action="store_true", help="remove the demo record if present")
    args = parser.parse_args()

    # Demo inject/remove handling
    if args.inject_demo:
        inject_demo_record()
    if args.remove_demo:
        data = load_json()
        before = len(data.get("records", []))
        data["records"] = [
            r for r in data.get("records", [])
            if not (r.get("domain") == "test-malicious.example" and r.get("ip") == "1.2.3.4")
        ]
        save_json(data)
        print(f"Removed demo records: {before - len(data['records'])}")

    # If user only wanted to inject/remove (without simulate), exit now
    if (args.inject_demo or args.remove_demo) and not args.simulate:
        print("Done. Exiting (use --simulate to run the monitor).")
        exit(0)

    # If not simulating, ensure API key exists
    if not args.simulate and not VT_API_KEY:
        print("ERROR: No VT_API_KEY found in environment (.env). Run with --simulate for offline testing.")
        exit(1)

    # Run monitor (simulate mode if requested). Stop with Ctrl+C.
    main_loop(simulate=args.simulate)

