#!/usr/bin/env python3
# inject_demo_record.py
# Run once to add a demo malicious record to dns_cache.json

import json, os
from datetime import datetime, timezone

JSON_PATH = "dns_cache.json"

def now_ts():
    return datetime.now(timezone.utc).isoformat()

def load_json():
    if os.path.exists(JSON_PATH):
        try:
            with open(JSON_PATH, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    return {"records": []}
                return json.loads(content)
        except Exception:
            print("Warning: existing JSON corrupted — starting fresh.")
            return {"records": []}
    return {"records": []}

def save_json(data):
    with open(JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

def inject_demo_record():
    data = load_json()

    domain = "test-malicious.example"
    ip = "1.2.3.4"

    # If same domain+ip already present, update timestamps and ensure vt_last_checked is cleared
    for r in data["records"]:
        if r.get("domain")==domain and r.get("ip")==ip:
            print("Record already present — updating timestamps and clearing vt_last_checked so it will be checked by the monitor.")
            r["last_seen"] = now_ts()
            r["times_seen"] = (r.get("times_seen") or 1) + 1
            r["vt_last_checked"] = None           # ensure monitor will check it
            r["vt_malicious_count"] = None
            r["vt_reputation"] = None
            r["vt_summary"] = None
            save_json(data)
            return

    new_rec = {
        "domain": domain,
        "ip": ip,
        "first_seen": now_ts(),
        "last_seen": now_ts(),
        "times_seen": 1,
        # Leave vt_last_checked as None so the monitor will pick it for checking:
        "vt_last_checked": None,
        "vt_malicious_count": None,
        "vt_reputation": None,
        "vt_summary": None
    }
    data["records"].append(new_rec)
    save_json(data)
    print(f"Injected demo record: {domain} -> {ip} into {JSON_PATH}")

if __name__ == "__main__":
    inject_demo_record()
