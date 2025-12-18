#!/usr/bin/env python3
import os, re, json, requests, urllib3
from datetime import datetime

# ======= CẤU HÌNH =======
API_KEY = "qpo9CK6J2CnTmNo1Au62zmdJfZWsb1KiQKhrc7Kx"
MISP_URL = "https://misp.cyberfortress.local"
EVENT_ID = "1808"

OUTPUT_SRC = "/var/www/html/misp-ip-src.txt"
OUTPUT_DST = "/var/www/html/misp-ip-dst.txt"
OUTPUT_DOMAIN = "/var/www/html/misp-domains.txt"
OUTPUT_URL = "/var/www/html/misp-urls.txt"

VERIFY_SSL = False      # False nếu là self-signed cert
WWW_USER = "www-data:www-data"

IPV4_REGEX = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
# =========================

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def log(msg):
    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}")


def fetch_values_from_misp(attr_type, validate_ip=True):
    """Gọi API /events/restSearch để lấy list values theo type"""
    url = f"{MISP_URL}/events/restSearch"
    headers = {
        "Authorization": API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    payload = {
        "returnFormat": "json",
        "eventid": EVENT_ID,
        "type": attr_type,
        "to_ids": True,
        "enforceWarninglist": True,
    }

    try:
        resp = requests.post(url, headers=headers, json=payload, verify=VERIFY_SSL, timeout=10)
        resp.raise_for_status()
    except Exception as e:
        log(f"[!] Lỗi gọi MISP ({attr_type}): {e}")
        return set()

    data = resp.json()
    values = set()
    for evt in data.get("response", []):
        event = evt.get("Event", {})
        for attr in event.get("Attribute", []):
            if attr.get("type") == attr_type and attr.get("to_ids"):
                val = attr.get("value", "").strip()
                if val:
                    # Chỉ validate IP nếu yêu cầu
                    if validate_ip:
                        if IPV4_REGEX.match(val):
                            values.add(val)
                    else:
                        values.add(val)

    log(f"Fetched {len(values)} valid values for {attr_type}")
    return values


def update_output_file(outfile, values, validate_ip=True):
    """Hợp nhất values mới + cũ, loại trùng, rồi ghi ra file"""
    os.makedirs(os.path.dirname(outfile), exist_ok=True)

    old_values = set()
    if os.path.exists(outfile):
        with open(outfile, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    # Chỉ validate IP nếu yêu cầu
                    if validate_ip:
                        if IPV4_REGEX.match(line):
                            old_values.add(line)
                    else:
                        old_values.add(line)

    all_values = old_values.union(values)
    with open(outfile, "w") as f:
        for val in sorted(all_values):
            f.write(val + "\n")

    os.system(f"chown {WWW_USER} {outfile} 2>/dev/null || true")
    os.system(f"chmod 644 {outfile} 2>/dev/null || true")

    log(f"✓ Updated {outfile}: {len(all_values)} total (added {len(all_values - old_values)})")


def main():
    log(f"=== Start fetch from MISP (event {EVENT_ID}) ===")
    
    # Fetch IP sources
    src_ips = fetch_values_from_misp("ip-src", validate_ip=True)
    if src_ips:
        update_output_file(OUTPUT_SRC, src_ips, validate_ip=True)
    
    # Fetch IP destinations
    dst_ips = fetch_values_from_misp("ip-dst", validate_ip=True)
    if dst_ips:
        update_output_file(OUTPUT_DST, dst_ips, validate_ip=True)
    
    # Fetch domains
    domains = fetch_values_from_misp("domain", validate_ip=False)
    if domains:
        update_output_file(OUTPUT_DOMAIN, domains, validate_ip=False)
    
    # Fetch URLs
    urls = fetch_values_from_misp("url", validate_ip=False)
    if urls:
        update_output_file(OUTPUT_URL, urls, validate_ip=False)

    log("=== Done ===")


if __name__ == "__main__":
    main()
