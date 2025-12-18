#!/usr/bin/env python3
import os
import re
import json
import requests
import urllib3
from datetime import datetime
from dotenv import load_dotenv

# ======= CẤU HÌNH: LOAD TỪ .ENV =======
# Xác định đường dẫn file .env (nằm cùng thư mục với script này)
script_dir = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(script_dir, '.env')

# Load file .env
load_dotenv(dotenv_path=env_path)

def get_env(key, default=None):
    """Hàm wrapper để lấy biến môi trường và báo lỗi nếu thiếu"""
    val = os.getenv(key, default)
    if val is None:
        print(f"[ERROR] Thiếu cấu hình: {key} trong file .env")
        exit(1)
    return val

API_KEY = get_env("API_KEY")
MISP_URL = get_env("MISP_URL")
EVENT_ID = get_env("EVENT_ID")

OUTPUT_SRC = get_env("OUTPUT_SRC", "/var/www/html/misp-ip-src.txt")
OUTPUT_DST = get_env("OUTPUT_DST", "/var/www/html/misp-ip-dst.txt")
OUTPUT_DOMAIN = get_env("OUTPUT_DOMAIN", "/var/www/html/misp-domains.txt")
OUTPUT_URL = get_env("OUTPUT_URL", "/var/www/html/misp-urls.txt")

# Xử lý biến Boolean từ string trong .env
verify_ssl_str = get_env("VERIFY_SSL", "False").lower()
VERIFY_SSL = verify_ssl_str in ("true", "1", "yes")

WWW_USER = get_env("WWW_USER", "www-data:www-data")

IPV4_REGEX = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
# ======================================

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
    # Đảm bảo thư mục tồn tại
    os.makedirs(os.path.dirname(outfile), exist_ok=True)

    old_values = set()
    if os.path.exists(outfile):
        try:
            with open(outfile, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        if validate_ip:
                            if IPV4_REGEX.match(line):
                                old_values.add(line)
                        else:
                            old_values.add(line)
        except Exception as e:
            log(f"[!] Lỗi đọc file cũ {outfile}: {e}")

    all_values = old_values.union(values)
    
    try:
        with open(outfile, "w") as f:
            for val in sorted(all_values):
                f.write(val + "\n")
        
        # Phân quyền file
        os.system(f"chown {WWW_USER} {outfile} 2>/dev/null || true")
        os.system(f"chmod 644 {outfile} 2>/dev/null || true")
        
        log(f"✓ Updated {outfile}: {len(all_values)} total (added {len(all_values - old_values)})")
    
    except Exception as e:
        log(f"[!] Lỗi ghi file {outfile}: {e}")


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