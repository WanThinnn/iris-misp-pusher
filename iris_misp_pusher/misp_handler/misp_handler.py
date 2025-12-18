#!/usr/bin/env python3
#
#
#  IRIS misp Source Code
#  Copyright (C) 2025 - iris-misp-pusher
#  thienlai159@gmail.com
#  Created by iris-misp-pusher - 2025-10-15
#
#  License MIT
# iris-misp-pusher/iris_misp_pusher/misp_handler/misp_handler.py

import requests
import re
import ipaddress
import urllib3
import os
from datetime import datetime

# --- Constants ---
IPV4_REGEX = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
# Ánh xạ IRIS → MISP type + category (event_id sẽ được truyền vào từ config)
IOC_TYPE_MAP = {
    "ip-src": ("ip-src", "Network activity"), "ip-dst": ("ip-dst", "Network activity"),
    "domain": ("domain", "Network activity"), "hostname": ("hostname", "Network activity"),
    "url": ("url", "Network activity"), "md5": ("md5", "Payload delivery"),
    "sha1": ("sha1", "Payload delivery"), "sha256": ("sha256", "Payload delivery"),
    "sha512": ("sha512", "Payload delivery"), "sha3-256": ("sha3-256", "Payload delivery"),
    "sha3-512": ("sha3-512", "Payload delivery"), "filename": ("filename", "Payload delivery"),
    "file-path": ("filename", "Payload delivery"), "filepath": ("filename", "Payload delivery"),
    "email-src": ("email-src", "Payload delivery"), "email-dst": ("email-dst", "Payload delivery"),
    "uri": ("url", "Network activity"), "link": ("url", "Network activity"),
}

# --- Utility Functions ---
def log(logger, msg):
    """Sử dụng logger của IRIS thay vì print"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logger.info(f"[{timestamp}] {msg}")

# ===== MISP API Functions =====
def check_misp_exists(logger, value, misp_url, misp_key, verify_ssl):
    """Kiểm tra IOC đã có trong MISP chưa"""
    url = f"{misp_url}/attributes/restSearch"
    headers = {
        "Authorization": misp_key, "Accept": "application/json", "Content-Type": "application/json",
    }
    payload = {"value": value, "returnFormat": "json"}
    try:
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        r = requests.post(url, headers=headers, json=payload, verify=verify_ssl, timeout=10)
        r.raise_for_status()
        data = r.json()
        return bool(data.get("response", {}).get("Attribute"))
    except Exception as e:
        log(logger, f"[!] check_misp_exists error for value '{value}': {e}")
        return False

def add_to_misp(logger, event_id, value, typ, category, misp_url, misp_key, verify_ssl, comment=None, tags=None):
    """Thêm IOC mới vào MISP."""
    url = f"{misp_url}/attributes/add/{event_id}"
    headers = {
        "Authorization": misp_key, "Accept": "application/json", "Content-Type": "application/json",
    }
    data = {"value": value, "type": typ, "category": category, "to_ids": True, "distribution": 0}
    if comment: data["comment"] = comment
    if tags: data["Tag"] = [{"name": t.strip()} for t in tags.split(",") if t.strip()]

    try:
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        r = requests.post(url, headers=headers, json=data, verify=verify_ssl, timeout=10)
        text = r.text.lower()
        if r.status_code // 100 == 2:
            log(logger, f"[OK] Added to MISP -> {typ}: {value}")
            return True
        elif any(x in text for x in ["could not add", "already exists", "duplicate"]):
            log(logger, f"[DUPLICATE] in MISP -> {typ}: {value}")
            return False
        else:
            log(logger, f"[FAIL] Add to MISP -> {typ}: {value} | {r.status_code} {r.text[:100]}")
            return False
    except Exception as e:
        log(logger, f"[ERR] Add to MISP -> {typ}: {value} | {e}")
        return False

# ===== Classification Logic =====
def guess_hash_type(value, ioc_tags=None):
    if not re.fullmatch(r"[a-fA-F0-9]+", value): return None
    length = len(value)
    tags = (ioc_tags or "").lower()
    if length == 32: return "md5"
    if length == 40: return "sha1"
    if length == 64: return "sha3-256" if "sha3" in tags or "keccak" in tags else "sha256"
    if length == 128: return "sha3-512" if "sha3" in tags or "keccak" in tags else "sha512"
    return None

def classify_ioc(value, event_ip_id, event_hash_id, iris_type=None, ioc_tags=None):
    """Phân loại IOC và trả về (misp_type, event_id, category)"""
    if iris_type in IOC_TYPE_MAP:
        misp_type, category = IOC_TYPE_MAP[iris_type]
        event_id = event_hash_id if misp_type in ["md5", "sha1", "sha256", "sha512", "sha3-256", "sha3-512", "filename"] else event_ip_id
        return misp_type, event_id, category

    try:
        ipaddress.ip_address(value)
        return "ip-src", event_ip_id, "Network activity"
    except:
        pass

    misp_type = guess_hash_type(value, ioc_tags)
    if misp_type:
        return misp_type, event_hash_id, "Payload delivery"

    return None, None, None


# ===== File Export Functions =====
def fetch_values_from_misp(logger, attr_type, event_id, misp_url, misp_key, verify_ssl):
    """Gọi API /events/restSearch để lấy list values theo type"""
    url = f"{misp_url}/events/restSearch"
    headers = {
        "Authorization": misp_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    payload = {
        "returnFormat": "json",
        "eventid": event_id,
        "type": attr_type,
        "to_ids": True,
        "enforceWarninglist": True,
    }

    try:
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        resp = requests.post(url, headers=headers, json=payload, verify=verify_ssl, timeout=10)
        resp.raise_for_status()
    except Exception as e:
        log(logger, f"[!] Lỗi gọi MISP ({attr_type}): {e}")
        return set()

    data = resp.json()
    values = set()
    for evt in data.get("response", []):
        event = evt.get("Event", {})
        for attr in event.get("Attribute", []):
            if attr.get("type") == attr_type and attr.get("to_ids"):
                val = attr.get("value", "").strip()
                if val:
                    # Chỉ validate IP nếu là ip-src hoặc ip-dst
                    if attr_type in ["ip-src", "ip-dst"]:
                        if IPV4_REGEX.match(val):
                            values.add(val)
                    else:
                        values.add(val)

    log(logger, f"Fetched {len(values)} valid values for {attr_type}")
    return values


def update_output_file(logger, outfile, values, www_user="www-data:www-data"):
    """Hợp nhất values mới + cũ, loại trùng, rồi ghi ra file"""
    try:
        os.makedirs(os.path.dirname(outfile), exist_ok=True)
    except Exception as e:
        log(logger, f"[!] Cannot create directory for {outfile}: {e}")
        return

    old_values = set()
    if os.path.exists(outfile):
        try:
            with open(outfile, "r") as f:
                old_values = set(line.strip() for line in f if line.strip())
        except Exception as e:
            log(logger, f"[!] Cannot read {outfile}: {e}")

    all_values = old_values.union(values)
    try:
        with open(outfile, "w") as f:
            for val in sorted(all_values):
                f.write(val + "\n")
    except Exception as e:
        log(logger, f"[!] Cannot write to {outfile}: {e}")
        return

    os.system(f"chown {www_user} {outfile} 2>/dev/null || true")
    os.system(f"chmod 644 {outfile} 2>/dev/null || true")

    log(logger, f"✓ Updated {outfile}: {len(all_values)} total (added {len(all_values - old_values)})")


# import traceback
# from jinja2 import Template

# import iris_interface.IrisInterfaceStatus as InterfaceStatus
# from app.datamgmt.manage.manage_attribute_db import add_tab_attribute_field


# class MispHandler(object):
#     def __init__(self, mod_config, server_config, logger):
#         self.mod_config = mod_config
#         self.server_config = server_config
#         self.misp = self.get_misp_instance()
#         self.log = logger

#     def get_misp_instance(self):
#         """
#         Returns an misp API instance depending if the key is premium or not

#         :return: { cookiecutter.keyword }} Instance
#         """
#         url = self.mod_config.get('misp_url')
#         key = self.mod_config.get('misp_key')
#         proxies = {}

#         if self.server_config.get('http_proxy'):
#             proxies['https'] = self.server_config.get('HTTPS_PROXY')

#         if self.server_config.get('https_proxy'):
#             proxies['http'] = self.server_config.get('HTTP_PROXY')

#         # TODO!
#         # Here get your misp instance and return it
#         # ex: return mispApi(url, key)
#         return "<TODO>"

#     def gen_domain_report_from_template(self, html_template, misp_report) -> InterfaceStatus:
#         """
#         Generates an HTML report for Domain, displayed as an attribute in the IOC

#         :param html_template: A string representing the HTML template
#         :param misp_report: The JSON report fetched with misp API
#         :return: InterfaceStatus
#         """
#         template = Template(html_template)
#         context = misp_report
#         pre_render = dict({"results": []})

#         for misp_result in context:
#             pre_render["results"].append(misp_result)

#         try:
#             rendered = template.render(pre_render)

#         except Exception:
#             print(traceback.format_exc())
#             log.error(traceback.format_exc())
#             return InterfaceStatus.I2Error(traceback.format_exc())

#         return InterfaceStatus.I2Success(data=rendered)

#     def handle_domain(self, ioc):
#         """
#         Handles an IOC of type domain and adds VT insights

#         :param ioc: IOC instance
#         :return: IIStatus
#         """

#         self.log.info(f'Getting domain report for {ioc.ioc_value}')

#         # TODO! do your stuff, then report it to the element (here an IOC)

#         if self.mod_config.get('misp_report_as_attribute') is True:
#             self.log.info('Adding new attribute misp Domain Report to IOC')

#             report = ["<TODO> report from misp"]

#             status = self.gen_domain_report_from_template(self.mod_config.get('misp_domain_report_template'), report)

#             if not status.is_success():
#                 return status

#             rendered_report = status.get_data()

#             try:
#                 add_tab_attribute_field(ioc, tab_name='misp Report', field_name="HTML report", field_type="html",
#                                         field_value=rendered_report)

#             except Exception:

#                 self.log.error(traceback.format_exc())
#                 return InterfaceStatus.I2Error(traceback.format_exc())
#         else:
#             self.log.info('Skipped adding attribute report. Option disabled')

#         return InterfaceStatus.I2Success()
