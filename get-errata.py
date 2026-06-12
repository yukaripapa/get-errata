#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# get-errata-cve21.py
# CVE-based Red Hat CSAF VEX security report generator
# v21.0: supports phone_mobile in contacts and includes v20/v19 CVE fallback logic.

import argparse
import json
import os
import re
import sys
import textwrap
from pathlib import Path
from string import Template
from datetime import datetime, timezone

import requests
import hashlib

VERSION = "24.0"
SUPPORTED_RHEL_STREAM_PREFIXES = ("BASEOS-", "APPSTREAM-")


def load_json_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_to_json(filename, data):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)


def load_template(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        print(f"Warning: template load failed from {path}: {e}")
        return None


def load_contacts(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def get_contact_value(contacts, placeholder, section=None, field=None):
    """Return contact value for Template placeholders.

    Supported contacts.json styles:
      - "APPROVER_NAME": "..."
      - "approver_name": "..."
      - "approver": {"name": "...", "phone_mobile": "..."}
      - "approverName": "..."

    For phone fields, also accepts phone_mobile, mobile, tel, telephone.
    """
    if not isinstance(contacts, dict):
        return ""

    candidates = [placeholder, placeholder.lower()]
    if section and field:
        field_aliases = [field]
        if field == "phone":
            field_aliases.extend(["phone_mobile", "mobile", "tel", "telephone"])
        candidates.extend([f"{section}_{alias}" for alias in field_aliases])
        candidates.extend([f"{section}_{alias}".upper() for alias in field_aliases])
        candidates.extend([f"{section}{alias.capitalize()}" for alias in field_aliases])

    for key in candidates:
        value = contacts.get(key)
        if value is not None:
            return str(value)

    if section and field:
        obj = contacts.get(section) or contacts.get(section.upper())
        if isinstance(obj, dict):
            field_aliases = [field]
            if field == "phone":
                field_aliases.extend(["phone_mobile", "mobile", "tel", "telephone"])
            for alias in field_aliases:
                value = obj.get(alias) or obj.get(alias.upper())
                if value is not None:
                    return str(value)
    return ""


def format_report_text(text, width=80, indent=3):
    if not text:
        return ""
    pad = " " * indent
    out = []
    for para in str(text).replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if para.strip():
            out.append(textwrap.fill(para, width=width, initial_indent=pad, subsequent_indent=pad))
        else:
            out.append("")
    return "\n".join(out)


def is_cve_id(value):
    return bool(re.fullmatch(r"CVE-\d{4}-\d{4,}", (value or "").strip(), re.IGNORECASE))


def normalize_cve_id(value):
    return (value or "").strip().upper()


def fetch_cve_vex(cve_id):
    cve_id = normalize_cve_id(cve_id)
    m = re.fullmatch(r"CVE-(\d{4})-\d{4,}", cve_id)
    if not m:
        raise ValueError(f"Invalid CVE identifier: {cve_id}")
    url = f"https://security.access.redhat.com/data/csaf/v2/vex/{m.group(1)}/{cve_id.lower()}.json"
    r = requests.get(url, headers={"accept": "application/json"}, timeout=30)
    r.raise_for_status()
    return r.json()


def first_vulnerability(vex):
    vulns = vex.get("vulnerabilities") or []
    return vulns[0] if vulns else {}


def extract_note_text(notes, category):
    for n in notes or []:
        if n.get("category") == category and n.get("text"):
            return n.get("text")
    return ""


def extract_package_name_from_title(text):
    if not text:
        return None
    s = str(text).strip()
    severity_prefixes = {
        "low", "moderate", "important", "critical",
        "security advisory (low)", "security advisory (moderate)",
        "security advisory (important)", "security advisory (critical)",
    }
    if ":" in s:
        first, rest = s.split(":", 1)
        first = first.strip()
        if first.lower() not in severity_prefixes:
            return first.lower() or None
        s = rest.strip()
    token = re.split(r"[:\s,]+", s, maxsplit=1)[0].strip()
    return token.lower() if token else None


def package_matches_target(pkg, target_pkg):
    if not target_pkg:
        return True
    pkg = (pkg or "").lower()
    target = str(target_pkg).lower()
    if pkg == target:
        return True
    # Allow versioned stream names: bind9, bind9.16, python3.11, etc.
    return bool(re.fullmatch(re.escape(target) + r"[0-9.]+", pkg))


def extract_package_name_from_product_id(product_id):
    if not product_id or ":" not in product_id:
        return None
    component = product_id.split(":", 1)[1]
    m = re.match(r"(?P<pkg>.+?)-\d+:", component)
    if m:
        return m.group("pkg")
    return component.split("-", 1)[0] if component else None


def display_package_name_from_product_id(product_id, fallback_pkg=None):
    pkg = extract_package_name_from_product_id(product_id) or fallback_pkg or "unknown"
    return str(pkg).lower()


def is_excluded_cve_stream(stream):
    stream_upper = (stream or "").upper()
    # E4S is not excluded; AUS and E4S are both shown as v.<minor>aus.
    return bool(
        re.search(r"(^|[.\-])TUS($|[.\-])", stream_upper) or
        re.search(r"(^|[.\-])EXTENSION($|[.\-])", stream_upper)
    )


def is_supported_rhel_stream(stream):
    su = (stream or "").upper()
    return su == "7SERVER-ELS" or su.startswith(SUPPORTED_RHEL_STREAM_PREFIXES)


def is_target_cve_product_id(product_id, target_pkg=None, arch="x86_64", mode="arch_strict"):
    if not product_id or ":" not in product_id:
        return False
    stream, component = product_id.split(":", 1)
    if is_excluded_cve_stream(stream) or not is_supported_rhel_stream(stream):
        return False

    if mode in ("src_strict", "src_relaxed"):
        m = re.fullmatch(r"(?P<pkg>.+?)-\d+:.+\.src", component)
    else:
        m = re.fullmatch(r"(?P<pkg>.+?)-\d+:.+\." + re.escape(arch) + r"(?:.*)?", component)
    if not m:
        return False
    if mode == "src_relaxed":
        return True
    return package_matches_target(m.group("pkg"), target_pkg)


def extract_cve_package_name(vex):
    doc = vex.get("document") or {}
    vuln = first_vulnerability(vex)
    for candidate in [doc.get("title"), vuln.get("title"), vuln.get("summary")]:
        pkg = extract_package_name_from_title(candidate)
        if pkg:
            return pkg
    notes = vuln.get("notes") or []
    for candidate in [extract_note_text(notes, "summary"), extract_note_text(notes, "description")]:
        pkg = extract_package_name_from_title(candidate)
        if pkg:
            return pkg
    return "unknown"


def extract_rhsa_id_from_url(url):
    m = re.search(r"RHSA-\d{4}:\d+", url or "")
    return m.group(0) if m else (url or "")


def parse_stream_version(stream):
    stream_upper = stream.upper()
    if stream_upper == "7SERVER-ELS":
        return "7", "v.7els"
    vm = re.search(r"-(\d+\.\d+)", stream)
    if not vm:
        return None, None
    minor_ver = vm.group(1)
    major_ver = minor_ver.split(".")[0]
    if any(x in stream_upper for x in [".AUS", ".E4S"]):
        vl = f"v.{minor_ver}aus"
    elif any(x in stream_upper for x in [".EUS", ".E2S"]):
        vl = f"v.{minor_ver}eus"
    else:
        vl = f"v.{minor_ver}"
    return major_ver, vl


def parse_cve_fixed_product_id(product_id, url, target_pkg="unknown", arch="x86_64", mode="arch_strict"):
    if "RHSA-" not in (url or ""):
        return None
    if not is_target_cve_product_id(product_id, target_pkg=target_pkg, arch=arch, mode=mode):
        return None
    stream, _component = product_id.split(":", 1)
    major_ver, vl = parse_stream_version(stream)
    if not major_ver:
        return None
    return {
        "product_id": product_id,
        "url": url,
        "product_name": "Red Hat Enterprise Linux",
        "vl": vl,
        "os": f"RHEL{major_ver}",
        "package": display_package_name_from_product_id(product_id, target_pkg),
        "patch_id": extract_rhsa_id_from_url(url),
        "mode": mode,
    }


def _collect_cve_patch_records_once(vex, arch="x86_64", mode="arch_strict"):
    vuln = first_vulnerability(vex)
    target_pkg = extract_cve_package_name(vex)
    records = []
    seen = set()
    for remediation in vuln.get("remediations") or []:
        if remediation.get("category") != "vendor_fix":
            continue
        url = remediation.get("url", "")
        for product_id in remediation.get("product_ids") or []:
            rec = parse_cve_fixed_product_id(product_id, url, target_pkg=target_pkg, arch=arch, mode=mode)
            if not rec:
                continue
            key = (rec["vl"], rec["os"], rec["package"], rec["patch_id"])
            if key in seen:
                continue
            seen.add(key)
            records.append(rec)
    return records


def collect_cve_patch_records(vex, arch="x86_64"):
    """Collect fixed RHSA patch rows.

    Priority:
      1. arch_strict: .x86_64 and title package match
      2. src_strict: .src and title package match
      3. src_relaxed: .src without title package match
    """
    records = _collect_cve_patch_records_once(vex, arch=arch, mode="arch_strict")
    if records:
        return records

    src_records = _collect_cve_patch_records_once(vex, arch=arch, mode="src_strict")
    if src_records:
        print("Info: No architecture-specific remediations were found; using matching .src product_ids as fallback.")
        return src_records

    relaxed_records = _collect_cve_patch_records_once(vex, arch=arch, mode="src_relaxed")
    if relaxed_records:
        print("Info: No package-matched remediations were found; using .src product_ids with relaxed package matching as fallback.")
    return relaxed_records


def build_cve_patch_table(records):
    return "\n".join(
        f"{r['product_name']}, {r['vl']} , {r['os']} , {r['package']}, {r['patch_id']}"
        for r in records
    )


def build_cve_report_info(cve_id, vex):
    doc = vex.get("document") or {}
    tracking = doc.get("tracking") or {}
    severity = ((doc.get("aggregate_severity") or {}).get("text") or "").strip()
    vuln = first_vulnerability(vex)
    notes = vuln.get("notes") or []
    title = vuln.get("title") or doc.get("title") or ""
    summary = title or extract_note_text(notes, "summary") or doc.get("title") or cve_id
    description = extract_note_text(notes, "description") or summary
    package_name = extract_cve_package_name(vex)

    refs = []
    for ref in vuln.get("references") or []:
        if ref.get("url"):
            refs.append({"href": ref.get("url"), "id": ref.get("summary") or ref.get("url"), "title": ref.get("summary") or ref.get("url"), "type": ref.get("category") or "external"})
    if not any(cve_id.lower() in (r.get("href", "").lower()) for r in refs):
        refs.append({"href": f"https://access.redhat.com/security/cve/{cve_id}", "id": cve_id, "title": cve_id, "type": "cve"})

    body = {
        "id": cve_id,
        "cves": cve_id,
        "severity": severity.capitalize() if severity else "",
        "synopsis": f"{severity.capitalize() + ': ' if severity else ''}{package_name} security update",
        "summary": summary,
        "description": f"Security Fix(es):\n\n* {summary} ({cve_id})\n\n{description}",
        "issued": tracking.get("initial_release_date") or tracking.get("current_release_date") or "",
        "lastUpdated": tracking.get("current_release_date") or "",
        "affectedProducts": ["Red Hat Enterprise Linux for x86_64 - Extended Update Support"],
        "references": refs,
        "bugzillas": [],
        "type": "security",
        "typeSeverity": f"Security Advisory ({severity.capitalize()})" if severity else "Security Advisory",
        "solution": "Refer to the related Red Hat Security Advisory listed in the patch table.",
    }
    return {"body": body}


def load_report_map(path):
    report_map = {}
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        report_map[parts[1]] = parts[0]
        except Exception as e:
            print(f"Warning: Failed to load {path}: {e}")
    return report_map


def guess_report_number(target):
    m = re.search(r"RHSA-20(\d{2}):(\d+)", target)
    if m:
        return f"L{m.group(1)}-{m.group(2)}-0T"
    m = re.search(r"CVE-20(\d{2})-(\d+)", target, re.IGNORECASE)
    if m:
        return f"L{m.group(1)}-{m.group(2)}-0T"
    return f"LYY-{target}-00"


def resolve_report_number(target, advisory_list):
    report_map = load_report_map(advisory_list)
    if target in report_map:
        print(f"Report number found in {advisory_list}: {report_map[target]}")
        return report_map[target]
    report_name = guess_report_number(target)
    print(f"Report number generated: {report_name}")
    return report_name


def extract_issue_datetime(info):
    body = (info or {}).get("body", {})
    for key in ["issued", "lastUpdated"]:
        value = body.get(key)
        if not value:
            continue
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except Exception:
            pass
    return None


def set_file_timestamp_to_issue(path, issue_dt):
    if not issue_dt:
        return False
    if issue_dt.tzinfo is None:
        issue_dt = issue_dt.replace(tzinfo=timezone.utc)
    try:
        ts = issue_dt.timestamp()
        os.utime(path, (ts, ts))
        return True
    except Exception:
        return False


def generate_security_report(errata_id, info, report_num, contacts, tpl_text, target_date,
                             product_table_rows_override=None, pkg_name_override=None,
                             errata_display_id=None):
    if not info or "body" not in info:
        return "Error: Invalid errata information"
    body = info["body"]
    data = {
        "REPORT_NUMBER": report_num,
        "DEPARTMENT": contacts.get("department", "DEPARTMENT") if isinstance(contacts, dict) else "DEPARTMENT",
        "APPROVER_NAME": get_contact_value(contacts, "APPROVER_NAME", "approver", "name"),
        "APPROVER_TITLE": get_contact_value(contacts, "APPROVER_TITLE", "approver", "title"),
        "APPROVER_PHONE": get_contact_value(contacts, "APPROVER_PHONE", "approver", "phone"),
        "APPROVER_EMAIL": get_contact_value(contacts, "APPROVER_EMAIL", "approver", "email"),
        "ISSUER_NAME": get_contact_value(contacts, "ISSUER_NAME", "issuer", "name"),
        "ISSUER_PHONE": get_contact_value(contacts, "ISSUER_PHONE", "issuer", "phone"),
        "ISSUER_EMAIL": get_contact_value(contacts, "ISSUER_EMAIL", "issuer", "email"),
        "PACKAGE_NAME": pkg_name_override or "unknown",
        "ERRATA_ID": errata_display_id or errata_id,
        "SUMMARY": format_report_text(body.get("summary", ""), width=80, indent=3),
        "DESCRIPTION": format_report_text(body.get("description", ""), width=80, indent=3),
        "PRODUCT_TABLE_ROWS": product_table_rows_override or "",
        "FOOTER_BLOCK": "",
        "APPLICABLE_SYSTEMS": "PRIMEQUEST, PRIMERGY",
        "CVES_SECTION": f"  - {errata_display_id or errata_id}\n          https://access.redhat.com/security/cve/{str(errata_display_id or errata_id).lower()}",
        "DATE": target_date.strftime("%Y.%m.%d"),
        "DATE_JP": target_date.strftime("%Y年%m月%d日"),
    }
    return Template(tpl_text).safe_substitute(data) if tpl_text else (product_table_rows_override or "")



def is_rhsa_id(value):
    return bool(re.fullmatch(r"RHSA-\d{4}:\d+", (value or "").strip(), re.IGNORECASE))


def json_value(data, key):
    try:
        if isinstance(data, str):
            data = json.loads(data)
        if isinstance(data, dict):
            return data.get(key)
    except Exception:
        pass
    return None


def get_access_token(offline_token):
    url = "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"
    payload = {
        "grant_type": "refresh_token",
        "client_id": "rhsm-api",
        "refresh_token": offline_token,
    }
    r = requests.post(url, data=payload, timeout=60)
    r.raise_for_status()
    token = json_value(r.text, "access_token")
    if not token:
        raise RuntimeError("Failed to retrieve access token from Red Hat SSO response.")
    return token


def fetch_errata_info(access_token, errata_id):
    url = f"https://api.access.redhat.com/management/v1/errata/{errata_id}"
    headers = {"Authorization": f"Bearer {access_token}", "accept": "application/json"}
    r = requests.get(url, headers=headers, timeout=60)
    r.raise_for_status()
    return r.json()


def fetch_errata_packages(access_token, errata_id, offset):
    url = f"https://api.access.redhat.com/management/v1/errata/{errata_id}/packages/?limit=50&offset={offset}"
    headers = {"Authorization": f"Bearer {access_token}", "accept": "application/json"}
    r = requests.get(url, headers=headers, timeout=60)
    r.raise_for_status()
    return r.json()


def calculate_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def verify_file_checksum(filepath, expected):
    try:
        return Path(filepath).exists() and calculate_sha256(filepath) == expected
    except Exception:
        return False


def is_critical_kernel_file(filename):
    critical_patterns = [
        r'^kernel-modules-core-.*\.rpm$',
        r'^kernel-modules-[0-9].*\.rpm$',
        r'^kernel-core-.*\.rpm$',
        r'^kernel-[0-9].*\.rpm$',
    ]
    exclude_patterns = [
        r'^kernel-debug', r'^kernel-devel', r'^kernel-headers', r'^kernel-tools',
        r'^kernel-doc', r'^kernel-abi', r'^kernel-modules-extra', r'^kernel-modules-internal'
    ]
    return (not any(re.match(p, filename) for p in exclude_patterns)) and any(re.match(p, filename) for p in critical_patterns)


def _find_first_href(data):
    if isinstance(data, dict):
        for key in ('href', 'url', 'downloadUrl'):
            value = data.get(key)
            if isinstance(value, str) and value.startswith('http'):
                return value
        for value in data.values():
            hit = _find_first_href(value)
            if hit:
                return hit
    elif isinstance(data, list):
        for item in data:
            hit = _find_first_href(item)
            if hit:
                return hit
    return None


def _extract_href_from_text(text):
    if not text:
        return None
    m = re.search(r'https?://[^\s"\']+', text)
    return m.group(0) if m else None


def _is_direct_download_response(resp):
    ctype = (resp.headers.get('content-type') or '').lower()
    dispo = (resp.headers.get('content-disposition') or '').lower()
    return ('application/x-rpm' in ctype or 'application/octet-stream' in ctype or
            '.rpm' in dispo or '.src.rpm' in dispo)


def _save_response_content(resp, out_path):
    with open(out_path, 'wb') as f:
        for chunk in resp.iter_content(chunk_size=1024 * 1024):
            if chunk:
                f.write(chunk)


def resolve_download_response(access_token, checksum):
    endpoint = f"https://api.access.redhat.com/management/v1/packages/{checksum}/download"
    headers = {"Authorization": f"Bearer {access_token}"}
    resp = requests.get(endpoint, headers=headers, timeout=60, stream=True, allow_redirects=False)

    if resp.status_code in (301, 302, 303, 307, 308):
        location = resp.headers.get('location')
        if location:
            return ('href', location)

    if _is_direct_download_response(resp):
        return ('response', resp)

    text_hint = None
    ctype = (resp.headers.get('content-type') or '').lower()
    if 'json' in ctype:
        try:
            payload = resp.json()
            href = _find_first_href(payload)
            if href:
                return ('href', href)
        except Exception:
            pass
    try:
        text_hint = resp.text
    except Exception:
        text_hint = None
    href = _extract_href_from_text(text_hint)
    if href:
        return ('href', href)

    # Final fallback: try with redirects enabled, because some environments may stream the RPM directly.
    resp2 = requests.get(endpoint, headers=headers, timeout=300, stream=True, allow_redirects=True)
    if _is_direct_download_response(resp2):
        return ('response', resp2)
    try:
        payload = resp2.json()
        href = _find_first_href(payload)
        if href:
            return ('href', href)
    except Exception:
        pass
    try:
        href = _extract_href_from_text(resp2.text)
        if href:
            return ('href', href)
    except Exception:
        pass
    raise RuntimeError(f'Unable to resolve download URL/content for checksum {checksum}; status={resp.status_code}, content-type={ctype or "unknown"}')


def download_file_with_retry(access_token, checksum, out_path, max_retries=3):
    out_path = str(out_path)
    last_error = None
    for attempt in range(1, max_retries + 1):
        try:
            mode, obj = resolve_download_response(access_token, checksum)
            if mode == 'response':
                _save_response_content(obj, out_path)
            else:
                with requests.get(obj, stream=True, timeout=300) as resp:
                    resp.raise_for_status()
                    _save_response_content(resp, out_path)
            if Path(out_path).exists() and Path(out_path).stat().st_size > 0:
                return True
            raise RuntimeError(f'Downloaded file is empty: {out_path}')
        except Exception as exc:
            last_error = exc
            try:
                Path(out_path).unlink(missing_ok=True)
            except Exception:
                pass
            print(f"Retry {attempt}/{max_retries} failed for {Path(out_path).name}: {exc}")
    if last_error:
        print(f"Download failed for {Path(out_path).name}: {last_error}")
    return False


def extract_package_name(info):
    if not info or 'body' not in info:
        return 'unknown'
    synopsis = (info['body'] or {}).get('synopsis', '')
    m = re.search(r':\s*(\S+)\s+', synopsis)
    return m.group(1) if m else 'unknown'


def extract_rhel_version(pkgs):
    for pkg in pkgs or []:
        for cs in pkg.get('contentSets', []) or []:
            m = re.search(r'rhel-(\d+)(?:\.(\d+))?-for-', cs)
            if m:
                return f"{m.group(1)}.{m.group(2)}" if m.group(2) else m.group(1)
    return 'unknown'


def check_affected_products(info):
    if not info or 'body' not in info:
        return False
    products = (info['body'] or {}).get('affectedProducts') or []
    if not products:
        return False
    target_products = {
        'Red Hat Enterprise Linux Server - AUS',
        'Red Hat Enterprise Linux for x86_64 - Extended Update Support',
        'Red Hat Enterprise Linux for x86_64 - Extended Life Cycle',
        'Red Hat Enterprise Linux for x86_64',
        'Red Hat Enterprise Linux Server - Extended Life Cycle Support',
    }
    print('Checking affected products:')
    matched = False
    for product in products:
        if product in target_products:
            print(f' [MATCH] {product}')
            matched = True
        else:
            print(f' [SKIP] {product}')
    return matched


def detect_applicable_systems(info):
    if not info or 'body' not in info:
        return 'PRIMEQUEST, PRIMERGY'
    summary = (info['body'] or {}).get('summary', '')
    return 'PRIMERGY' if '10.0' in summary else 'PRIMEQUEST, PRIMERGY'


def generate_rhsa_report(errata_id, info, pkgs, report_num, contacts, tpl_text, target_date,
                         product_table_rows_override=None, footer_block_override=None,
                         pkg_name_override=None, errata_display_id=None):
    if not info or 'body' not in info:
        return 'Error: Invalid errata information'

    body = info['body']
    pkg_name = pkg_name_override or extract_package_name(info)
    summary = body.get('summary', '')
    description = body.get('description', '')
    products = body.get('affectedProducts') or []
    applicable_systems = detect_applicable_systems(info)

    rhel_ver_str = extract_rhel_version(pkgs)
    if rhel_ver_str != 'unknown':
        rhel_major = rhel_ver_str.split('.')[0]
    else:
        m = re.search(r'Red Hat Enterprise Linux (\d+)', summary)
        rhel_major = m.group(1) if m else '?'

    full_ver = None
    vm = re.search(r'Red Hat Enterprise Linux (\d+\.\d+)', summary)
    if vm:
        full_ver = vm.group(1)
    else:
        for pkg in pkgs or []:
            for cs in pkg.get('contentSets', []) or []:
                m_cs = re.search(r'rhel-(\d+\.\d+)-for-', cs)
                if m_cs:
                    full_ver = m_cs.group(1)
                    break
            if full_ver:
                break
    if not full_ver:
        full_ver = rhel_major

    has_std = 'Red Hat Enterprise Linux for x86_64' in products
    has_eus = 'Red Hat Enterprise Linux for x86_64 - Extended Update Support' in products
    possible_aus = {
        'Red Hat Enterprise Linux Server - AUS',
        'Red Hat Enterprise Linux Server - Advanced mission critical Update Support',
    }
    has_aus = any(p in possible_aus or 'Advanced mission critical' in p or (p.endswith('- AUS') and 'Server' in p) for p in products)
    has_els = any('Extended Life Cycle Support' in p for p in products)
    if not has_els and ('ExtendedLifecycleSupport' in summary or 'Extended Lifecycle Support' in summary or 'Extended Life Cycle Support' in summary):
        has_els = True

    table_lines = []
    footnotes = []
    note_counter = 1
    base_os_name = f'Red Hat Enterprise Linux {rhel_major} (for Intel64)'

    if has_std:
        table_lines.append(f'{base_os_name}, v.{rhel_major}, RHEL{rhel_major}(Intel64), {pkg_name}, {errata_id}')
    if has_eus:
        mark = f'[※{note_counter}]'
        table_lines.append(f'{base_os_name}, v.{full_ver}, RHEL{rhel_major}(Intel64){mark}, {pkg_name}, {errata_id}')
        footnotes.append(f'{mark} RHEL Extended Update Support({full_ver}) 環境')
        note_counter += 1
    if has_aus:
        mark = f'[※{note_counter}]'
        table_lines.append(f'{base_os_name}, v.{full_ver}, RHEL{rhel_major}(Intel64){mark}, {pkg_name}, {errata_id}')
        footnotes.append(f'{mark} RHEL Advanced mission critical Update Support({full_ver}) 環境')
        note_counter += 1
    if has_els:
        mark = f'[※{note_counter}]'
        table_lines.append(f'{base_os_name}, v.{rhel_major}, RHEL{rhel_major}(Intel64){mark}, {pkg_name}, {errata_id}')
        footnotes.append(f'{mark} RHEL Extended Life Cycle Support {rhel_major} 環境')
        note_counter += 1
    if not table_lines:
        table_lines.append(f'{base_os_name}, v.{rhel_major}, RHEL{rhel_major}(Intel64), {pkg_name}, {errata_id}')

    product_table_rows = product_table_rows_override if product_table_rows_override is not None else '\n'.join(table_lines)
    footer_block = footer_block_override if footer_block_override is not None else '\n'.join(footnotes)

    data = {
        'REPORT_NUMBER': report_num,
        'DEPARTMENT': contacts.get('department', 'DEPARTMENT') if isinstance(contacts, dict) else 'DEPARTMENT',
        'APPROVER_NAME': get_contact_value(contacts, 'APPROVER_NAME', 'approver', 'name'),
        'APPROVER_TITLE': get_contact_value(contacts, 'APPROVER_TITLE', 'approver', 'title'),
        'APPROVER_PHONE': get_contact_value(contacts, 'APPROVER_PHONE', 'approver', 'phone'),
        'APPROVER_EMAIL': get_contact_value(contacts, 'APPROVER_EMAIL', 'approver', 'email'),
        'ISSUER_NAME': get_contact_value(contacts, 'ISSUER_NAME', 'issuer', 'name'),
        'ISSUER_PHONE': get_contact_value(contacts, 'ISSUER_PHONE', 'issuer', 'phone'),
        'ISSUER_EMAIL': get_contact_value(contacts, 'ISSUER_EMAIL', 'issuer', 'email'),
        'PACKAGE_NAME': pkg_name,
        'ERRATA_ID': errata_display_id or errata_id,
        'SUMMARY': format_report_text(summary, width=80, indent=3),
        'DESCRIPTION': format_report_text(description, width=80, indent=3),
        'PRODUCT_TABLE_ROWS': product_table_rows,
        'FOOTER_BLOCK': footer_block,
        'APPLICABLE_SYSTEMS': applicable_systems,
        'CVES_SECTION': '',
        'DATE': target_date.strftime('%Y.%m.%d'),
        'DATE_JP': target_date.strftime('%Y年%m月%d日'),
    }
    return Template(tpl_text).safe_substitute(data) if tpl_text else product_table_rows


def content_set_matches_arch(content_set, arch):
    if not content_set:
        return False
    if re.search(r'rhel-[67]', content_set):
        return bool(re.search(r'^rhel-[67]-server-', content_set))
    if arch == 'aarch64':
        return bool(re.search(r'^rhel-[891]0?-for-aarch64-', content_set))
    return bool(re.search(r'^rhel-[891]0?-for-x86_64-[ab]', content_set))


def select_rhsa_packages(pkgs, arch='x86_64', src_only=False):
    selected = []
    seen = set()
    for pkg in pkgs or []:
        checksum = pkg.get('checksum')
        filename = pkg.get('filename') or ''
        pkg_arch = (pkg.get('arch') or '').lower()
        if not checksum or not filename:
            continue
        if src_only:
            if pkg_arch != 'src':
                continue
        else:
            if pkg_arch and pkg_arch != arch.lower():
                continue
            content_sets = pkg.get('contentSets') or []
            if content_sets and not any(content_set_matches_arch(cs, arch) for cs in content_sets):
                continue
        if checksum in seen:
            continue
        seen.add(checksum)
        selected.append(pkg)
    selected.sort(key=lambda x: x.get('filename') or '')
    return selected


def write_tree_report(root_dir, out_path):
    root = Path(root_dir)
    lines = [f'{root.name}/']
    def walk(current, prefix=''):
        entries = sorted(current.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
        for idx, entry in enumerate(entries):
            branch = '└── ' if idx == len(entries) - 1 else '├── '
            lines.append(f"{prefix}{branch}{entry.name}{'/' if entry.is_dir() else ''}")
            if entry.is_dir():
                walk(entry, prefix + ('    ' if idx == len(entries) - 1 else '│   '))
    if root.exists():
        walk(root)
    Path(out_path).write_text('\n'.join(lines) + '\n', encoding='utf-8')


def write_hash_reports(root_dir, md5_path, sha256_path):
    import hashlib as _hashlib
    root = Path(root_dir)
    md5_lines = []
    sha_lines = []
    for rpm in sorted(root.rglob('*.rpm')):
        rel = rpm.relative_to(root)
        md5h = _hashlib.md5()
        sha = _hashlib.sha256()
        with open(rpm, 'rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                md5h.update(chunk)
                sha.update(chunk)
        md5_lines.append(f'{md5h.hexdigest()}  {rel}')
        sha_lines.append(f'{sha.hexdigest()}  {rel}')
    Path(md5_path).write_text('\n'.join(md5_lines) + ('\n' if md5_lines else ''), encoding='utf-8')
    Path(sha256_path).write_text('\n'.join(sha_lines) + ('\n' if sha_lines else ''), encoding='utf-8')


def pick_report_map_path(path_from_arg):
    if path_from_arg and Path(path_from_arg).exists():
        return path_from_arg
    if path_from_arg == 'advisory_list.txt' and Path('report-advisory.txt').exists():
        return 'report-advisory.txt'
    return path_from_arg


def resolve_output_style(is_cve_mode, encoding_mode='auto', newline_mode='auto'):
    if encoding_mode == 'auto':
        encoding = 'utf-8' if is_cve_mode else 'cp932'
    elif encoding_mode == 'sjis':
        encoding = 'cp932'
    else:
        encoding = 'utf-8'

    if newline_mode == 'auto':
        newline = None if is_cve_mode else '\r\n'
    elif newline_mode == 'crlf':
        newline = '\r\n'
    else:
        newline = None
    return encoding, newline


def write_report_file(out_path, text, is_cve_mode, encoding_mode='auto', newline_mode='auto'):
    encoding, newline = resolve_output_style(is_cve_mode, encoding_mode, newline_mode)
    with open(out_path, 'w', encoding=encoding, newline=newline) as f:
        f.write(text)
    return encoding, ('CRLF' if newline == '\r\n' else 'LF/default')


def handle_rhsa_mode(args, target_date):
    offline_token = os.getenv('OFFLINE_TOKEN')
    if not offline_token:
        raise RuntimeError('OFFLINE_TOKEN environment variable is not set.')

    arch = 'aarch64' if args.a else 'x86_64'
    errata_id = args.RHSA.strip().upper()
    access_token = get_access_token(offline_token)

    print(f'Fetching errata information for {errata_id}...')
    info = fetch_errata_info(access_token, errata_id)
    write_to_json(f'{errata_id}-info.json', info)
    print(f'Errata information saved to {errata_id}-info.json')

    all_pkgs = []
    offset = 0
    while True:
        page = fetch_errata_packages(access_token, errata_id, offset)
        body = page.get('body') or []
        all_pkgs.extend(body)
        pagination = page.get('pagination') or {}
        count = pagination.get('count', 0)
        if not body or count == 0:
            break
        if count < 50:
            break
        offset += count
    write_to_json(f'{errata_id}.json', all_pkgs)
    print(f'Errata package list saved to {errata_id}.json')

    affected_ok = check_affected_products(info)
    contacts = load_contacts(args.contacts or 'contacts.default.json')
    tpl_text = load_template(args.template or 'report_template.default.txt')
    report_map_path = pick_report_map_path(args.advisory_list)
    report_name = resolve_report_number(errata_id, report_map_path)

    if args.force_report or affected_ok:
        if args.force_report and not affected_ok:
            print('Notice: --force-report enabled. Skipping product check for report generation.')
        report = generate_rhsa_report(errata_id, info, all_pkgs, report_name, contacts, tpl_text, target_date)
        Path(args.outdir).mkdir(parents=True, exist_ok=True)
        out = Path(args.outdir) / f'{report_name}.txt'
        used_enc, used_nl = write_report_file(out, report, is_cve_mode=False, encoding_mode=args.encoding, newline_mode=args.newline)
        issue_dt = extract_issue_datetime(info)
        ok_ts = set_file_timestamp_to_issue(str(out), issue_dt)
        if ok_ts:
            print(f'Adjusted report timestamp to issued date: {issue_dt.isoformat()}')
        else:
            print('Note: Failed to adjust report timestamp or issued date not available.')
        print(f'Security report generated: {out} with date {target_date.strftime("%Y-%m-%d")} [{used_enc}, {used_nl}]')
    else:
        print('\n[INFO] Report generation skipped.')
        print('Reason: Affected products did not match the specific target list.')
        print('Tip: Use --force-report to bypass this check.\n')

    selected = select_rhsa_packages(all_pkgs, arch=arch, src_only=args.s)
    if args.g:
        before = len(selected)
        selected = [pkg for pkg in selected if 'debug' not in (pkg.get('filename') or '').lower()]
        print(f'Filtered debug-containing filenames with -g: {before} -> {len(selected)}')

    should_download = False
    if args.n:
        should_download = False
    else:
        if args.force_download:
            print('Notice: --force-download enabled. Skipping product check for download.')
            should_download = True
        elif affected_ok:
            should_download = True
        else:
            print('\n[INFO] RPM Download skipped.')
            print('Reason: Affected products did not match the specific target list.')
            print('Tip: Use --force-download to bypass this check.\n')

    if not selected:
        print('No matching RPM packages were found for the requested RHSA/architecture/options.')
        return

    base_dir = Path(args.outdir) / errata_id.replace(':', '-')
    target_subdir = 'SRPM' if args.s else arch
    target_dir = base_dir / target_subdir
    target_dir.mkdir(parents=True, exist_ok=True)

    downloaded = []
    critical_files = []
    failures = []

    for idx, pkg in enumerate(selected, 1):
        filename = pkg.get('filename') or ''
        checksum = pkg.get('checksum') or ''
        dest = target_dir / filename
        critical = is_critical_kernel_file(filename)
        if critical:
            critical_files.append((dest, checksum))
        if args.n:
            print(f'{idx}:{filename} [planned]')
            continue
        if not should_download:
            break
        print(f'{idx}:{filename}' + (' [Critical File]' if critical else ''))
        # refresh access token per file to stay close to cve14 behavior
        token = get_access_token(offline_token)
        ok = download_file_with_retry(token, checksum, str(dest), max_retries=3 if critical else 2)
        if ok:
            downloaded.append(dest)
        else:
            failures.append(filename)

    if should_download and critical_files:
        print('\n=== Critical Files Final Verification ===')
        all_ok = True
        for dest, checksum in critical_files:
            if verify_file_checksum(dest, checksum):
                print(f'✓ {dest.name} - OK')
            else:
                print(f'✗ {dest.name} - NG')
                all_ok = False
                print(' Final re-download attempt...')
                token = get_access_token(offline_token)
                if download_file_with_retry(token, checksum, str(dest), max_retries=2) and verify_file_checksum(dest, checksum):
                    print(' ✓ Re-download successful')
                else:
                    print(' ✗ Re-download failed')
        print('\nAll critical files downloaded successfully.' if all_ok else '\n⚠️ Some critical files have download issues.')

    nid = errata_id.replace(':', '-')
    write_tree_report(base_dir, base_dir / f'{nid}-tree.txt')
    if should_download:
        write_hash_reports(base_dir, base_dir / f'{nid}-md5sum.txt', base_dir / f'{nid}-sha256sum.txt')

    print(f'Output directory: {base_dir}')
    print(f'Matched packages: {len(selected)}')
    if args.n:
        print(f'Planned packages: {len(selected)}')
    elif should_download:
        print(f'Downloaded packages: {len(downloaded)}')
    if failures:
        print('Failed downloads:')
        for name in failures:
            print(f'  - {name}')


def main():
    ap = argparse.ArgumentParser(description='Red Hat CVE VEX security report generator + RHSA downloader/report generator')
    ap.add_argument('-a', action='store_true', help='arch is aarch64(default:x86_64)')
    ap.add_argument('-n', action='store_true', help='No download. List RHSA download targets only')
    ap.add_argument('-g', action='store_true', help='Skip files whose filename contains debug')
    ap.add_argument('-s', action='store_true', help='src.rpm only (RHSA mode)')
    ap.add_argument('-c', '--contacts', type=str, default=None, help='contacts JSON file')
    ap.add_argument('-t', '--template', type=str, default=None, help='template file')
    ap.add_argument('-o', '--outdir', type=str, default='.', help='output directory')
    ap.add_argument('-d', '--date', type=str, default=None, help='report date YYYY-MM-DD')
    ap.add_argument('--advisory-list', type=str, default='advisory_list.txt', help='report number mapping file')
    ap.add_argument('--force-report', action='store_true', help='Force RHSA report generation regardless of affected products')
    ap.add_argument('--force-download', action='store_true', help='Force RHSA RPM download regardless of affected products')
    ap.add_argument('--cve-json', type=str, default=None, help='use local Red Hat CSAF VEX JSON instead of downloading it')
    ap.add_argument('--encoding', choices=['auto', 'sjis', 'utf8'], default='auto', help='report output encoding: auto (RHSA=SJIS, CVE=UTF-8), sjis, utf8')
    ap.add_argument('--newline', choices=['auto', 'crlf', 'lf'], default='auto', help='report output newline: auto (RHSA=CRLF, CVE=LF/default), crlf, lf')
    ap.add_argument('RHSA', type=str, help='CVE identifier or RHSA identifier (e.g. CVE-2026-4786 or RHSA-2026:25217)')
    args = ap.parse_args()

    if args.date:
        try:
            target_date = datetime.strptime(args.date, '%Y-%m-%d')
        except ValueError:
            print(f"Error: Invalid date format '{args.date}'. Please use YYYY-MM-DD.")
            sys.exit(1)
    else:
        target_date = datetime.now()

    if is_rhsa_id(args.RHSA):
        handle_rhsa_mode(args, target_date)
        return

    if not is_cve_id(args.RHSA):
        print('Error: This script handles CVE identifiers for report generation and RHSA identifiers for report/download mode.')
        sys.exit(2)

    cve_id = normalize_cve_id(args.RHSA)
    contacts = load_contacts(args.contacts or 'contacts.default.json')
    tpl_text = load_template(args.template or 'report_template.default-cve.txt')
    arch = 'aarch64' if args.a else 'x86_64'

    print(f'Fetching Red Hat CSAF VEX information for {cve_id}...')
    if args.cve_json:
        vex = load_json_file(args.cve_json)
        print(f'CVE VEX information loaded from {args.cve_json}')
    else:
        vex = fetch_cve_vex(cve_id)
        write_to_json(f'{cve_id.lower()}-vex.json', vex)
        print(f'CVE VEX information saved to {cve_id.lower()}-vex.json')

    patch_records = collect_cve_patch_records(vex, arch=arch)
    if not patch_records:
        print('Warning: No displayable RHSA remediations were found for the requested architecture/rules.')
    else:
        print('\n=== CVE displayable product IDs and RHSA URLs ===')
        for r in patch_records:
            print(f'"{r["product_id"]}",')
            print(f'"url": "{r["url"]}"\n')
        print('=== 3-2. Patch table preview ===')
        print('3-2. 該当製品・対策Patch')
        print('(18)製品名     ,(19)VL  ,(20)対象OS     ,(21)パッケージ名    ,(22)Patch ID.')
        print('+--------------------------------------------------------------------------')
        print(build_cve_patch_table(patch_records))
        print('+--------------------------------------------------------------------------\n')

    info = build_cve_report_info(cve_id, vex)
    package_name = extract_cve_package_name(vex)
    report_name = resolve_report_number(cve_id, pick_report_map_path(args.advisory_list))
    report = generate_security_report(
        cve_id, info, report_name, contacts, tpl_text, target_date,
        product_table_rows_override=build_cve_patch_table(patch_records),
        pkg_name_override=package_name,
        errata_display_id=cve_id,
    )

    Path(args.outdir).mkdir(parents=True, exist_ok=True)
    out = Path(args.outdir) / f'{report_name}.txt'
    used_enc, used_nl = write_report_file(out, report, is_cve_mode=True, encoding_mode=args.encoding, newline_mode=args.newline)
    issue_dt = extract_issue_datetime(info)
    ok_ts = set_file_timestamp_to_issue(str(out), issue_dt)
    if ok_ts:
        print(f'Adjusted report timestamp to issued date: {issue_dt.isoformat()}')
    else:
        print('Note: Failed to adjust report timestamp or issued date not available.')
    print(f'Security report generated: {out} with date {target_date.strftime("%Y-%m-%d")} [{used_enc}, {used_nl}]')


if __name__ == '__main__':
    main()
