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

VERSION = "21.0"
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


def main():
    ap = argparse.ArgumentParser(description="Red Hat CVE VEX security report generator")
    ap.add_argument("-a", action="store_true", help="arch is aarch64(default:x86_64)")
    ap.add_argument("-c", "--contacts", type=str, default=None, help="contacts JSON file")
    ap.add_argument("-t", "--template", type=str, default=None, help="template file")
    ap.add_argument("-o", "--outdir", type=str, default=".", help="output directory")
    ap.add_argument("-d", "--date", type=str, default=None, help="report date YYYY-MM-DD")
    ap.add_argument("--advisory-list", type=str, default="advisory_list.txt", help="report number mapping file")
    ap.add_argument("--cve-json", type=str, default=None, help="use local Red Hat CSAF VEX JSON instead of downloading it")
    ap.add_argument("RHSA", type=str, help="CVE identifier, e.g. CVE-2026-4786")
    args = ap.parse_args()

    target_date = datetime.strptime(args.date, "%Y-%m-%d") if args.date else datetime.now()
    if not is_cve_id(args.RHSA):
        print("Error: This script handles CVE identifiers. Use a CVE such as CVE-2026-4786.")
        sys.exit(2)

    cve_id = normalize_cve_id(args.RHSA)
    contacts = load_contacts(args.contacts or "contacts.default.json")
    tpl_text = load_template(args.template or "report_template.default-cve.txt")
    arch = "aarch64" if args.a else "x86_64"

    print(f"Fetching Red Hat CSAF VEX information for {cve_id}...")
    if args.cve_json:
        vex = load_json_file(args.cve_json)
        print(f"CVE VEX information loaded from {args.cve_json}")
    else:
        vex = fetch_cve_vex(cve_id)
        write_to_json(f"{cve_id.lower()}-vex.json", vex)
        print(f"CVE VEX information saved to {cve_id.lower()}-vex.json")

    patch_records = collect_cve_patch_records(vex, arch=arch)
    if not patch_records:
        print("Warning: No displayable RHSA remediations were found for the requested architecture/rules.")
    else:
        print("\n=== CVE displayable product IDs and RHSA URLs ===")
        for r in patch_records:
            print(f"\"{r['product_id']}\",")
            print(f"\"url\": \"{r['url']}\"\n")
        print("=== 3-2. Patch table preview ===")
        print("3-2. 該当製品・対策Patch")
        print("(18)製品名     ,(19)VL  ,(20)対象OS     ,(21)パッケージ名    ,(22)Patch ID.")
        print("+--------------------------------------------------------------------------")
        print(build_cve_patch_table(patch_records))
        print("+--------------------------------------------------------------------------\n")

    info = build_cve_report_info(cve_id, vex)
    package_name = extract_cve_package_name(vex)
    report_name = resolve_report_number(cve_id, args.advisory_list)
    report = generate_security_report(
        cve_id, info, report_name, contacts, tpl_text, target_date,
        product_table_rows_override=build_cve_patch_table(patch_records),
        pkg_name_override=package_name,
        errata_display_id=cve_id,
    )

    Path(args.outdir).mkdir(parents=True, exist_ok=True)
    out = Path(args.outdir) / f"{report_name}.txt"
    with open(out, "w", encoding="utf-8") as f:
        f.write(report)

    issue_dt = extract_issue_datetime(info)
    ok_ts = set_file_timestamp_to_issue(str(out), issue_dt)
    if ok_ts:
        print(f"Adjusted report timestamp to issued date: {issue_dt.isoformat()}")
    else:
        print("Note: Failed to adjust report timestamp or issued date not available.")
    print(f"Security report generated: {out} with date {target_date.strftime('%Y-%m-%d')}")


if __name__ == "__main__":
    main()
