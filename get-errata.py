#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Tsuyoshi Nagata
#
VERSION = "10.5"
from itertools import count
import re, os, json, requests, time, sys, argparse, hashlib
from datetime import datetime
from string import Template
from pathlib import Path as _Path

def json_value(data, key):
    try:
        return json.loads(data).get(key)
    except json.JSONDecodeError:
        return None

def get_access_token(offline_token):
    url = "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"
    payload = {"grant_type":"refresh_token","client_id":"rhsm-api","refresh_token":offline_token}
    r = requests.post(url, data=payload); r.raise_for_status(); return json_value(r.text, "access_token")

def fetch_errata_info(access_token, errata_id):
    url = f"https://api.access.redhat.com/management/v1/errata/{errata_id}"
    h = {"Authorization": f"Bearer {access_token}", "accept":"application/json"}
    r = requests.get(url, headers=h); r.raise_for_status(); return r.json()

def fetch_errata_packages(access_token, errata_id, offset):
    url = f"https://api.access.redhat.com/management/v1/errata/{errata_id}/packages/?limit=50&offset={offset}"
    h = {"Authorization": f"Bearer {access_token}"}
    r = requests.get(url, headers=h); r.raise_for_status(); return r.json()

def write_to_json(filename, data):
    with open(filename,'w',encoding='utf-8') as f: json.dump(data,f,indent=4,ensure_ascii=False)

def calculate_sha256(filepath):
    try:
        s = hashlib.sha256();
        with open(filepath,'rb') as f:
            for b in iter(lambda: f.read(4096), b""): s.update(b)
        return s.hexdigest()
    except Exception:
        return None

def verify_file_checksum(filepath, expected):
    return os.path.exists(filepath) and calculate_sha256(filepath)==expected

def is_critical_kernel_file(fn):
    crit = [r'^kernel-modules-core-.*\.rpm$', r'^kernel-modules-[0-9].*\.rpm$', r'^kernel-core-.*\.rpm$', r'^kernel-[0-9].*\.rpm$']
    ex = [r'^kernel-debug', r'^kernel-devel', r'^kernel-headers', r'^kernel-tools', r'^kernel-doc', r'^kernel-abi', r'^kernel-modules-extra', r'^kernel-modules-internal']
    return (not any(re.match(p,fn) for p in ex)) and any(re.match(p,fn) for p in crit)

def download_file_with_retry(tok, checksum, fn, max_retries=3):
    for a in range(max_retries):
        if a>0: print(f" Retry {a}/{max_retries}..."); time.sleep(5)
        cmd = f"curl -H \"Authorization: Bearer {tok}\" \"https://api.access.redhat.com/management/v1/packages/{checksum}/download\" | jq | grep href.:|gawk '{{print \"curl \" $2 \" -o {fn}\"}}'|sed -e 's/,//g'|sh"
        os.system(cmd)
        if verify_file_checksum(fn, checksum): return True
        # if os.path.exists(fn): os.remove(fn)
    return False

def extract_package_name(info):
    if not info or 'body' not in info: return 'unknown'
    syn = info['body'].get('synopsis',''); m = re.search(r':\s*(\S+)\s+', syn)
    return m.group(1) if m else 'unknown'

def extract_rhel_version(pkgs):
    for p in pkgs:
        for cs in p.get('contentSets',[]):
            m = re.search(r'rhel-(\d+)(?:\.(\d+))?-for-', cs)
            if m: return f"{m.group(1)}.{m.group(2)}" if m.group(2) else m.group(1)
    return 'unknown'

def load_contacts(path):
    try:
        with open(path,'r',encoding='utf-8') as f: return json.load(f)
    except Exception as e:
        print(f"Warning: contacts load failed from {path}: {e}")
        return {}

def build_recipients_section(recipients):
    lines=[""]
    for r in (recipients or []):
        hdr = "".join([" →", r.get('label',''), (" "+r.get('org','')) if r.get('org') else '', (" "+r.get('name','')) if r.get('name') else ''])
        if hdr.strip(): lines.append(hdr)
        if r.get('email'): lines.append(f" E-mail:{r['email']}")
        if r.get('phone'): lines.append(f" TEL:{r['phone']}")
    return "\n".join(lines)

def load_template(path):
    try:
        with open(path,'r',encoding='utf-8') as f: return f.read()
    except Exception as e:
        print(f"Warning: template load failed from {path}: {e}")
        return None

def generate_security_report(errata_id, info, pkgs, report_num, contacts, tpl_text):
    if not info or 'body' not in info: return 'Error: Invalid errata information'
    body = info['body']; summary = body.get('summary','')
    footer_note2=""
    version_patch_level2=""
    pkg_name = extract_package_name(info)
    rhel_ver = extract_rhel_version(pkgs); rhel_major = rhel_ver.split('.')[0]
    vl_display = f"v.{rhel_major}"; os_display = f"RHEL{rhel_major}(Intel64)"; footer_note = ''
    vm = re.search(r"Red Hat Enterprise Linux (\d+\.\d+)", summary)
    if vm:
        fv = vm.group(1); variants={"Advanced Mission Critical Update Support":"Advanced mission critical Update Support","Update Services for SAP Solutions":"Update Services for SAP Solutions","Telecommunications Update Service":"Telecommunications Update Service","Extended Update Support":"Extended Update Support"}
        det=None
        for k,v in variants.items():
            if k in summary: det=v; break
        if det:
            rhel_major = fv.split('.')[0]; vl_display=f"v.{fv}"; os_display=f"RHEL{rhel_major}(Intel64)[※1]"; footer_note=f"[※1] RHEL {det}({fv}) 環境"; os_display2=f"RHEL{rhel_major}(Intel64)[※2]"
            if det and "Extended Update Support" in det:
                footer_note2=f"[※2] RHEL Advanced mission critical Update Support({fv}) 環境";
                version_patch_level2=f"Red Hat Enterprise Linux {rhel_major} (for Intel64), {vl_display}, {os_display2}, {pkg_name}, {errata_id}"
    date = datetime.now().strftime('%Y.%m.%d'); date_jp = datetime.now().strftime('%Y年%m月%d日')
    cves = [c.strip() for c in body.get('cves','').strip().split() if c.strip().startswith('CVE-')]
    bullets=[]
    for c in cves:
        for b in body.get('bugzillas',[]):
            t=b.get('title','');
            if c in t:
                parts=t.split(c,1);
                if len(parts)>1: bullets.append(f" * {parts[1].strip()} ({c})"); break
    cve_section="\n".join(bullets)
    cve_links="\n".join([f"  - {c}\n          https://access.redhat.com/security/cve/{c}" for c in cves])
    dept = contacts.get('department','DEPARTMENT')
    approver = contacts.get('approver',{})
    issuer = contacts.get('issuer',{})
    recipients = contacts.get('recipients',[])
    data = {
        'RECIPIENTS_SECTION': build_recipients_section(recipients),
        'REPORT_NUMBER': report_num,
        'DEPARTMENT': dept,
        'APPROVER_NAME': approver.get('name',''),
        'APPROVER_TITLE': approver.get('title',''),
        'APPROVER_EMAIL': approver.get('email',''),
        'APPROVER_PHONE': approver.get('phone_mobile',''),
        'ISSUER_NAME': issuer.get('name',''),
        'ISSUER_TITLE': issuer.get('title',''),
        'ISSUER_EMAIL': issuer.get('email',''),
        'ISSUER_PHONE': issuer.get('phone_mobile',''),
        'PACKAGE_NAME': pkg_name,
        'ERRATA_ID': errata_id,
        'SUMMARY': body.get('summary',''),
        'DESCRIPTION': body.get('description',''),
        'VL_DISPLAY': vl_display,
        'OS_DISPLAY': os_display,
        'RHEL_MAJOR': rhel_major,
        'FOOTER_NOTE': footer_note,
        'FOOTER_NOTE2': footer_note2,
        'VERSION_PATCH_LEVEL2': version_patch_level2,
        'CVES_SECTION': cve_section,
        'CVES_LINKS': cve_links,
        'DATE': date,
        'DATE_JP': date_jp,
    }
    if not tpl_text: return 'Error: No template provided (use -t or default file).'
    return Template(tpl_text).safe_substitute(data)

def main():
    ap = argparse.ArgumentParser(description='Red Hat Errata downloader + security report generator')
    ap.add_argument('-a', action='store_true', help='arch is aarch64(default:x86_64)')
    ap.add_argument('-n', action='store_true', help='No download. just recreate a download script')
    ap.add_argument('-g', action='store_true', help='Skip debug/debuginfo')
    ap.add_argument('-s', action='store_true', help='src.rpm only')
    ap.add_argument('-r', type=str, default='L25-9999-99', help='Security report number (e.g., L25-0449-00)')
    ap.add_argument('-c','--contacts', type=str, default=None, help='Path to contacts.json')
    ap.add_argument('-t','--template', type=str, default=None, help='Path to security_report_template.txt')
    ap.add_argument('-o','--outdir', type=str, default='.', help='Output directory for report')
    ap.add_argument('RHSA', type=str, help='Red Hat Security Advisory identifier (e.g., RHSA-2024:4108)')
    args = ap.parse_args()

    offline_token = os.getenv('OFFLINE_TOKEN')
    if not offline_token: raise Exception('OFFLINE_TOKEN environment variable is not set.')
    access_token = get_access_token(offline_token)
    errata_id = args.RHSA

    print(f"Fetching errata information for {errata_id}...")
    info = fetch_errata_info(access_token, errata_id)
    if info:
        write_to_json(f"{errata_id}-info.json", info)
        print(f"Errata information saved to {errata_id}-info.json")
    else:
        print("Warning: Failed to fetch errata information")

    filename = f"{errata_id}.json"; pkgs=[]
    for off in count(start=0, step=50):
        pd = fetch_errata_packages(access_token, errata_id, off)
        pkgs.extend(pd['body']);
        if pd['pagination']['count']==0: break
    write_to_json(filename, pkgs)

    # Defaults when -c / -t are not provided
    contacts_path = args.contacts or 'contacts.default.json'
    template_path = args.template or 'report_template.default.txt'
    contacts = load_contacts(contacts_path)
    tpl_text = load_template(template_path)
    temp_name = errata_id.split(":")[1]
    if info:
        report = generate_security_report(errata_id, info, pkgs, f"L25-{temp_name}-00", contacts, tpl_text)
        _Path(args.outdir).mkdir(parents=True, exist_ok=True)
        out = _Path(args.outdir) / f"L25-{temp_name}-00.txt"
        with open(out,'w',encoding='utf-8') as f: f.write(report)
        print(f"Security report generated: {out}")

    match=[]
    for it in pkgs:
        if it['arch']=='src': match.append(it); break
    pattern = r"^rhel-[891]0?-for-x86_64-[ab]"; pattern_a = r"^rhel-[891]0?-for-aarch64-[ab]"
    if args.a: pattern = pattern_a
    prev="e242e4a03507144df7ebd084d568fd2bf90d28b"
    for p in pkgs:
        c=p['checksum']
        for cs in p['contentSets']:
            pat = pattern
            if re.search(r"rhel-[67]", cs): pat = r"^rhel-[67]-server-"
            if re.search(pat, cs) and (prev!=c): match.append(p); prev=c; break

    #sh = f"{filename[:-5]}.sh"
    #with open(sh,'w',encoding='utf-8') as sf:
    #    sf.write(f'export access_token={access_token};')
    #    sf.write('export fileno=1;\n')
    #    for d in match:
    #        c=d['checksum']; fn=d['filename']
    #        sf.write(f'export filename={fn};')
    #        sf.write(f'export checksum={c};')
    #        sf.write('echo $fileno:$filename;let fileno=fileno+1;')
    #        sf.write('sleep 2;')
    #        sf.write("curl -H "Authorization: Bearer $access_token" "https://api.access.redhat.com/management/v1/packages/$checksum/download"
    # jq 
    # grep href.:
    # gawk '{{print "curl " $2 " -o $filename"}}'
    # sed -e 's/,//g'
    # sh ;
    # ")

    if not args.n:
        crit=[]; fno=1
        for d in match:
            tok = get_access_token(offline_token)
            c=d['checksum']; fn=d['filename']
            critical = is_critical_kernel_file(fn)
            if critical: crit.append({'filename':fn,'checksum':c}); print(f'{fno}:{fn} [Critical File]')
            if 'kernel-rt-debug' in fn: print(f'{fno}:{fn} Skipping kernel-rt-debug download'); fno+=1; continue
            if args.g and ('-debug' in fn): print(f'{fno}:{fn} Skipping debug download'); fno+=1; continue
            if args.s and ('src.rpm' not in fn): print(f'{fno}:{fn} Skipping download'); continue
            if critical:
                ok = download_file_with_retry(tok, c, fn, 3)
                if not ok: print(f'⚠️ Critical file {fn} download failed!')
            else:
                print(f'{fno}:{fn}')
                cmd = f"curl -H \"Authorization: Bearer {tok}\" \"https://api.access.redhat.com/management/v1/packages/{c}/download\" | jq | grep href.:|gawk '{{print \"curl \" $2 \" -o {fn}\"}}'|sed -e 's/,//g'|sh"
                os.system(cmd)
                if not os.path.exists(fn): os.system('sleep 5;'); os.system(cmd)
                os.system('sleep 2;')
            fno+=1
        if crit:
            print("\n=== Critical Files Final Verification ===")
            all_ok=True
            for cf in crit:
                if verify_file_checksum(cf['filename'], cf['checksum']): print(f"✓ {cf['filename']} - OK")
                else:
                    print(f"✗ {cf['filename']} - NG"); all_ok=False
                    print(" Final re-download attempt...")
                    tok=get_access_token(offline_token)
                    if download_file_with_retry(tok, cf['checksum'], cf['filename'], 2): print(" ✓ Re-download successful"); all_ok=True
                    else: print(" ✗ Re-download failed")
            print("\nAll critical files downloaded successfully." if all_ok else "\n⚠️ Some critical files have download issues.")

    ddir = errata_id.replace(':','-')
    os.system(f"mkdir -p {ddir}/SRPM; mv *src.rpm {ddir}/SRPM 2>/dev/null")
    arch = 'aarch64' if args.a else 'x86_64'
    os.system(f"mkdir -p {ddir}/{arch}; mv *.rpm {ddir}/{arch} 2>/dev/null")
    nid = errata_id.replace(':','-')
    os.system(f"md5sum {ddir}/*/*.rpm >{ddir}/{nid}-md5sum.txt 2>/dev/null")
    os.system(f"sha256sum {ddir}/*/*.rpm >{ddir}/{nid}-sha256sum.txt 2>/dev/null")
    os.system(f"LANG=C tree {ddir} >{ddir}/{nid}-tree.txt 2>/dev/null")

if __name__=='__main__':
    main()
