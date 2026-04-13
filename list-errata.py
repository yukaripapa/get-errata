#!/usr/bin/python
# SPDX-License-Identifier: GPL-2.0-or-later
# list-errata_v3_4.py
# - Reads default-support-list.txt at runtime
# - Package = 2nd word after severity prefix in synopsis
# - Match rule: exact match OR base-before-colon match (e.g., 'gimp:2.8' matches 'gimp')
# - Mark only when package matches AND synopsis has Important/Critical
# - When mark, run: ./get-errata.py -n {errata-id}
# - ALWAYS advance lookup_no each loop

import re
import os
import json
import requests
import time
import argparse
import sys
from datetime import datetime

TOKEN_URL = "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"
API_BASE = "https://api.access.redhat.com/management/v1"
REPORT_MARK = "need-action to generate report"
SUPPORT_LIST_PATH = 'default-support-list.txt'
REPORT_ADVISORY_FILE = 'report-advisory.txt'

# --- Teams Notification Settings ---
WEBHOOK_URL = os.getenv('WEBHOOK_URL')
if WEBHOOK_URL is None or WEBHOOK_URL.strip() == '':
    raise RuntimeError('WEBHOOK_URL 環境変数が設定されていません。')
MENTION_LIST = ['TEAMS-USER1', 'TEAMS-USER2']
_env_mentions = os.getenv('MENTION_LIST')
if _env_mentions:
    try:
        parsed = json.loads(_env_mentions)
        if isinstance(parsed, list):
            MENTION_LIST = [str(x).strip() for x in parsed if str(x).strip()]
        else:
            raise ValueError
    except Exception:
        tokens = re.split(r'[,\\s]+', _env_mentions)
        MENTION_LIST = [t.strip() for t in tokens if t.strip()]

def make_card(body, mention_list):
    entries = []
    text_head = ""
    for m in mention_list:
        text_head += f"<at>{m}@fujitsu.com</at>"
        entries.append({ "type": "mention",
                         "text": f"<at>{m}@fujitsu.com</at>",
                         "mentioned": {
                             "id": "memberEmail",
                             "name": f"{m.split('@')[0]}",
                         },
                         })
    body_list = [{
        "type": "TextBlock",
        "text": "セキュリティニュース監視 " + text_head,
    }]
    for line in body:
        body_list.append(
            {
                "type": "TextBlock",
                "text": line,
                "wrap": "true",
                "fontType": "monospace",
                "size": "small"
            })
    data = { "type": "message",
             "attachments":  [ {
                 "contentType": "application/vnd.microsoft.card.adaptive",
                 "contentUrl": "",
                 "content": {
                     "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                     "type": "AdaptiveCard",
                     "version": "1.4",
                     "body": body_list,
                     "msteams": {
                         "width": "full",
                         "entries": entries
                     }
                 }
             } ]
    }
    return data

def send_teams_notification(advisory_id, synopsis):
    report_no = None
    if os.path.exists(REPORT_ADVISORY_FILE):
        try:
            with open(REPORT_ADVISORY_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[1] == advisory_id:
                        report_no = parts[0]
                        break
        except Exception as e:
            print(f"[WARN] Notification skipped: Failed to read mapping file: {e}")
            return

    if not report_no:
        print(f"[WARN] Notification skipped: Report number not found for {advisory_id}")
        return

    report_path = os.path.join(f"./", f"{report_no}.txt")
    report_lines = []
    
    if os.path.exists(report_path):
        try:
            with open(report_path, 'r', encoding='utf-8') as f:
                report_lines = f.readlines()
        except Exception as e:
            print(f"[WARN] Failed to read report file {report_path}: {e}")
            report_lines = ["(Report file read error)"]
    else:
        report_lines = ["(Report file not found)"]

    body = []
    body.append(f"Advisory URL: https://access.redhat.com/errata/{advisory_id}")
    body.append(f"Synopsis: {synopsis}")
    body.append(f"should be mapped to Report ID:   {report_no}")
    body.append("-" * 40)

    card = make_card(body, MENTION_LIST)
    try:
        print(f"[NOTIFY] Sending Teams notification for {advisory_id}...")
        response = requests.post(WEBHOOK_URL, json=card)
        response.raise_for_status()
        print("[NOTIFY] Success.")
    except requests.exceptions.RequestException as e:
        print(f"Error occured in posting to teams: {e}", file=sys.stderr)

# ---------------------------------------

def json_value(data, key):
    try:
        parsed_data = json.loads(data)
        return parsed_data.get(key)
    except json.JSONDecodeError:
        return None

def get_access_token(offline_token):
    payload = {
        "grant_type": "refresh_token",
        "client_id": "rhsm-api",
        "refresh_token": offline_token,
    }
    r = requests.post(TOKEN_URL, data=payload)
    r.raise_for_status()
    token = json_value(r.text, "access_token")
    if not token:
        raise RuntimeError('access_token を取得できませんでした。')
    return token

def fetch_errata(access_token, errata_id):
    url = f"{API_BASE}/errata/{errata_id}"
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        r = requests.get(url, headers=headers)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()
    except requests.exceptions.HTTPError as e:
        print(f"[WARN] API HTTP Error fetching {errata_id}: {e}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[WARN] Network Error fetching {errata_id}: {e}")
        return None

def load_support_list(path: str) -> set:
    names = []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith('#'):
                    names.append(s.lower())
    except FileNotFoundError:
        pass
    return set(names)

# --- [修正箇所] synopsisだけでなく、APIのseverityフィールドも確実にチェックする ---
def has_high_severity(body: dict) -> bool:
    synopsis = (body.get('synopsis') or '').lower()
    severity = (body.get('severity') or '').lower()
    return ('important' in severity) or ('critical' in severity) or ('important' in synopsis) or ('critical' in synopsis)

def check_affected_products(info):
    if not info or 'body' not in info:
        return False
    products = info['body'].get('affectedProducts', [])
    if not products:
        return False
    target_products = {
        "Red Hat Enterprise Linux Server - AUS",
        "Red Hat Enterprise Linux for x86_64 - Extended Update Support",
        "Red Hat Enterprise Linux for x86_64",
        "Red Hat Enterprise Linux Server - Extended Life Cycle Support"
    }
    print("Checking affected products:")
    match_found = False
    for p in products:
        if p in target_products:
            print(f" [MATCH] {p}")
            match_found = True
        else:
            print(f" [SKIP] {p}")
    return match_found

def package_from_synopsis(synopsis: str) -> str:
    t = (synopsis or '').strip()
    m = re.match(r"^(Important|Critical|Moderate):\s*(.*)$", t, flags=re.IGNORECASE)
    if m:
        t = m.group(2).strip()
    m2 = re.match(r"^([A-Za-z0-9_.:-]+)", t)
    return m2.group(1).lower() if m2 else ''

def base_before_colon(token: str) -> str:
    if token is None:
        return ''
    parts = token.split(':', 1)
    return parts[0]

# --- [修正箇所] 引数として文字列(synopsis)ではなく辞書(body)を受け取るように変更 ---
def should_mark(body: dict, support_names: set) -> bool:
    synopsis = body.get('synopsis', '')
    pkg = package_from_synopsis(synopsis)
    base = base_before_colon(pkg)
    pkg_match = (pkg in support_names) or (base in support_names)
    return bool(pkg_match and has_high_severity(body))

def update_report_mapping(advisory_id: str):
    if not advisory_id:
        return

    current_yy = datetime.now().strftime("%y")
    prefix = f"L{current_yy}"
    
    max_seq = 0
    exists = False
    
    if os.path.exists(REPORT_ADVISORY_FILE):
        try:
            with open(REPORT_ADVISORY_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        rep_no, adv_id = parts[0], parts[1]
                        
                        if adv_id == advisory_id:
                            exists = True
                        
                        if rep_no.startswith(prefix) and rep_no.endswith("-00"):
                            try:
                                seq_str = rep_no.split('-')[1]
                                seq = int(seq_str)
                                if seq > max_seq:
                                    max_seq = seq
                            except (IndexError, ValueError):
                                pass
        except Exception as e:
            print(f"[WARN] Failed to read {REPORT_ADVISORY_FILE}: {e}")

    if exists:
        return

    new_seq = max_seq + 1
    new_report_no = f"{prefix}-{str(new_seq).zfill(4)}-00"
    
    try:
        with open(REPORT_ADVISORY_FILE, 'a', encoding='utf-8') as f:
            f.write(f"{new_report_no}\t{advisory_id}\n")
            f.close()
        print(f"[INFO] Added to {REPORT_ADVISORY_FILE}: {new_report_no}\t{advisory_id}")
    except Exception as e:
        print(f"[ERROR] Failed to write to {REPORT_ADVISORY_FILE}: {e}")

def run_report(advisory_id: str, synopsis: str, sleep_time: int = 5):
    if not advisory_id:
        return
    
    if sleep_time > 0:
        print(f"[REPORT] Sleeping {sleep_time} seconds before calling get-errata.py...")
        time.sleep(sleep_time)
        
    update_report_mapping(advisory_id)

    cmd = f"./get-errata/get-errata.py -c ./contacts.default.json -t ./report_template.default.txt --advisory-list ./report-advisory.txt -o ./ -n {advisory_id}"
    print(f"[REPORT] run: {cmd}")
    try:
        ret = os.system(cmd)
        if ret == 0:
            send_teams_notification(advisory_id,synopsis)
        else:
            print(f"[REPORT] Command failed with return code: {ret}")
    except Exception as e:
        print(f"[REPORT] failed: {e}")

def increment_lookup_no(lookup_no: str) -> str:
    year, no = lookup_no.split(":")
    no_i = int(no) + 1
    return f"{year}:{str(no_i).zfill(4)}"

def decrement_lookup_no(lookup_no: str) -> str:
    year, no = lookup_no.split(":")
    no_i = max(1, int(no) - 1)
    return f"{year}:{str(no_i).zfill(4)}"

MAX_ERROR_COUNT = 400
MAX_FETCH_COUNT = 40

def main():
    parser = argparse.ArgumentParser(description='Red Hat Errata crawler wrapper')
    parser.add_argument('--reverse-start', '-R', type=str,
                        help='Start advisory ID to scan backward (e.g., RHSA-2025:22802)')
    parser.add_argument('--reverse-count', type=int, default=1000,
                        help='How many IDs to go backward (default: 1000)')
    parser.add_argument('--sleep', type=int, default=5,
                        help='Sleep seconds between API calls (default: 5)')
    parser.add_argument('--exec-sleep', type=int, default=5,
                        help='Sleep seconds before executing get-errata.py to prevent HTTP 500 (default: 5)')
    args = parser.parse_args()

    offline_token = os.getenv('OFFLINE_TOKEN')
    if not offline_token:
        raise RuntimeError('OFFLINE_TOKEN 環境変数が設定されていません。')
    access_token = get_access_token(offline_token)
    support_names = load_support_list(SUPPORT_LIST_PATH)
    if not support_names:
        print('[WARN] default-support-list.txt が見つからないか空です。support マッチ無しで続行します。')

    # === Reverse Back-Report mode ===
    if args.reverse_start:
        start_id = args.reverse_start.strip()
        if not re.match(r'^(RHSA|RHBA)-\d{4}:\d{4,5}$', start_id):
            raise RuntimeError('書式エラー: --reverse-start は RHSA-YYYY:NNNN または RHBA-YYYY:NNNN を指定してください。')
        start_no = start_id[5:]
        current_no = start_no
        print(f"[Reverse] 指定開始ID: {start_id} から {args.reverse_count} 件分を逆方向にスキャンします (レポート生成のみ)。")
        
        for i in range(args.reverse_count):
            time.sleep(args.sleep)
            
            found_any = False
            for typ in ('RHSA', 'RHBA'):
                advisory_key = f'{typ}-{current_no}'
                data = fetch_errata(access_token, advisory_key)
                if data is None:
                    continue
                should_generate = False            
                if check_affected_products(data):
                    should_generate = True
                body = data.get('body', {})
                advisory_id = body.get('id', f'UNKNOWN-{current_no}')
                synopsis = body.get('synopsis', '')
                
                # --- [修正箇所] should_markにbody全体を渡す ---
                found_any = True if (should_generate and should_mark(body, support_names)) else False
                
                if found_any is True:
                    print(f"[Reverse] {advisory_id} : {synopsis} => Generating Security News...")
                    run_report(advisory_id, synopsis, args.exec_sleep)
            
            current_no = decrement_lookup_no(current_no)
        print('[Reverse] 逆スキャン完了。')
        return

    # === Default forward-scan behavior ===
    lookup_file_path = "get-errata/last_lookup.txt"
    try:
        with open(lookup_file_path, 'r', encoding='utf-8') as f:
            last_lookup_full = f.read().strip()
            print(f"チェック済みerrata番号: {last_lookup_full}")
    except FileNotFoundError:
        print(f"{lookup_file_path} が見つかりません。")
        return

    last_lookup = last_lookup_full[5:]
    lookup_no = increment_lookup_no(last_lookup)
    errata_list = []
    fetch_count = 0
    
    for _ in range(0, MAX_FETCH_COUNT):
        error_count = 0
        for _ in range(0, MAX_ERROR_COUNT):
            time.sleep(args.sleep)
            
            data = fetch_errata(access_token, f'RHSA-{lookup_no}')
            if data is None:
                data = fetch_errata(access_token, f'RHBA-{lookup_no}')
                
            if data is None:
                error_count += 1
            else:
                body = data.get('body', {})
                advisory_id = body.get('id', f'UNKNOWN-{lookup_no}')
                synopsis = body.get('synopsis', '')
                fetch_count += 1
                error_count = 0
                errata_list.append(body)
                should_generate = False
                if check_affected_products(data):
                    should_generate = True
                
                # --- [修正箇所] should_markにbody全体を渡す ---
                mark = REPORT_MARK if (should_generate and should_mark(body, support_names)) else ''
                
                display_id = advisory_id if not mark else f"**{advisory_id}**"
                print(f"Scanning {display_id} : {synopsis} {mark}")
                if mark == REPORT_MARK:
                    run_report(advisory_id, synopsis, args.exec_sleep)
                    
            lookup_no = increment_lookup_no(lookup_no)
            if error_count == MAX_ERROR_COUNT:
                break
        print(f"Total new {fetch_count} errata found.")
        break

    # optional: kernel/glibc download path retained
    download_list = []
    for e in errata_list:
        syn = e.get('synopsis', '')
        if re.search(r'(kernel|glibc)', syn) and not re.search(r'kernel-rt', syn):
            download_list.append(e)
            
    next_download_list = []
    for e in download_list:
        synopsis = e.get('synopsis', '')
        advisory_id = e.get('id', '')
        advisory_no = advisory_id[5:] if advisory_id else ''
        if advisory_no > last_lookup:
            next_download_list.append(e)
        should_generate = False
        
        time.sleep(args.sleep)
        data = fetch_errata(access_token, advisory_id)
        
        if check_affected_products(data):
            should_generate = True
        
        # --- [修正箇所] 取得したデータのbodyを使用して判定する ---
        fetched_body = data.get('body', e) if data else e
        mark = REPORT_MARK if (should_generate and should_mark(fetched_body, support_names)) else ''
        
        display_id = advisory_id if not mark else f"**{advisory_id}**"
        print(f"{display_id} {synopsis} {mark}")
        if mark == REPORT_MARK:
            run_report(advisory_id, synopsis, args.exec_sleep)

        if os.path.exists(advisory_id) and os.path.isdir(advisory_id):
            print(f"[REPORT] Directory '{advisory_id}' already exists. Skipping DOWNLOADING.")
            continue
            
        if args.exec_sleep > 0:
            print(f"[DOWNLOAD] Sleeping {args.exec_sleep} seconds before calling get-errata.py...")
            time.sleep(args.exec_sleep)
            
        os.system(f"mkdir {advisory_id}; cd {advisory_id}; ../get-errata/get-errata.py -c ../contacts.default.json -t ../report_template.default.txt --advisory-list ../report-advisory.txt -o ../ -g {advisory_id}")
        
    if next_download_list:
        print("以上のerrataのダウンロードを実行しました。")
    else:
        print("errataはありません。")
        
    if next_download_list:
        last_id = next_download_list[-1].get('id', '')
        if last_id:
            with open(lookup_file_path, 'w', encoding='utf-8') as f:
                print(last_id, file=f)

if __name__ == '__main__':
    main()
