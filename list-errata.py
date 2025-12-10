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
from datetime import datetime

TOKEN_URL = "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"
API_BASE = "https://api.access.redhat.com/management/v1"
REPORT_MARK = "need-action to generate report"
SUPPORT_LIST_PATH = 'default-support-list.txt'
REPORT_ADVISORY_FILE = 'report-advisory.txt'


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
    r = requests.get(url, headers=headers)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


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


def synopsis_has_high(synopsis: str) -> bool:
    s = (synopsis or '').lower()
    return ('important' in s) or ('critical' in s)


def package_from_synopsis(synopsis: str) -> str:
    t = (synopsis or '').strip()
    m = re.match(r"^(Important|Critical|Moderate):\s*(.*)$", t, flags=re.IGNORECASE)
    if m:
        t = m.group(2).strip()
    m2 = re.match(r"^([A-Za-z0-9_.:-]+)", t)
    return m2.group(1).lower() if m2 else ''


def base_before_colon(token: str) -> str:
    # Return substring before ':' if present; else the original token
    if token is None:
        return ''
    parts = token.split(':', 1)
    return parts[0]


def should_mark(synopsis: str, support_names: set) -> bool:
    pkg = package_from_synopsis(synopsis)
    base = base_before_colon(pkg)
    # exact match OR base-before-colon match
    pkg_match = (pkg in support_names) or (base in support_names)
    return bool(pkg_match and synopsis_has_high(synopsis))


def update_report_mapping(advisory_id: str):
    """
    report-advisory.txt を読み込み、アドバイザリIDがなければ新規レポート番号を採番して追記する。
    レポート番号形式: LYY-XXXX-00 (YY:西暦下2桁, XXXX:連番)
    """
    if not advisory_id:
        return

    # 現在の年のプレフィックス (例: "L25")
    current_yy = datetime.now().strftime("%y")
    prefix = f"L{current_yy}"
    
    max_seq = 0
    exists = False
    
    # ファイル読み込みと解析
    if os.path.exists(REPORT_ADVISORY_FILE):
        try:
            with open(REPORT_ADVISORY_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        rep_no, adv_id = parts[0], parts[1]
                        
                        # 既に存在するかチェック
                        if adv_id == advisory_id:
                            exists = True
                        
                        # 連番の最大値を取得 (現在の年のもののみ対象)
                        # 形式 LYY-XXXX-00 を想定
                        if rep_no.startswith(prefix) and rep_no.endswith("-00"):
                            try:
                                # L25-XXXX-00 -> split('-') -> ['L25', 'XXXX', '00']
                                seq_str = rep_no.split('-')[1]
                                seq = int(seq_str)
                                if seq > max_seq:
                                    max_seq = seq
                            except (IndexError, ValueError):
                                pass
        except Exception as e:
            print(f"[WARN] Failed to read {REPORT_ADVISORY_FILE}: {e}")

    if exists:
        # print(f"[INFO] Advisory {advisory_id} is already in {REPORT_ADVISORY_FILE}.")
        return

    # 新しい番号の生成 (最大値 + 1)
    new_seq = max_seq + 1
    new_report_no = f"{prefix}-{str(new_seq).zfill(4)}-00"
    
    # ファイルへ追記
    try:
        with open(REPORT_ADVISORY_FILE, 'a', encoding='utf-8') as f:
            # ファイル末尾に改行がない場合を考慮しつつ書き込み（通常は新規行として追加）
            f.write(f"{new_report_no}\t{advisory_id}\n")
        print(f"[INFO] Added to {REPORT_ADVISORY_FILE}: {new_report_no}\t{advisory_id}")
    except Exception as e:
        print(f"[ERROR] Failed to write to {REPORT_ADVISORY_FILE}: {e}")


def run_report(advisory_id: str):
    if not advisory_id:
        return
    
    # --- 追加: レポート番号の更新処理 ---
    # get-errata.pyを呼ぶ前にファイルが更新されている必要がある
    update_report_mapping(advisory_id)
    # --------------------------------

    # ディレクトリが存在するかチェック
    if os.path.exists(advisory_id) and os.path.isdir(advisory_id):
        print(f"[REPORT] Directory '{advisory_id}' already exists. Skipping report generation.")
        return
    cmd = f"mkdir {advisory_id}; cd {advisory_id}; ../get-errata/get-errata.py -c ../contacts.default.json -t ../report_template.default.txt -n {advisory_id}"
    print(f"[REPORT] run: {cmd}")
    try:
        os.system(cmd)
    except Exception as e:
        print(f"[REPORT] failed: {e}")


def increment_lookup_no(lookup_no: str) -> str:
    year, no = lookup_no.split(":")
    no_i = int(no) + 1
    return f"{year}:{str(no_i).zfill(4)}"

# New: decrement number part (one step back)
def decrement_lookup_no(lookup_no: str) -> str:
    year, no = lookup_no.split(":")
    no_i = max(1, int(no) - 1)
    return f"{year}:{str(no_i).zfill(4)}"


MAX_ERROR_COUNT = 300
MAX_FETCH_COUNT = 40


def main():
    parser = argparse.ArgumentParser(description='Red Hat Errata crawler wrapper')
    parser.add_argument('--reverse-start', '-R', type=str,
                        help='Start advisory ID to scan backward (e.g., RHSA-2025:22802)')
    parser.add_argument('--reverse-count', type=int, default=1000,
                        help='How many IDs to go backward (default: 1000)')
    parser.add_argument('--sleep', type=int, default=5,
                        help='Sleep seconds between API calls (default: 5)')
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
        # Accept either RHSA-YYYY:NNNN or RHBA-YYYY:NNNN as starting point
        start_id = args.reverse_start.strip()
        if not re.match(r'^(RHSA|RHBA)-\d{4}:\d{5}$', start_id):
            raise RuntimeError('書式エラー: --reverse-start は RHSA-YYYY:NNNN または RHBA-YYYY:NNNN を指定してください。')
        start_no = start_id[5:]  # YYYY:NNNN
        current_no = start_no
        print(f"[Reverse] 指定開始ID: {start_id} から {args.reverse_count} 件分を逆方向にスキャンします (レポート生成のみ)。")
        for i in range(args.reverse_count):
            # Try both RHSA and RHBA for the current number
            found_any = False
            for typ in ('RHSA', 'RHBA'):
                advisory_key = f'{typ}-{current_no}'
                data = fetch_errata(access_token, advisory_key)
                if data is None:
                    continue
                body = data.get('body', {})
                advisory_id = body.get('id', f'UNKNOWN-{current_no}')
                synopsis = body.get('synopsis', '')
                found_any = True if should_mark(synopsis, support_names) else False
                # Match generate report ONLY (no download). get-errata.py -n already skips download.
                if found_any is True:
                    print(f"[Reverse] {advisory_id} : {synopsis} => レポート生成")
                    run_report(advisory_id)
                    time.sleep(args.sleep)
            # Go to previous number regardless of found status
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
    lookup_no = increment_lookup_no(last_lookup)  # 成否に関係なく前進
    errata_list = []
    fetch_count = 0
    for _ in range(0, MAX_FETCH_COUNT):
        error_count = 0
        time.sleep(args.sleep)
        for _ in range(0, MAX_ERROR_COUNT):
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
                mark = REPORT_MARK if should_mark(synopsis, support_names) else ''
                display_id = advisory_id if not mark else f"**{advisory_id}**"
                print(f"Scanning {display_id} : {synopsis} {mark}")
                if mark == REPORT_MARK:
                    run_report(advisory_id)
            lookup_no = increment_lookup_no(lookup_no)  # 成否に関係なく前進
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
        mark = REPORT_MARK if should_mark(synopsis, support_names) else ''
        display_id = advisory_id if not mark else f"**{advisory_id}**"
        print(f"{display_id} {synopsis} {mark}")
        if mark == REPORT_MARK:
            run_report(advisory_id)
        os.system(f"mkdir {advisory_id}; cd {advisory_id}; ../get-errata/get-errata.py -c ../contacts.default.json -t ../report_template.default.txt -g {advisory_id}")
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
