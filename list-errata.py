#! /usr/bin/python
# SPDX-License-Identifier: GPL-2.0-or-later
# Tsuyoshi Nagata
#
# list-errata.py : a collector of rhn errata tickets.
#
# ex. $ list-errata.py
#
#   rhnからダウンロードが必要なerrata番号の一覧を取得する。
#
# 実行条件
# ・エラッタ取得(get-errata.py)スクリプトが存在する事。
# ・最終エラッタ取得ファイル(last_lookup.txt)が存在する事。
# ・環境変数OFFLINE_TOKENが設定されている事。
#
#  list-errata.py
#         +get-errata
#                 +-lookup_errata.txt
#                 +-get-errata.py


from itertools import count
import re
import os
import json
import requests
import subprocess
import time
import sys

def json_value(data, key):
  """
  Extracts the value of a specific key from a JSON string.

  Args:
      data: The JSON string to parse.
      key: The key of the value to extract.

  Returns:
      The value associated with the key, or None if not found.
  """
  try:
    parsed_data = json.loads(data)
    return parsed_data.get(key)
  except json.JSONDecodeError:
    print("Error: Invalid JSON data provided.")
    return None

def get_access_token(offline_token):
  """
  Fetches a new access token using the provided refresh token.

  Args:
      offline_token: The refresh token to use for obtaining a new access token.

  Returns:
      The access token retrieved from the server, or None on error.
  """
  url = "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token"
  payload = {
    "grant_type": "refresh_token",
    "client_id": "rhsm-api",
    "refresh_token": offline_token
  }

  try:
    response = requests.post(url, data=payload)
    response.raise_for_status()  # Raise an exception for non-2xx status codes

    # Extract the access token from the JSON response
    data = response.text
    access_token = json_value(data, "access_token")
    return access_token
  except requests.exceptions.RequestException as e:
    print(f"Error: Failed to retrieve access token. {e}")
    return None

def fetch_errata_packages(access_token, errata_id, offset):
  """
  Fetches Red Hat Errata packages using the specified access token and offset.

  Args:
      access_token: The access token to use for authentication.
      errata_id: The ID of the errata to query.
      offset: The offset for paginating the results.

  Returns:
      The JSON response from the API call, or None on error.
  """
  url = f"https://api.access.redhat.com/management/v1/errata/{errata_id}/packages/?offset={offset}"
  headers = {"Authorization": f"Bearer {access_token}"}

  try:
    response = requests.get(url, headers=headers)
    response.raise_for_status()  # Raise an exception for non-2xx status codes
    return response.json()
  except requests.exceptions.RequestException as e:
    print(f"Error: Failed to fetch errata packages. {e}")
    return None

def fetch_errata_list(access_token):
  """
  Fetches Red Hat Errata packages using the specified access token and offset.

  Args:
      access_token: The access token to use for authentication.
      content_set: The strings of the product-groups to query.
        rhel-7-server-els-rpms
        rhel-8-for-x86_64-baseos-aus-rpms
        rhel-9-for-x86_64-baseos-aus-rpms

  Returns:
      The JSON response from the API call, or None on error.
  """
  url = f"https://api.access.redhat.com/management/v1/errata"
  headers = {"Authorization": f"Bearer {access_token}"}

  try:
    response = requests.get(url, headers=headers)
    response.raise_for_status()  # Raise an exception for non-2xx status codes
    return response.json()
  except requests.exceptions.RequestException as e:
    print(f"Error: Failed to fetch errata list. {e}")
    return None
  
def write_to_json(filename, data):
  """
  Appends the provided data to an existing JSON file.

  Args:
      filename: The name of the JSON file to append to.
      data: The JSON data to append.
  """
  outfile = open(filename, 'r+')
  # Read existing data
  #existing_data = json.loads(outfile)
  # Append new data
  package_list=data
  #print(f"\nexistin_data {existing_data}\n")
  #existing_data.extend(package_list)
  # Seek to the beginning of the file
  outfile.seek(0)
  # Overwrite with updated data
  json.dump(package_list, outfile, indent=4)

def download_package(access_token, checksum, filename, package):
  durl = f"https://api.access.redhat.com/management/v1/packages/{checksum}"
  durlheaders = {"Authorization": f"Bearer {access_token}"}
  print(f"durl: {durl} {durlheaders}\n")
  try:
    response = requests.get(durl, headers=durlheaders)
    response.raise_for_status()  # Raise an exception for non-2xx status codes
    return response.json()
  except requests.exceptions.RequestException as e:
    print(f"Error: Failed to fetch errata packages. {e}")
    return None

  #try:
  #  dresponse = requests.get(durl, headers=headers)
  #  print("dresponse {dresponse}")
  #  dresponse.raise_for_status()  # Raise an exception for non-2xx status codes
  #  return dresponse.json()
  #except drequests.exceptions.RequestException as e:
  #  print(f"Error: Failed to fetch download packages. {e}")
  #  return None
  
def main():
# Replace 'YOUR_OFFLINE_TOKEN' with your actual refresh token
# 環境変数からオフライントークンを取得
#
# 以下のurlから事前にオフライントークンを作成しておく。（30日間有効）
# https://access.redhat.com/management/api
#
  offline_token = os.getenv('OFFLINE_TOKEN')
  if not offline_token:
    raise Exception('OFFLINE_TOKEN 環境変数が設定されていません。')
  access_token = get_access_token(offline_token)
  #if len(sys.argv) > 1:
  #  errata_id = sys.argv[1]
  #else:
  #  print("RHSA番号を指定してください")
  #  exit()

  # last_lookup変数に最後にダウンロードしたerrata番号を読み込む
  lookup_file_path = "get-errata/last_lookup.txt"
  try:
    with open(lookup_file_path, "r") as file:
        last_lookup = file.read().strip()  # ファイルの内容を読み込み、改行を削除
        print(f"ダウンロード済みerrata番号: {last_lookup}")
  except FileNotFoundError:
    print(f"{file_path} が見つかりませんでした。")
  adv_pattern = r".{9}$"  # 下9桁の文字を表す正規表現パターン 'RHSA-2024:1234'
  lookup_no = str(re.search(adv_pattern, last_lookup)) # lookup_no ='2024:1234'
  max_advisory_no = lookup_no
  # Initialize an empty list to store all packages
  download_list = []
  content_sets = [ "rhel-7-server-els-rpms", "rhel-8-for-x86_64-baseos-aus-rpms", "rhel-9-for-x86_64-baseos-aus-rpms" ]      
  errata_list = []
  fetch_erratas = fetch_errata_list(access_token)
  errata_list.extend(fetch_erratas['body'])
  for errata_tkt in errata_list:
      #print(f"{errata_tkt['advisoryId']} {errata_tkt['synopsis']}")
      if re.search(r'kernel|glibc', errata_tkt['synopsis']):
          # Append the matching package to the 'download_list' list
          download_list.append(errata_tkt)

  next_download_list = []
  for errata_tkt in download_list:
      synopsis=errata_tkt['synopsis']
      advisoryid=errata_tkt['advisoryId']
      advisory_no = str(re.search(adv_pattern, advisoryid))
      if advisory_no > lookup_no :
          if advisory_no > max_advisory_no:
              max_advisory = errata_tkt
              max_advisory_no = advisory_no
          next_download_list.append(errata_tkt)  
          print(f"{advisoryid} {synopsis}")
          # ダウンロードスクリプトだけ作成'-n'する.
          os.system(f"mkdir {advisoryid}; cd {advisoryid}; ../get-errata/get-errata.py -n {advisoryid}")
  if next_download_list :
      print("以上のerrataのダウンロードが必要です。")
  else:
      print("errataはありません。")
      exit()      
#
# 最終ダウンロード情報を更新する
  if max_advisory_no > lookup_no :
      max_advisory_no = str(max_advisory['advisoryId'])
      with open(lookup_file_path, 'w') as file:
          print(max_advisory_no, file=file)
      file.close()
#
# ダウンロード処理の実行
#
  for download_tkt in next_download_list:
      synopsis=download_tkt['synopsis']
      advisoryid=download_tkt['advisoryId']
      rpm_packages = []
      for offset in count(start=0, step=50):
          packages_data = fetch_errata_packages(access_token, advisoryid, offset)
          packages=packages_data['body']
          pageinfo=packages_data['pagination']          
          rpm_packages.extend(packages)
          if pageinfo['count']==0 :
             break
      src_pkg_name='none'
      for item in rpm_packages:
          src_pkg_name=item['filename']
          arch=item['arch']        
          if arch == 'src':
              src_pkg_name=item['filename']
              break
      print(f"{advisoryid} {src_pkg_name}")              
      os.system(f"cd {advisoryid}; bash {advisoryid}.sh")
      os.system(f"cd {advisoryid}; rm {advisoryid}.sh  {advisoryid}.json")
      #os.system(f"cd {advisoryid}; mkdir SRPMS; mv *src.rpm SRPMS; mkdir X86_64; mv *rpm X86_64")
      #os.system(f"md5sum {advisoryid}/*/*rpm >{advisoryid}/{advisoryid}-md5sum.txt")
      os.system(f"sha256sum {advisoryid}/*rpm >{advisoryid}/{advisoryid}-sha256sum.txt")
      #os.system(f"LANG=C tree {advisoryid} >{advisoryid}/{advisoryid}-tree.txt")            

  #
  # main()終了
  
#
# main()の実行
if __name__ == "__main__":
  main()


  

