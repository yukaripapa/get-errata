#! /usr/bin/python
# SPDX-License-Identifier: GPL-2.0-or-later
# Tsuyoshi Nagata
#
# get-errata.py : a tool of rhn errata-page downloader.
#
# ex. $ get-errata.py RHSA-2023:0951
#
#   errata番号からダウンロード実行シェルを作成する
#
help_txt='\n# get-errata.py : a tool of rhn errata-page downloader.\n\n  ex. $ get-errata.py RHSA-2023:0951\n\n   errata番号からダウンロード実行シェルを作成する\n'


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
  url = f"https://api.access.redhat.com/management/v1/errata/{errata_id}/packages/?limit=50&offset={offset}"
  headers = {"Authorization": f"Bearer {access_token}"}

  try:
    response = requests.get(url, headers=headers)
    response.raise_for_status()  # Raise an exception for non-2xx status codes
    return response.json()
  except requests.exceptions.RequestException as e:
    print(f"Error: Failed to fetch errata packages. {e}")
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
  #access_token = os.getenv('ACCESS_TOKEN')
  #if access_token:
  #  print(f"Access Token: {access_token}")
  #else:
  #  print("Failed to obtain access token.")
  #errata_id = 'RHSA-2024:4108'
  if len(sys.argv) > 1:
    errata_id = sys.argv[1]
  else:
    print("RHSA番号を指定してください")
    print(f"{help_txt}")    
    exit()
  filename = f"{errata_id}.json"  # Output filename
  # Initialize an empty list to store all packages
  all_packages = []

  # Creates an empty JSON file if it doesn't already exist.
  outfile = open(filename, 'w') 
  json.dump(all_packages, outfile)  # Write an empty JSON object

  # Fetch and append packages for each offset
  for offset in count(start=0, step=50):
    packages_data = fetch_errata_packages(access_token, errata_id, offset)
    packages=packages_data['body']
    all_packages.extend(packages)
    pageinfo=packages_data['pagination']
    if pageinfo['count']==0 :
      break


  # Append all collected packages to the output file
  write_to_json(filename, all_packages)
  matching_packages = []
  # ソースコードパッケージを取り出す
  #tokens = [{"offline_token": f"{offline_token}","access_token": f"{access_token}",}]
  #matching_packages.append(tokens)
  #  src_packages = [item for item in all_packages if item['arch'] == 'src']
  #  matching_packages.append(src_packages)
  for item in all_packages:
    if item['arch'] == 'src':
       matching_packages.append(item)
       break
  #matching_packages = []
  # x86_64のpackagesだけ取り出す
  # Define the pattern to match
  #   rhel-9-for-x86_64-baseos-aus
  pattern = r"rhel-[89]-for-x86_64-[ab]"
  prevchecksum="e242e4a03507144df7ebd084d568fd2bf90d28b"
  # Iterate through each package in the original list
  for package in all_packages:
      checksum=package['checksum']

      # Check if any 'contentSets' element matches the pattern
      for content_set in package['contentSets']:
          if re.search(r"rhel-7", content_set):
             pattern = r"rhel-7-server-els-" 
          if re.search(pattern, content_set) and (prevchecksum != checksum):
              # Append the matching package to the 'matching_packages' list
              matching_packages.append(package)
              prevchecksum=checksum

  #write_to_json(filename, matching_packages)              
  # Download 
  #for package in matching_packages:
  #      #
  #    if package['arch']:
  #      print(f"Downloading \n{package}\n")
  #      checksum=package['checksum']
  #      filename=package['filename']
  #      download_data=download_package(access_token, checksum, filename, package)
  #      print(f"\n{download_data}\n")
  #      break
  script_name = f"{filename[:-5]}.sh"
  shellfile = open(script_name, "w")
  shellfile.write(f'export access_token={access_token};')
  shellfile.write(f'export fileno=1;')  
  shellfile.write('\n')
  fileno=1
  for download_pkg in matching_packages:
    checksum=download_pkg['checksum']
    filename=download_pkg['filename']
    shellfile.write(f'export filename={filename};')
    shellfile.write(f'export checksum={checksum};')
    shellfile.write(f'echo $fileno:$filename;let fileno=fileno+1;')
    curl_str="curl -H \"Authorization: Bearer $access_token\" \"https://api.access.redhat.com/management/v1/packages/$checksum/download\" | jq | grep href.:|gawk '{print \"curl \" $2 \" -o $filename\"}'|sed -e 's/,//g'|sh ;"
    shellfile.write(curl_str)
    shellfile.write('\n')    

    #  shellfile.close()
  
if __name__ == "__main__":
  main()


  

