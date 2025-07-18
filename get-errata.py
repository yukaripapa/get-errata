#! /usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Tsuyoshi Nagata
#
# get-errata.py : a tool of rhn errata-page downloader.
#
# ex. $ get-errata.py RHBA-2025:6279
#
VERSION="10.1"
#   
#
help_txt=f'\n# get-errata.py : a tool of rhn errata-page downloader.\n\n  ex. $ get-errata.py RHBA-2025:6279\n\n{VERSION}\n   Generate a shell script that downloads and executes the packages based on the errata number.\n'


from itertools import count
import re
import os
import json
import requests
import subprocess
import time
import sys
import argparse


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
  with open(filename, 'w') as outfile:
    json.dump(data, outfile, indent=4)

def main():
  # get Options
  parser = argparse.ArgumentParser(description='Sample Script with Options')
  # Adding flag options
  #  parser.add_argument('-h', action='store_true', help='Display help')
  parser.add_argument('-a', action='store_true', help='arch is aarch64(default:x86_64)')
  parser.add_argument('-n', action='store_true', help='No download. just recreatea download script')
  parser.add_argument('-g', action='store_true', help='Skip debug/debuginfo/src')
  parser.add_argument('-s', action='store_true', help='src.rpm only')    
  parser.add_argument('-v', '--version', action='version', version=f'%(prog)s ver={VERSION}')
  parser.add_argument('RHSA', type=str, help='Red Hat Security Advisory identifier (e.g., RHSA-2024:4108)')
  # Parsing arguments
  args = parser.parse_args()

  # Using arguments
  if args.a:
      print('aarch64 download')
  if args.n:
      print('Skip Downloading')  
  if args.g:
      print('Skip debug/debuginfo/src')  
  if args.s:
      print('Only src.rpm')  

  # Replace 'OFFLINE_TOKEN' with your actual refresh token
  #
  # Create an offline token in advance from the following URL (valid for 30 days).
  # https://access.redhat.com/management/api
  #
  offline_token = os.getenv('OFFLINE_TOKEN')
  # user offline token
  # offline_token = 'users offline token'
  if not offline_token:
    raise Exception('OFFLINE_TOKEN environment variable is not set.')
  
  access_token = get_access_token(offline_token)
  
  if len(sys.argv) > 1:
    errata_id = args.RHSA
  else:
    print("Please specify an RHSA no.")
    print(f"{help_txt}")    
    exit()
  
  filename = f"{errata_id}.json"  # Output filename
  # Initialize an empty list to store all packages
  all_packages = []

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
  # Get the source code package
  for item in all_packages:
    if item['arch'] == 'src':
       matching_packages.append(item)
       break
  
  # Extract only the packages that are for x86_64 architecture.
  # Define the pattern to match
  #   rhel-9-for-x86_64-baseos-aus
  pattern = r"^rhel-[891]0?-for-x86_64-[ab]"
  if args.a:
      pattern = r"^rhel-[891]0?-for-aarch64-[ab]"
  prevchecksum="e242e4a03507144df7ebd084d568fd2bf90d28b"
  # Iterate through each package in the original list
  for package in all_packages:
      checksum=package['checksum']

      # Check if any 'contentSets' element matches the pattern
      for content_set in package['contentSets']:
          if re.search(r"rhel-[67]", content_set):
             pattern = r"^rhel-[67]-server-" 
          if re.search(pattern, content_set) and (prevchecksum != checksum) :
              # Append the matching package to the 'matching_packages' list
              matching_packages.append(package)
              prevchecksum=checksum
              break

  script_name = f"{filename[:-5]}.sh"
  with open(script_name, "w") as shellfile:
    shellfile.write(f'export access_token={access_token};')
    shellfile.write(f'export fileno=1;\n')  
    
    fileno=1
    for download_pkg in matching_packages:
      checksum=download_pkg['checksum']
      filename=download_pkg['filename']
      shellfile.write(f'export filename={filename};')
      shellfile.write(f'export checksum={checksum};')
      shellfile.write(f'echo $fileno:$filename;let fileno=fileno+1;')
      shellfile.write(f'sleep 2;')      
      curl_str=f"curl -H \"Authorization: Bearer $access_token\" \"https://api.access.redhat.com/management/v1/packages/$checksum/download\" | jq | grep href.:|gawk '{{print \"curl \" $2 \" -o $filename\"}}'|sed -e 's/,//g'|sh ;\n"
      shellfile.write(curl_str)

  # Option '-n' just create scripts.
  if not args.n :
      # just execute download job
      shellfile.close()
      fileno=1
      for download_pkg in matching_packages:
        access_token = get_access_token(offline_token)
        checksum=download_pkg['checksum']
        filename=download_pkg['filename']

        # 'kernel-rt-debug'が含まれているかチェック
        if ('kernel-rt-debug' in filename) :
            print(f'{fileno}:{filename} kernel-rt-debug のダウンロードをスキップします')
            fileno += 1
            continue

        # '-debug'/'src.rpm'が含まれているかチェック
        # if args.g and (('-debug' in filename) or ('src.rpm' in filename)) :
        if args.g and (('-debug' in filename)) :          
            print(f'{fileno}:{filename} debug/src のダウンロードをスキップします')
            fileno += 1
            continue

        # 'src.rpm'が含まれているかチェック
        if args.s and (not 'src.rpm' in filename) :
            print(f'{fileno}:{filename} のダウンロードをスキップします')
            continue

        curl_str=f"curl -H \"Authorization: Bearer {access_token}\" \"https://api.access.redhat.com/management/v1/packages/{checksum}/download\" | jq | grep href.:|gawk '{{print \"curl \" $2 \" -o {filename}\"}}'|sed -e 's/,//g'|sh ;\n"
        print(f'{fileno}:{filename}')
        os.system(curl_str)      
        # Check if the file exists after the download
        if not os.path.exists(filename):
            os.system('sleep 5;')
            # 再ダウンロード
            os.system(curl_str)

        # Add a small delay before next downloading
        os.system('sleep 2;')
        fileno+=1
      
      #os.system(f"rm {script_name} {errata_id}.json")


  #
  # making directory and move rpms.
  errata_id=errata_id.replace(':', '-')
  os.system(f"mkdir -p {errata_id}/SRPM; mv *src.rpm {errata_id}/SRPM")
  archdir='x86_64'
  if args.a:
      archdir='aarch64'
  os.system(f"mkdir -p {errata_id}/{archdir}; mv *.rpm {errata_id}/{archdir}")  
  #
  # making checksums
  new_errata_id = errata_id.replace(':', '-')
  os.system(f"md5sum  {errata_id}/*/*rpm >{errata_id}/{new_errata_id}-md5sum.txt")
  os.system(f"sha256sum  {errata_id}/*/*rpm >{errata_id}/{new_errata_id}-sha256sum.txt")
  os.system(f"LANG=C tree {errata_id} >{errata_id}/{new_errata_id}-tree.txt")

  
if __name__ == "__main__":
  main()
  
