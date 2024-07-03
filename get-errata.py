#! /usr/bin/python
# SPDX-License-Identifier: GPL-2.0-or-later
# Tsuyoshi Nagata
#
# get-errata.py : a tool of rhn errata-page downloader.
#
# ex. $ get-errata.py RHSA-2023:0951
#
VERSION="6.10"
#   
#
help_txt=f'\n# get-errata.py : a tool of rhn errata-page downloader.\n\n  ex. $ get-errata.py RHSA-2023:0951\n\n{VERSION}\n   Generate a shell script that downloads and executes the packages based on the errata number.\n'


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
  outfile = open(filename, 'r+')
  package_list=data
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

def main():
  # get Options
  parser = argparse.ArgumentParser(description='Sample Script with Options')
  # Adding flag options
  #  parser.add_argument('-h', action='store_true', help='Display help')
  parser.add_argument('-a', action='store_true', help='arch is aarch64(default:x86_64)')
  parser.add_argument('-n', action='store_true', help='No download. just recreatea download script')
  parser.add_argument('-v', '--version', action='version', version=f'%(prog)s ver={VERSION}')
  parser.add_argument('RHSA', type=str, help='Red Hat Security Advisory identifier (e.g., RHSA-2024:4108)')
  # Parsing arguments
  args = parser.parse_args()

  # Using arguments
  if args.a:
      print('aarch64 download')
  if args.n:
      print('Skip Downloading')  

      

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
  # Get the source code package
  for item in all_packages:
    if item['arch'] == 'src':
       matching_packages.append(item)
       break
  #matching_packages = []
  # Extract only the packages that are for x86_64 architecture.
  # Define the pattern to match
  #   rhel-9-for-x86_64-baseos-aus
  pattern = r"rhel-[89]-for-x86_64-[ab]"
  if args.a:
      pattern = r"rhel-[89]-for-aarch64-[ab]"
  prevchecksum="e242e4a03507144df7ebd084d568fd2bf90d28b"
  # Iterate through each package in the original list
  for package in all_packages:
      checksum=package['checksum']

      # Check if any 'contentSets' element matches the pattern
      for content_set in package['contentSets']:
          if re.search(r"rhel-7", content_set):
             pattern = r"rhel-7-server-" 
          if re.search(pattern, content_set) and (prevchecksum != checksum):
              # Append the matching package to the 'matching_packages' list
              matching_packages.append(package)
              prevchecksum=checksum

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

  #
  # closing shellfile
  shellfile.close()

  # Option '-n' just create scripts.
  if args.n :
      print('skip downloading')
  else:
      # just execute download script
      os.system(f"bash {script_name}")
      os.system(f"rm {script_name} {errata_id}.json")
  #
  # making directory and move rpms.
  os.system(f"mkdir -p {errata_id}/SRPM; mv *src.rpm {errata_id}/SRPM")
  archdir='x86_64'
  if args.a:
      archdir='aarch64'
  os.system(f"mkdir {errata_id}/{archdir}; mv *.rpm {errata_id}/{archdir}")  
  #
  # making checksums
  os.system(f"md5sum  {errata_id}/*/*rpm >{errata_id}/{errata_id}-md5sum.txt")
  os.system(f"sha256sum  {errata_id}/*/*rpm >{errata_id}/{errata_id}-sha256sum.txt")
  os.system(f"LANG=C tree {errata_id} >{errata_id}/{errata_id}-tree.txt")

  
if __name__ == "__main__":
  main()

