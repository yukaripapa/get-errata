#! /usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Tsuyoshi Nagata
#
# verify_checksum.py : a tool of checksum rhsa download checker.
#
# ex. $ verify_checksum.py RHBA-2025:6279
#
VERSION="4.1"
#   

import os
import sys
import json
import hashlib
import glob

def calculate_sha256(file_path):
    """
    Calculate the SHA256 checksum of a file.
    Read the file in chunks to efficiently use memory.
    """
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256.update(byte_block)
        return sha256.hexdigest()
    except FileNotFoundError:
        print(f"\nError: File not found {file_path}")
        return None
    except Exception as e:
        print(f"\nError: Problem occurred while reading the file {file_path}: {e}")
        return None

def verify_advisory_dir(advisory_dir_path):
    """
    Verify RPM checksums within a specified advisory folder.
    """
    print(f"--- Processing directory: {advisory_dir_path} ---")
    advisory_name = os.path.basename(advisory_dir_path)

    # 1. Find JSON files in the folder
    json_files = glob.glob(os.path.join(advisory_dir_path, '*.json'))
    if not json_files:
        print(f"Warning: No JSON files found in {advisory_dir_path}. Skipping.")
        return False
    
    json_file_path = json_files[0]
    print(f"Checksum file found: {json_file_path}")

    # 2. Load expected checksum information from the JSON file
    try:
        with open(json_file_path, 'r', encoding='utf-8') as f:
            packages_data = json.load(f)
    except json.JSONDecodeError:
        print(f"Error: {json_file_path} is an invalid JSON file.")
        return False
    except FileNotFoundError:
        print(f"Error: JSON file not found: {json_file_path}")
        return False

    expected_checksums = {pkg['filename']: pkg['checksum'] for pkg in packages_data}
    if not expected_checksums:
        print(f"Warning: No package information in {json_file_path}.")
        return False

    # 3. Find all RPM files to be verified
    inner_dir_name = advisory_name.replace(':', '-')
    rpm_search_pattern = os.path.join(advisory_dir_path, inner_dir_name, '*', '*.rpm')
    rpm_files = glob.glob(rpm_search_pattern)

    if not rpm_files:
        print(f"Warning: No RPM files found for verification. Search pattern: {rpm_search_pattern}")
    else:
        print(f"Number of RPM files found: {len(rpm_files)}")
    
    all_ok = True

    # 4. Verify checksums of each RPM file
    print("\nVerifying RPM files...")
    for rpm_path in rpm_files:
        rpm_filename = os.path.basename(rpm_path)

        if rpm_filename not in expected_checksums:
            print(f"  - {rpm_filename}: [Skipped] No information in JSON.")
            continue

        expected_sum = expected_checksums[rpm_filename]
        print(f"  - Verifying: {rpm_filename}...", end='', flush=True)
        
        calculated_sum = calculate_sha256(rpm_path)

        if calculated_sum is None:
            all_ok = False
            continue

        if calculated_sum == expected_sum:
            print(" [  OK  ]")
        else:
            print(" [Failed]")
            print(f"    - Expected: {expected_sum}")
            print(f"    - Calculated: {calculated_sum}")
            all_ok = False
            
    print(f"\nVerification result for {advisory_name}: {'Success' if all_ok else 'Failed'}")
    print("--------------------------------------------------\n")
    return all_ok

def print_help():
    """
    Print help message for the script usage.
    """
    print("Usage: python3 verify_checksums.py <directory1> <directory2> ...")
    print("Options:")
    print("  -h, --help     Show this help message and exit.")

def main():
    """
    Main processing of the script.
    Verify advisory folders specified by command line arguments.
    """
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print_help()
        sys.exit(0)

    target_dirs = sys.argv[1:]

    print(f"Processing {len(target_dirs)} directories.")
    print("==================================================")

    overall_success = True
    for dir_path in target_dirs:
        if not os.path.isdir(dir_path):
            print(f"--- Processing directory: {dir_path} ---")
            print(f"Warning: '{dir_path}' does not exist or is not a directory. Skipping.")
            print("--------------------------------------------------\n")
            overall_success = False
            continue
        
        if not verify_advisory_dir(dir_path):
            overall_success = False
            
    print("==================================================")
    if overall_success:
        print("Checksum verification completed successfully for all specified directories. ✅")
    else:
        print("Checksum mismatch detected in some files. ❌")
    print("==================================================")

if __name__ == "__main__":
    main()
