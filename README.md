# get-errata

## Overview
`get-errata.py` is a Python script designed to automate the retrieval of Red Hat Security Advisory (RHSA) information, generate security reports, and download relevant RPM packages. It interacts with the Red Hat API to fetch detailed errata data and verify if the advisory affects specific target systems.

## Key Features
- **Errata Information Retrieval**: Fetches detailed JSON metadata and package lists using an offline token.
- **Affected Product Detection**: Identifies if the errata applies to target products (e.g., RHEL Server, EUS, AUS). Skips processing if not relevant (override with `--force-report` or `--force-download`).
- **Security Report Generation**:
  - Creates a formatted text report based on a template.
  - Converts the report to **Shift_JIS** encoding with **CRLF** line endings.
  - Adjusts the file timestamp to match the advisory's issue date.
- **RPM Package Download**:
  - Downloads only necessary packages based on architecture (`x86_64` or `aarch64`) and type (Debug/Source exclusion).
  - Verifies SHA256 checksums and automatically retries critical file downloads.
  - Organizes downloads into structured directories (`SRPM`, `x86_64`, etc.).

## Usage
```bash
usage: get-errata.py [-h] [-a] [-n] [-g] [-s] [-c CONTACTS] [-t TEMPLATE] [-o OUTDIR] [-d DATE]
                     [--advisory-list ADVISORY_LIST] [--force-report] [--force-download] RHSA
```

### Arguments
- **Positional arguments:**
  - `RHSA`: Red Hat Security Advisory identifier (e.g., `RHSA-2024:xxxx`)

- **Optional arguments:**
  - `-h, --help`: Show this help message and exit.
  - `-a`: Specify architecture (default: `x86_64`). Use `-a` for `aarch64`.
  - `-n`: No download. Skip downloading RPM packages.
  - `-g`: Skip debug/debuginfo packages.
  - `-s`: Download source RPMs only.
  - `-c, --contacts`: Path to `contacts.json` (default: `contacts.default.json`).
  - `-t, --template`: Path to report template (default: `report_template.default.txt`).
  - `-o, --outdir`: Output directory for the report (default: current directory).
  - `-d, --date`: Set report date (YYYY-MM-DD). Default is today.
  - `--advisory-list`: Path to advisory list file (default: `report-advisory.txt`).
  - `--force-report`: Force report generation regardless of affected products.
  - `--force-download`: Force RPM download regardless of affected products.

## Example Execution
```bash
# Basic usage
get-errata.py RHSA-2025:8888

# Specify custom date and force report generation
get-errata.py -d 2025-01-01 --force-report RHSA-2025:8888
```

## Authentication
Before running the tool, you need to obtain a Red Hat Subscription Management (RHSM) API key (Offline Token).
Generate the token from Red Hat's management portal:

**Key Generation URL:**
[https://access.redhat.com/management/api](https://access.redhat.com/management/api)

Export the token as an environment variable:
```bash
export OFFLINE_TOKEN='your_generated_token_here'
```

---

# list-errata

## Overview
`list-errata.py` is a companion script that scans Red Hat Errata advisories in sequence, identifies those matching specific criteria (e.g., severity and supported packages), and triggers report generation. It can also send notifications to Microsoft Teams via a webhook.

## Key Features
- Iterates through RHSA/RHBA advisories using Red Hat API.
- Matches advisories based on severity (`Important` or `Critical`) and supported package list.
- Automatically generates security reports by invoking `get-errata.py`.
- Sends notifications to Teams using an Adaptive Card format.

## Environment Variables
- `OFFLINE_TOKEN`: Required for Red Hat API authentication.
- `WEBHOOK_URL`: Required for Teams notifications.
- `MENTION_LIST`: Optional. Comma/space-separated or JSON array of user IDs for Teams mentions.  
  Default: `['TEAMS-USER1', 'TEAMS-USER2']`

## Usage
```bash
usage: list-errata.py [--reverse-start RHSA-YYYY:NNNN] [--reverse-count N] [--sleep SECONDS]
```

### Arguments
- `--reverse-start, -R`: Start advisory ID for backward scanning (e.g., `RHSA-2025:22802`).
- `--reverse-count`: Number of advisories to scan backward (default: 1000).
- `--sleep`: Sleep interval between API calls (default: 5 seconds).

## Example Execution
Forward scan mode:
```bash
list-errata.py --sleep 5
```

Reverse scan mode:
```bash
list-errata.py --reverse-start RHSA-2025:22802 --reverse-count 500
```

## Notification Behavior
When a matching advisory is found:
- Generates a report using `get-errata.py`.
- Posts a Teams message with advisory details and mentions specified users.
