# get-errata

## Overview
`get-errata.py` is a Python script designed to retrieve detailed information about Red Hat Security Advisories (RHSA) and optionally download related RPM packages. It also generates formatted security reports for internal distribution.

## Usage
```bash
usage: get-errata.py [-h] [-a] [-n] [-g] [-s] [-v] RHSA
```

### Arguments
- **Positional arguments:**
  - `RHSA`: Red Hat Security Advisory identifier (e.g., `RHSA-2025:0055`)

- **Optional arguments:**
  - `-h, --help`: Show this help message and exit.
  - `-a`: Specify architecture. Default is `x86_64`, but `aarch64` can be specified.
  - `-n`: No download. Just recreate the download script.
  - `-g`: Skip debug/debuginfo packages.
  - `-s`: Source RPM only.
  - `-v, --version`: Show program's version number and exit.

## Example Execution
```bash
get-errata.py RHSA-2025:8888
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
