# get-errata

## Overview
`get-errata.py` is a script designed to retrieve information about Red Hat Security Advisories (RHSA).

## Usage
```bash
usage: get-errata.py [-h] [-a] [-n] [-g] [-s] [-v] RHSA
```

### Arguments
- **Positional arguments:**
  - `RHSA`: Red Hat Security Advisory identifier (e.g., RHSA-2025:0055)

- **Optional arguments:**
  - `-h, --help`: Show this help message and exit.
  - `-a`: Specify architecture. Default is `x86_64`, but `aarch64` can be specified.
  - `-n`: No download. Just recreate the download script.
  - `-g`: Skip debug/debuginfo/src.
  - `-s`: Source RPM only.
  - `-v, --version`: Show program's version number and exit.

## Example Execution
Below is an example of executing the script with a specific RHSA:

```bash
get-errata.py RHSA-2025:8888
```

## Obtaining RHSM API Key
Before running the tool, you need to obtain a Red Hat Subscription Management (RHSM) API key. The API key can be generated from Red Hat's management portal.

### Key Generation URL
To generate an API key, visit the following URL:

[https://access.redhat.com/management/api](https://access.redhat.com/management/api)

Once you have obtained the API key, use it as the necessary authentication information when executing the script.
```
export OFFLINE_TOKEN='Generated strings from API key url.'
