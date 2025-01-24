# get-errata
usage: get-errata.py [-h] [-a] [-n] [-g] [-s] [-v] RHSA

Sample Script with Options

positional arguments:
  RHSA           Red Hat Security Advisory identifier (e.g., RHSA-2025:0055)

optional arguments:
* -h, --help     show this help message and exit
* -a             arch is aarch64(default:x86_64)
* -n             No download. just recreate download script
* -g             Skip debug/debuginfo/src
* -s             src.rpm only
* -v, --version  show program's version number and exit


