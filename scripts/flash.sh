#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 1 ]]; then
  echo "Usage: $0 /dev/ttyUSB0" >&2
  exit 2
fi
idf.py -p "$1" flash
