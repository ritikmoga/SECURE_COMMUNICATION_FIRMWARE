#!/usr/bin/env bash
set -euo pipefail
idf.py set-target esp32s3
idf.py build
