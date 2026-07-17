#!/usr/bin/env python3
from __future__ import annotations

import shutil
import ssl
import sys


def main() -> int:
    missing: list[str] = []
    for command in ("git", "cmake", "ninja", "idf.py"):
        if shutil.which(command) is None:
            missing.append(command)

    print(f"Python: {sys.version.split()[0]}")
    print(f"OpenSSL: {ssl.OPENSSL_VERSION}")
    print(f"TLS 1.3 available: {ssl.HAS_TLSv1_3}")

    if missing:
        print("Missing commands:", ", ".join(missing))
        print("Open an activated ESP-IDF terminal and run this script again.")
        return 1

    print("Core ESP-IDF build tools found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
