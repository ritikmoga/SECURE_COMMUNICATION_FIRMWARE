#!/usr/bin/env python3
"""Export the minimum development files needed by the relay.

The output intentionally excludes the CA private key and all device private keys.
"""

from __future__ import annotations

import argparse
import re
import shutil
from pathlib import Path

DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,30}$")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pki-dir", default="pki")
    parser.add_argument("--output", default="relay-runtime")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()

    source = Path(args.pki_dir).resolve()
    output = Path(args.output).resolve()

    required = [
        source / "ca" / "ca.crt",
        source / "relay" / "relay.crt",
        source / "relay" / "relay.key",
        source / "devices",
    ]
    for path in required:
        if not path.exists():
            raise SystemExit(f"Missing {path}. Generate the development PKI first.")

    device_ids = sorted(
        path.name
        for path in (source / "devices").iterdir()
        if path.is_dir()
        and DEVICE_ID_RE.fullmatch(path.name)
        and (path / "client.crt").is_file()
    )
    if not device_ids:
        raise SystemExit("No provisioned device certificates were found.")

    if output.exists():
        if not args.overwrite:
            raise SystemExit(f"{output} exists. Use --overwrite to replace it.")
        shutil.rmtree(output)

    (output / "ca").mkdir(parents=True)
    (output / "relay").mkdir(parents=True)
    shutil.copy2(source / "ca" / "ca.crt", output / "ca" / "ca.crt")
    shutil.copy2(source / "relay" / "relay.crt", output / "relay" / "relay.crt")
    shutil.copy2(source / "relay" / "relay.key", output / "relay" / "relay.key")
    (output / "allowed_devices.txt").write_text(
        "\n".join(device_ids) + "\n",
        encoding="utf-8",
    )

    print(f"Relay runtime bundle created in: {output}")
    print(f"Authorized devices: {', '.join(device_ids)}")
    print("CA and device private keys were not copied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
