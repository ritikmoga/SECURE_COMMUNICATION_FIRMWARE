#!/usr/bin/env python3
"""Copy one device's credentials into the ESP-IDF project and generate
its trusted peer identity registry.
"""

from __future__ import annotations

import argparse
import re
import shutil
from pathlib import Path

DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,30}$")


def c_string_literal(text: str) -> str:
    lines = text.splitlines(keepends=True)
    escaped: list[str] = []
    for line in lines:
        line = (
            line.replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\r", "\\r")
            .replace("\n", "\\n")
        )
        escaped.append(f'"{line}"')
    if not escaped:
        return '""'
    return "\n".join(escaped)


def validate_id(value: str) -> None:
    if not DEVICE_ID_RE.fullmatch(value):
        raise SystemExit(
            f"Invalid device ID {value!r}. Use 1-31 letters, digits, '_' or '-'."
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--device", required=True)
    parser.add_argument("--peers", nargs="+", required=True)
    parser.add_argument("--pki-dir", default="pki")
    parser.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[1]),
    )
    args = parser.parse_args()

    validate_id(args.device)
    for peer in args.peers:
        validate_id(peer)
    if args.device in args.peers:
        raise SystemExit("A device cannot list itself as a peer.")
    if len(set(args.peers)) != len(args.peers):
        raise SystemExit("Peer IDs must be unique.")

    project_root = Path(args.project_root).resolve()
    pki_dir = Path(args.pki_dir).resolve()
    device_dir = pki_dir / "devices" / args.device
    certs_dir = project_root / "main" / "certs"
    generated_dir = project_root / "main" / "generated"

    required = [
        pki_dir / "ca" / "ca.crt",
        device_dir / "client.crt",
        device_dir / "client.key",
        device_dir / "identity.key",
    ]
    for path in required:
        if not path.exists():
            raise SystemExit(f"Missing {path}. Run generate_dev_pki.py first.")

    certs_dir.mkdir(parents=True, exist_ok=True)
    generated_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy2(pki_dir / "ca" / "ca.crt", certs_dir / "relay_ca.crt")
    shutil.copy2(device_dir / "client.crt", certs_dir / "client.crt")
    shutil.copy2(device_dir / "client.key", certs_dir / "client.key")
    shutil.copy2(device_dir / "identity.key", certs_dir / "identity.key")

    (generated_dir / "device_config.h").write_text(
        '#pragma once\n'
        f'#define SCF_DEVICE_ID "{args.device}"\n',
        encoding="utf-8",
    )

    declarations: list[str] = ['#include "peer_store.h"', ""]
    entries: list[str] = []
    for index, peer in enumerate(args.peers):
        peer_key_path = pki_dir / "devices" / peer / "identity.pub"
        if not peer_key_path.exists():
            raise SystemExit(f"Missing peer identity key: {peer_key_path}")
        pem = peer_key_path.read_text(encoding="utf-8")
        symbol = f"peer_key_{index}"
        declarations.extend(
            [
                f"static const char {symbol}[] =",
                c_string_literal(pem) + ";",
                "",
            ]
        )
        entries.append(
            f'    {{ .id = "{peer}", .identity_pub_pem = {symbol} }}'
        )

    declarations.append("const peer_identity_t g_peer_identities[] = {")
    declarations.append(",\n".join(entries))
    declarations.append("};")
    declarations.append("")
    declarations.append(
        "const size_t g_peer_identity_count = "
        "sizeof(g_peer_identities) / sizeof(g_peer_identities[0]);"
    )
    declarations.append("")

    (generated_dir / "peer_registry.c").write_text(
        "\n".join(declarations),
        encoding="utf-8",
    )

    print(f"Configured firmware identity: {args.device}")
    print(f"Trusted peers: {', '.join(args.peers)}")
    print("Now set Wi-Fi and relay settings with: idf.py menuconfig")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
