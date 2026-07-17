#!/usr/bin/env python3
"""Minimal metadata-only relay for Secure Comm Firmware.

The relay authenticates each client with mTLS and forwards already encrypted
JSON frames. It never receives end-to-end session keys or plaintext.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
import ssl
from collections import defaultdict, deque
from functools import partial
from pathlib import Path
from typing import Deque

MAX_LINE = 4096
MAX_OFFLINE_PER_DEVICE = 100
ALLOWED_FRAME_TYPES = {"hello", "data"}
DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,30}$")

clients: dict[str, asyncio.StreamWriter] = {}
offline: dict[str, Deque[bytes]] = defaultdict(
    lambda: deque(maxlen=MAX_OFFLINE_PER_DEVICE)
)
clients_lock = asyncio.Lock()


def certificate_common_name(cert: dict) -> str | None:
    for relative_distinguished_name in cert.get("subject", ()):
        for key, value in relative_distinguished_name:
            if key == "commonName":
                return value
    return None


async def send_json(writer: asyncio.StreamWriter, payload: dict) -> None:
    line = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"
    writer.write(line)
    await writer.drain()


async def register_client(
    device_id: str, writer: asyncio.StreamWriter
) -> None:
    async with clients_lock:
        previous = clients.get(device_id)
        clients[device_id] = writer
        queued = list(offline.pop(device_id, ()))

    if previous is not None and previous is not writer:
        previous.close()

    await send_json(
        writer,
        {"type": "status", "message": f"registered as {device_id}"},
    )
    for line in queued:
        writer.write(line)
    if queued:
        await writer.drain()


async def forward_frame(
    source_id: str,
    payload: dict,
    raw_line: bytes,
    allowed_devices: frozenset[str],
) -> None:
    frame_type = payload.get("type")
    sender = payload.get("from")
    recipient = payload.get("to")

    if frame_type not in ALLOWED_FRAME_TYPES:
        raise ValueError("unsupported frame type")
    if sender != source_id:
        raise ValueError("'from' must match the mTLS certificate identity")
    if not isinstance(recipient, str) or recipient not in allowed_devices:
        raise ValueError("recipient is not authorized")
    if len(raw_line) > MAX_LINE:
        raise ValueError("frame too large")

    framed = raw_line.rstrip(b"\r\n") + b"\n"
    async with clients_lock:
        destination = clients.get(recipient)
        if destination is None:
            offline[recipient].append(framed)
            return

    destination.write(framed)
    await destination.drain()


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    allowed_devices: frozenset[str],
) -> None:
    ssl_object: ssl.SSLObject | None = writer.get_extra_info("ssl_object")
    peer = writer.get_extra_info("peername")
    cert = ssl_object.getpeercert() if ssl_object else {}
    certificate_id = certificate_common_name(cert)
    registered_id: str | None = None

    logging.info("TLS connection from %s certificate=%s", peer, certificate_id)

    try:
        if not certificate_id:
            raise ValueError("client certificate has no common name")
        if certificate_id not in allowed_devices:
            raise ValueError("client certificate identity is not authorized")

        first_line = await reader.readline()
        if not first_line or len(first_line) > MAX_LINE:
            raise ValueError("missing or oversized registration")

        registration = json.loads(first_line)
        if registration.get("type") != "register":
            raise ValueError("first frame must be register")
        registered_id = registration.get("device_id")
        if registered_id != certificate_id:
            raise ValueError("registration ID must match certificate common name")

        await register_client(registered_id, writer)

        while not reader.at_eof():
            raw_line = await reader.readline()
            if not raw_line:
                break
            if len(raw_line) > MAX_LINE:
                raise ValueError("frame too large")

            payload = json.loads(raw_line)
            if not isinstance(payload, dict):
                raise ValueError("JSON frame must be an object")
            await forward_frame(
                registered_id,
                payload,
                raw_line,
                allowed_devices,
            )

    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        logging.warning("Rejected client %s: %s", peer, exc)
        try:
            await send_json(writer, {"type": "error", "message": str(exc)})
        except Exception:
            pass
    except (ConnectionError, asyncio.IncompleteReadError) as exc:
        logging.info("Client disconnected %s: %s", peer, exc)
    finally:
        if registered_id:
            async with clients_lock:
                if clients.get(registered_id) is writer:
                    clients.pop(registered_id, None)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def load_allowed_devices(pki: Path, allowlist_path: str | None) -> frozenset[str]:
    if allowlist_path:
        values = {
            line.strip()
            for line in Path(allowlist_path).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
    else:
        devices_dir = pki / "devices"
        values = {
            path.name
            for path in devices_dir.iterdir()
            if path.is_dir() and (path / "client.crt").is_file()
        } if devices_dir.is_dir() else set()

    invalid = sorted(value for value in values if not DEVICE_ID_RE.fullmatch(value))
    if invalid:
        raise ValueError(f"invalid device IDs in relay allowlist: {', '.join(invalid)}")
    if not values:
        raise ValueError(
            "relay allowlist is empty; provide --allowlist or keep device directories under pki/devices"
        )
    return frozenset(values)


def make_ssl_context(
    certificate: Path,
    private_key: Path,
    ca_certificate: Path,
    allow_tls12: bool,
) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, private_key)
    context.load_verify_locations(cafile=ca_certificate)
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = (
        ssl.TLSVersion.TLSv1_2 if allow_tls12 else ssl.TLSVersion.TLSv1_3
    )
    return context


async def async_main(args: argparse.Namespace) -> None:
    pki = Path(args.pki).resolve()
    allowed_devices = load_allowed_devices(pki, args.allowlist)
    logging.info("Authorized device identities: %s", ", ".join(sorted(allowed_devices)))
    context = make_ssl_context(
        pki / "relay" / "relay.crt",
        pki / "relay" / "relay.key",
        pki / "ca" / "ca.crt",
        args.allow_tls12,
    )

    server = await asyncio.start_server(
        partial(handle_client, allowed_devices=allowed_devices),
        args.host,
        args.port,
        ssl=context,
        limit=MAX_LINE + 1,
    )

    addresses = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    logging.info("Secure relay listening on %s", addresses)
    async with server:
        await server.serve_forever()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=7443)
    parser.add_argument("--pki", default="pki")
    parser.add_argument(
        "--allowlist",
        help=(
            "Optional text file containing one authorized device ID per line. "
            "By default, IDs are loaded from pki/devices/."
        ),
    )
    parser.add_argument(
        "--allow-tls12",
        action="store_true",
        help="Permit TLS 1.2 when a platform cannot use TLS 1.3.",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    try:
        asyncio.run(async_main(args))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
