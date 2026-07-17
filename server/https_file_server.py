#!/usr/bin/env python3
"""Small HTTPS server for development OTA testing."""

from __future__ import annotations

import argparse
import functools
import http.server
import ssl
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", default="ota")
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--pki", default="pki")
    args = parser.parse_args()

    directory = Path(args.directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    pki = Path(args.pki).resolve()

    handler = functools.partial(
        http.server.SimpleHTTPRequestHandler,
        directory=str(directory),
    )
    server = http.server.ThreadingHTTPServer((args.bind, args.port), handler)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(
        certfile=pki / "relay" / "relay.crt",
        keyfile=pki / "relay" / "relay.key",
    )
    server.socket = context.wrap_socket(server.socket, server_side=True)

    print(f"HTTPS OTA files: https://{args.bind}:{args.port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
