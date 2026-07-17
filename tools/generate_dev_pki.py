#!/usr/bin/env python3
"""Generate a development CA, relay certificate, mTLS device certificates,
and separate ECDSA identity keys for the secure communication firmware.

Development only: private keys are written without passphrases.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,30}$")


def write_private_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def write_public_key(path: Path, key: ec.EllipticCurvePublicKey) -> None:
    path.write_bytes(
        key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def build_name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Comm Development"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def sign_certificate(
    *,
    subject: x509.Name,
    public_key: ec.EllipticCurvePublicKey,
    issuer: x509.Name,
    issuer_key: ec.EllipticCurvePrivateKey,
    is_ca: bool,
    san: x509.SubjectAlternativeName | None = None,
    eku: x509.ExtendedKeyUsage | None = None,
    days: int = 825,
) -> x509.Certificate:
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=is_ca,
                crl_sign=is_ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if san is not None:
        builder = builder.add_extension(san, critical=False)
    if eku is not None:
        builder = builder.add_extension(eku, critical=False)
    return builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())


def make_san(relay_host: str) -> x509.SubjectAlternativeName:
    entries: list[x509.GeneralName] = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
    ]
    try:
        entries.append(x509.IPAddress(ipaddress.ip_address(relay_host)))
    except ValueError:
        entries.append(x509.DNSName(relay_host))
    return x509.SubjectAlternativeName(entries)


def validate_device_ids(device_ids: list[str]) -> None:
    if len(set(device_ids)) != len(device_ids):
        raise ValueError("Device IDs must be unique.")
    for device_id in device_ids:
        if not DEVICE_ID_RE.fullmatch(device_id):
            raise ValueError(
                f"Invalid device ID {device_id!r}. Use 1-31 letters, digits, '_' or '-'."
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--devices", nargs="+", required=True, help="Device IDs, e.g. alice bob")
    parser.add_argument("--relay-host", required=True, help="Relay DNS name or IP used by firmware")
    parser.add_argument("--output", default="pki", help="Output directory")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()

    validate_device_ids(args.devices)
    output = Path(args.output).resolve()
    if output.exists() and any(output.iterdir()):
        if not args.overwrite:
            raise SystemExit(f"{output} is not empty. Use --overwrite to replace it.")
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)

    ca_dir = output / "ca"
    relay_dir = output / "relay"
    devices_dir = output / "devices"
    ca_dir.mkdir(exist_ok=True)
    relay_dir.mkdir(exist_ok=True)
    devices_dir.mkdir(exist_ok=True)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = build_name("Secure Comm Development CA")
    ca_cert = sign_certificate(
        subject=ca_name,
        public_key=ca_key.public_key(),
        issuer=ca_name,
        issuer_key=ca_key,
        is_ca=True,
        days=3650,
    )
    write_private_key(ca_dir / "ca.key", ca_key)
    (ca_dir / "ca.crt").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    relay_key = ec.generate_private_key(ec.SECP256R1())
    relay_cert = sign_certificate(
        subject=build_name(args.relay_host),
        public_key=relay_key.public_key(),
        issuer=ca_name,
        issuer_key=ca_key,
        is_ca=False,
        san=make_san(args.relay_host),
        eku=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
    )
    write_private_key(relay_dir / "relay.key", relay_key)
    (relay_dir / "relay.crt").write_bytes(relay_cert.public_bytes(serialization.Encoding.PEM))

    for device_id in args.devices:
        device_dir = devices_dir / device_id
        device_dir.mkdir(parents=True, exist_ok=True)

        client_key = ec.generate_private_key(ec.SECP256R1())
        client_cert = sign_certificate(
            subject=build_name(device_id),
            public_key=client_key.public_key(),
            issuer=ca_name,
            issuer_key=ca_key,
            is_ca=False,
            eku=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
        )
        write_private_key(device_dir / "client.key", client_key)
        (device_dir / "client.crt").write_bytes(
            client_cert.public_bytes(serialization.Encoding.PEM)
        )

        identity_key = ec.generate_private_key(ec.SECP256R1())
        write_private_key(device_dir / "identity.key", identity_key)
        write_public_key(device_dir / "identity.pub", identity_key.public_key())

    print(f"Development PKI created in: {output}")
    print("Keep pki/ out of Git and never use these unencrypted development keys in production.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
