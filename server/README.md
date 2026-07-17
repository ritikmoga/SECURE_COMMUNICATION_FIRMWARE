# Relay and development OTA server

Export a relay-only runtime bundle, then start the relay from the project root:

```bash
python tools/export_relay_bundle.py --pki-dir pki --output relay-runtime
python server/relay_server.py --pki relay-runtime --allowlist relay-runtime/allowed_devices.txt --host 0.0.0.0 --port 7443
```

The bundle excludes the CA private key and every device private key.

The relay requires a client certificate signed by the generated CA. The
certificate common name must equal the `device_id` in the registration frame.

For development OTA testing:

```bash
mkdir ota
copy build\secure_comm_firmware.bin ota\secure_comm_firmware.bin
python server/https_file_server.py --pki pki --directory ota --port 8443
```

The relay can see sender, recipient, timing, and ciphertext sizes, but it does
not receive plaintext or end-to-end session keys.
