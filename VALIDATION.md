# Validation record

Validated in the artifact-generation environment on 2026-07-17:

- Python source compilation for `tools/`, `server/`, and `tests/`.
- Protocol cryptographic model test (`pytest`).
- Development PKI generation for multiple device identities.
- PKI overwrite behavior removes stale device identities.
- Relay certificate chain and IP Subject Alternative Name verification.
- Per-device firmware provisioning output.
- Relay-only bundle excludes the CA private key and all device private keys.
- Live TLS 1.3 mutual-TLS connection using Alice and Bob certificates.
- Authenticated relay registration and opaque ciphertext-frame forwarding.

The ESP-IDF C firmware was not compiled or flashed in this environment because
`idf.py` and the ESP32-S3 toolchain are not installed here. Run
`python tools/verify_environment.py`, then `idf.py set-target esp32s3` and
`idf.py build` in an activated ESP-IDF terminal before flashing hardware.
