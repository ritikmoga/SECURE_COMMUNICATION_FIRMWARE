<<<<<<< HEAD
# Secure Communication Firmware

A complete reference project for two or more ESP32-S3 devices that exchange
end-to-end encrypted messages through an authenticated relay.

This is a strong starter architecture, not a certified or independently audited
security product. Do not use it for medical, emergency, financial, military, or
other safety-critical communication without a professional security review.

## What this project protects

Each ESP32-S3 device:

1. Synchronizes system time before certificate validation.
2. Authenticates the relay with its CA certificate.
3. Authenticates itself to the relay with a unique client certificate.
4. Authenticates peer devices with provisioned long-term identity public keys.
5. Creates a fresh ephemeral P-256 ECDH key on every boot.
6. Signs its ephemeral handshake with its P-256 identity key.
7. Derives separate transmit and receive keys with HKDF-SHA-256.
8. Encrypts each message with AES-256-GCM.
9. Uses a session ID plus monotonic counter to prevent replay and nonce reuse.
10. Supports HTTPS OTA, boot confirmation, rollback, signed images, Secure Boot
   v2, and flash encryption.

The relay only forwards encrypted JSON frames. It can observe metadata such as
device IDs, timing, message size, and online status, but it does not receive the
end-to-end keys or plaintext.

## Reference architecture

```text
                mutual TLS                   mutual TLS
+-------------+  TLS 1.3   +-------------+   TLS 1.3  +-------------+
| ESP32 Alice |============| Relay server |============| ESP32 Bob   |
+-------------+             +-------------+             +-------------+
       |                                                        |
       +---- signed ephemeral ECDH + AES-256-GCM end-to-end -----+
```

For three or more devices, every device contains the trusted identity public key
of each peer. Messages are encrypted separately inside each pairwise session.

## Hardware

Required:

- Two or more ESP32-S3 development boards.
- One USB data cable per board.
- A Windows, macOS, or Linux computer.
- A Wi-Fi network shared by the boards and relay computer.

Recommended for a production redesign:

- An ESP32 variant with suitable hardware key protection, or an external secure
  element.
- A controlled provisioning station.
- Stable power during first security-feature enablement and OTA.
- A private signing service or offline signing machine.

## Software and VS Code extensions

Install:

- ESP-IDF 6.0.x through Espressif Installation Manager.
- Visual Studio Code.
- Git.
- Python 3.10 or newer.
- The Python dependencies in `requirements-dev.txt`.

Recommended VS Code extensions are declared in `.vscode/extensions.json`:

- Espressif IDF
- C/C++
- Python
- YAML

Open the folder in VS Code and choose **Install Recommended Extensions**.

## Project tree

```text
secure-comm-firmware/
├── .vscode/                    VS Code extension and task settings
├── main/
│   ├── app_main.c              Startup, console, tasks
│   ├── wifi_manager.*          Wi-Fi station connection
│   ├── tls_transport.*         Mutual TLS relay connection
│   ├── crypto_engine.*         ECDH, signatures, HKDF, AES-GCM
│   ├── protocol.*              JSON frames, handshake, replay checks
│   ├── session_manager.*       Pairwise peer sessions
│   ├── peer_store.*            Trusted peer lookup
│   ├── ota_manager.*           HTTPS OTA and rollback confirmation
│   ├── certs/                  Generated per-device credentials
│   └── generated/              Generated device ID and peer public keys
├── server/
│   ├── relay_server.py         mTLS authenticated ciphertext relay
│   └── https_file_server.py    Development HTTPS OTA server
├── tools/
│   ├── generate_dev_pki.py     Development CA and key generator
│   ├── configure_device.py     Select one device before building
│   ├── export_relay_bundle.py  Export relay files without CA/device keys
│   └── verify_environment.py   Tool check
├── scripts/                    Build, flash, and monitor helpers
├── tests/                      Protocol model test
├── partitions.csv              Two OTA slots
├── sdkconfig.defaults          Base ESP-IDF configuration
├── SECURITY.md                 Threat model and limitations
└── CMakeLists.txt
```

# Complete setup on Windows

## Step 1 — Install ESP-IDF

1. Install Visual Studio Code.
2. Install the **Espressif IDF** extension.
3. Install ESP-IDF 6.0.x using Espressif Installation Manager.
4. From the Installation Manager dashboard, open an activated **IDF Terminal**.
5. Avoid project paths containing spaces.

Run:

```powershell
idf.py --version
python --version
git --version
```

Then enter the extracted project:

```powershell
cd C:\Projects\secure-comm-firmware
python tools\verify_environment.py
```

## Step 2 — Create the Python environment

From a normal PowerShell or the IDF terminal:

```powershell
cd C:\Projects\secure-comm-firmware
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

Run the protocol model test:

```powershell
python -m pytest tests -q
```

## Step 3 — Find the relay computer IP

Run:

```powershell
ipconfig
```

Use the IPv4 address of the Wi-Fi adapter, for example:

```text
192.168.1.50
```

The relay host used when generating certificates must exactly match the host
entered later in `menuconfig`.

## Step 4 — Generate development certificates and identity keys

Example for two devices:

```powershell
python tools\generate_dev_pki.py `
  --devices alice bob `
  --relay-host 192.168.1.50
```

Example for four devices:

```powershell
python tools\generate_dev_pki.py `
  --devices alice bob charlie diana `
  --relay-host 192.168.1.50
```

This creates:

```text
pki/
├── ca/
├── relay/
└── devices/
    ├── alice/
    ├── bob/
    └── ...
```

Never commit `pki/`. The `--overwrite` option deletes the old development PKI
before regenerating it so removed device identities cannot remain accidentally.

## Step 5 — Start the relay

Allow inbound TCP port `7443` in the computer firewall only on the trusted
private network.

First export a relay-only runtime bundle. This prevents the relay process from
receiving the CA private key or any device private key:

```powershell
python tools\export_relay_bundle.py `
  --pki-dir pki `
  --output relay-runtime
```

Start the relay:

```powershell
python server\relay_server.py `
  --pki relay-runtime `
  --allowlist relay-runtime\allowed_devices.txt `
  --host 0.0.0.0 `
  --port 7443
```

The default relay requires TLS 1.3 and rejects identities or recipients outside
the allowlist. A development-only compatibility fallback is available with
`--allow-tls12`.

Keep this terminal running.

## Step 6 — Prepare and flash Alice

Open another activated IDF terminal:

```powershell
cd C:\Projects\secure-comm-firmware

python tools\configure_device.py `
  --device alice `
  --peers bob

idf.py set-target esp32s3
idf.py menuconfig
```

Inside `menuconfig`, open:

```text
Secure Communication Firmware
```

Set:

```text
Wi-Fi SSID:             your Wi-Fi name
Wi-Fi password:         your Wi-Fi password
Relay hostname or IP:   192.168.1.50
Relay TLS port:         7443
NTP server:             pool.ntp.org or your trusted LAN NTP server
Time sync timeout:      30 seconds
Require TLS 1.3:        enabled
```

Save and exit.

Connect Alice's ESP32-S3, find its COM port in Device Manager, then run:

```powershell
idf.py -p COM5 build flash monitor
```

Expected logs include:

```text
Connected to Wi-Fi
System time synchronized
Mutual TLS connected
registered as alice
```

Exit the serial monitor with its displayed exit shortcut before using the port
from another terminal.

## Step 7 — Prepare and flash Bob

The generated source and embedded certificates are per-device, so configure Bob
before building Bob's image:

```powershell
python tools\configure_device.py `
  --device bob `
  --peers alice

idf.py fullclean
idf.py -p COM6 build flash monitor
```

The Wi-Fi and relay settings remain in `sdkconfig`. Verify them with
`idf.py menuconfig` when using a copied project directory or a separate machine.

When both boards are online, each should log:

```text
End-to-end session established
```

## Step 8 — Send encrypted messages

In Alice's serial monitor:

```text
send bob Hello Bob, this is encrypted.
```

Bob should log:

```text
MESSAGE from alice: Hello Bob, this is encrypted.
```

Reply from Bob:

```text
send alice Hello Alice.
```

Other commands:

```text
peers
hello bob
help
```

`hello <peer>` retransmits the current boot's signed handshake. Restarting a
device creates a genuinely new ephemeral key, boot nonce, and end-to-end session.

# Add a third or later party

Generate all identities together, or regenerate development PKI with every
device listed.

Configure Alice to trust Bob and Charlie:

```powershell
python tools\configure_device.py `
  --device alice `
  --peers bob charlie
```

Configure Charlie to trust Alice and Bob:

```powershell
python tools\configure_device.py `
  --device charlie `
  --peers alice bob
```

Every communicating pair must trust each other's identity public key. Rebuild
and flash each affected device.

This pairwise design is suitable for a small group. For large dynamic groups,
replace the custom pairwise layer with a reviewed implementation of Messaging
Layer Security rather than inventing group key management.

# Development HTTPS OTA

## Step 1 — Build the new image

After changing the firmware:

```powershell
idf.py build
mkdir ota
copy build\secure_comm_firmware.bin ota\secure_comm_firmware.bin
```

## Step 2 — Start the HTTPS file server

```powershell
python server\https_file_server.py `
  --pki pki `
  --directory ota `
  --bind 0.0.0.0 `
  --port 8443
```

## Step 3 — Trigger OTA from the device console

```text
ota https://192.168.1.50:8443/secure_comm_firmware.bin
```

The new image boots in pending-verification state. The firmware confirms it only
after NVS, Wi-Fi, cryptography, mutual TLS, and relay registration succeed.
Otherwise the bootloader can roll back when rollback support is enabled.

For production, the firmware image must also be signed and verified by Secure
Boot. HTTPS alone does not replace code-signing.

# Production security enablement

Do not enable these settings on your only development board. Some eFuse changes
are permanent and mistakes can make the board difficult or impossible to
recover.

## Step 1 — Finish all development testing first

Confirm:

- Both boards connect after repeated power cycles.
- Invalid relay certificates are rejected.
- Unknown peers are rejected.
- Modified ciphertext is rejected.
- Repeated counters are rejected.
- OTA rollback works.
- You have a spare board and known-good serial recovery procedure.

## Step 2 — Create an offline signing-key directory

```powershell
mkdir release-keys
espsecure.py generate_signing_key `
  --version 2 `
  release-keys\secure_boot_signing_key.pem
```

Back this key up securely. Do not commit it or copy it onto the relay server.

## Step 3 — Enable the production options

Run:

```powershell
idf.py menuconfig
```

Under **Security features**:

1. Enable Secure Boot.
2. Select Secure Boot v2.
3. Enable signing binaries during build.
4. Select the Secure Boot v2 private signing key.
5. Enable flash encryption.
6. Use **Release** mode for production.
7. Keep insecure debug allowances disabled.
8. Disable JTAG and unrestricted UART download access for the production
   lifecycle.
9. Consider anti-rollback only after the complete OTA/version policy is tested.

Under **Bootloader config**:

1. Keep app rollback enabled.
2. Configure a deliberate health-check window.
3. Do not mark an update valid until all required self-tests pass.

## Step 4 — Use separate release and development boards

Development board:

- Debugging available.
- Development flash encryption mode or no flash encryption.
- Replaceable development keys.
- Not distributed.

Production board:

- Unique device certificate.
- Unique identity key.
- Secure Boot v2.
- Flash encryption release mode.
- Debug interfaces restricted.
- Signed OTA only.
- Recorded device serial number and certificate identity.

## Step 5 — Improve private-key storage

The included starter embeds PEM private keys in the firmware image. Flash
encryption helps protect them at rest, but production should move private-key
operations to one of:

- An ESP32 hardware ECDSA/eFuse-backed key path supported by the selected chip.
- An external secure element.
- A device-specific wrapped-key design with a reviewed provisioning process.

The private key should be non-exportable after provisioning.

## Step 6 — Replace development PKI

Use a controlled CA hierarchy:

- Offline root CA.
- Restricted intermediate CA for device enrollment.
- No CA private key on the relay host.
- Separate relay/server certificate profile.
- Unique certificate per device.
- Certificate revocation and replacement process.
- Expiration monitoring.
- Factory provisioning audit log.

Never use the development CA or unencrypted generated keys in deployed products.

# Security tests

Run these before release.

## Transport tests

- A relay certificate with the wrong hostname must fail.
- A relay signed by another CA must fail.
- A client certificate with a mismatched common name must be rejected.
- An expired or revoked device certificate must be rejected by the production
  relay policy.
- TLS 1.0 and TLS 1.1 must not be accepted.

## End-to-end tests

- Change one bit in `ciphertext`: decryption must fail.
- Change one bit in `tag`: decryption must fail.
- Change `from`, `to`, `session_id`, or `counter`: authentication must fail.
- Resend a previous valid frame: replay check must reject it.
- Send a hello signed by an untrusted key: handshake must fail.
- Reboot one device while the other remains online: both sides must establish
  a new session without accepting ciphertext from the old session.
- Replay the same signed hello: established counters must not reset.
- Confirm Alice's transmit key equals Bob's receive key, not Bob's transmit key.

## Firmware lifecycle tests

- Unsigned firmware must not boot after Secure Boot is enabled.
- An interrupted OTA must retain a bootable image.
- A failing health check must roll back.
- A known vulnerable lower security version must be blocked after anti-rollback
  is deliberately enabled.
- Flash readout should not expose plaintext firmware after production flash
  encryption is enabled.

## Robustness tests

- Oversized JSON frame.
- Invalid UTF-8.
- Malformed Base64.
- Rapid reconnects.
- Relay restart.
- Wi-Fi loss.
- Full offline queue.
- Message counter near its limit.
- Low-memory conditions.
- Power loss during OTA.

# Important files to customize

| File | Purpose |
|---|---|
| `main/Kconfig.projbuild` | Wi-Fi, relay, TLS, OTA, message size settings |
| `main/app_main.c` | Product startup and console integration |
| `main/protocol.c` | Handshake and encrypted frame processing |
| `main/crypto_engine.c` | Cryptographic operations |
| `main/ota_manager.c` | OTA policy and update health check |
| `server/relay_server.py` | Relay authentication and routing policy |
| `partitions.csv` | OTA partition sizes |
| `SECURITY.md` | Threat model and remaining limitations |

# Common errors

## `Run tools/configure_device.py before building`

Provision a device:

```powershell
python tools\configure_device.py --device alice --peers bob
```

## Certificate hostname mismatch

The following three values must match:

1. `--relay-host` passed to `generate_dev_pki.py`
2. `Relay hostname or IP` in `idf.py menuconfig`
3. The address used by the device

Regenerate development PKI when this changes.

## TLS connection fails immediately

Check:

- Relay is running.
- Windows Firewall permits port 7443 on the private network.
- Device and computer are on the same LAN.
- Computer IP did not change.
- The configured NTP server is reachable. Certificate validation requires a
  valid system clock before the mutual-TLS connection begins.
- For an isolated LAN, run or configure a trusted local NTP source instead of
  relying on a public pool. Production designs should use a reviewed secure-time
  policy because ordinary SNTP is not authenticated.
- TLS 1.3 is enabled in ESP-IDF. For diagnosis only, disable `Require TLS 1.3`
  and start the relay with `--allow-tls12`.

## `No secure session`

Run:

```text
hello bob
```

Then verify the other device is connected and both devices provisioned each
other's current identity public keys.

## Firmware no longer flashes after production security settings

Stop and review the exact Secure Boot and flash-encryption state. Do not erase or
burn additional eFuses blindly. Use the corresponding signed/encrypted flashing
workflow for the device's current lifecycle state.

# What this project does not hide

Even with end-to-end encryption, the relay can observe:

- Device identifiers.
- Which devices communicate.
- Connection times.
- Message timing.
- Approximate message sizes.
- Online/offline status.

Hiding this metadata requires a substantially different privacy architecture.

# License

Use the code as a reference starter. Add an explicit project license and obtain
a cryptographic and firmware security review before commercial deployment.

---

## Presentation and UI concept assets

This repository also includes:

- `docs/presentation/secure_comm_firmware_project_presentation.pptx`
- `docs/screenshots/01_dashboard_overview.png`
- `docs/screenshots/02_secure_chat.png`
- `docs/screenshots/03_connected_devices.png`
- `docs/screenshots/04_system_logs.png`
- `docs/screenshots/05_relay_server_backend.png`
- `docs/screenshots/06_ota_server_backend.png`
- `docs/screenshots/07_certificate_management.png`
- `docs/screenshots/08_device_cli_interaction.png`

The browser dashboard screenshots are concept mockups for presentation purposes. The implemented runtime components are the ESP32-S3 firmware, authenticated relay, device CLI, and HTTPS OTA file server.
=======
# SECURE_COMMUNICATION_FIRMWARE
A platform or medium of communication between two or more parties at a time and there will be no risk of data breaching.
>>>>>>> c36a40a3a56a7ab6ab13717e8fa109389f6cb7f8
