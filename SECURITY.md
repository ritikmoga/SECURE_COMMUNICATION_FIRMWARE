# Security model

This repository is a reference implementation, not an audited cryptographic product.

## Protections included

- Initial system-time synchronization before X.509 validation.
- Mutual TLS between each device and the relay.
- End-to-end encryption between devices using ephemeral P-256 ECDH.
- Long-term P-256 identity signatures over ephemeral handshakes.
- HKDF-SHA-256 key derivation.
- AES-256-GCM message encryption and authentication.
- Per-session monotonic counters and nonce construction for replay protection.
- Signed OTA support and rollback confirmation.
- Production guidance for Secure Boot v2 and flash encryption.
- Relay authorization based on the client certificate common name.

## Important limitations

- Peer identity public keys are provisioned out-of-band.
- The reference relay keeps only in-memory offline queues.
- The development SNTP flow is not authenticated; production needs a reviewed secure-time policy.
- A device reboot creates new ephemeral keys, but the firmware does not implement a full Double Ratchet or MLS.
- Metadata such as sender, recipient, message size, and timing is visible to the relay.
- Private keys are embedded into the firmware image in the starter workflow. Production hardware should use an eFuse-backed signing peripheral or external secure element.
- Do not enable irreversible eFuse security settings until the development build works and recovery procedures have been tested.
- Obtain an independent security review before production deployment.
