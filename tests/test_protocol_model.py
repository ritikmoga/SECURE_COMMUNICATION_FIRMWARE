from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive(
    local_id: str,
    peer_id: str,
    local_private: ec.EllipticCurvePrivateKey,
    peer_public: ec.EllipticCurvePublicKey,
    transcript_hash: bytes,
) -> tuple[bytes, bytes, bytes]:
    shared = local_private.exchange(ec.ECDH(), peer_public)
    output = HKDF(
        algorithm=hashes.SHA256(),
        length=72,
        salt=transcript_hash,
        info=b"SCF-E2E-P256-AES256GCM-v1",
    ).derive(shared)
    low_to_high = output[:32]
    high_to_low = output[32:64]
    session_id = output[64:]
    if local_id < peer_id:
        return low_to_high, high_to_low, session_id
    return high_to_low, low_to_high, session_id


def test_directional_keys_and_round_trip() -> None:
    alice_private = ec.generate_private_key(ec.SECP256R1())
    bob_private = ec.generate_private_key(ec.SECP256R1())
    transcript_hash = bytes(range(32))

    alice_tx, alice_rx, alice_session = derive(
        "alice", "bob", alice_private, bob_private.public_key(), transcript_hash
    )
    bob_tx, bob_rx, bob_session = derive(
        "bob", "alice", bob_private, alice_private.public_key(), transcript_hash
    )

    assert alice_tx == bob_rx
    assert alice_rx == bob_tx
    assert alice_session == bob_session
    assert alice_tx != alice_rx

    counter = 1
    nonce = alice_session[:4] + counter.to_bytes(8, "big")
    aad = b"protocol-model"
    plaintext = b"hello from alice"

    ciphertext = AESGCM(alice_tx).encrypt(nonce, plaintext, aad)
    recovered = AESGCM(bob_rx).decrypt(nonce, ciphertext, aad)
    assert recovered == plaintext
