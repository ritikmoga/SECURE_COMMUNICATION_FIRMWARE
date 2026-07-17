#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/pk.h"

#include "session_manager.h"

#define SCF_SIGNATURE_MAX_BYTES MBEDTLS_PK_SIGNATURE_MAX_SIZE
#define SCF_GCM_TAG_BYTES 16
#define SCF_GCM_NONCE_BYTES 12

typedef struct {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ecp_group group;
    mbedtls_mpi ephemeral_private;
    mbedtls_ecp_point ephemeral_public;
    mbedtls_pk_context identity_key;
    uint8_t ephemeral_public_bin[SCF_EPHEMERAL_PUBLIC_BYTES];
    uint8_t boot_nonce[SCF_BOOT_NONCE_BYTES];
} scf_crypto_t;

esp_err_t crypto_engine_init(scf_crypto_t *crypto);
void crypto_engine_free(scf_crypto_t *crypto);

esp_err_t crypto_sign_hello(
    scf_crypto_t *crypto,
    const char *from,
    const char *to,
    uint8_t *signature,
    size_t signature_capacity,
    size_t *signature_length);

esp_err_t crypto_verify_hello(
    const char *peer_public_key_pem,
    const char *from,
    const char *to,
    const uint8_t peer_ephemeral_public[SCF_EPHEMERAL_PUBLIC_BYTES],
    const uint8_t peer_boot_nonce[SCF_BOOT_NONCE_BYTES],
    const uint8_t *signature,
    size_t signature_length);

esp_err_t crypto_derive_session(
    scf_crypto_t *crypto,
    const char *local_id,
    const char *peer_id,
    const uint8_t peer_ephemeral_public[SCF_EPHEMERAL_PUBLIC_BYTES],
    const uint8_t peer_boot_nonce[SCF_BOOT_NONCE_BYTES],
    uint8_t tx_key[SCF_SESSION_KEY_BYTES],
    uint8_t rx_key[SCF_SESSION_KEY_BYTES],
    uint8_t session_id[SCF_SESSION_ID_BYTES]);

esp_err_t crypto_encrypt_message(
    const uint8_t key[SCF_SESSION_KEY_BYTES],
    const char *from,
    const char *to,
    const uint8_t session_id[SCF_SESSION_ID_BYTES],
    uint64_t counter,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    uint8_t tag[SCF_GCM_TAG_BYTES]);

esp_err_t crypto_decrypt_message(
    const uint8_t key[SCF_SESSION_KEY_BYTES],
    const char *from,
    const char *to,
    const uint8_t session_id[SCF_SESSION_ID_BYTES],
    uint64_t counter,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    const uint8_t tag[SCF_GCM_TAG_BYTES],
    uint8_t *plaintext);
