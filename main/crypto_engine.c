#include "crypto_engine.h"

#include <stdbool.h>
#include <string.h>

#include "esp_log.h"
#include "mbedtls/base64.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"
#include "mbedtls/version.h"

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "psa/crypto.h"
#endif

static const char *TAG = "crypto";
static const unsigned char PERSONALIZATION[] = "secure-comm-firmware-v1";
static const unsigned char HKDF_INFO[] = "SCF-E2E-P256-AES256GCM-v1";

extern const unsigned char identity_key_start[] asm("_binary_certs_identity_key_start");
extern const unsigned char identity_key_end[] asm("_binary_certs_identity_key_end");

static int sha256_bytes(const unsigned char *input, size_t length, unsigned char output[32])
{
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    return mbedtls_sha256(input, length, output, 0);
#else
    return mbedtls_sha256_ret(input, length, output, 0);
#endif
}

static bool append_bytes(
    unsigned char *buffer,
    size_t capacity,
    size_t *offset,
    const void *data,
    size_t length)
{
    if (buffer == NULL || offset == NULL || data == NULL || *offset + length > capacity) {
        return false;
    }

    memcpy(buffer + *offset, data, length);
    *offset += length;
    return true;
}

static bool append_id(
    unsigned char *buffer,
    size_t capacity,
    size_t *offset,
    const char *id)
{
    if (id == NULL) {
        return false;
    }

    size_t length = strlen(id);
    if (length == 0 || length >= SCF_DEVICE_ID_MAX || length > UINT8_MAX) {
        return false;
    }

    uint8_t length_byte = (uint8_t)length;
    return append_bytes(buffer, capacity, offset, &length_byte, 1) &&
           append_bytes(buffer, capacity, offset, id, length);
}

static esp_err_t build_hello_hash(
    const char *from,
    const char *to,
    const uint8_t ephemeral_public[SCF_EPHEMERAL_PUBLIC_BYTES],
    const uint8_t boot_nonce[SCF_BOOT_NONCE_BYTES],
    uint8_t output_hash[32])
{
    unsigned char canonical[192];
    size_t offset = 0;
    const uint8_t version = 1;

    bool ok = append_bytes(canonical, sizeof(canonical), &offset, &version, 1) &&
              append_id(canonical, sizeof(canonical), &offset, from) &&
              append_id(canonical, sizeof(canonical), &offset, to) &&
              append_bytes(
                  canonical,
                  sizeof(canonical),
                  &offset,
                  ephemeral_public,
                  SCF_EPHEMERAL_PUBLIC_BYTES) &&
              append_bytes(
                  canonical,
                  sizeof(canonical),
                  &offset,
                  boot_nonce,
                  SCF_BOOT_NONCE_BYTES);

    if (!ok) {
        return ESP_ERR_INVALID_ARG;
    }

    return sha256_bytes(canonical, offset, output_hash) == 0 ? ESP_OK : ESP_FAIL;
}

static esp_err_t build_transcript_hash(
    const char *local_id,
    const char *peer_id,
    const uint8_t local_public[SCF_EPHEMERAL_PUBLIC_BYTES],
    const uint8_t peer_public[SCF_EPHEMERAL_PUBLIC_BYTES],
    const uint8_t local_nonce[SCF_BOOT_NONCE_BYTES],
    const uint8_t peer_nonce[SCF_BOOT_NONCE_BYTES],
    uint8_t output_hash[32])
{
    const bool local_is_low = strcmp(local_id, peer_id) < 0;
    const char *low_id = local_is_low ? local_id : peer_id;
    const char *high_id = local_is_low ? peer_id : local_id;
    const uint8_t *low_public = local_is_low ? local_public : peer_public;
    const uint8_t *high_public = local_is_low ? peer_public : local_public;
    const uint8_t *low_nonce = local_is_low ? local_nonce : peer_nonce;
    const uint8_t *high_nonce = local_is_low ? peer_nonce : local_nonce;

    unsigned char transcript[320];
    size_t offset = 0;
    const uint8_t version = 1;

    bool ok = append_bytes(transcript, sizeof(transcript), &offset, &version, 1) &&
              append_id(transcript, sizeof(transcript), &offset, low_id) &&
              append_bytes(
                  transcript,
                  sizeof(transcript),
                  &offset,
                  low_public,
                  SCF_EPHEMERAL_PUBLIC_BYTES) &&
              append_bytes(
                  transcript,
                  sizeof(transcript),
                  &offset,
                  low_nonce,
                  SCF_BOOT_NONCE_BYTES) &&
              append_id(transcript, sizeof(transcript), &offset, high_id) &&
              append_bytes(
                  transcript,
                  sizeof(transcript),
                  &offset,
                  high_public,
                  SCF_EPHEMERAL_PUBLIC_BYTES) &&
              append_bytes(
                  transcript,
                  sizeof(transcript),
                  &offset,
                  high_nonce,
                  SCF_BOOT_NONCE_BYTES);

    if (!ok) {
        return ESP_ERR_INVALID_ARG;
    }

    return sha256_bytes(transcript, offset, output_hash) == 0 ? ESP_OK : ESP_FAIL;
}

static esp_err_t build_aad(
    const char *from,
    const char *to,
    const uint8_t session_id[SCF_SESSION_ID_BYTES],
    uint64_t counter,
    uint8_t *aad,
    size_t aad_capacity,
    size_t *aad_length)
{
    if (aad == NULL || aad_length == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t counter_be[8];
    for (size_t i = 0; i < 8; ++i) {
        counter_be[7 - i] = (uint8_t)(counter >> (i * 8));
    }

    size_t offset = 0;
    const uint8_t version = 1;
    bool ok = append_bytes(aad, aad_capacity, &offset, &version, 1) &&
              append_id(aad, aad_capacity, &offset, from) &&
              append_id(aad, aad_capacity, &offset, to) &&
              append_bytes(aad, aad_capacity, &offset, session_id, SCF_SESSION_ID_BYTES) &&
              append_bytes(aad, aad_capacity, &offset, counter_be, sizeof(counter_be));

    if (!ok) {
        return ESP_ERR_INVALID_ARG;
    }

    *aad_length = offset;
    return ESP_OK;
}

static void build_gcm_nonce(
    const uint8_t session_id[SCF_SESSION_ID_BYTES],
    uint64_t counter,
    uint8_t nonce[SCF_GCM_NONCE_BYTES])
{
    memcpy(nonce, session_id, 4);
    for (size_t i = 0; i < 8; ++i) {
        nonce[11 - i] = (uint8_t)(counter >> (i * 8));
    }
}

esp_err_t crypto_engine_init(scf_crypto_t *crypto)
{
    if (crypto == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(crypto, 0, sizeof(*crypto));
    mbedtls_entropy_init(&crypto->entropy);
    mbedtls_ctr_drbg_init(&crypto->ctr_drbg);
    mbedtls_ecp_group_init(&crypto->group);
    mbedtls_mpi_init(&crypto->ephemeral_private);
    mbedtls_ecp_point_init(&crypto->ephemeral_public);
    mbedtls_pk_init(&crypto->identity_key);

#if defined(MBEDTLS_USE_PSA_CRYPTO)
    if (psa_crypto_init() != PSA_SUCCESS) {
        ESP_LOGE(TAG, "PSA Crypto initialization failed");
        crypto_engine_free(crypto);
        return ESP_FAIL;
    }
#endif

    int result = mbedtls_ctr_drbg_seed(
        &crypto->ctr_drbg,
        mbedtls_entropy_func,
        &crypto->entropy,
        PERSONALIZATION,
        sizeof(PERSONALIZATION) - 1);
    if (result != 0) {
        ESP_LOGE(TAG, "DRBG seed failed: -0x%04x", -result);
        crypto_engine_free(crypto);
        return ESP_FAIL;
    }

#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    result = mbedtls_pk_parse_key(
        &crypto->identity_key,
        identity_key_start,
        (size_t)(identity_key_end - identity_key_start),
        NULL,
        0,
        mbedtls_ctr_drbg_random,
        &crypto->ctr_drbg);
#else
    result = mbedtls_pk_parse_key(
        &crypto->identity_key,
        identity_key_start,
        (size_t)(identity_key_end - identity_key_start),
        NULL,
        0);
#endif
    if (result != 0) {
        ESP_LOGE(TAG, "Identity private key parse failed: -0x%04x", -result);
        crypto_engine_free(crypto);
        return ESP_FAIL;
    }

    result = mbedtls_ecp_group_load(&crypto->group, MBEDTLS_ECP_DP_SECP256R1);
    if (result != 0) {
        ESP_LOGE(TAG, "P-256 group load failed: -0x%04x", -result);
        crypto_engine_free(crypto);
        return ESP_FAIL;
    }

    result = mbedtls_ecp_gen_keypair(
        &crypto->group,
        &crypto->ephemeral_private,
        &crypto->ephemeral_public,
        mbedtls_ctr_drbg_random,
        &crypto->ctr_drbg);
    if (result != 0) {
        ESP_LOGE(TAG, "Ephemeral key generation failed: -0x%04x", -result);
        crypto_engine_free(crypto);
        return ESP_FAIL;
    }

    size_t public_length = 0;
    result = mbedtls_ecp_point_write_binary(
        &crypto->group,
        &crypto->ephemeral_public,
        MBEDTLS_ECP_PF_UNCOMPRESSED,
        &public_length,
        crypto->ephemeral_public_bin,
        sizeof(crypto->ephemeral_public_bin));
    if (result != 0 || public_length != SCF_EPHEMERAL_PUBLIC_BYTES) {
        ESP_LOGE(TAG, "Ephemeral public key export failed");
        crypto_engine_free(crypto);
        return ESP_FAIL;
    }

    result = mbedtls_ctr_drbg_random(
        &crypto->ctr_drbg,
        crypto->boot_nonce,
        sizeof(crypto->boot_nonce));
    if (result != 0) {
        ESP_LOGE(TAG, "Boot nonce generation failed");
        crypto_engine_free(crypto);
        return ESP_FAIL;
    }

    return ESP_OK;
}

void crypto_engine_free(scf_crypto_t *crypto)
{
    if (crypto == NULL) {
        return;
    }

    mbedtls_pk_free(&crypto->identity_key);
    mbedtls_ecp_point_free(&crypto->ephemeral_public);
    mbedtls_mpi_free(&crypto->ephemeral_private);
    mbedtls_ecp_group_free(&crypto->group);
    mbedtls_ctr_drbg_free(&crypto->ctr_drbg);
    mbedtls_entropy_free(&crypto->entropy);
    mbedtls_platform_zeroize(crypto, sizeof(*crypto));
}

esp_err_t crypto_sign_hello(
    scf_crypto_t *crypto,
    const char *from,
    const char *to,
    uint8_t *signature,
    size_t signature_capacity,
    size_t *signature_length)
{
    if (crypto == NULL || signature == NULL || signature_length == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t hash[32];
    esp_err_t result = build_hello_hash(
        from,
        to,
        crypto->ephemeral_public_bin,
        crypto->boot_nonce,
        hash);
    if (result != ESP_OK) {
        return result;
    }

    int mbed_result;
#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    mbed_result = mbedtls_pk_sign(
        &crypto->identity_key,
        MBEDTLS_MD_SHA256,
        hash,
        sizeof(hash),
        signature,
        signature_capacity,
        signature_length,
        mbedtls_ctr_drbg_random,
        &crypto->ctr_drbg);
#else
    (void)signature_capacity;
    mbed_result = mbedtls_pk_sign(
        &crypto->identity_key,
        MBEDTLS_MD_SHA256,
        hash,
        sizeof(hash),
        signature,
        signature_length,
        mbedtls_ctr_drbg_random,
        &crypto->ctr_drbg);
#endif

    mbedtls_platform_zeroize(hash, sizeof(hash));
    return mbed_result == 0 ? ESP_OK : ESP_FAIL;
}

esp_err_t crypto_verify_hello(
    const char *peer_public_key_pem,
    const char *from,
    const char *to,
    const uint8_t peer_ephemeral_public[SCF_EPHEMERAL_PUBLIC_BYTES],
    const uint8_t peer_boot_nonce[SCF_BOOT_NONCE_BYTES],
    const uint8_t *signature,
    size_t signature_length)
{
    if (peer_public_key_pem == NULL || signature == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t hash[32];
    esp_err_t result = build_hello_hash(
        from,
        to,
        peer_ephemeral_public,
        peer_boot_nonce,
        hash);
    if (result != ESP_OK) {
        return result;
    }

    mbedtls_pk_context peer_key;
    mbedtls_pk_init(&peer_key);

    int mbed_result = mbedtls_pk_parse_public_key(
        &peer_key,
        (const unsigned char *)peer_public_key_pem,
        strlen(peer_public_key_pem) + 1);
    if (mbed_result == 0) {
        mbed_result = mbedtls_pk_verify(
            &peer_key,
            MBEDTLS_MD_SHA256,
            hash,
            sizeof(hash),
            signature,
            signature_length);
    }

    mbedtls_pk_free(&peer_key);
    mbedtls_platform_zeroize(hash, sizeof(hash));
    return mbed_result == 0 ? ESP_OK : ESP_ERR_INVALID_CRC;
}

esp_err_t crypto_derive_session(
    scf_crypto_t *crypto,
    const char *local_id,
    const char *peer_id,
    const uint8_t peer_ephemeral_public[SCF_EPHEMERAL_PUBLIC_BYTES],
    const uint8_t peer_boot_nonce[SCF_BOOT_NONCE_BYTES],
    uint8_t tx_key[SCF_SESSION_KEY_BYTES],
    uint8_t rx_key[SCF_SESSION_KEY_BYTES],
    uint8_t session_id[SCF_SESSION_ID_BYTES])
{
    if (crypto == NULL || local_id == NULL || peer_id == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    mbedtls_ecp_point peer_point;
    mbedtls_mpi shared_secret;
    mbedtls_ecp_point_init(&peer_point);
    mbedtls_mpi_init(&shared_secret);

    int result = mbedtls_ecp_point_read_binary(
        &crypto->group,
        &peer_point,
        peer_ephemeral_public,
        SCF_EPHEMERAL_PUBLIC_BYTES);
    if (result == 0) {
        result = mbedtls_ecp_check_pubkey(&crypto->group, &peer_point);
    }
    if (result == 0) {
        result = mbedtls_ecdh_compute_shared(
            &crypto->group,
            &shared_secret,
            &peer_point,
            &crypto->ephemeral_private,
            mbedtls_ctr_drbg_random,
            &crypto->ctr_drbg);
    }

    uint8_t shared_bytes[32] = {0};
    uint8_t transcript_hash[32] = {0};
    uint8_t output[SCF_SESSION_KEY_BYTES * 2 + SCF_SESSION_ID_BYTES] = {0};

    if (result == 0) {
        result = mbedtls_mpi_write_binary(&shared_secret, shared_bytes, sizeof(shared_bytes));
    }

    if (result == 0 &&
        build_transcript_hash(
            local_id,
            peer_id,
            crypto->ephemeral_public_bin,
            peer_ephemeral_public,
            crypto->boot_nonce,
            peer_boot_nonce,
            transcript_hash) != ESP_OK) {
        result = -1;
    }

    if (result == 0) {
        const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        if (md == NULL) {
            result = -1;
        } else {
            result = mbedtls_hkdf(
                md,
                transcript_hash,
                sizeof(transcript_hash),
                shared_bytes,
                sizeof(shared_bytes),
                HKDF_INFO,
                sizeof(HKDF_INFO) - 1,
                output,
                sizeof(output));
        }
    }

    if (result == 0) {
        const bool local_is_low = strcmp(local_id, peer_id) < 0;
        const uint8_t *low_to_high = output;
        const uint8_t *high_to_low = output + SCF_SESSION_KEY_BYTES;

        memcpy(tx_key, local_is_low ? low_to_high : high_to_low, SCF_SESSION_KEY_BYTES);
        memcpy(rx_key, local_is_low ? high_to_low : low_to_high, SCF_SESSION_KEY_BYTES);
        memcpy(
            session_id,
            output + (SCF_SESSION_KEY_BYTES * 2),
            SCF_SESSION_ID_BYTES);
    }

    mbedtls_platform_zeroize(shared_bytes, sizeof(shared_bytes));
    mbedtls_platform_zeroize(transcript_hash, sizeof(transcript_hash));
    mbedtls_platform_zeroize(output, sizeof(output));
    mbedtls_mpi_free(&shared_secret);
    mbedtls_ecp_point_free(&peer_point);

    return result == 0 ? ESP_OK : ESP_FAIL;
}

esp_err_t crypto_encrypt_message(
    const uint8_t key[SCF_SESSION_KEY_BYTES],
    const char *from,
    const char *to,
    const uint8_t session_id[SCF_SESSION_ID_BYTES],
    uint64_t counter,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    uint8_t tag[SCF_GCM_TAG_BYTES])
{
    if (key == NULL || from == NULL || to == NULL || session_id == NULL ||
        plaintext == NULL || ciphertext == NULL || tag == NULL || counter == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t nonce[SCF_GCM_NONCE_BYTES];
    uint8_t aad[128];
    size_t aad_length = 0;
    build_gcm_nonce(session_id, counter, nonce);

    esp_err_t result = build_aad(
        from,
        to,
        session_id,
        counter,
        aad,
        sizeof(aad),
        &aad_length);
    if (result != ESP_OK) {
        return result;
    }

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int mbed_result = mbedtls_gcm_setkey(
        &gcm,
        MBEDTLS_CIPHER_ID_AES,
        key,
        SCF_SESSION_KEY_BYTES * 8);
    if (mbed_result == 0) {
        mbed_result = mbedtls_gcm_crypt_and_tag(
            &gcm,
            MBEDTLS_GCM_ENCRYPT,
            plaintext_length,
            nonce,
            sizeof(nonce),
            aad,
            aad_length,
            plaintext,
            ciphertext,
            SCF_GCM_TAG_BYTES,
            tag);
    }

    mbedtls_gcm_free(&gcm);
    mbedtls_platform_zeroize(nonce, sizeof(nonce));
    mbedtls_platform_zeroize(aad, sizeof(aad));
    return mbed_result == 0 ? ESP_OK : ESP_FAIL;
}

esp_err_t crypto_decrypt_message(
    const uint8_t key[SCF_SESSION_KEY_BYTES],
    const char *from,
    const char *to,
    const uint8_t session_id[SCF_SESSION_ID_BYTES],
    uint64_t counter,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    const uint8_t tag[SCF_GCM_TAG_BYTES],
    uint8_t *plaintext)
{
    if (key == NULL || from == NULL || to == NULL || session_id == NULL ||
        ciphertext == NULL || tag == NULL || plaintext == NULL || counter == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t nonce[SCF_GCM_NONCE_BYTES];
    uint8_t aad[128];
    size_t aad_length = 0;
    build_gcm_nonce(session_id, counter, nonce);

    esp_err_t result = build_aad(
        from,
        to,
        session_id,
        counter,
        aad,
        sizeof(aad),
        &aad_length);
    if (result != ESP_OK) {
        return result;
    }

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int mbed_result = mbedtls_gcm_setkey(
        &gcm,
        MBEDTLS_CIPHER_ID_AES,
        key,
        SCF_SESSION_KEY_BYTES * 8);
    if (mbed_result == 0) {
        mbed_result = mbedtls_gcm_auth_decrypt(
            &gcm,
            ciphertext_length,
            nonce,
            sizeof(nonce),
            aad,
            aad_length,
            tag,
            SCF_GCM_TAG_BYTES,
            ciphertext,
            plaintext);
    }

    mbedtls_gcm_free(&gcm);
    mbedtls_platform_zeroize(nonce, sizeof(nonce));
    mbedtls_platform_zeroize(aad, sizeof(aad));
    return mbed_result == 0 ? ESP_OK : ESP_ERR_INVALID_CRC;
}
