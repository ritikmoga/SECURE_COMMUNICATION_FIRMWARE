#include "protocol.h"

#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "esp_log.h"
#include "mbedtls/base64.h"
#include "mbedtls/platform_util.h"
#include "peer_store.h"
#include "sdkconfig.h"

#define JSON_LINE_CAPACITY 4096
#define BASE64_CIPHERTEXT_CAPACITY (((CONFIG_SCF_MAX_MESSAGE_BYTES + 2) / 3) * 4 + 1)

static const char *TAG = "protocol";

static esp_err_t b64_encode(
    const uint8_t *input,
    size_t input_length,
    char *output,
    size_t output_capacity)
{
    size_t written = 0;
    int result = mbedtls_base64_encode(
        (unsigned char *)output,
        output_capacity,
        &written,
        input,
        input_length);
    if (result != 0 || written >= output_capacity) {
        return ESP_ERR_NO_MEM;
    }

    output[written] = '\0';
    return ESP_OK;
}

static esp_err_t b64_decode_exact(
    const char *input,
    uint8_t *output,
    size_t expected_length)
{
    size_t written = 0;
    int result = mbedtls_base64_decode(
        output,
        expected_length,
        &written,
        (const unsigned char *)input,
        strlen(input));
    return (result == 0 && written == expected_length) ? ESP_OK : ESP_ERR_INVALID_SIZE;
}

static esp_err_t send_json(scf_protocol_t *protocol, cJSON *root)
{
    char *serialized = cJSON_PrintUnformatted(root);
    if (serialized == NULL) {
        return ESP_ERR_NO_MEM;
    }

    if (strlen(serialized) >= JSON_LINE_CAPACITY) {
        cJSON_free(serialized);
        return ESP_ERR_INVALID_SIZE;
    }

    esp_err_t result = tls_transport_send_line(protocol->transport, serialized);
    cJSON_free(serialized);
    return result;
}

void protocol_init(
    scf_protocol_t *protocol,
    const char *device_id,
    scf_transport_t *transport,
    scf_crypto_t *crypto,
    scf_session_manager_t *sessions)
{
    protocol->device_id = device_id;
    protocol->transport = transport;
    protocol->crypto = crypto;
    protocol->sessions = sessions;
}

esp_err_t protocol_send_register(scf_protocol_t *protocol)
{
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return ESP_ERR_NO_MEM;
    }

    cJSON_AddStringToObject(root, "type", "register");
    cJSON_AddStringToObject(root, "device_id", protocol->device_id);
    esp_err_t result = send_json(protocol, root);
    cJSON_Delete(root);
    return result;
}

esp_err_t protocol_send_hello(scf_protocol_t *protocol, const char *peer_id)
{
    if (peer_store_find(peer_id) == NULL) {
        ESP_LOGE(TAG, "Peer '%s' is not provisioned", peer_id);
        return ESP_ERR_NOT_FOUND;
    }

    uint8_t signature[SCF_SIGNATURE_MAX_BYTES];
    size_t signature_length = 0;
    esp_err_t result = crypto_sign_hello(
        protocol->crypto,
        protocol->device_id,
        peer_id,
        signature,
        sizeof(signature),
        &signature_length);
    if (result != ESP_OK) {
        return result;
    }

    char public_b64[128];
    char nonce_b64[64];
    char signature_b64[192];

    result = b64_encode(
        protocol->crypto->ephemeral_public_bin,
        SCF_EPHEMERAL_PUBLIC_BYTES,
        public_b64,
        sizeof(public_b64));
    if (result == ESP_OK) {
        result = b64_encode(
            protocol->crypto->boot_nonce,
            SCF_BOOT_NONCE_BYTES,
            nonce_b64,
            sizeof(nonce_b64));
    }
    if (result == ESP_OK) {
        result = b64_encode(
            signature,
            signature_length,
            signature_b64,
            sizeof(signature_b64));
    }
    mbedtls_platform_zeroize(signature, sizeof(signature));

    if (result != ESP_OK) {
        return result;
    }

    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return ESP_ERR_NO_MEM;
    }

    cJSON_AddStringToObject(root, "type", "hello");
    cJSON_AddStringToObject(root, "from", protocol->device_id);
    cJSON_AddStringToObject(root, "to", peer_id);
    cJSON_AddStringToObject(root, "ephemeral_public", public_b64);
    cJSON_AddStringToObject(root, "boot_nonce", nonce_b64);
    cJSON_AddStringToObject(root, "signature", signature_b64);

    result = send_json(protocol, root);
    cJSON_Delete(root);

    if (result == ESP_OK) {
        session_manager_lock(protocol->sessions);
        scf_session_t *session = session_manager_get_or_create(protocol->sessions, peer_id);
        if (session != NULL) {
            session->hello_sent = true;
        }
        session_manager_unlock(protocol->sessions);
    }

    return result;
}

esp_err_t protocol_send_hello_all(scf_protocol_t *protocol)
{
    esp_err_t final_result = ESP_OK;

    for (size_t i = 0; i < g_peer_identity_count; ++i) {
        esp_err_t result = protocol_send_hello(protocol, g_peer_identities[i].id);
        if (result != ESP_OK) {
            final_result = result;
        }
    }

    return final_result;
}

esp_err_t protocol_send_message(
    scf_protocol_t *protocol,
    const char *peer_id,
    const char *message)
{
    if (peer_id == NULL || message == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    size_t message_length = strlen(message);
    if (message_length == 0 || message_length > CONFIG_SCF_MAX_MESSAGE_BYTES) {
        ESP_LOGE(TAG, "Message must contain 1..%d bytes", CONFIG_SCF_MAX_MESSAGE_BYTES);
        return ESP_ERR_INVALID_SIZE;
    }

    uint8_t tx_key[SCF_SESSION_KEY_BYTES];
    uint8_t session_id[SCF_SESSION_ID_BYTES];
    uint64_t counter = 0;

    session_manager_lock(protocol->sessions);
    scf_session_t *session = session_manager_find(protocol->sessions, peer_id);
    if (session == NULL || !session->established) {
        session_manager_unlock(protocol->sessions);
        ESP_LOGW(TAG, "No secure session with '%s'; send hello first", peer_id);
        return ESP_ERR_INVALID_STATE;
    }

    if (session->tx_counter == UINT64_MAX) {
        session_manager_unlock(protocol->sessions);
        ESP_LOGE(TAG, "Transmit counter exhausted for '%s'; reboot to create a new session", peer_id);
        return ESP_ERR_INVALID_STATE;
    }

    counter = ++session->tx_counter;
    memcpy(tx_key, session->tx_key, sizeof(tx_key));
    memcpy(session_id, session->session_id, sizeof(session_id));
    session_manager_unlock(protocol->sessions);

    uint8_t ciphertext[CONFIG_SCF_MAX_MESSAGE_BYTES];
    uint8_t tag[SCF_GCM_TAG_BYTES];

    esp_err_t result = crypto_encrypt_message(
        tx_key,
        protocol->device_id,
        peer_id,
        session_id,
        counter,
        (const uint8_t *)message,
        message_length,
        ciphertext,
        tag);
    mbedtls_platform_zeroize(tx_key, sizeof(tx_key));
    if (result != ESP_OK) {
        return result;
    }

    char session_b64[32];
    char ciphertext_b64[BASE64_CIPHERTEXT_CAPACITY];
    char tag_b64[32];
    char counter_text[24];

    result = b64_encode(session_id, sizeof(session_id), session_b64, sizeof(session_b64));
    if (result == ESP_OK) {
        result = b64_encode(ciphertext, message_length, ciphertext_b64, sizeof(ciphertext_b64));
    }
    if (result == ESP_OK) {
        result = b64_encode(tag, sizeof(tag), tag_b64, sizeof(tag_b64));
    }

    mbedtls_platform_zeroize(ciphertext, sizeof(ciphertext));
    mbedtls_platform_zeroize(tag, sizeof(tag));

    if (result != ESP_OK) {
        return result;
    }

    snprintf(counter_text, sizeof(counter_text), "%" PRIu64, counter);

    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return ESP_ERR_NO_MEM;
    }

    cJSON_AddStringToObject(root, "type", "data");
    cJSON_AddStringToObject(root, "from", protocol->device_id);
    cJSON_AddStringToObject(root, "to", peer_id);
    cJSON_AddStringToObject(root, "session_id", session_b64);
    cJSON_AddStringToObject(root, "counter", counter_text);
    cJSON_AddStringToObject(root, "ciphertext", ciphertext_b64);
    cJSON_AddStringToObject(root, "tag", tag_b64);

    result = send_json(protocol, root);
    cJSON_Delete(root);
    return result;
}

static esp_err_t handle_hello(scf_protocol_t *protocol, const cJSON *root)
{
    const cJSON *from = cJSON_GetObjectItemCaseSensitive(root, "from");
    const cJSON *to = cJSON_GetObjectItemCaseSensitive(root, "to");
    const cJSON *public_item = cJSON_GetObjectItemCaseSensitive(root, "ephemeral_public");
    const cJSON *nonce_item = cJSON_GetObjectItemCaseSensitive(root, "boot_nonce");
    const cJSON *signature_item = cJSON_GetObjectItemCaseSensitive(root, "signature");

    if (!cJSON_IsString(from) || !cJSON_IsString(to) ||
        !cJSON_IsString(public_item) || !cJSON_IsString(nonce_item) ||
        !cJSON_IsString(signature_item)) {
        return ESP_ERR_INVALID_ARG;
    }

    if (strcmp(to->valuestring, protocol->device_id) != 0 ||
        strlen(from->valuestring) >= SCF_DEVICE_ID_MAX) {
        return ESP_ERR_INVALID_ARG;
    }

    const peer_identity_t *peer = peer_store_find(from->valuestring);
    if (peer == NULL) {
        ESP_LOGW(TAG, "Rejected hello from unprovisioned peer '%s'", from->valuestring);
        return ESP_ERR_NOT_FOUND;
    }

    uint8_t peer_public[SCF_EPHEMERAL_PUBLIC_BYTES];
    uint8_t peer_nonce[SCF_BOOT_NONCE_BYTES];
    uint8_t signature[SCF_SIGNATURE_MAX_BYTES];
    size_t signature_length = 0;

    esp_err_t result = b64_decode_exact(
        public_item->valuestring,
        peer_public,
        sizeof(peer_public));
    if (result == ESP_OK) {
        result = b64_decode_exact(
            nonce_item->valuestring,
            peer_nonce,
            sizeof(peer_nonce));
    }
    if (result == ESP_OK) {
        int decode_result = mbedtls_base64_decode(
            signature,
            sizeof(signature),
            &signature_length,
            (const unsigned char *)signature_item->valuestring,
            strlen(signature_item->valuestring));
        result = decode_result == 0 ? ESP_OK : ESP_ERR_INVALID_SIZE;
    }
    if (result != ESP_OK) {
        return result;
    }

    result = crypto_verify_hello(
        peer->identity_pub_pem,
        from->valuestring,
        protocol->device_id,
        peer_public,
        peer_nonce,
        signature,
        signature_length);
    mbedtls_platform_zeroize(signature, sizeof(signature));
    if (result != ESP_OK) {
        ESP_LOGW(TAG, "Invalid identity signature from '%s'", from->valuestring);
        return result;
    }

    bool should_reply = false;
    uint8_t tx_key[SCF_SESSION_KEY_BYTES];
    uint8_t rx_key[SCF_SESSION_KEY_BYTES];
    uint8_t session_id[SCF_SESSION_ID_BYTES];

    result = crypto_derive_session(
        protocol->crypto,
        protocol->device_id,
        from->valuestring,
        peer_public,
        peer_nonce,
        tx_key,
        rx_key,
        session_id);
    if (result != ESP_OK) {
        return result;
    }

    session_manager_lock(protocol->sessions);
    scf_session_t *session = session_manager_get_or_create(
        protocol->sessions,
        from->valuestring);
    if (session == NULL) {
        result = ESP_ERR_NO_MEM;
    } else {
        /*
         * A signed hello may be retransmitted by the relay or replayed by an
         * attacker. Treat an already-established, byte-identical handshake as
         * idempotent. Resetting counters for the same key/session would make
         * previously accepted ciphertext replayable.
         */
        bool duplicate_handshake = session->established &&
            memcmp(session->peer_ephemeral_pub, peer_public, sizeof(peer_public)) == 0 &&
            memcmp(session->peer_boot_nonce, peer_nonce, sizeof(peer_nonce)) == 0 &&
            memcmp(session->session_id, session_id, sizeof(session_id)) == 0;

        /*
         * Reply to a genuinely new peer boot/handshake even if this device has
         * sent a hello before. This lets one peer reboot and re-establish a
         * session while the other peer remains online. Duplicate hellos do not
         * trigger another reply, preventing an acknowledgement loop.
         */
        should_reply = !session->hello_sent || !duplicate_handshake;

        if (!duplicate_handshake) {
            memcpy(session->peer_ephemeral_pub, peer_public, sizeof(peer_public));
            memcpy(session->peer_boot_nonce, peer_nonce, sizeof(peer_nonce));
            memcpy(session->tx_key, tx_key, sizeof(tx_key));
            memcpy(session->rx_key, rx_key, sizeof(rx_key));
            memcpy(session->session_id, session_id, sizeof(session_id));
            session->tx_counter = 0;
            session->rx_counter = 0;
            session->established = true;
        }
    }
    session_manager_unlock(protocol->sessions);

    mbedtls_platform_zeroize(tx_key, sizeof(tx_key));
    mbedtls_platform_zeroize(rx_key, sizeof(rx_key));

    if (result != ESP_OK) {
        return result;
    }

    ESP_LOGI(TAG, "End-to-end session established with '%s'", from->valuestring);

    if (should_reply) {
        return protocol_send_hello(protocol, from->valuestring);
    }

    return ESP_OK;
}

static esp_err_t handle_data(scf_protocol_t *protocol, const cJSON *root)
{
    const cJSON *from = cJSON_GetObjectItemCaseSensitive(root, "from");
    const cJSON *to = cJSON_GetObjectItemCaseSensitive(root, "to");
    const cJSON *session_item = cJSON_GetObjectItemCaseSensitive(root, "session_id");
    const cJSON *counter_item = cJSON_GetObjectItemCaseSensitive(root, "counter");
    const cJSON *ciphertext_item = cJSON_GetObjectItemCaseSensitive(root, "ciphertext");
    const cJSON *tag_item = cJSON_GetObjectItemCaseSensitive(root, "tag");

    if (!cJSON_IsString(from) || !cJSON_IsString(to) ||
        !cJSON_IsString(session_item) || !cJSON_IsString(counter_item) ||
        !cJSON_IsString(ciphertext_item) || !cJSON_IsString(tag_item)) {
        return ESP_ERR_INVALID_ARG;
    }

    if (strcmp(to->valuestring, protocol->device_id) != 0) {
        return ESP_ERR_INVALID_ARG;
    }

    errno = 0;
    char *counter_end = NULL;
    uint64_t counter = strtoull(counter_item->valuestring, &counter_end, 10);
    if (errno == ERANGE || counter == 0 || counter_end == NULL || *counter_end != '\0') {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t received_session_id[SCF_SESSION_ID_BYTES];
    uint8_t tag[SCF_GCM_TAG_BYTES];
    uint8_t ciphertext[CONFIG_SCF_MAX_MESSAGE_BYTES];
    size_t ciphertext_length = 0;

    esp_err_t result = b64_decode_exact(
        session_item->valuestring,
        received_session_id,
        sizeof(received_session_id));
    if (result == ESP_OK) {
        result = b64_decode_exact(tag_item->valuestring, tag, sizeof(tag));
    }
    if (result == ESP_OK) {
        int decode_result = mbedtls_base64_decode(
            ciphertext,
            sizeof(ciphertext),
            &ciphertext_length,
            (const unsigned char *)ciphertext_item->valuestring,
            strlen(ciphertext_item->valuestring));
        result = (decode_result == 0 && ciphertext_length > 0) ?
            ESP_OK : ESP_ERR_INVALID_SIZE;
    }
    if (result != ESP_OK) {
        return result;
    }

    uint8_t rx_key[SCF_SESSION_KEY_BYTES];
    uint8_t expected_session_id[SCF_SESSION_ID_BYTES];

    session_manager_lock(protocol->sessions);
    scf_session_t *session = session_manager_find(protocol->sessions, from->valuestring);
    if (session == NULL || !session->established ||
        memcmp(session->session_id, received_session_id, SCF_SESSION_ID_BYTES) != 0) {
        session_manager_unlock(protocol->sessions);
        return ESP_ERR_INVALID_STATE;
    }

    if (counter <= session->rx_counter) {
        session_manager_unlock(protocol->sessions);
        ESP_LOGW(TAG, "Replay/out-of-order message rejected from '%s'", from->valuestring);
        return ESP_ERR_INVALID_STATE;
    }

    memcpy(rx_key, session->rx_key, sizeof(rx_key));
    memcpy(expected_session_id, session->session_id, sizeof(expected_session_id));
    session_manager_unlock(protocol->sessions);

    uint8_t plaintext[CONFIG_SCF_MAX_MESSAGE_BYTES + 1];
    result = crypto_decrypt_message(
        rx_key,
        from->valuestring,
        protocol->device_id,
        expected_session_id,
        counter,
        ciphertext,
        ciphertext_length,
        tag,
        plaintext);
    mbedtls_platform_zeroize(rx_key, sizeof(rx_key));
    mbedtls_platform_zeroize(ciphertext, sizeof(ciphertext));
    mbedtls_platform_zeroize(tag, sizeof(tag));

    if (result != ESP_OK) {
        ESP_LOGW(TAG, "Message authentication failed from '%s'", from->valuestring);
        return result;
    }

    plaintext[ciphertext_length] = '\0';

    session_manager_lock(protocol->sessions);
    session = session_manager_find(protocol->sessions, from->valuestring);
    if (session != NULL && session->established && counter > session->rx_counter) {
        session->rx_counter = counter;
    }
    session_manager_unlock(protocol->sessions);

    ESP_LOGI(TAG, "MESSAGE from %s: %s", from->valuestring, (char *)plaintext);
    mbedtls_platform_zeroize(plaintext, sizeof(plaintext));
    return ESP_OK;
}

esp_err_t protocol_handle_line(scf_protocol_t *protocol, const char *line)
{
    cJSON *root = cJSON_Parse(line);
    if (root == NULL) {
        ESP_LOGW(TAG, "Rejected malformed JSON");
        return ESP_ERR_INVALID_ARG;
    }

    const cJSON *type = cJSON_GetObjectItemCaseSensitive(root, "type");
    esp_err_t result = ESP_ERR_NOT_SUPPORTED;

    if (cJSON_IsString(type)) {
        if (strcmp(type->valuestring, "hello") == 0) {
            result = handle_hello(protocol, root);
        } else if (strcmp(type->valuestring, "data") == 0) {
            result = handle_data(protocol, root);
        } else if (strcmp(type->valuestring, "status") == 0) {
            const cJSON *message = cJSON_GetObjectItemCaseSensitive(root, "message");
            if (cJSON_IsString(message)) {
                ESP_LOGI(TAG, "Relay status: %s", message->valuestring);
            }
            result = ESP_OK;
        } else if (strcmp(type->valuestring, "error") == 0) {
            const cJSON *message = cJSON_GetObjectItemCaseSensitive(root, "message");
            ESP_LOGE(TAG, "Relay error: %s", cJSON_IsString(message) ? message->valuestring : "unknown");
            result = ESP_FAIL;
        }
    }

    cJSON_Delete(root);
    return result;
}
