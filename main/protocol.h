#pragma once

#include "crypto_engine.h"
#include "session_manager.h"
#include "tls_transport.h"

typedef struct {
    const char *device_id;
    scf_transport_t *transport;
    scf_crypto_t *crypto;
    scf_session_manager_t *sessions;
} scf_protocol_t;

void protocol_init(
    scf_protocol_t *protocol,
    const char *device_id,
    scf_transport_t *transport,
    scf_crypto_t *crypto,
    scf_session_manager_t *sessions);

esp_err_t protocol_send_register(scf_protocol_t *protocol);
esp_err_t protocol_send_hello(scf_protocol_t *protocol, const char *peer_id);
esp_err_t protocol_send_hello_all(scf_protocol_t *protocol);
esp_err_t protocol_send_message(
    scf_protocol_t *protocol,
    const char *peer_id,
    const char *message);

esp_err_t protocol_handle_line(scf_protocol_t *protocol, const char *line);
