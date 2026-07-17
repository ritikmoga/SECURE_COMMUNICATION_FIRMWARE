#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "peer_store.h"

#define SCF_MAX_PEERS 8
#define SCF_SESSION_KEY_BYTES 32
#define SCF_SESSION_ID_BYTES 8
#define SCF_EPHEMERAL_PUBLIC_BYTES 65
#define SCF_BOOT_NONCE_BYTES 16

typedef struct {
    bool used;
    bool hello_sent;
    bool established;
    char peer_id[SCF_DEVICE_ID_MAX];
    uint8_t peer_ephemeral_pub[SCF_EPHEMERAL_PUBLIC_BYTES];
    uint8_t peer_boot_nonce[SCF_BOOT_NONCE_BYTES];
    uint8_t tx_key[SCF_SESSION_KEY_BYTES];
    uint8_t rx_key[SCF_SESSION_KEY_BYTES];
    uint8_t session_id[SCF_SESSION_ID_BYTES];
    uint64_t tx_counter;
    uint64_t rx_counter;
} scf_session_t;

typedef struct {
    SemaphoreHandle_t lock;
    scf_session_t slots[SCF_MAX_PEERS];
} scf_session_manager_t;

bool session_manager_init(scf_session_manager_t *manager);
scf_session_t *session_manager_get_or_create(scf_session_manager_t *manager, const char *peer_id);
scf_session_t *session_manager_find(scf_session_manager_t *manager, const char *peer_id);
void session_manager_lock(scf_session_manager_t *manager);
void session_manager_unlock(scf_session_manager_t *manager);
