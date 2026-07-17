#pragma once

#include <stddef.h>

#define SCF_DEVICE_ID_MAX 32

typedef struct {
    const char *id;
    const char *identity_pub_pem;
} peer_identity_t;

extern const peer_identity_t g_peer_identities[];
extern const size_t g_peer_identity_count;

const peer_identity_t *peer_store_find(const char *peer_id);
