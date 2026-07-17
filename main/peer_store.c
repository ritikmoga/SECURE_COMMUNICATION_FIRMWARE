#include "peer_store.h"

#include <string.h>

const peer_identity_t *peer_store_find(const char *peer_id)
{
    if (peer_id == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < g_peer_identity_count; ++i) {
        if (strcmp(g_peer_identities[i].id, peer_id) == 0) {
            return &g_peer_identities[i];
        }
    }

    return NULL;
}
