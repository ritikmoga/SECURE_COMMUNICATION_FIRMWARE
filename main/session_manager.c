#include "session_manager.h"

#include <string.h>

bool session_manager_init(scf_session_manager_t *manager)
{
    if (manager == NULL) {
        return false;
    }

    memset(manager, 0, sizeof(*manager));
    manager->lock = xSemaphoreCreateMutex();
    return manager->lock != NULL;
}

void session_manager_lock(scf_session_manager_t *manager)
{
    if (manager != NULL && manager->lock != NULL) {
        xSemaphoreTake(manager->lock, portMAX_DELAY);
    }
}

void session_manager_unlock(scf_session_manager_t *manager)
{
    if (manager != NULL && manager->lock != NULL) {
        xSemaphoreGive(manager->lock);
    }
}

scf_session_t *session_manager_find(scf_session_manager_t *manager, const char *peer_id)
{
    if (manager == NULL || peer_id == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < SCF_MAX_PEERS; ++i) {
        if (manager->slots[i].used && strcmp(manager->slots[i].peer_id, peer_id) == 0) {
            return &manager->slots[i];
        }
    }

    return NULL;
}

scf_session_t *session_manager_get_or_create(scf_session_manager_t *manager, const char *peer_id)
{
    scf_session_t *existing = session_manager_find(manager, peer_id);
    if (existing != NULL) {
        return existing;
    }

    if (manager == NULL || peer_id == NULL || strlen(peer_id) >= SCF_DEVICE_ID_MAX) {
        return NULL;
    }

    for (size_t i = 0; i < SCF_MAX_PEERS; ++i) {
        if (!manager->slots[i].used) {
            memset(&manager->slots[i], 0, sizeof(manager->slots[i]));
            manager->slots[i].used = true;
            strlcpy(manager->slots[i].peer_id, peer_id, sizeof(manager->slots[i].peer_id));
            return &manager->slots[i];
        }
    }

    return NULL;
}
