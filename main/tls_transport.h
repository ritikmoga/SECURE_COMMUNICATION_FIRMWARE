#pragma once

#include <stddef.h>

#include "esp_err.h"
#include "esp_tls.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

typedef struct {
    esp_tls_t *tls;
    SemaphoreHandle_t write_lock;
} scf_transport_t;

esp_err_t tls_transport_connect(scf_transport_t *transport);
void tls_transport_close(scf_transport_t *transport);
esp_err_t tls_transport_send_line(scf_transport_t *transport, const char *line);
int tls_transport_read_line(scf_transport_t *transport, char *buffer, size_t capacity);
