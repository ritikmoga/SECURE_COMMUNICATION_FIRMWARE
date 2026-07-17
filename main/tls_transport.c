#include "tls_transport.h"

#include <errno.h>
#include <string.h>

#include "esp_log.h"
#include "sdkconfig.h"

static const char *TAG = "transport";

extern const unsigned char relay_ca_crt_start[] asm("_binary_certs_relay_ca_crt_start");
extern const unsigned char relay_ca_crt_end[] asm("_binary_certs_relay_ca_crt_end");
extern const unsigned char client_crt_start[] asm("_binary_certs_client_crt_start");
extern const unsigned char client_crt_end[] asm("_binary_certs_client_crt_end");
extern const unsigned char client_key_start[] asm("_binary_certs_client_key_start");
extern const unsigned char client_key_end[] asm("_binary_certs_client_key_end");

static esp_err_t write_all(esp_tls_t *tls, const void *data, size_t length)
{
    const unsigned char *cursor = data;
    size_t remaining = length;

    while (remaining > 0) {
        ssize_t written = esp_tls_conn_write(tls, cursor, remaining);
        if (written == ESP_TLS_ERR_SSL_WANT_READ || written == ESP_TLS_ERR_SSL_WANT_WRITE) {
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }
        if (written <= 0) {
            ESP_LOGE(TAG, "TLS write failed: %d", (int)written);
            return ESP_FAIL;
        }

        cursor += written;
        remaining -= (size_t)written;
    }

    return ESP_OK;
}

esp_err_t tls_transport_connect(scf_transport_t *transport)
{
    if (transport == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(transport, 0, sizeof(*transport));
    transport->write_lock = xSemaphoreCreateMutex();
    if (transport->write_lock == NULL) {
        return ESP_ERR_NO_MEM;
    }

    esp_tls_cfg_t config = {
        .cacert_buf = relay_ca_crt_start,
        .cacert_bytes = (unsigned int)(relay_ca_crt_end - relay_ca_crt_start),
        .clientcert_buf = client_crt_start,
        .clientcert_bytes = (unsigned int)(client_crt_end - client_crt_start),
        .clientkey_buf = client_key_start,
        .clientkey_bytes = (unsigned int)(client_key_end - client_key_start),
        .common_name = CONFIG_SCF_RELAY_HOST,
        .skip_common_name = false,
        .timeout_ms = 15000,
#if CONFIG_SCF_TLS13_ONLY
        .tls_version = ESP_TLS_VER_TLS_1_3,
#else
        .tls_version = ESP_TLS_VER_ANY,
#endif
    };

    transport->tls = esp_tls_init();
    if (transport->tls == NULL) {
        vSemaphoreDelete(transport->write_lock);
        transport->write_lock = NULL;
        return ESP_ERR_NO_MEM;
    }

    int result = esp_tls_conn_new_sync(
        CONFIG_SCF_RELAY_HOST,
        (int)strlen(CONFIG_SCF_RELAY_HOST),
        CONFIG_SCF_RELAY_PORT,
        &config,
        transport->tls);

    if (result != 1) {
        ESP_LOGE(TAG, "TLS connection failed");
        tls_transport_close(transport);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Mutual TLS connected to %s:%d", CONFIG_SCF_RELAY_HOST, CONFIG_SCF_RELAY_PORT);
    return ESP_OK;
}

void tls_transport_close(scf_transport_t *transport)
{
    if (transport == NULL) {
        return;
    }

    if (transport->tls != NULL) {
        esp_tls_conn_destroy(transport->tls);
        transport->tls = NULL;
    }

    if (transport->write_lock != NULL) {
        vSemaphoreDelete(transport->write_lock);
        transport->write_lock = NULL;
    }
}

esp_err_t tls_transport_send_line(scf_transport_t *transport, const char *line)
{
    if (transport == NULL || transport->tls == NULL || line == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    xSemaphoreTake(transport->write_lock, portMAX_DELAY);
    esp_err_t result = write_all(transport->tls, line, strlen(line));
    if (result == ESP_OK) {
        result = write_all(transport->tls, "\n", 1);
    }
    xSemaphoreGive(transport->write_lock);

    return result;
}

int tls_transport_read_line(scf_transport_t *transport, char *buffer, size_t capacity)
{
    if (transport == NULL || transport->tls == NULL || buffer == NULL || capacity < 2) {
        return -1;
    }

    size_t used = 0;

    while (used + 1 < capacity) {
        unsigned char ch = 0;
        ssize_t count = esp_tls_conn_read(transport->tls, &ch, 1);

        if (count == ESP_TLS_ERR_SSL_WANT_READ || count == ESP_TLS_ERR_SSL_WANT_WRITE) {
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }

        if (count <= 0) {
            return (used == 0) ? (int)count : (int)used;
        }

        if (ch == '\n') {
            buffer[used] = '\0';
            return (int)used;
        }

        if (ch != '\r') {
            buffer[used++] = (char)ch;
        }
    }

    buffer[used] = '\0';
    ESP_LOGW(TAG, "Incoming line exceeded %u bytes", (unsigned)capacity);
    return (int)used;
}
