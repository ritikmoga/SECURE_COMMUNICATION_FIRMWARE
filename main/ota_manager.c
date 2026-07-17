#include "ota_manager.h"

#include <string.h>

#include "esp_app_desc.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_system.h"

static const char *TAG = "ota";

extern const unsigned char relay_ca_crt_start[] asm("_binary_certs_relay_ca_crt_start");
extern const unsigned char relay_ca_crt_end[] asm("_binary_certs_relay_ca_crt_end");

esp_err_t ota_manager_confirm_running_image(void)
{
#if CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t state;

    if (esp_ota_get_state_partition(running, &state) == ESP_OK &&
        state == ESP_OTA_IMG_PENDING_VERIFY) {
        ESP_LOGI(TAG, "New firmware passed startup checks; confirming image");
        return esp_ota_mark_app_valid_cancel_rollback();
    }
#endif
    return ESP_OK;
}

esp_err_t ota_manager_update(const char *url)
{
    if (url == NULL || strncmp(url, "https://", 8) != 0) {
        ESP_LOGE(TAG, "OTA URL must use HTTPS");
        return ESP_ERR_INVALID_ARG;
    }

    esp_http_client_config_t http_config = {
        .url = url,
        .cert_pem = (const char *)relay_ca_crt_start,
        .cert_len = (size_t)(relay_ca_crt_end - relay_ca_crt_start),
        .timeout_ms = 15000,
        .keep_alive_enable = true,
    };

    esp_https_ota_config_t ota_config = {
        .http_config = &http_config,
    };

    ESP_LOGI(TAG, "Downloading signed firmware from %s", url);
    esp_err_t result = esp_https_ota(&ota_config);
    if (result != ESP_OK) {
        ESP_LOGE(TAG, "OTA failed: %s", esp_err_to_name(result));
        return result;
    }

    ESP_LOGI(TAG, "OTA complete; restarting");
    esp_restart();
    return ESP_OK;
}
