#include "wifi_manager.h"

#include <string.h>
#include <time.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_netif_sntp.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "sdkconfig.h"

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAILED_BIT    BIT1
#define WIFI_MAX_RETRIES   10

static const char *TAG = "wifi";
static EventGroupHandle_t s_wifi_event_group;
static int s_retry_count;

static esp_err_t synchronize_system_time(void)
{
    if (strlen(CONFIG_SCF_NTP_SERVER) == 0) {
        ESP_LOGE(TAG, "Set an NTP server with: idf.py menuconfig");
        return ESP_ERR_INVALID_STATE;
    }

    esp_sntp_config_t config = ESP_NETIF_SNTP_DEFAULT_CONFIG(CONFIG_SCF_NTP_SERVER);
    esp_err_t result = esp_netif_sntp_init(&config);
    if (result != ESP_OK) {
        ESP_LOGE(TAG, "SNTP initialization failed: %s", esp_err_to_name(result));
        return result;
    }

    result = esp_netif_sntp_sync_wait(
        pdMS_TO_TICKS(CONFIG_SCF_TIME_SYNC_TIMEOUT_SECONDS * 1000));
    if (result != ESP_OK) {
        ESP_LOGE(TAG, "System time synchronization failed: %s", esp_err_to_name(result));
        return result;
    }

    time_t now = 0;
    time(&now);
    if (now < 1704067200) { /* 2024-01-01 UTC: reject an obviously unset clock. */
        ESP_LOGE(TAG, "System clock is still invalid after SNTP synchronization");
        return ESP_ERR_INVALID_STATE;
    }

    struct tm utc_time = {0};
    gmtime_r(&now, &utc_time);
    ESP_LOGI(
        TAG,
        "System time synchronized: %04d-%02d-%02dT%02d:%02d:%02dZ",
        utc_time.tm_year + 1900,
        utc_time.tm_mon + 1,
        utc_time.tm_mday,
        utc_time.tm_hour,
        utc_time.tm_min,
        utc_time.tm_sec);
    return ESP_OK;
}

static void wifi_event_handler(
    void *arg,
    esp_event_base_t event_base,
    int32_t event_id,
    void *event_data)
{
    (void)arg;
    (void)event_data;

    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
        return;
    }

    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_count < WIFI_MAX_RETRIES) {
            ++s_retry_count;
            esp_wifi_connect();
            ESP_LOGW(TAG, "Wi-Fi disconnected; retry %d/%d", s_retry_count, WIFI_MAX_RETRIES);
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAILED_BIT);
        }
        return;
    }

    if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        s_retry_count = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

esp_err_t wifi_manager_connect(void)
{
    if (strlen(CONFIG_SCF_WIFI_SSID) == 0) {
        ESP_LOGE(TAG, "Set Wi-Fi credentials with: idf.py menuconfig");
        return ESP_ERR_INVALID_STATE;
    }

    s_wifi_event_group = xEventGroupCreate();
    if (s_wifi_event_group == NULL) {
        return ESP_ERR_NO_MEM;
    }

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_netif_create_default_wifi_sta();

    wifi_init_config_t init_config = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init_config));

    esp_event_handler_instance_t any_id_instance;
    esp_event_handler_instance_t got_ip_instance;

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT,
        ESP_EVENT_ANY_ID,
        &wifi_event_handler,
        NULL,
        &any_id_instance));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT,
        IP_EVENT_STA_GOT_IP,
        &wifi_event_handler,
        NULL,
        &got_ip_instance));

    wifi_config_t wifi_config = {0};
    strlcpy((char *)wifi_config.sta.ssid, CONFIG_SCF_WIFI_SSID, sizeof(wifi_config.sta.ssid));
    strlcpy((char *)wifi_config.sta.password, CONFIG_SCF_WIFI_PASSWORD, sizeof(wifi_config.sta.password));
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    wifi_config.sta.pmf_cfg.capable = true;
    wifi_config.sta.pmf_cfg.required = false;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    EventBits_t bits = xEventGroupWaitBits(
        s_wifi_event_group,
        WIFI_CONNECTED_BIT | WIFI_FAILED_BIT,
        pdFALSE,
        pdFALSE,
        portMAX_DELAY);

    esp_err_t result = ESP_FAIL;
    if ((bits & WIFI_CONNECTED_BIT) != 0) {
        ESP_LOGI(TAG, "Connected to Wi-Fi");
        result = synchronize_system_time();
    } else {
        ESP_LOGE(TAG, "Failed to connect to Wi-Fi");
    }

    esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, got_ip_instance);
    esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, any_id_instance);
    vEventGroupDelete(s_wifi_event_group);
    s_wifi_event_group = NULL;

    return result;
}
