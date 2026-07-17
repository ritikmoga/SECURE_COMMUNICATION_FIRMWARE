#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "device_config.h"
#include "crypto_engine.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "ota_manager.h"
#include "peer_store.h"
#include "protocol.h"
#include "sdkconfig.h"
#include "session_manager.h"
#include "tls_transport.h"
#include "wifi_manager.h"

#define RX_LINE_CAPACITY 4096
#define CONSOLE_LINE_CAPACITY (CONFIG_SCF_MAX_MESSAGE_BYTES + SCF_DEVICE_ID_MAX + 32)

static const char *TAG = "app";

typedef struct {
    scf_crypto_t crypto;
    scf_session_manager_t sessions;
    scf_transport_t transport;
    scf_protocol_t protocol;
} app_context_t;

static app_context_t s_app;

static void print_help(void)
{
    printf(
        "\nCommands:\n"
        "  send <peer> <message>  Send an end-to-end encrypted message\n"
        "  hello <peer>           Retransmit this boot's signed handshake\n"
        "  peers                  Show provisioned peers and session state\n"
        "  ota <https-url>        Install a signed HTTPS firmware update\n"
        "  help                   Show this help\n\n");
}

static void print_peers(void)
{
    session_manager_lock(&s_app.sessions);

    printf("Provisioned peers:\n");
    for (size_t i = 0; i < g_peer_identity_count; ++i) {
        scf_session_t *session = session_manager_find(
            &s_app.sessions,
            g_peer_identities[i].id);
        printf(
            "  %-20s session=%s tx=%llu rx=%llu\n",
            g_peer_identities[i].id,
            (session != NULL && session->established) ? "ready" : "not-ready",
            (unsigned long long)((session != NULL) ? session->tx_counter : 0),
            (unsigned long long)((session != NULL) ? session->rx_counter : 0));
    }

    session_manager_unlock(&s_app.sessions);
}

static void receiver_task(void *argument)
{
    (void)argument;
    char line[RX_LINE_CAPACITY];

    while (true) {
        int length = tls_transport_read_line(&s_app.transport, line, sizeof(line));
        if (length <= 0) {
            ESP_LOGE(TAG, "Relay connection closed; restarting device");
            vTaskDelay(pdMS_TO_TICKS(1500));
            esp_restart();
        }

        esp_err_t result = protocol_handle_line(&s_app.protocol, line);
        if (result != ESP_OK && result != ESP_ERR_NOT_SUPPORTED) {
            ESP_LOGW(TAG, "Rejected incoming frame: %s", esp_err_to_name(result));
        }
    }
}

static void console_task(void *argument)
{
    (void)argument;
    char line[CONSOLE_LINE_CAPACITY];

    print_help();

    while (true) {
        printf("scf> ");
        fflush(stdout);

        if (fgets(line, sizeof(line), stdin) == NULL) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0') {
            continue;
        }

        if (strcmp(line, "help") == 0) {
            print_help();
            continue;
        }

        if (strcmp(line, "peers") == 0) {
            print_peers();
            continue;
        }

        if (strncmp(line, "hello ", 6) == 0) {
            const char *peer = line + 6;
            esp_err_t result = protocol_send_hello(&s_app.protocol, peer);
            printf("%s\n", result == ESP_OK ? "Hello sent" : esp_err_to_name(result));
            continue;
        }

        if (strncmp(line, "send ", 5) == 0) {
            char *peer = line + 5;
            char *space = strchr(peer, ' ');
            if (space == NULL) {
                printf("Usage: send <peer> <message>\n");
                continue;
            }

            *space = '\0';
            const char *message = space + 1;
            esp_err_t result = protocol_send_message(
                &s_app.protocol,
                peer,
                message);
            printf("%s\n", result == ESP_OK ? "Encrypted message sent" : esp_err_to_name(result));
            continue;
        }

        if (strncmp(line, "ota ", 4) == 0) {
            esp_err_t result = ota_manager_update(line + 4);
            printf("%s\n", esp_err_to_name(result));
            continue;
        }

        if (strcmp(line, "ota") == 0 && strlen(CONFIG_SCF_OTA_URL) > 0) {
            esp_err_t result = ota_manager_update(CONFIG_SCF_OTA_URL);
            printf("%s\n", esp_err_to_name(result));
            continue;
        }

        printf("Unknown command. Type 'help'.\n");
    }
}

static esp_err_t initialize_nvs(void)
{
    esp_err_t result = nvs_flash_init();
    if (result == ESP_ERR_NVS_NO_FREE_PAGES ||
        result == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        result = nvs_flash_init();
    }
    return result;
}

void app_main(void)
{
    ESP_ERROR_CHECK(initialize_nvs());

    if (strcmp(SCF_DEVICE_ID, "UNPROVISIONED") == 0) {
        ESP_LOGE(TAG, "Run tools/configure_device.py before building");
        return;
    }

    if (g_peer_identity_count == 0) {
        ESP_LOGE(TAG, "No peer identity keys were provisioned");
        return;
    }

    ESP_LOGI(TAG, "Starting secure communication firmware as '%s'", SCF_DEVICE_ID);

    ESP_ERROR_CHECK(wifi_manager_connect());
    ESP_ERROR_CHECK(crypto_engine_init(&s_app.crypto));

    if (!session_manager_init(&s_app.sessions)) {
        ESP_LOGE(TAG, "Session manager initialization failed");
        return;
    }

    ESP_ERROR_CHECK(tls_transport_connect(&s_app.transport));

    protocol_init(
        &s_app.protocol,
        SCF_DEVICE_ID,
        &s_app.transport,
        &s_app.crypto,
        &s_app.sessions);

    ESP_ERROR_CHECK(protocol_send_register(&s_app.protocol));
    ESP_ERROR_CHECK(protocol_send_hello_all(&s_app.protocol));

    // The firmware has passed its startup self-test: NVS, Wi-Fi, crypto,
    // certificate verification, mutual TLS, and relay registration.
    ESP_ERROR_CHECK(ota_manager_confirm_running_image());

    xTaskCreate(receiver_task, "scf_receiver", 8192, NULL, 6, NULL);
    xTaskCreate(console_task, "scf_console", 6144, NULL, 5, NULL);
}
