#pragma once

#include "esp_err.h"

esp_err_t ota_manager_confirm_running_image(void);
esp_err_t ota_manager_update(const char *url);
