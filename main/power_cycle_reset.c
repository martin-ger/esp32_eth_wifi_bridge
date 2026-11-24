#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "nvs.h"

#include "power_cycle_reset.h"
#include "wifi_config.h"
#include "router_config.h"

// ============================================================================
// Factory-Reset-on-Power-Cycle feature
// ============================================================================
#ifdef CONFIG_POWER_CYCLE_RESET_ENABLED

static const char *TAG_PC = "PWR_CYCLE_RESET";

#define PWR_CYCLE_KEY     "pwr_cycles"
#define MAX_POWER_CYCLES  CONFIG_POWER_CYCLE_RESET_COUNT
#define CYCLE_TIMEOUT_SEC CONFIG_POWER_CYCLE_RESET_TIMEOUT_SEC

static esp_timer_handle_t s_stable_timer;

/* One-shot timer callback: device has been up long enough, clear the counter. */
static void pwr_cycle_stable_cb(void *arg)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err == ESP_OK) {
        err = nvs_set_u8(nvs, PWR_CYCLE_KEY, 0);
        if (err == ESP_OK) err = nvs_commit(nvs);
        nvs_close(nvs);
    }
    if (err == ESP_OK) {
        ESP_LOGI(TAG_PC, "Stable for %d s, power cycle counter cleared", CYCLE_TIMEOUT_SEC);
    } else {
        ESP_LOGE(TAG_PC, "Failed to clear power cycle counter: %s", esp_err_to_name(err));
    }
    esp_timer_delete(s_stable_timer);
    s_stable_timer = NULL;
}

void check_power_cycle_factory_reset(void)
{
    esp_reset_reason_t r = esp_reset_reason();
    if (r != ESP_RST_POWERON && r != ESP_RST_EXT) {
        /* not a power cycle: don't count, don't arm the timer */
        return;
    }

    nvs_handle_t nvs;
    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_PC, "Error opening NVS handle: %s", esp_err_to_name(err));
        return;
    }

    uint8_t pwr_cycles = 0;
    nvs_get_u8(nvs, PWR_CYCLE_KEY, &pwr_cycles);   /* stays 0 if not found */
    pwr_cycles++;

    ESP_LOGI(TAG_PC, "Power cycle %d of %d", pwr_cycles, MAX_POWER_CYCLES);

    if (pwr_cycles >= MAX_POWER_CYCLES) {
        nvs_close(nvs);
        ESP_LOGW(TAG_PC, "Threshold reached, performing factory reset");
        /* Erases the whole PARAM_NAMESPACE, including the counter itself */
        err = factory_reset_settings();
        if (err == ESP_OK) {
            ESP_LOGW(TAG_PC, "Settings erased, restarting with factory defaults...");
        } else {
            ESP_LOGE(TAG_PC, "Factory reset failed: %s", esp_err_to_name(err));
        }
        vTaskDelay(pdMS_TO_TICKS(100));   /* let the log drain */
        esp_restart();
    }

    ESP_LOGI(TAG_PC, "Power off within %d s to register cycle %d of %d",
             CYCLE_TIMEOUT_SEC, pwr_cycles + 1, MAX_POWER_CYCLES);

    err = nvs_set_u8(nvs, PWR_CYCLE_KEY, pwr_cycles);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_PC, "Failed to store power cycle counter: %s", esp_err_to_name(err));
        return;
    }

    const esp_timer_create_args_t args = {
        .callback = pwr_cycle_stable_cb,
        .name = "pwr_cyc_rst",
    };
    err = esp_timer_create(&args, &s_stable_timer);
    if (err == ESP_OK) {
        err = esp_timer_start_once(s_stable_timer, (uint64_t)CYCLE_TIMEOUT_SEC * 1000000ULL);
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG_PC, "Failed to start stability timer: %s", esp_err_to_name(err));
    }
}

#else

void check_power_cycle_factory_reset(void)
{
}

#endif // CONFIG_POWER_CYCLE_RESET_ENABLED
