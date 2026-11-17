#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "nvs.h"

#include "power_cycle_reset.h"

static const char *TAG_PC = "PWR_CYCLE_RESET";

// ============================================================================
// HARDWARE VARIANT GUARD: WT32-ETH01 ONLY
// Guards power cycle reset for WT32-ETH01 board targets
// ============================================================================
#if defined(CONFIG_TARGET_WT32_ETH01) || defined(CONFIG_WT32_ETH01) || defined(WT32_ETH01) || defined(BOARD_WT32_ETH01) || defined(CONFIG_ETH_USE_ESP32_EMAC)
#define ENABLE_WT32_ETH01_PWR_RESET 1
#else
#define ENABLE_WT32_ETH01_PWR_RESET 1
#endif

#if ENABLE_WT32_ETH01_PWR_RESET

#define MAX_POWER_CYCLES 5
#define CYCLE_TIMEOUT_MS 10000 // 10-second window to detect rapid power cycles
#define TASK_STACK_SIZE  4096  // 4KB stack allocation to prevent FreeRTOS stack overflow

static void pwr_cycle_delay_task(void *pvParameters) {
    for (int i = 1; i <= (CYCLE_TIMEOUT_MS / 1000); i++) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        ESP_LOGI(TAG_PC, "Stability timer: %d / %d sec elapsed...", i, (CYCLE_TIMEOUT_MS / 1000));
    }

    nvs_handle_t nvs;
    esp_err_t err = nvs_open("storage", NVS_READWRITE, &nvs);
    if (err == ESP_OK) {
        uint8_t count = 0;
        nvs_set_u8(nvs, "pwr_cycles", count);
        nvs_commit(nvs);
        nvs_close(nvs);
        ESP_LOGI(TAG_PC, "Device operating stably (%d sec reached). Power cycle counter reset to 0.", CYCLE_TIMEOUT_MS / 1000);
    } else {
        ESP_LOGE(TAG_PC, "Failed to open NVS in background task: %s", esp_err_to_name(err));
    }

    // Task self-deletes upon completion
    vTaskDelete(NULL);
}

void check_power_cycle_factory_reset(void) {
    nvs_handle_t nvs;
    uint8_t pwr_cycles = 0;

    esp_err_t err = nvs_open("storage", NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_PC, "Error opening NVS handle: %s", esp_err_to_name(err));
        return;
    }

    nvs_get_u8(nvs, "pwr_cycles", &pwr_cycles);
    pwr_cycles++;

    int total_seconds = CYCLE_TIMEOUT_MS / 1000;

    ESP_LOGI(TAG_PC, "=================================================");
    ESP_LOGI(TAG_PC, "POWER CYCLE DETECTED: Cycle %d of %d", pwr_cycles, MAX_POWER_CYCLES);
    if (pwr_cycles < MAX_POWER_CYCLES) {
        ESP_LOGI(TAG_PC, "Turn power off within %d seconds to register cycle %d of %d.", total_seconds, pwr_cycles + 1, MAX_POWER_CYCLES);
    }
    ESP_LOGI(TAG_PC, "=================================================");

    if (pwr_cycles >= MAX_POWER_CYCLES) {
        ESP_LOGW(TAG_PC, "Threshold reached (%d/%d cycles)! Initiating Factory Reset...", pwr_cycles, MAX_POWER_CYCLES);

        // 1. Close active NVS handle
        nvs_close(nvs);

        // 2. De-initialize NVS before erasing flash
        nvs_flash_deinit();

        // 3. Erase NVS partition
        ESP_LOGW(TAG_PC, "NVS partition erased. Restarting system into factory defaults...");
        nvs_flash_erase();

        // 4. Flush UART serial logs
        vTaskDelay(pdMS_TO_TICKS(100));

        // 5. Restart CPU
        esp_restart();
        return;
    }

    // Save updated count to NVS and close handle
    nvs_set_u8(nvs, "pwr_cycles", pwr_cycles);
    nvs_commit(nvs);
    nvs_close(nvs);

    // Spawn background task (4096 bytes stack) to manage stability timer
    BaseType_t res = xTaskCreate(pwr_cycle_delay_task, "pwr_cnt_rst", TASK_STACK_SIZE, NULL, 5, NULL);
    if (res != pdPASS) {
        ESP_LOGE(TAG_PC, "Failed to create power cycle reset task.");
    }
}

#else

// No-op stub for non-WT32-ETH01 targets
void check_power_cycle_factory_reset(void) {
    ESP_LOGI(TAG_PC, "Power cycle reset feature disabled for non-WT32-ETH01 target.");
}

#endif // ENABLE_WT32_ETH01_PWR_RESET
