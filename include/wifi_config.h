/* WiFi AP config, NVS helpers, and set_ap.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

extern char* static_ip;
extern char* subnet_mask;
extern char* gateway_addr;
extern char* ap_ssid;
extern char* ap_passwd;
extern char* ap_dns;
extern char* hostname;

extern uint16_t connect_count;
extern bool ap_connect;

extern uint32_t my_ip;

// AP SSID hidden (0 = visible, 1 = hidden)
extern uint8_t ap_ssid_hidden;

// AP auth mode (0 = WPA2/WPA3, 1 = WPA2 only, 2 = WPA3 only)
extern uint8_t ap_authmode;

// AP WiFi channel (0 = auto/1, 1-13 = fixed channel)
extern uint8_t ap_channel;

void preprocess_string(char* str);
int set_mgmt_ip(int argc, char **argv);
int set_ap(int argc, char **argv);
int set_ap_mac(int argc, char **argv);

// AP disable flag (persisted in NVS as "ap_disabled")
extern bool ap_disabled;

// Dynamically enable or disable the AP interface (persists to NVS)
void ap_set_enabled(bool enabled);

esp_err_t get_config_param_blob(char* name, uint8_t** blob, size_t blob_len);
esp_err_t get_config_param_int(char* name, int* param);
esp_err_t get_config_param_str(char* name, char** param);

esp_err_t set_config_param_str(const char* name, const char* value);
esp_err_t set_config_param_int(const char* name, int32_t value);
esp_err_t set_config_param_blob(const char* name, const void* data, size_t len);

#ifdef __cplusplus
}
#endif
