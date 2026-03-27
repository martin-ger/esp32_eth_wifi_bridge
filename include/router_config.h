/* Core bridge configuration constants, byte counters, LED state,
 * uptime, and netif hooks.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include "esp_netif.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PARAM_NAMESPACE "esp32_nat"

#define AP_MAX_CONNECTIONS 8

#define DEFAULT_HOSTNAME "esp32bridge"

// Bridge netif (management IP)
extern esp_netif_t *br_netif;

// Byte counting variables for ETH interface
extern uint64_t sta_bytes_sent;
extern uint64_t sta_bytes_received;

// LED GPIO configuration (-1 means disabled/none)
extern int led_gpio;

// LED low-active mode (0 = active-high, 1 = active-low/inverted)
extern uint8_t led_lowactive;

// Shared LED toggle state (packet-driven flicker)
extern uint8_t led_toggle;

// Byte counting functions
void init_byte_counter(void);
uint64_t get_sta_bytes_sent(void);
uint64_t get_sta_bytes_received(void);
void reset_sta_byte_counts(void);
void resync_connect_count(void);

// Uptime functions
uint32_t get_uptime_seconds(void);
void format_uptime(uint32_t seconds, char *buf, size_t buf_len);
void format_boot_time(char *buf, size_t buf_len);

// AP netif hook functions
void init_ap_netif_hooks(void);

#ifdef __cplusplus
}
#endif
