/* Core bridge configuration constants, byte counters, LED state,
 * uptime, and netif hooks.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include "esp_netif.h"
#include "sdkconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PARAM_NAMESPACE "esp32_nat"

#define AP_MAX_CONNECTIONS 8

// Factory defaults (menuconfig -> Factory Defaults). Used only as fallbacks
// when the corresponding NVS key is missing; never written to NVS.
#define DEFAULT_HOSTNAME        CONFIG_DEFAULT_HOSTNAME
#define DEFAULT_AP_SSID         CONFIG_DEFAULT_AP_SSID
#define DEFAULT_AP_PASSWORD     CONFIG_DEFAULT_AP_PASSWORD
#define DEFAULT_WIFI_COUNTRY    CONFIG_DEFAULT_WIFI_COUNTRY
#define DEFAULT_TX_POWER_DBM    CONFIG_DEFAULT_TX_POWER_DBM
#define DEFAULT_STATIC_IP       CONFIG_DEFAULT_STATIC_IP
#define DEFAULT_SUBNET_MASK     CONFIG_DEFAULT_SUBNET_MASK
#define DEFAULT_GATEWAY         CONFIG_DEFAULT_GATEWAY
#ifdef CONFIG_DEFAULT_DHCPS_ENABLED
#define DEFAULT_DHCPS_ENABLED   1
#else
#define DEFAULT_DHCPS_ENABLED   0
#endif
#define DEFAULT_DHCPS_START_IP  CONFIG_DEFAULT_DHCPS_START_IP
#define DEFAULT_DHCPS_END_IP    CONFIG_DEFAULT_DHCPS_END_IP
#define DEFAULT_DHCPS_LEASE_MIN CONFIG_DEFAULT_DHCPS_LEASE_MIN
#define DEFAULT_DHCPS_DNS_IP    CONFIG_DEFAULT_DHCPS_DNS_IP
#ifdef CONFIG_DEFAULT_WEB_ENABLED
#define DEFAULT_WEB_DISABLED    "0"
#else
#define DEFAULT_WEB_DISABLED    "1"
#endif
#define DEFAULT_WEB_PORT        CONFIG_DEFAULT_WEB_PORT

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
