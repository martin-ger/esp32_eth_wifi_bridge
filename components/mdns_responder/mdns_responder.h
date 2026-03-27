/* Minimal mDNS responder for bridge netifs.
 *
 * The ESP-IDF mDNS component cannot work with bridge netifs because it
 * tries to match incoming packets against the receiving lwIP netif, which
 * for a bridge is always the underlying port (ETH/WiFi), not the bridge
 * itself.  This responder sidesteps the issue by using a plain lwIP UDP
 * PCB bound to INADDR_ANY on port 5353.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Start the mDNS responder.
 *
 * @param hostname  Unqualified hostname (e.g. "esp32bridge").
 *                  The responder answers queries for "<hostname>.local".
 * @param ip_addr   IPv4 address to return (network byte order).
 *                  Pass 0 to defer; call mdns_responder_set_ip() later.
 */
esp_err_t mdns_responder_start(const char *hostname, uint32_t ip_addr);

/** Update the IPv4 address returned in A-record answers. */
void mdns_responder_set_ip(uint32_t ip_addr);

/** Update the hostname (takes effect for subsequent queries). */
void mdns_responder_set_hostname(const char *hostname);

/** Stop the responder and free resources. */
void mdns_responder_stop(void);

#ifdef __cplusplus
}
#endif
