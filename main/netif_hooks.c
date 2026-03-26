/* Network interface hooks: byte counting and PCAP capture.
 *
 * Hooks into the lwIP netif input/linkoutput chains for both ETH
 * and AP bridge port interfaces to intercept packets for monitoring.
 */

#include <inttypes.h>
#include <string.h>
#include <time.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_eth.h"
#include "driver/gpio.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/pbuf.h"
#include "client_stats.h"
#include "pcap_capture.h"
#include "router_config.h"
#include "wifi_config.h"

extern esp_netif_t *eth_port_netif;
extern esp_netif_t *wifi_port_netif;

static const char *TAG = "netif_hooks";

// Original netif input and linkoutput function pointers (ETH port)
static netif_input_fn original_netif_input = NULL;
static netif_linkoutput_fn original_netif_linkoutput = NULL;
static struct netif *sta_netif = NULL;

// Original AP netif function pointers (WiFi AP port)
static netif_input_fn original_ap_netif_input = NULL;
static netif_linkoutput_fn original_ap_netif_linkoutput = NULL;
static struct netif *ap_netif = NULL;

// Per-client traffic statistics for AP clients
static client_stats_entry_t client_stats[CLIENT_STATS_MAX];

static inline client_stats_entry_t* find_client_stats(const uint8_t *mac) {
    for (int i = 0; i < CLIENT_STATS_MAX; i++) {
        if (client_stats[i].active && memcmp(client_stats[i].mac, mac, 6) == 0) {
            return &client_stats[i];
        }
    }
    return NULL;
}

void client_stats_on_connect(const uint8_t *mac) {
    client_stats_entry_t *existing = find_client_stats(mac);
    if (existing) {
        existing->connected = 1;
        return;
    }
    int free_slot = -1;
    int disconnected_slot = -1;
    for (int i = 0; i < CLIENT_STATS_MAX; i++) {
        if (!client_stats[i].active) {
            free_slot = i;
            break;
        } else if (!client_stats[i].connected && disconnected_slot < 0) {
            disconnected_slot = i;
        }
    }
    int slot = (free_slot >= 0) ? free_slot : disconnected_slot;
    if (slot >= 0) {
        memcpy(client_stats[slot].mac, mac, 6);
        client_stats[slot].bytes_sent = 0;
        client_stats[slot].bytes_received = 0;
        client_stats[slot].packets_sent = 0;
        client_stats[slot].packets_received = 0;
        client_stats[slot].active = 1;
        client_stats[slot].connected = 1;
    }
}

void client_stats_on_disconnect(const uint8_t *mac) {
    client_stats_entry_t *entry = find_client_stats(mac);
    if (entry) {
        entry->connected = 0;
    }
}

int client_stats_get_all(client_stats_entry_t *out, int max_entries) {
    int count = 0;
    for (int i = 0; i < CLIENT_STATS_MAX && count < max_entries; i++) {
        if (client_stats[i].active) {
            memcpy(&out[count], &client_stats[i], sizeof(client_stats_entry_t));
            count++;
        }
    }
    return count;
}

void client_stats_reset_all(void) {
    for (int i = 0; i < CLIENT_STATS_MAX; i++) {
        if (client_stats[i].active) {
            client_stats[i].bytes_sent = 0;
            client_stats[i].bytes_received = 0;
            client_stats[i].packets_sent = 0;
            client_stats[i].packets_received = 0;
        }
    }
}

void format_bytes_human(uint64_t bytes, char *buf, size_t len) {
    if (bytes >= 1073741824ULL)
        snprintf(buf, len, "%.1f GB", (double)bytes / 1073741824.0);
    else if (bytes >= 1048576ULL)
        snprintf(buf, len, "%.1f MB", (double)bytes / 1048576.0);
    else if (bytes >= 1024ULL)
        snprintf(buf, len, "%.1f KB", (double)bytes / 1024.0);
    else
        snprintf(buf, len, "%" PRIu64 " B", bytes);
}

// ETH port input hook: count received bytes, PCAP capture
static err_t netif_input_hook(struct pbuf *p, struct netif *netif) {
    // PCAP capture (ETH interface)
    if (pcap_should_capture(false, false)) {
        pcap_capture_packet(p);
    }

    // Count received bytes and toggle LED
    if (netif == sta_netif && p != NULL) {
        sta_bytes_received += p->tot_len;
        if (led_gpio >= 0 && ap_connect) {
            led_toggle ^= 1;
            gpio_set_level(led_gpio, led_toggle ^ led_lowactive);
        }
    }

    if (original_netif_input != NULL) {
        return original_netif_input(p, netif);
    }
    return ERR_VAL;
}

// ETH port output hook: count sent bytes, PCAP capture
static err_t netif_linkoutput_hook(struct netif *netif, struct pbuf *p) {
    // PCAP capture (ETH interface)
    if (pcap_should_capture(false, false)) {
        pcap_capture_packet(p);
    }

    // Count sent bytes and toggle LED
    if (netif == sta_netif && p != NULL) {
        sta_bytes_sent += p->tot_len;
        if (led_gpio >= 0 && ap_connect) {
            led_toggle ^= 1;
            gpio_set_level(led_gpio, led_toggle ^ led_lowactive);
        }
    }

    if (original_netif_linkoutput != NULL) {
        return original_netif_linkoutput(netif, p);
    }
    return ERR_IF;
}

void init_byte_counter(void) {
    if (eth_port_netif != NULL && original_netif_input == NULL) {
        extern struct netif *esp_netif_get_netif_impl(esp_netif_t *esp_netif);
        sta_netif = esp_netif_get_netif_impl(eth_port_netif);
        if (sta_netif != NULL) {
            original_netif_input = sta_netif->input;
            sta_netif->input = netif_input_hook;
            original_netif_linkoutput = sta_netif->linkoutput;
            sta_netif->linkoutput = netif_linkoutput_hook;
            ESP_LOGI(TAG, "Byte counter initialized for ETH interface");
        }
    }
}

uint64_t get_sta_bytes_sent(void) {
    return sta_bytes_sent;
}

uint64_t get_sta_bytes_received(void) {
    return sta_bytes_received;
}

void reset_sta_byte_counts(void) {
    sta_bytes_sent = 0;
    sta_bytes_received = 0;
}

void resync_connect_count(void) {
    wifi_sta_list_t sta_list;
    if (esp_wifi_ap_get_sta_list(&sta_list) == ESP_OK) {
        connect_count = sta_list.num;
    }
}

// Uptime functions
uint32_t get_uptime_seconds(void) {
    return (uint32_t)(esp_timer_get_time() / 1000000ULL);
}

void format_uptime(uint32_t seconds, char *buf, size_t buf_len) {
    uint32_t days = seconds / 86400;
    uint32_t hours = (seconds % 86400) / 3600;
    uint32_t mins = (seconds % 3600) / 60;
    uint32_t secs = seconds % 60;

    if (days > 0) {
        snprintf(buf, buf_len, "%lud %02lu:%02lu:%02lu",
                 (unsigned long)days, (unsigned long)hours,
                 (unsigned long)mins, (unsigned long)secs);
    } else {
        snprintf(buf, buf_len, "%02lu:%02lu:%02lu",
                 (unsigned long)hours, (unsigned long)mins, (unsigned long)secs);
    }
}

void format_boot_time(char *buf, size_t buf_len) {
    time_t now;
    time(&now);
    if (now < 100000) {
        snprintf(buf, buf_len, "unknown");
        return;
    }
    time_t boot_time = now - (time_t)get_uptime_seconds();
    struct tm timeinfo;
    localtime_r(&boot_time, &timeinfo);
    snprintf(buf, buf_len, "%04d-%02d-%02d %02d:%02d:%02d",
             timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
             timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
}

// AP port input hook: per-client stats, PCAP capture
static err_t ap_netif_input_hook(struct pbuf *p, struct netif *netif) {
    // Per-client byte counting: source MAC = client
    if (p != NULL && p->len >= 14) {
        const uint8_t *src_mac = ((const uint8_t *)p->payload) + 6;
        client_stats_entry_t *entry = find_client_stats(src_mac);
        if (entry) {
            entry->bytes_received += p->tot_len;
            entry->packets_received++;
        }
    }

    // PCAP capture (AP interface)
    if (pcap_should_capture(false, true)) {
        pcap_capture_packet(p);
    }

    if (original_ap_netif_input != NULL) {
        return original_ap_netif_input(p, netif);
    }
    return ERR_VAL;
}

// AP port output hook: per-client stats, PCAP capture
static err_t ap_netif_linkoutput_hook(struct netif *netif, struct pbuf *p) {
    // Per-client byte counting: dest MAC = client
    if (p != NULL && p->len >= 14) {
        const uint8_t *dst_mac = (const uint8_t *)p->payload;
        client_stats_entry_t *entry = find_client_stats(dst_mac);
        if (entry) {
            entry->bytes_sent += p->tot_len;
            entry->packets_sent++;
        }
    }

    // PCAP capture (AP interface)
    if (pcap_should_capture(false, true)) {
        pcap_capture_packet(p);
    }

    if (original_ap_netif_linkoutput != NULL) {
        return original_ap_netif_linkoutput(netif, p);
    }
    return ERR_IF;
}

void init_ap_netif_hooks(void) {
    if (wifi_port_netif != NULL && original_ap_netif_input == NULL) {
        extern struct netif *esp_netif_get_netif_impl(esp_netif_t *esp_netif);
        ap_netif = esp_netif_get_netif_impl(wifi_port_netif);

        if (ap_netif != NULL) {
            original_ap_netif_input = ap_netif->input;
            ap_netif->input = ap_netif_input_hook;

            original_ap_netif_linkoutput = ap_netif->linkoutput;
            ap_netif->linkoutput = ap_netif_linkoutput_hook;

            ESP_LOGI(TAG, "AP netif hooks initialized");
        }
    }
}
