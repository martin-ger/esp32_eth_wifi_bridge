/* ESP32 Ethernet-WiFi L2 Bridge - Main application
 *
 * Entry point, global variable definitions, Ethernet/WiFi initialization,
 * bridge setup, event handlers, LED status thread, and console REPL.
 *
 * Modular source files:
 *   netif_hooks.c   - Network interface hooks (byte counting, PCAP)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include "esp_system.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_console.h"
#include "esp_vfs_dev.h"
#include "driver/gpio.h"
#include "driver/uart.h"
#include "driver/uart_vfs.h"
#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"
#include "linenoise/linenoise.h"
#include "argtable3/argtable3.h"
#include "esp_vfs_fat.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "esp_ota_ops.h"

#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_eth.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_netif_br_glue.h"

#include "lwip/opt.h"
#include "lwip/err.h"
#include "lwip/sys.h"

#include "cmd_system.h"
#include "cmd_router.h"
#include <esp_http_server.h>

#include "router_globals.h"
#include "lwip/ip_addr.h"
#include "pcap_capture.h"
#include "mdns_responder.h"
#include "remote_console.h"
#include "syslog_client.h"

// Byte counting variables
uint64_t sta_bytes_sent = 0;
uint64_t sta_bytes_received = 0;

// AP SSID hidden (0 = visible, 1 = hidden)
uint8_t ap_ssid_hidden = 0;

// AP auth mode (0 = WPA2/WPA3, 1 = WPA2 only, 2 = WPA3 only)
uint8_t ap_authmode = 0;

// AP WiFi channel (0 = auto/1, 1-13 = fixed channel)
uint8_t ap_channel = 0;

/* FreeRTOS event group to signal when we are connected */
static EventGroupHandle_t wifi_event_group;
const int WIFI_CONNECTED_BIT = BIT0;

/* Global vars */
uint16_t connect_count = 0;
bool ap_connect = false;
bool has_static_ip = false;
int led_gpio = -1;
uint8_t led_lowactive = 0;
uint8_t led_toggle = 0;

uint32_t my_ip;

esp_netif_t *br_netif = NULL;       // Bridge virtual interface (management IP)
esp_netif_t *eth_port_netif = NULL;  // ETH physical port (no IP)
esp_netif_t *wifi_port_netif = NULL; // WiFi AP physical port (no IP)
esp_eth_handle_t eth_handle = NULL;
bool ap_disabled = false;

#include "http_server.h"

static const char *TAG = "ESP32 Bridge";

/* Console command history on FATFS */
#if CONFIG_STORE_HISTORY

#define MOUNT_PATH "/data"
#define HISTORY_PATH MOUNT_PATH "/history.txt"

static void initialize_filesystem(void)
{
    static wl_handle_t wl_handle;
    const esp_vfs_fat_mount_config_t mount_config = {
            .max_files = 4,
            .format_if_mount_failed = true
    };
    esp_err_t err = esp_vfs_fat_spiflash_mount_rw_wl(MOUNT_PATH, "storage", &mount_config, &wl_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to mount FATFS (%s)", esp_err_to_name(err));
        return;
    }
}
#endif // CONFIG_STORE_HISTORY

static void initialize_nvs(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK( nvs_flash_erase() );
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
}

static void initialize_console(void)
{
    /* Disable buffering on stdin */
    setvbuf(stdin, NULL, _IONBF, 0);

#if CONFIG_ESP_CONSOLE_UART_DEFAULT || CONFIG_ESP_CONSOLE_UART_CUSTOM
    fflush(stdout);
    fsync(fileno(stdout));

    uart_vfs_dev_port_set_rx_line_endings(0, ESP_LINE_ENDINGS_CR);
    uart_vfs_dev_port_set_tx_line_endings(0, ESP_LINE_ENDINGS_CRLF);

    const uart_config_t uart_config = {
            .baud_rate = CONFIG_ESP_CONSOLE_UART_BAUDRATE,
            .data_bits = UART_DATA_8_BITS,
            .parity = UART_PARITY_DISABLE,
            .stop_bits = UART_STOP_BITS_1,
            .source_clk = UART_SCLK_DEFAULT,
    };
    ESP_ERROR_CHECK( uart_driver_install(CONFIG_ESP_CONSOLE_UART_NUM,
            256, 0, 0, NULL, 0) );
    ESP_ERROR_CHECK( uart_param_config(CONFIG_ESP_CONSOLE_UART_NUM, &uart_config) );

    uart_vfs_dev_use_driver(CONFIG_ESP_CONSOLE_UART_NUM);
#endif

#if CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG
    fcntl(fileno(stdout), F_SETFL, O_NONBLOCK);
    fcntl(fileno(stdin), F_SETFL, O_NONBLOCK);

    usb_serial_jtag_vfs_set_rx_line_endings(ESP_LINE_ENDINGS_CR);
    usb_serial_jtag_vfs_set_tx_line_endings(ESP_LINE_ENDINGS_CRLF);
    usb_serial_jtag_driver_config_t usb_serial_jtag_config = {
        .tx_buffer_size = 256,
        .rx_buffer_size = 256,
    };
    usb_serial_jtag_driver_install(&usb_serial_jtag_config);
    usb_serial_jtag_vfs_use_driver();
#endif

    esp_console_config_t console_config = {
            .max_cmdline_args = 12,
            .max_cmdline_length = 256,
#if CONFIG_LOG_COLORS
            .hint_color = atoi(LOG_COLOR_CYAN)
#endif
    };
    ESP_ERROR_CHECK( esp_console_init(&console_config) );

    linenoiseSetMultiLine(1);
    linenoiseSetCompletionCallback(&esp_console_get_completion);
    linenoiseSetHintsCallback((linenoiseHintsCallback*) &esp_console_get_hint);
    linenoiseHistorySetMaxLen(100);

#if CONFIG_STORE_HISTORY
    linenoiseHistoryLoad(HISTORY_PATH);
#endif
}

void * led_status_thread(void * p)
{
    bool led_enabled = (led_gpio >= 0);
    if (led_enabled) {
        ESP_LOGI(TAG, "LED status on GPIO %d%s", led_gpio, led_lowactive ? " (low-active)" : "");
        gpio_reset_pin(led_gpio);
        gpio_set_direction(led_gpio, GPIO_MODE_OUTPUT);
    } else {
        ESP_LOGI(TAG, "LED status disabled (no GPIO configured)");
    }

    while (true)
    {
        // LED status: OFF=disconnected, ON=connected (packet hooks flicker it off)
        if (led_enabled) {
            gpio_set_level(led_gpio, ap_connect ^ led_lowactive);
        }

        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

/* Event handlers */

static void eth_event_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data)
{
    if (event_base == ETH_EVENT) {
        if (event_id == ETHERNET_EVENT_CONNECTED) {
            ESP_LOGI(TAG, "Ethernet link up");
            // For static IP, no GOT_IP fires — join multicast now that the netif is up
            if (has_static_ip) {
                mdns_responder_set_ip(esp_ip4addr_aton(static_ip));
            }
        } else if (event_id == ETHERNET_EVENT_DISCONNECTED) {
            ESP_LOGI(TAG, "Ethernet link down");
            ap_connect = false;
            xEventGroupClearBits(wifi_event_group, WIFI_CONNECTED_BIT);
        } else if (event_id == ETHERNET_EVENT_START) {
            ESP_LOGI(TAG, "Ethernet started");
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_ETH_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "Bridge got ip:" IPSTR, IP2STR(&event->ip_info.ip));
        ap_connect = true;
        my_ip = event->ip_info.ip.addr;

        init_byte_counter();
        syslog_notify_connected();
        mdns_responder_set_ip(event->ip_info.ip.addr);

        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wifi_ap_event_handler(void* arg, esp_event_base_t event_base,
                                   int32_t event_id, void* event_data)
{
    if (event_id == WIFI_EVENT_AP_START) {
        ESP_LOGI(TAG, "AP started");
        init_ap_netif_hooks();
    } else if (event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t* event = (wifi_event_ap_staconnected_t*) event_data;
        connect_count++;
        client_stats_on_connect(event->mac);
        ESP_LOGI(TAG, "Client connected: %02X:%02X:%02X:%02X:%02X:%02X - %d total",
                 event->mac[0], event->mac[1], event->mac[2],
                 event->mac[3], event->mac[4], event->mac[5],
                 connect_count);
    } else if (event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t* event = (wifi_event_ap_stadisconnected_t*) event_data;
        connect_count--;
        client_stats_on_disconnect(event->mac);
        ESP_LOGI(TAG, "Client disconnected: %02X:%02X:%02X:%02X:%02X:%02X - %d remain",
                 event->mac[0], event->mac[1], event->mac[2],
                 event->mac[3], event->mac[4], event->mac[5],
                 connect_count);
    }
}

const int CONNECTED_BIT = BIT0;

void ap_set_enabled(bool enabled)
{
    if (enabled) {
        esp_wifi_start();
    } else {
        connect_count = 0;
        esp_wifi_stop();
    }
    ap_disabled = !enabled;
    set_config_param_int("ap_disabled", ap_disabled ? 1 : 0);
    ESP_LOGI(TAG, "AP interface %s", enabled ? "enabled" : "disabled");
}

static wifi_auth_mode_t get_ap_authmode(void)
{
    switch (ap_authmode) {
        case 1: return WIFI_AUTH_WPA2_PSK;
        case 2: return WIFI_AUTH_WPA3_PSK;
        default: return WIFI_AUTH_WPA2_WPA3_PSK;
    }
}

void bridge_init(const char* static_ip, const char* subnet_mask, const char* gateway_addr,
                 const uint8_t* ap_mac, const char* ap_ssid, const char* ap_passwd)
{
    wifi_event_group = xEventGroupCreate();

    esp_netif_init();
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // --- Ethernet driver ---
    // Power on LAN8720 PHY via GPIO before EMAC init (WT32-ETH01)
#if CONFIG_ETH_PHY_POWER_GPIO >= 0
    gpio_config_t phy_power_cfg = {
        .pin_bit_mask = (1ULL << CONFIG_ETH_PHY_POWER_GPIO),
        .mode = GPIO_MODE_OUTPUT,
    };
    gpio_config(&phy_power_cfg);
    gpio_set_level(CONFIG_ETH_PHY_POWER_GPIO, 1);
    vTaskDelay(pdMS_TO_TICKS(20));
#endif

    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    eth_esp32_emac_config_t emac_config = ETH_ESP32_EMAC_DEFAULT_CONFIG();
    emac_config.smi_gpio.mdc_num = CONFIG_ETH_MDC_GPIO;
    emac_config.smi_gpio.mdio_num = CONFIG_ETH_MDIO_GPIO;
    esp_eth_mac_t *mac = esp_eth_mac_new_esp32(&emac_config, &mac_config);

    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    phy_config.phy_addr = CONFIG_ETH_PHY_ADDR;
    phy_config.reset_gpio_num = -1;
    esp_eth_phy_t *phy = esp_eth_phy_new_lan87xx(&phy_config);

    esp_eth_config_t config = ETH_DEFAULT_CONFIG(mac, phy);
    ESP_ERROR_CHECK(esp_eth_driver_install(&config, &eth_handle));

    // --- ETH port netif (no IP, bridge port) ---
    esp_netif_inherent_config_t eth_netif_config = ESP_NETIF_INHERENT_DEFAULT_ETH();
    eth_netif_config.flags = 0;  // Must be zero for bridge port
    eth_netif_config.if_key = "ETH_0";
    eth_netif_config.if_desc = "eth0";
    eth_netif_config.route_prio = 50;
    esp_netif_config_t netif_cfg = {
        .base = &eth_netif_config,
        .stack = ESP_NETIF_NETSTACK_DEFAULT_ETH
    };
    eth_port_netif = esp_netif_new(&netif_cfg);
    ESP_ERROR_CHECK(esp_netif_attach(eth_port_netif, esp_eth_new_netif_glue(eth_handle)));

    // --- WiFi AP init ---
    wifi_init_config_t wifi_cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wifi_cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

    wifi_config_t ap_config = {
        .ap = {
            .channel = ap_channel ? ap_channel : 1,
            .authmode = get_ap_authmode(),
            .ssid_hidden = ap_ssid_hidden,
            .max_connection = AP_MAX_CONNECTIONS,
            .beacon_interval = 100,
        }
    };
    strlcpy((char*)ap_config.ap.ssid, ap_ssid, sizeof(ap_config.ap.ssid));
    if (strlen(ap_passwd) < 8) {
        ap_config.ap.authmode = WIFI_AUTH_OPEN;
    } else {
        strlcpy((char*)ap_config.ap.password, ap_passwd, sizeof(ap_config.ap.password));
    }

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &ap_config));
    if (ap_mac != NULL) {
        ESP_ERROR_CHECK(esp_wifi_set_mac(ESP_IF_WIFI_AP, ap_mac));
    }

    // --- WiFi AP port netif (no IP, bridge port) ---
    esp_netif_inherent_config_t wifi_netif_config = ESP_NETIF_INHERENT_DEFAULT_WIFI_AP();
    wifi_netif_config.flags = ESP_NETIF_FLAG_AUTOUP;
    wifi_netif_config.ip_info = NULL;  // No IP on physical port
    wifi_port_netif = esp_netif_create_wifi(WIFI_IF_AP, &wifi_netif_config);
    ESP_ERROR_CHECK(esp_wifi_set_default_wifi_ap_handlers());

    // --- Bridge netif (management IP via DHCP or static) ---
    esp_netif_inherent_config_t br_config = ESP_NETIF_INHERENT_DEFAULT_BR();
    bridgeif_config_t bridgeif_config = {
        .max_fdb_dyn_entries = 10,
        .max_fdb_sta_entries = 2,
        .max_ports = 2  // ETH + WiFi AP
    };
    br_config.bridge_info = &bridgeif_config;

    // Set bridge MAC to ETH MAC
    uint8_t eth_mac_addr[6];
    ESP_ERROR_CHECK(esp_read_mac(eth_mac_addr, ESP_MAC_ETH));
    memcpy(br_config.mac, eth_mac_addr, 6);

    esp_netif_config_t br_netif_cfg = {
        .base = &br_config,
        .stack = ESP_NETIF_NETSTACK_DEFAULT_BR,
    };
    br_netif = esp_netif_new(&br_netif_cfg);

    // Bridge glue: attach ports
    esp_netif_br_glue_handle_t br_glue = esp_netif_br_glue_new();
    ESP_ERROR_CHECK(esp_netif_br_glue_add_port(br_glue, eth_port_netif));
    ESP_ERROR_CHECK(esp_netif_br_glue_add_wifi_port(br_glue, wifi_port_netif));
    ESP_ERROR_CHECK(esp_netif_attach(br_netif, br_glue));

    // Set hostname on bridge interface
    esp_netif_set_hostname(br_netif, hostname);

    // Static IP on bridge if configured
    uint32_t initial_ip = 0;
    if (strlen(static_ip) > 0 && strlen(subnet_mask) > 0 && strlen(gateway_addr) > 0) {
        has_static_ip = true;
        esp_netif_ip_info_t ipInfo;
        ipInfo.ip.addr = esp_ip4addr_aton(static_ip);
        ipInfo.gw.addr = esp_ip4addr_aton(gateway_addr);
        ipInfo.netmask.addr = esp_ip4addr_aton(subnet_mask);
        esp_netif_dhcpc_stop(br_netif);
        esp_netif_set_ip_info(br_netif, &ipInfo);
        initial_ip = ipInfo.ip.addr;
    }

    // Start mDNS responder (IP=0 for DHCP; updated in GOT_IP handler)
    mdns_responder_start(hostname, initial_ip);

    // Register event handlers
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, &eth_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &eth_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_ap_event_handler, NULL));

    // Enable promiscuous mode on ETH (required for bridge MAC forwarding)
    bool promiscuous = true;
    esp_eth_ioctl(eth_handle, ETH_CMD_S_PROMISCUOUS, &promiscuous);

    // Start interfaces
    ESP_ERROR_CHECK(esp_eth_start(eth_handle));
    if (!ap_disabled) {
        ESP_ERROR_CHECK(esp_wifi_start());
    } else {
        ESP_LOGI(TAG, "AP interface disabled at boot");
    }

    ESP_LOGI(TAG, "Ethernet-WiFi L2 Bridge initialized");
}

char* static_ip = NULL;
char* subnet_mask = NULL;
char* gateway_addr = NULL;
uint8_t* ap_mac = NULL;
char* ap_ssid = NULL;
char* ap_passwd = NULL;
char* ap_dns = NULL;
char* hostname = NULL;

char* param_set_default(const char* def_val) {
    char * retval = malloc(strlen(def_val)+1);
    if (retval == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for default parameter");
        return NULL;
    }
    strcpy(retval, def_val);
    return retval;
}

void app_main(void)
{
    initialize_nvs();
    load_log_level();

    /* Restore timezone from NVS */
    {
        char *tz = NULL;
        if (get_config_param_str("tz", &tz) == ESP_OK && tz[0] != '\0') {
            setenv("TZ", tz, 1);
            tzset();
            ESP_LOGI(TAG, "Timezone set to: %s", tz);
        }
        free(tz);
    }

    /* OTA rollback support */
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t ota_state;
    if (esp_ota_get_state_partition(running, &ota_state) == ESP_OK) {
        if (ota_state == ESP_OTA_IMG_PENDING_VERIFY) {
            ESP_LOGI(TAG, "OTA: confirming new firmware on partition '%s'", running->label);
            esp_ota_mark_app_valid_cancel_rollback();
        }
    }

#if CONFIG_STORE_HISTORY
    initialize_filesystem();
    ESP_LOGI(TAG, "Command history enabled");
#else
    ESP_LOGI(TAG, "Command history disabled");
#endif

    // Load config from NVS
    get_config_param_str("static_ip", &static_ip);
    if (static_ip == NULL) static_ip = param_set_default("");
    get_config_param_str("subnet_mask", &subnet_mask);
    if (subnet_mask == NULL) subnet_mask = param_set_default("");
    get_config_param_str("gateway_addr", &gateway_addr);
    if (gateway_addr == NULL) gateway_addr = param_set_default("");

    get_config_param_blob("ap_mac", &ap_mac, 6);
    get_config_param_str("ap_ssid", &ap_ssid);
    if (ap_ssid == NULL) ap_ssid = param_set_default(DEFAULT_HOSTNAME);
    get_config_param_str("ap_passwd", &ap_passwd);
    if (ap_passwd == NULL) ap_passwd = param_set_default("");
    get_config_param_str("ap_dns", &ap_dns);
    if (ap_dns == NULL) ap_dns = param_set_default("");
    get_config_param_str("hostname", &hostname);
    if (hostname == NULL || hostname[0] == '\0') hostname = param_set_default(DEFAULT_HOSTNAME);

    // Load LED GPIO setting from NVS (default -1 = disabled)
    int led_gpio_setting = -1;
    if (get_config_param_int("led_gpio", &led_gpio_setting) == ESP_OK) {
        led_gpio = led_gpio_setting;
    }

    int led_lowactive_setting = 0;
    if (get_config_param_int("led_low", &led_lowactive_setting) == ESP_OK) {
        led_lowactive = (led_lowactive_setting != 0) ? 1 : 0;
    }

    // Load AP disabled setting
    int ap_disabled_setting = 0;
    if (get_config_param_int("ap_disabled", &ap_disabled_setting) == ESP_OK) {
        ap_disabled = (ap_disabled_setting != 0);
    }
    if (ap_disabled) {
        ESP_LOGI(TAG, "AP interface disabled (NVS)");
    }

    // Load AP SSID hidden setting
    int hidden_setting = 0;
    if (get_config_param_int("ap_hidden", &hidden_setting) == ESP_OK) {
        ap_ssid_hidden = (hidden_setting != 0) ? 1 : 0;
    }

    // Load AP auth mode
    int authmode_setting = 0;
    if (get_config_param_int("ap_authmode", &authmode_setting) == ESP_OK) {
        if (authmode_setting >= 0 && authmode_setting <= 2) {
            ap_authmode = (uint8_t)authmode_setting;
        }
    }

    // Load AP channel
    int channel_setting = 0;
    if (get_config_param_int("ap_channel", &channel_setting) == ESP_OK) {
        if (channel_setting >= 1 && channel_setting <= 13) ap_channel = (uint8_t)channel_setting;
    }

    // Initialize bridge
    bridge_init(static_ip, subnet_mask, gateway_addr, ap_mac, ap_ssid, ap_passwd);

    // Apply TX power setting from NVS (must be after esp_wifi_start)
    int tx_power_dbm = 0;
    if (get_config_param_int("tx_power", &tx_power_dbm) == ESP_OK && tx_power_dbm >= 2 && tx_power_dbm <= 20) {
        int8_t power_qdbm = (int8_t)(tx_power_dbm * 4);
        esp_err_t ret = esp_wifi_set_max_tx_power(power_qdbm);
        if (ret == ESP_OK) {
            int8_t actual = 0;
            esp_wifi_get_max_tx_power(&actual);
            ESP_LOGI(TAG, "TX power set to %.1f dBm", actual * 0.25);
        } else {
            ESP_LOGW(TAG, "Failed to set TX power: %s", esp_err_to_name(ret));
        }
    }

    pthread_t t1;
    pthread_create(&t1, NULL, led_status_thread, NULL);

    // Web server
    char* web_disabled = NULL;
    get_config_param_str("web_disabled", &web_disabled);
    if (web_disabled == NULL) web_disabled = param_set_default("0");
    if (strcmp(web_disabled, "0") == 0) {
        int web_port_setting = 80;
        get_config_param_int("web_port", &web_port_setting);
        ESP_LOGI(TAG, "Starting web server on port %d", web_port_setting);
        start_webserver((uint16_t)web_port_setting);
    }
    free(web_disabled);

    // Initialize PCAP capture (TCP server on port 19000)
    pcap_init();

    // Initialize remote console (TCP server on port 2323, disabled by default)
    remote_console_init();

    // Initialize syslog client (UDP forwarding, disabled by default)
    syslog_init();

    initialize_console();

    /* Register commands */
    esp_console_register_help_command();
    register_system();
    register_router();

    const char* prompt = LOG_COLOR_I "bridge> " LOG_RESET_COLOR;

    printf("\n"
           "ESP32 Ethernet-WiFi L2 Bridge\n"
           "Type 'help' to get the list of commands.\n"
           "Use UP/DOWN arrows to navigate through command history.\n"
           "Press TAB when typing command name to auto-complete.\n"
           "\nConfigure AP using 'set_ap' and restart.\n");

    int probe_status = linenoiseProbe();
    if (probe_status) {
        printf("\n"
               "Your terminal application does not support escape sequences.\n"
               "Line editing and history features are disabled.\n"
               "On Windows, try using Putty instead.\n");
        linenoiseSetDumbMode(1);
#if CONFIG_LOG_COLORS
        prompt = "bridge> ";
#endif //CONFIG_LOG_COLORS
    }

    /* Main loop */
    while(true) {
        char* line = linenoise(prompt);
        if (line == NULL) {
            continue;
        }
        linenoiseHistoryAdd(line);
#if CONFIG_STORE_HISTORY
        linenoiseHistorySave(HISTORY_PATH);
#endif

        int ret;
        esp_err_t err = esp_console_run(line, &ret);
        if (err == ESP_ERR_NOT_FOUND) {
            printf("Unrecognized command\n");
        } else if (err == ESP_ERR_INVALID_ARG) {
            // command was empty
        } else if (err == ESP_OK && ret != ESP_OK) {
            printf("Command returned non-zero error code: 0x%x (%s)\n", ret, esp_err_to_name(ret));
        } else if (err != ESP_OK) {
            printf("Internal error: %s\n", esp_err_to_name(err));
        }
        linenoiseFree(line);
    }
}
