/* CLI commands for the L2 Ethernet-WiFi bridge
 *
 * Stripped-down version: no NAT, no portmap, no DHCP reservations,
 * no ACL firewall, no VPN, no OLED, no WiFi STA.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <inttypes.h>
#include <stdint.h>
#include "esp_log.h"
#include "esp_console.h"
#include "esp_system.h"
#include "esp_sleep.h"
#include "spi_flash_mmap.h"
#include "driver/uart.h"
#include "argtable3/argtable3.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"
#include "nvs.h"
#include "esp_wifi.h"

#include "lwip/ip4_addr.h"

#include "mbedtls/sha256.h"
#include "esp_random.h"

#include "driver/gpio.h"
#include "router_globals.h"
#include "cmd_router.h"
#include "pcap_capture.h"
#include "remote_console.h"
#include "syslog_client.h"
#include "esp_ota_ops.h"
#include "esp_app_desc.h"

#ifdef CONFIG_FREERTOS_USE_STATS_FORMATTING_FUNCTIONS
#define WITH_TASKS_INFO 1
#endif

static const char *TAG = "cmd_router";

static void register_set_hostname(void);
static void register_set_ap_mac_only(void);
static void register_set_mgmt_ip(void);
static void register_set_ap(void);
static void register_set_ap_hidden(void);
static void register_set_ap_auth(void);
static void register_ap(void);
static void register_set_ap_channel(void);
static void register_set_ap_dns(void);
static void register_show(void);
static void register_set_router_password(void);
static void register_web_ui(void);
static void register_bytes(void);
static void register_pcap(void);
static void register_set_led_gpio(void);
static void register_set_led_lowactive(void);
static void register_set_tx_power(void);
static void register_remote_console_cmd(void);
static void register_syslog_cmd(void);
static void register_set_tz(void);

/* Check if character is a valid hex digit */
static inline int is_hex_digit(char c)
{
    return (c >= '0' && c <= '9') ||
           (c >= 'A' && c <= 'F') ||
           (c >= 'a' && c <= 'f');
}

/* Convert hex digit to value (assumes valid hex digit) */
static inline uint8_t hex_digit_value(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    else
        return toupper((unsigned char)c) - 'A' + 10;
}

/* Check if string represents a boolean true value */
static inline bool parse_bool_true(const char *str)
{
    return (strcasecmp(str, "true") == 0 ||
            strcasecmp(str, "yes") == 0 ||
            strcasecmp(str, "on") == 0 ||
            strcmp(str, "1") == 0);
}

/* Check if string represents a boolean false value */
static inline bool parse_bool_false(const char *str)
{
    return (strcasecmp(str, "false") == 0 ||
            strcasecmp(str, "no") == 0 ||
            strcasecmp(str, "off") == 0 ||
            strcmp(str, "0") == 0);
}

void preprocess_string(char* str)
{
    char *p, *q;

    for (p = q = str; *p != 0; p++)
    {
        if (*(p) == '%' && *(p + 1) != 0 && *(p + 2) != 0 &&
            is_hex_digit(*(p + 1)) && is_hex_digit(*(p + 2)))
        {
            // Valid percent-encoded hex sequence
            p++;
            uint8_t a = hex_digit_value(*p) << 4;
            p++;
            a += hex_digit_value(*p);
            *q++ = a;
        }
        else if (*(p) == '+') {
            *q++ = ' ';
        } else {
            *q++ = *p;
        }
    }
    *q = '\0';
}

esp_err_t get_config_param_str(char* name, char** param)
{
    nvs_handle_t nvs;

    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READONLY, &nvs);
    if (err == ESP_OK) {
        size_t len;
        if ( (err = nvs_get_str(nvs, name, NULL, &len)) == ESP_OK) {
            *param = (char *)malloc(len);
            if (*param == NULL) {
                nvs_close(nvs);
                return ESP_ERR_NO_MEM;
            }
            err = nvs_get_str(nvs, name, *param, &len);
            ESP_LOGI(TAG, "%s %s", name, *param);
        } else {
            return err;
        }
        nvs_close(nvs);
    } else {
        return err;
    }
    return ESP_OK;
}

esp_err_t get_config_param_int(char* name, int* param)
{
    nvs_handle_t nvs;

    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READONLY, &nvs);
    if (err == ESP_OK) {
        if ( (err = nvs_get_i32(nvs, name, (int32_t*)(param))) == ESP_OK) {
            ESP_LOGI(TAG, "%s %d", name, *param);
        } else {
            return err;
        }
        nvs_close(nvs);
    } else {
        return err;
    }
    return ESP_OK;
}

esp_err_t get_config_param_blob(char* name, uint8_t** blob, size_t blob_len)
{
    nvs_handle_t nvs;

    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READONLY, &nvs);
    if (err == ESP_OK) {
        size_t len;
        if ( (err = nvs_get_blob(nvs, name, NULL, &len)) == ESP_OK) {
            if (len != blob_len) {
                nvs_close(nvs);
                return ESP_ERR_NVS_INVALID_LENGTH;
            }
            *blob = (uint8_t *)malloc(len);
            if (*blob == NULL) {
                nvs_close(nvs);
                return ESP_ERR_NO_MEM;
            }
            err = nvs_get_blob(nvs, name, *blob, &len);
            ESP_LOGI(TAG, "%s: %d", name, len);
        } else {
            return err;
        }
        nvs_close(nvs);
    } else {
        return err;
    }
    return ESP_OK;
}

esp_err_t set_config_param_str(const char* name, const char* value)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;
    err = nvs_set_str(nvs, name, value);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    return err;
}

esp_err_t set_config_param_int(const char* name, int32_t value)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;
    err = nvs_set_i32(nvs, name, value);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    return err;
}

esp_err_t set_config_param_blob(const char* name, const void* data, size_t len)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(nvs, name, data, len);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    return err;
}

void register_router(void)
{
    register_show();
    register_set_ap_mac_only();
    register_set_mgmt_ip();
    register_set_ap();
    register_set_ap_dns();
    register_bytes();
    register_pcap();
    register_web_ui();
    register_set_router_password();
    register_set_led_gpio();
    register_set_led_lowactive();
    register_set_tx_power();
    register_set_ap_hidden();
    register_set_ap_auth();
    register_ap();
    register_set_ap_channel();
    register_set_hostname();
    register_remote_console_cmd();
    register_syslog_cmd();
    register_set_tz();
}

/** Arguments used by 'set_mgmt_ip' function */
static struct {
    struct arg_str *static_ip;
    struct arg_str *subnet_mask;
    struct arg_str *gateway_addr;
    struct arg_end *end;
} set_mgmt_ip_arg;

/* 'set_mgmt_ip' command - set bridge management IP */
int set_mgmt_ip(int argc, char **argv)
{
    esp_err_t err;
    nvs_handle_t nvs;

    /* "set_mgmt_ip dhcp" clears static IP and reverts to DHCP */
    if (argc == 2 && strcmp(argv[1], "dhcp") == 0) {
        err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
        if (err != ESP_OK) {
            return err;
        }
        nvs_erase_key(nvs, "static_ip");
        nvs_erase_key(nvs, "subnet_mask");
        nvs_erase_key(nvs, "gateway_addr");
        err = nvs_commit(nvs);
        nvs_close(nvs);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "Static IP cleared. Will use DHCP after reboot.");
        }
        return err;
    }

    int nerrors = arg_parse(argc, argv, (void **) &set_mgmt_ip_arg);
    if (nerrors != 0) {
        arg_print_errors(stderr, set_mgmt_ip_arg.end, argv[0]);
        return 1;
    }

    preprocess_string((char*)set_mgmt_ip_arg.static_ip->sval[0]);
    preprocess_string((char*)set_mgmt_ip_arg.subnet_mask->sval[0]);
    preprocess_string((char*)set_mgmt_ip_arg.gateway_addr->sval[0]);

    err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        return err;
    }

    err = nvs_set_str(nvs, "static_ip", set_mgmt_ip_arg.static_ip->sval[0]);
    if (err == ESP_OK) {
        err = nvs_set_str(nvs, "subnet_mask", set_mgmt_ip_arg.subnet_mask->sval[0]);
        if (err == ESP_OK) {
            err = nvs_set_str(nvs, "gateway_addr", set_mgmt_ip_arg.gateway_addr->sval[0]);
            if (err == ESP_OK) {
              err = nvs_commit(nvs);
                if (err == ESP_OK) {
                    ESP_LOGI(TAG, "Bridge management IP settings %s/%s/%s stored.", set_mgmt_ip_arg.static_ip->sval[0], set_mgmt_ip_arg.subnet_mask->sval[0], set_mgmt_ip_arg.gateway_addr->sval[0]);
                }
            }
        }
    }
    nvs_close(nvs);
    return err;
}

static void register_set_mgmt_ip(void)
{
    set_mgmt_ip_arg.static_ip = arg_str1(NULL, NULL, "<ip>", "IP");
    set_mgmt_ip_arg.subnet_mask = arg_str1(NULL, NULL, "<subnet>", "Subnet Mask");
    set_mgmt_ip_arg.gateway_addr = arg_str1(NULL, NULL, "<gw>", "Gateway Address");
    set_mgmt_ip_arg.end = arg_end(3);

    const esp_console_cmd_t cmd = {
        .command = "set_mgmt_ip",
        .help = "Set bridge management IP, or 'set_mgmt_ip dhcp' to use DHCP",
        .hint = NULL,
        .func = &set_mgmt_ip,
        .argtable = &set_mgmt_ip_arg
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/** Arguments used by 'set_mac' function */
static struct {
    struct arg_int *mac0;
    struct arg_int *mac1;
    struct arg_int *mac2;
    struct arg_int *mac3;
    struct arg_int *mac4;
    struct arg_int *mac5;
    struct arg_end *end;
} set_mac_arg;

esp_err_t set_mac(const char *key, const char *interface, int argc, char **argv) {
    esp_err_t err;
    nvs_handle_t nvs;

    int nerrors = arg_parse(argc, argv, (void **) &set_mac_arg);
    if (nerrors != 0) {
        arg_print_errors(stderr, set_mac_arg.end, argv[0]);
        return 1;
    }

    err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        return err;
    }

    uint8_t mac[] = {set_mac_arg.mac0->ival[0], set_mac_arg.mac1->ival[0], set_mac_arg.mac2->ival[0], set_mac_arg.mac3->ival[0], set_mac_arg.mac4->ival[0], set_mac_arg.mac5->ival[0]};
    err = nvs_set_blob(nvs, key, mac, sizeof(mac));
    if (err == ESP_OK) {
        err = nvs_commit(nvs);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "%s mac address %02X:%02X:%02X:%02X:%02X:%02X stored.", interface, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        }
    }
    nvs_close(nvs);
    return err;
}

int set_ap_mac(int argc, char **argv) {
    return set_mac("ap_mac", "AP", argc, argv);
}

static void register_set_ap_mac_only(void)
{
    set_mac_arg.mac0 = arg_int1(NULL, NULL, "<octet>", "First octet");
    set_mac_arg.mac1 = arg_int1(NULL, NULL, "<octet>", "Second octet");
    set_mac_arg.mac2 = arg_int1(NULL, NULL, "<octet>", "Third octet");
    set_mac_arg.mac3 = arg_int1(NULL, NULL, "<octet>", "Fourth octet");
    set_mac_arg.mac4 = arg_int1(NULL, NULL, "<octet>", "Fifth octet");
    set_mac_arg.mac5 = arg_int1(NULL, NULL, "<octet>", "Sixth octet");
    set_mac_arg.end = arg_end(6);

    const esp_console_cmd_t cmd_ap = {
        .command = "set_ap_mac",
        .help = "Set MAC address of the AP interface",
        .hint = NULL,
        .func = &set_ap_mac,
        .argtable = &set_mac_arg
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd_ap) );
}

/** Arguments used by 'set_ap' function */
static struct {
    struct arg_str *ssid;
    struct arg_str *password;
    struct arg_end *end;
} set_ap_args;

/* 'set_ap' command */
int set_ap(int argc, char **argv)
{
    esp_err_t err;
    nvs_handle_t nvs;

    int nerrors = arg_parse(argc, argv, (void **) &set_ap_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, set_ap_args.end, argv[0]);
        return 1;
    }

    preprocess_string((char*)set_ap_args.ssid->sval[0]);
    preprocess_string((char*)set_ap_args.password->sval[0]);

    if (strlen(set_ap_args.password->sval[0]) < 8) {
        printf("AP will be open (no passwd needed).\n");
    }

    err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        return err;
    }

    err = nvs_set_str(nvs, "ap_ssid", set_ap_args.ssid->sval[0]);
    if (err == ESP_OK) {
        err = nvs_set_str(nvs, "ap_passwd", set_ap_args.password->sval[0]);
        if (err == ESP_OK) {
            err = nvs_commit(nvs);
            if (err == ESP_OK) {
                ESP_LOGI(TAG, "AP settings %s/%s stored.", set_ap_args.ssid->sval[0], set_ap_args.password->sval[0]);
            }
        }
    }
    nvs_close(nvs);
    return err;
}

static void register_set_ap(void)
{
    set_ap_args.ssid = arg_str1(NULL, NULL, "<ssid>", "SSID of AP");
    set_ap_args.password = arg_str1(NULL, NULL, "<passwd>", "Password of AP");
    set_ap_args.end = arg_end(2);

    const esp_console_cmd_t cmd = {
        .command = "set_ap",
        .help = "Set SSID and password of the SoftAP",
        .hint = NULL,
        .func = &set_ap,
        .argtable = &set_ap_args
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/** Arguments used by 'set_ap_dns' function */
static struct {
    struct arg_str *dns_str;
    struct arg_end *end;
} set_ap_dns_arg;

/* 'set_ap_dns' command */
static int set_ap_dns(int argc, char **argv)
{
    esp_err_t err;

    int nerrors = arg_parse(argc, argv, (void **) &set_ap_dns_arg);
    if (nerrors != 0) {
        arg_print_errors(stderr, set_ap_dns_arg.end, argv[0]);
        return 1;
    }

    preprocess_string((char*)set_ap_dns_arg.dns_str->sval[0]);

    err = set_config_param_str("ap_dns", set_ap_dns_arg.dns_str->sval[0]);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "AP DNS server '%s' stored.", set_ap_dns_arg.dns_str->sval[0]);
        printf("AP DNS set to: %s\n", set_ap_dns_arg.dns_str->sval[0]);
        if (strlen(set_ap_dns_arg.dns_str->sval[0]) == 0) {
            printf("DNS will be learned from upstream (default behavior).\n");
        }
        printf("Restart to apply.\n");
    }

    // Update global
    free(ap_dns);
    ap_dns = strdup(set_ap_dns_arg.dns_str->sval[0]);

    return err;
}

static void register_set_ap_dns(void)
{
    set_ap_dns_arg.dns_str = arg_str1(NULL, NULL, "<dns>", "DNS server IP (empty string to clear)");
    set_ap_dns_arg.end = arg_end(1);

    const esp_console_cmd_t cmd = {
        .command = "set_ap_dns",
        .help = "Set DNS server for AP clients (empty to use upstream)",
        .hint = NULL,
        .func = &set_ap_dns,
        .argtable = &set_ap_dns_arg
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/* 'set_hostname' command */
static struct {
    struct arg_str *name;
    struct arg_end *end;
} set_hostname_arg;

static int set_hostname_cmd(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **) &set_hostname_arg);
    if (nerrors != 0) {
        arg_print_errors(stderr, set_hostname_arg.end, argv[0]);
        return 1;
    }

    const char *name = set_hostname_arg.name->sval[0];
    preprocess_string((char*)name);

    // Validate: max 32 chars, only alphanumeric and hyphens (RFC 952)
    size_t len = strlen(name);
    if (len > 32) {
        printf("Hostname too long (max 32 characters).\n");
        return 1;
    }
    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-')) {
            printf("Invalid character '%c'. Use only letters, digits, and hyphens.\n", c);
            return 1;
        }
    }

    esp_err_t err = set_config_param_str("hostname", name);
    if (err != ESP_OK) {
        printf("Error saving hostname: %s\n", esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "Hostname set to '%s'", name);
    if (len > 0) {
        printf("Hostname set to: %s\n", name);
    } else {
        printf("Hostname cleared (will use default 'espressif').\n");
    }
    printf("Restart to apply.\n");

    free(hostname);
    hostname = strdup(name);

    return err;
}

static void register_set_hostname(void)
{
    set_hostname_arg.name = arg_str1(NULL, NULL, "<name>", "DHCP hostname (empty to clear)");
    set_hostname_arg.end = arg_end(1);

    const esp_console_cmd_t cmd = {
        .command = "set_hostname",
        .help = "Set DHCP client hostname for upstream network (empty to use default)",
        .hint = NULL,
        .func = &set_hostname_cmd,
        .argtable = &set_hostname_arg
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/* 'web_ui' command */
static int web_ui_cmd(int argc, char **argv)
{
    if (argc < 2) {
        /* Show current status */
        char* lock = NULL;
        get_config_param_str("web_disabled", &lock);
        bool enabled = (lock == NULL || strcmp(lock, "0") == 0);
        int port = 80;
        get_config_param_int("web_port", &port);
        printf("Web interface: %s (port %d)\n", enabled ? "enabled" : "disabled", port);
        printf("\nUsage:\n");
        printf("  web_ui enable           - Enable web interface (after reboot)\n");
        printf("  web_ui disable          - Disable web interface (after reboot)\n");
        printf("  web_ui port <port>      - Set web server port (after reboot)\n");
        if (lock != NULL) free(lock);
        return 0;
    }

    const char *action = argv[1];
    esp_err_t err;

    if (strcmp(action, "enable") == 0) {
        err = set_config_param_str("web_disabled", "0");
        if (err == ESP_OK) {
            ESP_LOGW(TAG, "Web interface enabled via CLI.");
            printf("Web interface will be enabled after reboot.\n");
        }
    } else if (strcmp(action, "disable") == 0) {
        err = set_config_param_str("web_disabled", "1");
        if (err == ESP_OK) {
            ESP_LOGW(TAG, "Web interface disabled via CLI.");
            printf("Web interface will be disabled after reboot.\n");
            printf("Use 'web_ui enable' to re-enable it.\n");
        }
    } else if (strcmp(action, "port") == 0) {
        if (argc < 3) {
            int port = 80;
            get_config_param_int("web_port", &port);
            printf("Current web server port: %d\n", port);
            printf("Usage: web_ui port <port>\n");
            return 0;
        }
        int port = atoi(argv[2]);
        if (port < 1 || port > 65535) {
            printf("Invalid port: %s (must be 1-65535)\n", argv[2]);
            return 1;
        }
        err = set_config_param_int("web_port", port);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "Web server port set to %d.", port);
            printf("Web server port set to %d (after reboot).\n", port);
        }
    } else {
        printf("Unknown action: %s\n", action);
        printf("Usage: web_ui <enable|disable|port>\n");
        return 1;
    }

    return err;
}

static void register_web_ui(void)
{
    const esp_console_cmd_t cmd = {
        .command = "web_ui",
        .help = "Manage the web interface\n"
                "  web_ui              - Show current status\n"
                "  web_ui enable       - Enable web interface (after reboot)\n"
                "  web_ui disable      - Disable web interface (after reboot)\n"
                "  web_ui port <port>  - Set web server port (after reboot)",
        .hint = " <enable|disable|port>",
        .func = &web_ui_cmd,
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/* --- Password hashing (SHA-256 + 16-byte salt) --- */
/* NVS key "web_password" stores "salt_hex:hash_hex" (32 + 1 + 64 = 97 chars) */

#define PW_SALT_LEN 16
#define PW_HASH_LEN 32   /* SHA-256 output */

static void pw_bytes_to_hex(const uint8_t *src, size_t len, char *out)
{
    for (size_t i = 0; i < len; i++) {
        sprintf(out + i * 2, "%02x", src[i]);
    }
    out[len * 2] = '\0';
}

static int pw_hex_to_bytes(const char *src, uint8_t *dst, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned int b;
        if (sscanf(src + i * 2, "%2x", &b) != 1) return -1;
        dst[i] = (uint8_t)b;
    }
    return 0;
}

static void pw_compute_hash(const uint8_t *salt, size_t salt_len,
                            const char *plaintext, uint8_t *hash_out)
{
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);  /* 0 = SHA-256 (not 224) */
    mbedtls_sha256_update(&ctx, salt, salt_len);
    mbedtls_sha256_update(&ctx, (const uint8_t *)plaintext, strlen(plaintext));
    mbedtls_sha256_finish(&ctx, hash_out);
    mbedtls_sha256_free(&ctx);
}

bool is_web_password_set(void)
{
    nvs_handle_t nvs;
    if (nvs_open(PARAM_NAMESPACE, NVS_READONLY, &nvs) != ESP_OK) return false;

    size_t len = 0;
    esp_err_t err = nvs_get_str(nvs, "web_password", NULL, &len);
    nvs_close(nvs);
    return (err == ESP_OK && len > 1);  /* len includes null terminator */
}

bool verify_web_password(const char *plaintext)
{
    nvs_handle_t nvs;
    if (nvs_open(PARAM_NAMESPACE, NVS_READONLY, &nvs) != ESP_OK) return false;

    size_t stored_len = 0;
    esp_err_t err = nvs_get_str(nvs, "web_password", NULL, &stored_len);
    if (err != ESP_OK || stored_len <= 1) { nvs_close(nvs); return false; }

    char *stored = malloc(stored_len);
    if (!stored) { nvs_close(nvs); return false; }
    nvs_get_str(nvs, "web_password", stored, &stored_len);
    nvs_close(nvs);

    /* New format: "salt_hex:hash_hex" (32 + 1 + 64 = 97 chars + null) */
    char *colon = strchr(stored, ':');
    if (colon && (colon - stored) == PW_SALT_LEN * 2
              && strlen(colon + 1) == PW_HASH_LEN * 2) {
        /* Hashed format */
        uint8_t salt[PW_SALT_LEN], stored_hash[PW_HASH_LEN], computed_hash[PW_HASH_LEN];
        if (pw_hex_to_bytes(stored, salt, PW_SALT_LEN) != 0 ||
            pw_hex_to_bytes(colon + 1, stored_hash, PW_HASH_LEN) != 0) {
            free(stored);
            return false;
        }
        pw_compute_hash(salt, PW_SALT_LEN, plaintext, computed_hash);
        free(stored);

        /* Constant-time comparison */
        volatile int diff = 0;
        for (int i = 0; i < PW_HASH_LEN; i++) {
            diff |= stored_hash[i] ^ computed_hash[i];
        }
        return diff == 0;
    }

    /* Legacy plaintext format - compare directly, then migrate */
    bool match = (strcmp(stored, plaintext) == 0);
    free(stored);
    if (match) {
        /* Silently migrate to hashed format */
        set_web_password_hashed(plaintext);
    }
    return match;
}

esp_err_t set_web_password_hashed(const char *plaintext)
{
    if (plaintext[0] == '\0') {
        /* Empty = disable password */
        return set_config_param_str("web_password", "");
    }

    uint8_t salt[PW_SALT_LEN], hash[PW_HASH_LEN];
    esp_fill_random(salt, PW_SALT_LEN);
    pw_compute_hash(salt, PW_SALT_LEN, plaintext, hash);

    /* Format: "salt_hex:hash_hex" */
    char buf[PW_SALT_LEN * 2 + 1 + PW_HASH_LEN * 2 + 1];
    pw_bytes_to_hex(salt, PW_SALT_LEN, buf);
    buf[PW_SALT_LEN * 2] = ':';
    pw_bytes_to_hex(hash, PW_HASH_LEN, buf + PW_SALT_LEN * 2 + 1);

    return set_config_param_str("web_password", buf);
}

/* 'set_router_password' command */
static int set_router_password_cmd(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: set_router_password <password>\n");
        printf("Use empty string \"\" to disable password protection\n");
        return 1;
    }

    esp_err_t err = set_web_password_hashed(argv[1]);
    if (err == ESP_OK) {
        if (argv[1][0] == '\0') {
            ESP_LOGW(TAG, "Web password protection disabled via CLI.");
            printf("Password protection disabled.\n");
        } else {
            ESP_LOGW(TAG, "Web password changed via CLI.");
            printf("Password updated successfully.\n");
        }
    } else {
        printf("Failed to set password\n");
    }
    return err;
}

static void register_set_router_password(void)
{
    const esp_console_cmd_t cmd = {
        .command = "set_router_password",
        .help = "Set bridge password for web and remote console (empty string to disable)",
        .hint = NULL,
        .func = &set_router_password_cmd,
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/* 'show' command arguments */
static struct {
    struct arg_str *type;
    struct arg_end *end;
} show_args;

/* 'show' command implementation */
static int show(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **) &show_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, show_args.end, argv[0]);
        return 1;
    }

    if (show_args.type->count == 0) {
        printf("Usage: show <status|config|ota>\n");
        printf("  status   - Show bridge status (connection, clients, memory)\n");
        printf("  config   - Show bridge configuration (AP/ETH settings)\n");
        printf("  ota      - Show OTA partition info\n");
        return 1;
    }

    const char *type = show_args.type->sval[0];

    if (strcmp(type, "status") == 0) {
        printf("L2 Bridge Status:\n");
        printf("=================\n");

        // Uptime
        char uptime_str[32];
        format_uptime(get_uptime_seconds(), uptime_str, sizeof(uptime_str));
        char boot_time_str[32];
        format_boot_time(boot_time_str, sizeof(boot_time_str));
        printf("Uptime: %s (since %s)\n", uptime_str, boot_time_str);

        // Ethernet link status
        if (ap_connect) {
            printf("Uplink ETH: connected\n");
        } else {
            printf("Uplink ETH: not connected\n");
        }

        // Management IP
        if (my_ip) {
            ip4_addr_t addr;
            addr.addr = my_ip;
            printf("Management IP: " IPSTR "\n", IP2STR(&addr));
        } else {
            printf("Management IP: none\n");
        }

        // Byte counts
        printf("Bytes sent/received: %" PRIu64 " / %" PRIu64 " bytes\n", get_sta_bytes_sent(), get_sta_bytes_received());

        // Free heap
        printf("Free heap: %lu bytes\n", (unsigned long)esp_get_free_heap_size());

        // AP interface state
        printf("AP interface: %s\n", ap_disabled ? "disabled" : "enabled");

        // Connected WiFi clients
        resync_connect_count();
        printf("Connected WiFi clients: %u\n", connect_count);
        if (connect_count > 0) {
            // List connected stations from WiFi driver
            wifi_sta_list_t sta_list;
            if (esp_wifi_ap_get_sta_list(&sta_list) == ESP_OK && sta_list.num > 0) {
                // Fetch per-client traffic stats
                client_stats_entry_t stats[CLIENT_STATS_MAX];
                int stats_count = client_stats_get_all(stats, CLIENT_STATS_MAX);

                printf("\nClient Details:\n");
                printf("MAC Address        TX / RX\n");
                printf("-----------------  ------------------\n");

                for (int i = 0; i < sta_list.num; i++) {
                    char mac_str[18];
                    sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X",
                            sta_list.sta[i].mac[0], sta_list.sta[i].mac[1], sta_list.sta[i].mac[2],
                            sta_list.sta[i].mac[3], sta_list.sta[i].mac[4], sta_list.sta[i].mac[5]);

                    // Find matching traffic stats by MAC
                    char traffic_str[32] = "-";
                    for (int j = 0; j < stats_count; j++) {
                        if (memcmp(stats[j].mac, sta_list.sta[i].mac, 6) == 0) {
                            char tx_buf[12], rx_buf[12];
                            format_bytes_human(stats[j].bytes_sent, tx_buf, sizeof(tx_buf));
                            format_bytes_human(stats[j].bytes_received, rx_buf, sizeof(rx_buf));
                            snprintf(traffic_str, sizeof(traffic_str), "%s / %s", tx_buf, rx_buf);
                            break;
                        }
                    }

                    printf("%-17s  %s\n", mac_str, traffic_str);
                }
            }
        }

    } else if (strcmp(type, "config") == 0) {
        char* cfg_static_ip = NULL;
        char* cfg_subnet_mask = NULL;
        char* cfg_gateway_addr = NULL;
        char* cfg_ap_ssid = NULL;
        char* cfg_ap_passwd = NULL;

        get_config_param_str("static_ip", &cfg_static_ip);
        get_config_param_str("subnet_mask", &cfg_subnet_mask);
        get_config_param_str("gateway_addr", &cfg_gateway_addr);
        get_config_param_str("ap_ssid", &cfg_ap_ssid);
        get_config_param_str("ap_passwd", &cfg_ap_passwd);

        printf("L2 Bridge Configuration:\n");
        printf("========================\n");

        bool hide_pw = remote_console_is_capturing();

        printf("Uplink: Ethernet\n");

        if (cfg_static_ip != NULL && strlen(cfg_static_ip) > 0) {
            printf("  Management IP: %s\n", cfg_static_ip);
            printf("  Subnet Mask: %s\n", cfg_subnet_mask != NULL ? cfg_subnet_mask : "<undef>");
            printf("  Gateway: %s\n", cfg_gateway_addr != NULL ? cfg_gateway_addr : "<undef>");
        } else {
            printf("  Management IP: DHCP\n");
        }
        printf("  Hostname: %s\n", (hostname && hostname[0]) ? hostname : "(default)");

        printf("\nAP Settings:\n");
        printf("  SSID: %s\n", cfg_ap_ssid != NULL ? cfg_ap_ssid : "<undef>");
        printf("  Password: %s\n", cfg_ap_passwd == NULL ? "<undef>" : hide_pw ? "***" : cfg_ap_passwd);
        printf("  DNS Server: %s\n", (ap_dns && ap_dns[0]) ? ap_dns : "(upstream)");
        {
            const char *auth_modes[] = {"WPA2/WPA3", "WPA2", "WPA3"};
            printf("  Security: %s\n", auth_modes[ap_authmode <= 2 ? ap_authmode : 0]);
        }
        printf("  Channel: %s", ap_channel > 0 ? "" : "auto\n");
        if (ap_channel > 0) printf("%d\n", ap_channel);
        printf("  Hidden: %s\n", ap_ssid_hidden ? "yes" : "no");

        char* web_lock = NULL;
        get_config_param_str("web_disabled", &web_lock);
        bool web_enabled = (web_lock == NULL || strcmp(web_lock, "0") == 0);
        int web_port = 80;
        get_config_param_int("web_port", &web_port);
        printf("\nWeb Interface: %s (port %d)\n", web_enabled ? "enabled" : "disabled", web_port);
        if (web_lock != NULL) free(web_lock);

        int8_t tx_power = 0;
        if (esp_wifi_get_max_tx_power(&tx_power) == ESP_OK) {
            printf("TX Power: %.1f dBm\n", tx_power * 0.25);
        }

        // Cleanup
        if (cfg_static_ip != NULL) free(cfg_static_ip);
        if (cfg_subnet_mask != NULL) free(cfg_subnet_mask);
        if (cfg_gateway_addr != NULL) free(cfg_gateway_addr);
        if (cfg_ap_ssid != NULL) free(cfg_ap_ssid);
        if (cfg_ap_passwd != NULL) free(cfg_ap_passwd);

    } else if (strcmp(type, "ota") == 0) {
        const esp_partition_t *running = esp_ota_get_running_partition();
        const esp_app_desc_t *app_desc = esp_app_get_description();
        const esp_partition_t *next = esp_ota_get_next_update_partition(NULL);
        const esp_partition_t *last = esp_ota_get_last_invalid_partition();

        printf("Running partition: %s (0x%lx, %luK)\n",
            running ? running->label : "unknown",
            running ? (unsigned long)running->address : 0,
            running ? (unsigned long)running->size / 1024 : 0);
        printf("Firmware version: %s\n", app_desc ? app_desc->version : "unknown");
        printf("Built: %s %s\n",
            app_desc ? app_desc->date : "unknown",
            app_desc ? app_desc->time : "");
        printf("IDF version: %s\n", app_desc ? app_desc->idf_ver : "unknown");
        printf("Next OTA partition: %s (0x%lx, %luK)\n",
            next ? next->label : "none",
            next ? (unsigned long)next->address : 0,
            next ? (unsigned long)next->size / 1024 : 0);

        if (last) {
            printf("Last invalid partition: %s\n", last->label);
        }

        esp_ota_img_states_t ota_state;
        if (running && esp_ota_get_state_partition(running, &ota_state) == ESP_OK) {
            const char *state_str = "unknown";
            switch (ota_state) {
                case ESP_OTA_IMG_NEW:             state_str = "new (first boot pending)"; break;
                case ESP_OTA_IMG_PENDING_VERIFY:  state_str = "pending verify"; break;
                case ESP_OTA_IMG_VALID:           state_str = "valid"; break;
                case ESP_OTA_IMG_INVALID:         state_str = "invalid"; break;
                case ESP_OTA_IMG_ABORTED:         state_str = "aborted"; break;
                default: break;
            }
            printf("Image state: %s\n", state_str);
        }

    } else {
        printf("Invalid parameter. Use: show <status|config|ota>\n");
        return 1;
    }

    return 0;
}

static void register_show(void)
{
    show_args.type = arg_str1(NULL, NULL, "[status|config|ota]", "Type of information");
    show_args.end = arg_end(1);

    const esp_console_cmd_t cmd = {
        .command = "show",
        .help = "Show bridge status, config, or OTA info",
        .hint = NULL,
        .func = &show,
        .argtable = &show_args
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/* 'bytes' command */
static struct {
    struct arg_str* action;
    struct arg_end* end;
} bytes_args;

static int bytes(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **) &bytes_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, bytes_args.end, argv[0]);
        return 1;
    }

    if (bytes_args.action->count == 0) {
        // Show current byte counts
        printf("ETH Interface Byte Counts:\n");
        printf("  Sent:     %" PRIu64 " bytes\n", get_sta_bytes_sent());
        printf("  Received: %" PRIu64 " bytes\n", get_sta_bytes_received());
        return 0;
    }

    const char *action = bytes_args.action->sval[0];
    if (strcmp(action, "reset") == 0) {
        reset_sta_byte_counts();
        printf("Byte counts reset to zero\n");
    } else {
        printf("Usage: bytes [reset]\n");
        printf("  bytes     - Show current byte counts\n");
        printf("  bytes reset - Reset byte counts to zero\n");
        return 1;
    }

    return 0;
}

static void register_bytes(void)
{
    bytes_args.action = arg_str0(NULL, NULL, "[reset]", "reset byte counts or show current counts");
    bytes_args.end = arg_end(1);

    const esp_console_cmd_t cmd = {
        .command = "bytes",
        .help = "Show or reset ETH interface byte counts",
        .hint = NULL,
        .func = &bytes,
        .argtable = &bytes_args
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/* 'pcap' command arguments */
static struct {
    struct arg_str* action;
    struct arg_int* snaplen;
    struct arg_end* end;
} pcap_args;

/* 'pcap' command implementation */
static int pcap(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **) &pcap_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, pcap_args.end, argv[0]);
        return 1;
    }

    if (pcap_args.action->count == 0) {
        printf("Usage: pcap <action> [args]\n");
        printf("  start      - Start promiscuous capture\n");
        printf("  stop       - Stop capture\n");
        printf("  status     - Show capture status\n");
        printf("  snaplen [n]- Get or set max capture bytes (64-1600)\n");
        return 1;
    }

    const char *action = pcap_args.action->sval[0];

    if (strcmp(action, "start") == 0) {
        pcap_set_mode(PCAP_MODE_PROMISCUOUS);
        printf("PCAP capture started (snaplen=%d)\n", pcap_get_snaplen());
        printf("Connect Wireshark to TCP port 19000\n");
    } else if (strcmp(action, "stop") == 0) {
        pcap_set_mode(PCAP_MODE_OFF);
        printf("PCAP capture stopped\n");
    } else if (strcmp(action, "snaplen") == 0) {
        int val = 0;
        bool has_value = false;

        if (pcap_args.snaplen->count > 0) {
            val = pcap_args.snaplen->ival[0];
            has_value = true;
        }

        if (has_value) {
            if (pcap_set_snaplen((uint16_t)val)) {
                printf("Snaplen set to %d bytes\n", pcap_get_snaplen());
            } else {
                printf("Error: snaplen must be between 64 and 1600\n");
                return 1;
            }
        } else {
            printf("Current snaplen: %d bytes\n", pcap_get_snaplen());
        }
    } else if (strcmp(action, "status") == 0) {
        printf("PCAP Capture Status:\n");
        printf("====================\n");
        printf("Active:   %s\n", pcap_get_mode() != PCAP_MODE_OFF ? "yes" : "no");
        printf("Client:   %s\n", pcap_client_connected() ? "connected" : "not connected");
        printf("Snaplen:  %d bytes\n", pcap_get_snaplen());

        size_t used, total;
        pcap_get_buffer_usage(&used, &total);
        printf("Buffer:   %u / %u bytes (%.1f%%)\n",
               (unsigned)used, (unsigned)total,
               total > 0 ? (100.0f * used / total) : 0.0f);

        printf("Captured: %lu packets\n", (unsigned long)pcap_get_captured_count());
        printf("Dropped:  %lu packets\n", (unsigned long)pcap_get_dropped_count());
        printf("\nConnection: nc <esp32_ip> 19000 | wireshark -k -i -\n");
    } else {
        printf("Invalid action. Use: pcap <start|stop|status|snaplen>\n");
        return 1;
    }

    return 0;
}

static void register_pcap(void)
{
    pcap_args.action = arg_str1(NULL, NULL, "<action>", "start|stop|status|snaplen");
    pcap_args.snaplen = arg_int0(NULL, NULL, "<bytes>", "snaplen value (64-1600)");
    pcap_args.end = arg_end(3);

    const esp_console_cmd_t cmd = {
        .command = "pcap",
        .help = "Control PCAP packet capture (TCP port 19000)",
        .hint = NULL,
        .func = &pcap,
        .argtable = &pcap_args
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/* 'set_led_gpio' command */
static int set_led_gpio_cmd(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: set_led_gpio <gpio_number|none>\n");
        printf("  gpio_number: GPIO pin number (0-48)\n");
        printf("  none: disable LED status blinking\n");
        printf("\nCurrent setting: ");
        if (led_gpio < 0) {
            printf("none (disabled)\n");
        } else {
            printf("GPIO %d\n", led_gpio);
        }
        return 0;
    }

    esp_err_t err;
    int gpio_num;

    // Parse argument
    if (strcasecmp(argv[1], "none") == 0 || strcmp(argv[1], "-1") == 0) {
        gpio_num = -1;
    } else {
        char *endptr;
        gpio_num = strtol(argv[1], &endptr, 10);
        if (*endptr != '\0' || gpio_num < 0 || gpio_num > 48) {
            printf("Invalid GPIO number. Use 0-48 or 'none'.\n");
            return 1;
        }
    }

    err = set_config_param_int("led_gpio", gpio_num);
    if (err == ESP_OK) {
        if (gpio_num < 0) {
            ESP_LOGI(TAG, "LED GPIO disabled.");
            printf("LED status blinking disabled.\n");
        } else {
            ESP_LOGI(TAG, "LED GPIO set to %d.", gpio_num);
            printf("LED status blinking set to GPIO %d.\n", gpio_num);
        }
        printf("Restart the device for changes to take effect.\n");
    } else {
        printf("Failed to save setting\n");
    }
    return err;
}

static void register_set_led_gpio(void)
{
    const esp_console_cmd_t cmd = {
        .command = "set_led_gpio",
        .help = "Set GPIO for status LED blinking (use 'none' to disable)",
        .hint = NULL,
        .func = &set_led_gpio_cmd,
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/* 'set_led_lowactive' command - set LED low-active (inverted) mode */
static int set_led_lowactive_cmd(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: set_led_lowactive <true|false>\n");
        printf("  true: LED is active-low (inverted, common for onboard LEDs)\n");
        printf("  false: LED is active-high (default)\n");
        printf("\nCurrent setting: %s\n", led_lowactive ? "true (low-active)" : "false (active-high)");
        return 0;
    }

    esp_err_t err;
    int value;

    // Parse boolean argument
    if (parse_bool_true(argv[1])) {
        value = 1;
    } else if (parse_bool_false(argv[1])) {
        value = 0;
    } else {
        printf("Invalid value. Use true/false.\n");
        return 1;
    }

    err = set_config_param_int("led_low", value);
    if (err == ESP_OK) {
        led_lowactive = value;
        if (value) {
            ESP_LOGI(TAG, "LED set to low-active (inverted) mode.");
            printf("LED set to low-active (inverted) mode.\n");
        } else {
            ESP_LOGI(TAG, "LED set to active-high (normal) mode.");
            printf("LED set to active-high (normal) mode.\n");
        }
        printf("Change takes effect immediately.\n");
    } else {
        printf("Failed to save setting\n");
    }
    return err;
}

static void register_set_led_lowactive(void)
{
    const esp_console_cmd_t cmd = {
        .command = "set_led_lowactive",
        .help = "Set LED to low-active (inverted) mode for active-low LEDs",
        .hint = NULL,
        .func = &set_led_lowactive_cmd,
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/* 'set_tx_power' command - set WiFi TX power */
static int set_tx_power_cmd(int argc, char **argv)
{
    int8_t current_power = 0;
    esp_err_t ret = esp_wifi_get_max_tx_power(&current_power);

    if (argc < 2) {
        printf("Usage: set_tx_power <dBm>\n");
        printf("  dBm: 2-20 (0 = max/default)\n");
        printf("  Actual steps: 2, 5, 7, 8, 11, 13, 14, 15, 16, 18, 20\n");
        if (ret == ESP_OK) {
            printf("\nCurrent TX power: %.1f dBm (raw: %d)\n", current_power * 0.25, current_power);
        }
        int saved = 0;
        get_config_param_int("tx_power", &saved);
        if (saved > 0) {
            printf("Saved setting: %d dBm\n", saved);
        } else {
            printf("Saved setting: max (default)\n");
        }
        return 0;
    }

    char *endptr;
    long dbm = strtol(argv[1], &endptr, 10);
    if (*endptr != '\0' || (dbm != 0 && (dbm < 2 || dbm > 20))) {
        printf("Invalid value. Use 2-20 dBm (0 = max/default).\n");
        return 1;
    }

    esp_err_t err = set_config_param_int("tx_power", (int32_t)dbm);

    if (err != ESP_OK) {
        printf("Failed to save setting\n");
        return err;
    }

    if (dbm == 0) {
        printf("TX power set to max (default). Restart to apply.\n");
    } else {
        int8_t power_qdbm = (int8_t)(dbm * 4);
        ret = esp_wifi_set_max_tx_power(power_qdbm);
        if (ret == ESP_OK) {
            esp_wifi_get_max_tx_power(&current_power);
            printf("TX power set to %.1f dBm (applied immediately, saved for reboot).\n", current_power * 0.25);
        } else {
            printf("Saved for next reboot. Could not apply now: %s\n", esp_err_to_name(ret));
        }
    }
    return 0;
}

static void register_set_tx_power(void)
{
    const esp_console_cmd_t cmd = {
        .command = "set_tx_power",
        .help = "Set WiFi TX power in dBm (2-20, 0 = max/default)",
        .hint = NULL,
        .func = &set_tx_power_cmd,
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/* 'set_ap_hidden' command - hide or show AP SSID */
static int set_ap_hidden_cmd(int argc, char **argv)
{
    if (argc < 2) {
        printf("AP SSID hidden: %s\n", ap_ssid_hidden ? "yes" : "no");
        return 0;
    }

    esp_err_t err;
    int hidden_val;

    // Parse argument
    if (parse_bool_true(argv[1])) {
        hidden_val = 1;
    } else if (parse_bool_false(argv[1])) {
        hidden_val = 0;
    } else {
        printf("Invalid value. Use true/false.\n");
        return 1;
    }

    err = set_config_param_int("ap_hidden", hidden_val);
    if (err == ESP_OK) {
        ap_ssid_hidden = (uint8_t)hidden_val;
        ESP_LOGI(TAG, "AP SSID hidden set to: %s", hidden_val ? "yes" : "no");
        printf("AP SSID hidden set to: %s\n", hidden_val ? "yes" : "no");
        printf("Restart the device for changes to take effect.\n");
    } else {
        printf("Failed to save setting\n");
    }
    return err;
}

static void register_set_ap_hidden(void)
{
    const esp_console_cmd_t cmd = {
        .command = "set_ap_hidden",
        .help = "Hide or show the AP SSID (on/off, requires restart)",
        .hint = NULL,
        .func = &set_ap_hidden_cmd,
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/* 'set_ap_auth' command - set AP authentication mode */
static int set_ap_auth_cmd(int argc, char **argv)
{
    const char *modes[] = {"wpa2wpa3", "wpa2", "wpa3"};

    if (argc < 2) {
        printf("AP auth mode: %s\n", modes[ap_authmode <= 2 ? ap_authmode : 0]);
        return 0;
    }

    int mode_val = -1;
    if (strcasecmp(argv[1], "wpa2wpa3") == 0 || strcasecmp(argv[1], "wpa2/wpa3") == 0) {
        mode_val = 0;
    } else if (strcasecmp(argv[1], "wpa2") == 0) {
        mode_val = 1;
    } else if (strcasecmp(argv[1], "wpa3") == 0) {
        mode_val = 2;
    } else {
        printf("Invalid mode. Use: wpa2, wpa3, or wpa2wpa3\n");
        return 1;
    }

    esp_err_t err = set_config_param_int("ap_authmode", mode_val);
    if (err == ESP_OK) {
        ap_authmode = (uint8_t)mode_val;
        printf("AP auth mode set to: %s\n", modes[mode_val]);
        printf("Restart the device for changes to take effect.\n");
    } else {
        printf("Failed to save setting\n");
    }
    return err;
}

static void register_set_ap_auth(void)
{
    const esp_console_cmd_t cmd = {
        .command = "set_ap_auth",
        .help = "Set AP auth mode (wpa2, wpa3, or wpa2wpa3; requires restart)",
        .hint = NULL,
        .func = &set_ap_auth_cmd,
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/* 'set_ap_channel' command - set AP WiFi channel */
static int set_ap_channel_cmd(int argc, char **argv)
{
    if (argc < 2) {
        if (ap_channel == 0) {
            printf("AP channel: auto\n");
        } else {
            printf("AP channel: %d\n", ap_channel);
        }
        return 0;
    }

    int channel_val = atoi(argv[1]);
    if (channel_val < 0 || channel_val > 13) {
        printf("Invalid channel. Use 0 (auto) or 1-13.\n");
        return 1;
    }

    esp_err_t err = set_config_param_int("ap_channel", channel_val);
    if (err == ESP_OK) {
        ap_channel = (uint8_t)channel_val;
        if (channel_val == 0) {
            printf("AP channel set to: auto\n");
        } else {
            printf("AP channel set to: %d\n", channel_val);
        }
        printf("Restart the device for changes to take effect.\n");
    } else {
        printf("Failed to save setting\n");
    }
    return err;
}

static void register_set_ap_channel(void)
{
    const esp_console_cmd_t cmd = {
        .command = "set_ap_channel",
        .help = "Set AP WiFi channel (0=auto, 1-13=fixed, requires restart)",
        .hint = NULL,
        .func = &set_ap_channel_cmd,
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/* 'ap' command - enable/disable AP interface dynamically */
static int ap_cmd(int argc, char **argv)
{
    if (argc < 2) {
        wifi_mode_t mode = WIFI_MODE_NULL;
        esp_wifi_get_mode(&mode);
        bool running = (mode == WIFI_MODE_AP);
        printf("AP interface: %s\n", running ? "enabled" : "disabled");
        printf("  (NVS setting: %s)\n", ap_disabled ? "disabled" : "enabled");
        printf("\nUsage:\n");
        printf("  ap enable   - Enable AP interface immediately\n");
        printf("  ap disable  - Disable AP interface immediately\n");
        return 0;
    }

    const char *action = argv[1];
    if (strcmp(action, "enable") == 0) {
        if (!ap_disabled) {
            printf("AP interface is already enabled.\n");
            return 0;
        }
        ap_set_enabled(true);
        printf("AP interface enabled.\n");
    } else if (strcmp(action, "disable") == 0) {
        if (ap_disabled) {
            printf("AP interface is already disabled.\n");
            return 0;
        }
        ap_set_enabled(false);
        printf("AP interface disabled.\n");
    } else {
        printf("Unknown action: %s\n", action);
        printf("Usage: ap <enable|disable>\n");
        return 1;
    }
    return 0;
}

static void register_ap(void)
{
    const esp_console_cmd_t cmd = {
        .command = "ap",
        .help = "Enable or disable the AP interface\n"
                "  ap          - Show current AP status\n"
                "  ap enable   - Enable AP interface\n"
                "  ap disable  - Disable AP interface",
        .hint = " <enable|disable>",
        .func = &ap_cmd,
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/* 'remote_console' command implementation */
static int remote_console_cmd(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: remote_console <action> [args]\n");
        printf("  status              - Show remote console status\n");
        printf("  enable              - Enable remote console\n");
        printf("  disable             - Disable remote console\n");
        printf("  port <port>         - Set TCP port (requires restart)\n");
        printf("  bind <both|ap|eth>  - Set interface binding\n");
        printf("  timeout <seconds>   - Set idle timeout (0=none)\n");
        printf("  kick                - Disconnect current session\n");
        return 0;
    }

    const char *action = argv[1];

    if (strcmp(action, "status") == 0) {
        remote_console_config_t config;
        remote_console_status_t status;
        remote_console_get_config(&config);
        remote_console_get_status(&status);

        printf("Remote Console Status:\n");
        printf("======================\n");
        printf("Enabled:        %s\n", config.enabled ? "yes" : "no");
        printf("Port:           %d\n", config.port);

        printf("Interface:      %s%s\n",
               (config.bind & RC_BIND_AP) ? "AP " : "",
               (config.bind & RC_BIND_ETH) ? "ETH " : "");
        printf("Idle timeout:   %lu sec\n", (unsigned long)config.idle_timeout_sec);

        const char *state_str[] = {"disabled", "listening", "auth wait", "active"};
        printf("State:          %s\n", state_str[status.state]);

        if (status.state == RC_STATE_ACTIVE) {
            printf("Client IP:      %s\n", status.client_ip);
            printf("Session time:   %lu sec\n", (unsigned long)status.session_duration_sec);
            printf("Idle:           %lu sec\n", (unsigned long)status.idle_sec);
        }

        printf("Connections:    %lu total\n", (unsigned long)status.total_connections);
        printf("Auth failures:  %lu\n", (unsigned long)status.failed_auths);

        printf("\nWARNING: Currently uses plain TCP (not encrypted).\n");

    } else if (strcmp(action, "enable") == 0) {
        esp_err_t err = remote_console_enable();
        if (err == ESP_OK) {
            ESP_LOGW(TAG, "Remote console enabled via CLI.");
            printf("Remote console enabled.\n");
        } else {
            printf("Error: %s\n", esp_err_to_name(err));
        }

    } else if (strcmp(action, "disable") == 0) {
        remote_console_disable();
        ESP_LOGW(TAG, "Remote console disabled via CLI.");
        printf("Remote console disabled.\n");

    } else if (strcmp(action, "port") == 0) {
        if (argc < 3) {
            printf("Usage: remote_console port <port>\n");
            return 1;
        }
        int port = atoi(argv[2]);
        if (port < 1 || port > 65535) {
            printf("Invalid port number (1-65535)\n");
            return 1;
        }
        remote_console_set_port((uint16_t)port);
        ESP_LOGW(TAG, "Remote console port changed to %d via CLI.", port);
        printf("Port set to %d. Restart or disable/enable to apply.\n", port);

    } else if (strcmp(action, "bind") == 0) {
        if (argc < 3) {
            printf("Usage: remote_console bind <ap,eth>\n");
            printf("  Comma-separated list, e.g.: ap,eth\n");
            return 1;
        }
        uint8_t bind = 0;
        char arg_copy[64];
        strncpy(arg_copy, argv[2], sizeof(arg_copy) - 1);
        arg_copy[sizeof(arg_copy) - 1] = '\0';
        char *token = strtok(arg_copy, ",");
        while (token) {
            if ((strcmp(token, "ap") == 0)||(strcmp(token, "AP")) == 0) bind |= RC_BIND_AP;
            else if ((strcmp(token, "eth") == 0)||(strcmp(token, "ETH") == 0)) bind |= RC_BIND_ETH;
            else {
                printf("Unknown interface: %s. Use: ap, eth\n", token);
                return 1;
            }
            token = strtok(NULL, ",");
        }
        if (bind == 0) {
            printf("Must specify at least one interface\n");
            return 1;
        }
        remote_console_set_bind(bind);
        ESP_LOGW(TAG, "Remote console bind changed to %s via CLI.", argv[2]);
        printf("Bind set. Restart or disable/enable to apply.\n");

    } else if (strcmp(action, "timeout") == 0) {
        if (argc < 3) {
            printf("Usage: remote_console timeout <seconds>\n");
            return 1;
        }
        uint32_t timeout = (uint32_t)atoi(argv[2]);
        remote_console_set_timeout(timeout);
        ESP_LOGI(TAG, "Remote console timeout changed to %lu sec via CLI.", (unsigned long)timeout);
        printf("Timeout set to %lu seconds.\n", (unsigned long)timeout);

    } else if (strcmp(action, "kick") == 0) {
        esp_err_t err = remote_console_kick();
        if (err == ESP_OK) {
            ESP_LOGW(TAG, "Remote console session kicked via CLI.");
            printf("Kick request sent.\n");
        } else {
            printf("No active session to kick.\n");
        }

    } else {
        printf("Unknown action: %s\n", action);
        return 1;
    }

    return 0;
}

static void register_remote_console_cmd(void)
{
    const esp_console_cmd_t cmd = {
        .command = "remote_console",
        .help = "Manage remote console (network CLI access)\n"
                "  remote_console status              - Show status and connection info\n"
                "  remote_console enable               - Enable remote console\n"
                "  remote_console disable              - Disable remote console\n"
                "  remote_console port <port>          - Set TCP port (default: 2323)\n"
                "  remote_console bind <ap,eth>         - Set interface binding\n"
                "  remote_console timeout <seconds>    - Set idle timeout (0=none)\n"
                "  remote_console kick                 - Disconnect current session",
        .hint = " <action> [<args>]",
        .func = &remote_console_cmd,
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/* 'syslog' command - configure remote syslog forwarding */
static int syslog_cmd(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: syslog <action> [args]\n");
        printf("  status                    - Show syslog configuration\n");
        printf("  enable <server> [<port>]  - Enable syslog (default port 514)\n");
        printf("  disable                   - Disable syslog forwarding\n");
        return 0;
    }

    const char *action = argv[1];

    if (strcmp(action, "status") == 0) {
        bool enabled;
        char server[SYSLOG_MAX_SERVER_LEN];
        uint16_t port;
        syslog_get_config(&enabled, server, sizeof(server), &port);

        printf("Syslog Status:\n");
        printf("==============\n");
        printf("Enabled:  %s\n", enabled ? "yes" : "no");
        printf("Server:   %s\n", server[0] ? server : "(not set)");
        printf("Port:     %u\n", port);

    } else if (strcmp(action, "enable") == 0) {
        if (argc < 3) {
            printf("Usage: syslog enable <server> [<port>]\n");
            return 1;
        }
        const char *server = argv[2];
        uint16_t port = SYSLOG_DEFAULT_PORT;
        if (argc >= 4) {
            int p = atoi(argv[3]);
            if (p < 1 || p > 65535) {
                printf("Invalid port number (1-65535)\n");
                return 1;
            }
            port = (uint16_t)p;
        }
        esp_err_t err = syslog_enable(server, port);
        if (err == ESP_OK) {
            ESP_LOGW(TAG, "Syslog enabled: %s:%u via CLI.", server, port);
            printf("Syslog enabled: %s:%u\n", server, port);
        } else {
            printf("Error: %s\n", esp_err_to_name(err));
        }

    } else if (strcmp(action, "disable") == 0) {
        syslog_disable();
        ESP_LOGW(TAG, "Syslog disabled via CLI.");
        printf("Syslog disabled.\n");

    } else {
        printf("Unknown action: %s\n", action);
        return 1;
    }

    return 0;
}

static void register_syslog_cmd(void)
{
    const esp_console_cmd_t cmd = {
        .command = "syslog",
        .help = "Manage remote syslog forwarding\n"
                "  syslog status                    - Show syslog configuration\n"
                "  syslog enable <server> [<port>]  - Enable syslog (default port 514)\n"
                "  syslog disable                   - Disable syslog forwarding",
        .hint = " <action> [<args>]",
        .func = &syslog_cmd,
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/* 'set_tz' command - set timezone */
static int set_tz_cmd(int argc, char **argv)
{
    if (argc < 2) {
        const char *tz = getenv("TZ");
        printf("Timezone: %s\n", tz ? tz : "(not set, using UTC)");
        printf("\nUsage: set_tz <POSIX TZ string>\n");
        printf("Examples:\n");
        printf("  set_tz UTC               - UTC\n");
        printf("  set_tz CET-1CEST,M3.5.0,M10.5.0/3  - Central Europe\n");
        printf("  set_tz EST5EDT,M3.2.0,M11.1.0       - US Eastern\n");
        printf("  set_tz PST8PDT,M3.2.0,M11.1.0       - US Pacific\n");
        printf("  set_tz clear             - Clear timezone (revert to UTC)\n");
        return 0;
    }

    if (strcmp(argv[1], "clear") == 0) {
        unsetenv("TZ");
        tzset();
        set_config_param_str("tz", "");
        printf("Timezone cleared (using UTC).\n");
        return 0;
    }

    setenv("TZ", argv[1], 1);
    tzset();
    set_config_param_str("tz", argv[1]);

    /* Show current time to confirm */
    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S %Z", &tm_info);
    printf("Timezone set to: %s\n", argv[1]);
    printf("Current time:    %s\n", buf);

    return 0;
}

static void register_set_tz(void)
{
    const esp_console_cmd_t cmd = {
        .command = "set_tz",
        .help = "Set timezone (POSIX TZ string)\n"
                "  set_tz                   - Show current timezone\n"
                "  set_tz <TZ string>       - Set timezone\n"
                "  set_tz clear             - Clear timezone (revert to UTC)",
        .hint = " <TZ string>",
        .func = &set_tz_cmd,
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}
