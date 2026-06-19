/* Web interface (HTTP server) for ESP32 Ethernet-WiFi Bridge.
 *
 * Pages:
 *   /          - Bridge status dashboard: ETH link, clients, traffic, login
 *   /config    - Bridge configuration: AP settings, management IP, hostname
 *
 * Password-protected pages use cookie-based sessions (30-min timeout).
 * HTML templates are defined in pages.h as C macro strings.
 */
#include "esp_netif.h"
#include "lwip/ip_addr.h"
#include "lwip/inet.h"

#include <esp_wifi.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_system.h>
#include <esp_timer.h>
#include <sys/param.h>
#include "nvs_flash.h"

#include <esp_http_server.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "lwip/sockets.h"

#include "pages.h"
#include "favicon_png.h"
#include "router_globals.h"
#include "remote_console.h"
#include "pcap_capture.h"
#include "esp_ota_ops.h"
#include "esp_app_format.h"
#include "esp_app_desc.h"

static const char *TAG = "HTTPServer";

/* Stream one HTTP chunk and abort the handler immediately if the send fails.
 *
 * httpd_resp_send_chunk() blocks up to config.send_wait_timeout when the client
 * is gone or its TCP window is full.  The page handlers issue dozens of chunks
 * in sequence; without checking the result, a dead client makes the handler
 * spin through every remaining chunk (one timeout each), wedging the single
 * httpd worker and pinning that connection's buffers/socket.
 *
 * Returning ESP_FAIL on the first failed chunk lets httpd tear the connection
 * down at once.  Handlers that stream with SEND_CHUNK must NOT hold a heap
 * allocation across the chunk loop: a bail-out returns immediately and would
 * leak it.  Render from a stack buffer, or free before streaming begins. */
#define SEND_CHUNK(req, ...) \
    do { \
        if (httpd_resp_send_chunk((req), __VA_ARGS__) != ESP_OK) { \
            return ESP_FAIL; \
        } \
    } while (0)

/* Escape src into a fixed stack buffer (truncating if needed) and free the
 * heap copy from html_escape().  Page handlers use this so they never hold an
 * html_escape() allocation across a chunked SEND_CHUNK render. */
char* html_escape(const char* src);
static void html_escape_to(char *dst, size_t dst_len, const char *src)
{
    char *e = html_escape(src ? src : "");
    strlcpy(dst, e ? e : "", dst_len);
    free(e);
}

/* Get client IP address string from HTTP request */
static const char *get_client_ip(httpd_req_t *req, char *buf, size_t buf_len)
{
    int sockfd = httpd_req_to_sockfd(req);
    struct sockaddr_in6 addr6;
    socklen_t addr_len = sizeof(addr6);
    if (getpeername(sockfd, (struct sockaddr *)&addr6, &addr_len) == 0) {
        /* ESP-IDF httpd uses IPv6 sockets; IPv4 clients appear as
         * ::ffff:x.x.x.x (IPv4-mapped IPv6).  Extract the IPv4 part. */
        if (addr6.sin6_family == AF_INET6) {
            struct in_addr ipv4;
            memcpy(&ipv4, addr6.sin6_addr.s6_addr + 12, 4);
            inet_ntoa_r(ipv4, buf, buf_len);
        } else {
            struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr6;
            inet_ntoa_r(addr4->sin_addr, buf, buf_len);
        }
    } else {
        strncpy(buf, "unknown", buf_len);
    }
    return buf;
}

esp_timer_handle_t restart_timer;

/* Session management for password protection */
#define MAX_SESSION_TOKEN_LEN 32
#define SESSION_TIMEOUT_US (30 * 60 * 1000000LL) // 30 minutes

static char current_session_token[MAX_SESSION_TOKEN_LEN + 1] = {0};
static bool session_active = false;
static int64_t session_expiry_time = 0;

static void restart_timer_callback(void* arg)
{
    ESP_LOGI(TAG, "Restarting now...");
    esp_restart();
}

esp_timer_create_args_t restart_timer_args = {
        .callback = &restart_timer_callback,
        /* argument specified here will be passed to timer callback function */
        .arg = (void*) 0,
        .name = "restart_timer"
};

/* Session management helper functions */

/* Generate random session token */
static void generate_session_token(char* token_out, size_t len)
{
    const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len - 1; i++) {
        token_out[i] = hex_chars[esp_random() % 16];
    }
    token_out[len - 1] = '\0';
}

/* Clear session state */
static void clear_session(void)
{
    session_active = false;
    current_session_token[0] = '\0';
    session_expiry_time = 0;
}

/* Password checking uses shared functions from web_password.h:
 * is_web_password_set(), verify_web_password(), set_web_password_hashed() */

/* Extract cookie value from request headers */
static bool get_cookie_value(httpd_req_t *req, const char* cookie_name,
                              char* value_out, size_t max_len)
{
    size_t cookie_header_len = httpd_req_get_hdr_value_len(req, "Cookie");
    if (cookie_header_len == 0) {
        return false;
    }

    char* cookie_header = malloc(cookie_header_len + 1);
    if (cookie_header == NULL) {
        return false;
    }

    if (httpd_req_get_hdr_value_str(req, "Cookie", cookie_header, cookie_header_len + 1) != ESP_OK) {
        free(cookie_header);
        return false;
    }

    // Search for the cookie name
    char search_pattern[64];
    snprintf(search_pattern, sizeof(search_pattern), "%s=", cookie_name);
    char* cookie_start = strstr(cookie_header, search_pattern);

    if (cookie_start == NULL) {
        free(cookie_header);
        return false;
    }

    // Move past the "name=" part
    cookie_start += strlen(search_pattern);

    // Find the end of the cookie value (semicolon or end of string)
    char* cookie_end = strchr(cookie_start, ';');
    size_t cookie_len = cookie_end ? (size_t)(cookie_end - cookie_start) : strlen(cookie_start);

    if (cookie_len >= max_len) {
        cookie_len = max_len - 1;
    }

    strncpy(value_out, cookie_start, cookie_len);
    value_out[cookie_len] = '\0';

    free(cookie_header);
    return true;
}

/* Check if request has valid session cookie */
static bool is_authenticated(httpd_req_t *req)
{
    // If no session is active, not authenticated
    if (!session_active) {
        return false;
    }

    // Check if session has expired
    int64_t current_time = esp_timer_get_time();
    if (current_time > session_expiry_time) {
        clear_session();
        return false;
    }

    // Extract session cookie
    char session_token[MAX_SESSION_TOKEN_LEN + 1];
    if (!get_cookie_value(req, "session", session_token, sizeof(session_token))) {
        return false;
    }

    // Validate token matches
    if (strcmp(session_token, current_session_token) != 0) {
        return false;
    }

    // Extend session expiry on successful auth
    session_expiry_time = current_time + SESSION_TIMEOUT_US;

    return true;
}

/* Cookie header buffer - must be static because httpd_resp_set_hdr stores pointer, not copy */
static char session_cookie_header[128];

/* Create new session and set cookie */
static esp_err_t create_session(httpd_req_t *req)
{
    // Generate new session token
    generate_session_token(current_session_token, sizeof(current_session_token));

    // Set session active and expiry
    session_active = true;
    session_expiry_time = esp_timer_get_time() + SESSION_TIMEOUT_US;

    // Set cookie in response (using static buffer because httpd stores pointer)
    snprintf(session_cookie_header, sizeof(session_cookie_header),
             "session=%s; Path=/; SameSite=Strict", current_session_token);
    httpd_resp_set_hdr(req, "Set-Cookie", session_cookie_header);

    ESP_LOGI(TAG, "Session created, expires in 30 minutes");
    return ESP_OK;
}

/* Forward declarations */
char* html_escape(const char* src);

/* Stream the common index page HTML (status table, auth UI, footer).
 * Returns ESP_FAIL via SEND_CHUNK if a send fails (dead client); the caller
 * propagates it so httpd tears the connection down. */
static esp_err_t stream_index_html(httpd_req_t *req, bool authenticated,
                               bool password_protection_enabled, const char *login_message)
{
    char row[512];

    /* --- Begin chunked response --- */
    SEND_CHUNK(req, INDEX_CHUNK_HEAD, HTTPD_RESP_USE_STRLEN);

    /* Stream logout button if authenticated */
    if (authenticated) {
        SEND_CHUNK(req,
            "<div style='text-align: right; margin-bottom: 0.5rem;'>"
            "<a href='/?logout=1' style='padding: 0.4rem 1rem; background: rgba(255,82,82,0.15); color: #ff5252; border: 1px solid #ff5252; border-radius: 6px; text-decoration: none; font-size: 0.85rem; font-weight: 500;'>Logout</a>"
            "</div>", HTTPD_RESP_USE_STRLEN);
    }

    /* Open status table */
    SEND_CHUNK(req, INDEX_CHUNK_STATUS_OPEN, HTTPD_RESP_USE_STRLEN);

    /* Stream ETH link status */
    if (ap_connect) {
        SEND_CHUNK(req,
            "<tr><td>ETH Link:</td><td><strong style='color:#4caf50;'>Connected</strong></td></tr>",
            HTTPD_RESP_USE_STRLEN);
    } else {
        SEND_CHUNK(req,
            "<tr><td>ETH Link:</td><td><strong style='color:#ff5252;'>Disconnected</strong></td></tr>",
            HTTPD_RESP_USE_STRLEN);
    }

    /* Stream Management IP row */
    if (br_netif) {
        esp_netif_ip_info_t ip_info;
        if (esp_netif_get_ip_info(br_netif, &ip_info) == ESP_OK && ip_info.ip.addr != 0) {
            snprintf(row, sizeof(row), "<tr><td>Management IP:</td><td>" IPSTR "</td></tr>",
                     IP2STR(&ip_info.ip));
        } else {
            snprintf(row, sizeof(row), "<tr><td>Management IP:</td><td>N/A</td></tr>");
        }
    } else {
        esp_ip4_addr_t addr;
        addr.addr = my_ip;
        if (my_ip != 0) {
            snprintf(row, sizeof(row), "<tr><td>Management IP:</td><td>" IPSTR "</td></tr>",
                     IP2STR(&addr));
        } else {
            snprintf(row, sizeof(row), "<tr><td>Management IP:</td><td>N/A</td></tr>");
        }
    }
    SEND_CHUNK(req, row, HTTPD_RESP_USE_STRLEN);

    /* Stream AP SSID row */
    if (ap_disabled) {
        SEND_CHUNK(req,
            "<tr><td>WiFi AP:</td><td><strong style='color:#ff5252;'>Disabled</strong></td></tr>",
            HTTPD_RESP_USE_STRLEN);
    } else {
        char safe_ap_ssid[200];
        html_escape_to(safe_ap_ssid, sizeof(safe_ap_ssid), ap_ssid);
        snprintf(row, sizeof(row), "<tr><td>WiFi AP:</td><td><strong>%s</strong></td></tr>", safe_ap_ssid);
        SEND_CHUNK(req, row, HTTPD_RESP_USE_STRLEN);
    }

    /* Stream Connected Clients row */
    resync_connect_count();
    snprintf(row, sizeof(row), "<tr><td>Clients:</td><td>%d</td></tr>", connect_count);
    SEND_CHUNK(req, row, HTTPD_RESP_USE_STRLEN);

    /* Stream Traffic stats row */
    uint64_t bytes_sent = get_sta_bytes_sent();
    uint64_t bytes_received = get_sta_bytes_received();
    char sent_buf[16], recv_buf[16];
    format_bytes_human(bytes_sent, sent_buf, sizeof(sent_buf));
    format_bytes_human(bytes_received, recv_buf, sizeof(recv_buf));
    snprintf(row, sizeof(row), "<tr><td>Traffic:</td><td>%s sent / %s received</td></tr>", sent_buf, recv_buf);
    SEND_CHUNK(req, row, HTTPD_RESP_USE_STRLEN);

    /* Stream PCAP status row */
    {
        pcap_capture_mode_t pcap_mode = pcap_get_mode();
        const char *pcap_color = (pcap_mode != PCAP_MODE_OFF) ? "#4caf50" : "#888";
        snprintf(row, sizeof(row),
            "<tr><td>PCAP:</td><td><strong style='color:%s;'>%s</strong> &mdash; %lu captured, %lu dropped%s</td></tr>",
            pcap_color, pcap_mode_to_string(pcap_mode),
            (unsigned long)pcap_get_captured_count(),
            (unsigned long)pcap_get_dropped_count(),
            pcap_client_connected() ? " (client connected)" : "");
        SEND_CHUNK(req, row, HTTPD_RESP_USE_STRLEN);
    }

    /* Stream Uptime row */
    char uptime_str[32];
    format_uptime(get_uptime_seconds(), uptime_str, sizeof(uptime_str));
    char boot_time_str[32];
    format_boot_time(boot_time_str, sizeof(boot_time_str));
    snprintf(row, sizeof(row), "<tr><td>Uptime:</td><td>%s (since %s)</td></tr>", uptime_str, boot_time_str);
    SEND_CHUNK(req, row, HTTPD_RESP_USE_STRLEN);

    /* Stream Free Heap row */
    snprintf(row, sizeof(row), "<tr><td>Free Heap:</td><td>%lu bytes</td></tr>",
             (unsigned long)esp_get_free_heap_size());
    SEND_CHUNK(req, row, HTTPD_RESP_USE_STRLEN);

    /* Close status table */
    SEND_CHUNK(req, INDEX_CHUNK_STATUS_CLOSE, HTTPD_RESP_USE_STRLEN);

    /* Navigation buttons */
    SEND_CHUNK(req, INDEX_CHUNK_BUTTONS, HTTPD_RESP_USE_STRLEN);

    /* --- Auth UI Section (streamed directly) --- */

    /* Show message if any */
    if (login_message[0] != '\0') {
        const char* msg_style;
        if (strstr(login_message, "ERROR") != NULL) {
            msg_style = "background: #ffebee; color: #c62828; border: 2px solid #ef5350";
        } else {
            msg_style = "background: #e8f5e9; color: #2e7d32; border: 2px solid #66bb6a";
        }
        snprintf(row, sizeof(row),
                 "<div style='margin-top: 1.5rem; padding: 1rem; %s; border-radius: 8px; font-size: 0.95rem;'>%s</div>",
                 msg_style, login_message);
        SEND_CHUNK(req, row, HTTPD_RESP_USE_STRLEN);
    }

    /* Show warning if no password protection */
    if (!password_protection_enabled) {
        SEND_CHUNK(req,
            "<div style='margin-top: 1.5rem; padding: 1rem; background: #fff3cd; border: 2px solid #ffa726; border-radius: 8px;'>"
            "<strong style='color: #f57c00;'>No Password Protection</strong>"
            "<p style='margin-top: 0.5rem; color: #666; font-size: 0.9rem;'>Anyone on this network can access bridge settings. Set a password below.</p>"
            "</div>", HTTPD_RESP_USE_STRLEN);
    }

    /* Show login form if password is set and not authenticated — POST method */
    if (password_protection_enabled && !authenticated) {
        SEND_CHUNK(req,
            "<div style='margin-top: 1.5rem; padding: 1.5rem; background: rgba(40, 30, 15, 0.6); border: 1px solid rgba(255, 179, 0, 0.2); border-radius: 12px;'>"
            "<h2 style='margin-top: 0; margin-bottom: 1rem; color: #ffb300; font-size: 1.1rem;'>Login Required</h2>"
            "<form action='' method='POST'>"
            "<input type='password' name='login_password' placeholder='Enter password' style='width: 100%; padding: 0.75rem; margin-bottom: 0.75rem; background: rgba(255,255,255,0.1); border: 1px solid rgba(255,179,0,0.3); border-radius: 8px; color: #e0e0e0; font-size: 1rem;'/>"
            "<input type='submit' value='Login' style='width: 100%; padding: 0.75rem; background: linear-gradient(135deg, #f7971e 0%, #ffd200 100%); color: #1a1510; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer;'/>"
            "</form>"
            "</div>", HTTPD_RESP_USE_STRLEN);
    }

    /* Show password management form if authenticated or no password set — POST method */
    if (authenticated || !password_protection_enabled) {
        const char* form_title = password_protection_enabled ? "Change Password" : "Set Password";
        SEND_CHUNK(req,
            "<div style='margin-top: 1.5rem; padding: 1.5rem; background: rgba(40, 30, 15, 0.6); border: 1px solid rgba(255, 179, 0, 0.2); border-radius: 12px;'>"
            "<h2 style='margin-top: 0; margin-bottom: 1rem; color: #ffb300; font-size: 1.1rem;'>", HTTPD_RESP_USE_STRLEN);
        SEND_CHUNK(req, form_title, HTTPD_RESP_USE_STRLEN);
        SEND_CHUNK(req,
            "</h2>"
            "<form action='' method='POST'>"
            "<input type='password' name='new_password' placeholder='New password (empty to disable)' style='width: 100%; padding: 0.75rem; margin-bottom: 0.75rem; background: rgba(255,255,255,0.1); border: 1px solid rgba(255,179,0,0.3); border-radius: 8px; color: #e0e0e0; font-size: 1rem;'/>"
            "<input type='password' name='confirm_password' placeholder='Confirm password' style='width: 100%; padding: 0.75rem; margin-bottom: 0.75rem; background: rgba(255,255,255,0.1); border: 1px solid rgba(255,179,0,0.3); border-radius: 8px; color: #e0e0e0; font-size: 1rem;'/>"
            "<input type='submit' value='", HTTPD_RESP_USE_STRLEN);
        SEND_CHUNK(req, form_title, HTTPD_RESP_USE_STRLEN);
        SEND_CHUNK(req,
            "' style='width: 100%; padding: 0.75rem; background: linear-gradient(135deg, #e65100 0%, #bf360c 100%); color: #fff; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer;'/>"
            "<p style='margin-top: 0.75rem; color: #888; font-size: 0.85rem;'>Leave empty to disable password protection.</p>"
            "</form>"
            "</div>", HTTPD_RESP_USE_STRLEN);
    }

    /* Footer */
    {
        const esp_app_desc_t *app_desc = esp_app_get_description();
        char footer[512];
        snprintf(footer, sizeof(footer), INDEX_CHUNK_TAIL,
                 app_desc ? app_desc->version : "unknown",
                 app_desc ? app_desc->date : "",
                 app_desc ? app_desc->time : "");
        SEND_CHUNK(req, footer, HTTPD_RESP_USE_STRLEN);
    }

    /* End chunked response */
    SEND_CHUNK(req, NULL, 0);

    return ESP_OK;
}

/* --- OTA Firmware Upload handler --- */

static esp_err_t ota_upload_handler(httpd_req_t *req)
{
    bool password_protection_enabled = is_web_password_set();
    if (password_protection_enabled && !is_authenticated(req)) {
        { char _ip[16]; ESP_LOGW(TAG, "Unauthenticated access to /api/ota-upload from %s", get_client_ip(req, _ip, sizeof(_ip))); }
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "Not authenticated");
        return ESP_FAIL;
    }

    const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
    if (update_partition == NULL) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"ok\":false,\"msg\":\"No OTA partition found\"}", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    if (req->content_len == 0) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"ok\":false,\"msg\":\"Empty request\"}", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    if (req->content_len > update_partition->size) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"ok\":false,\"msg\":\"Firmware too large for partition\"}", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    ESP_LOGI(TAG, "OTA upload: %d bytes -> partition '%s' at 0x%lx",
             req->content_len, update_partition->label, (unsigned long)update_partition->address);

    esp_ota_handle_t ota_handle;
    esp_err_t err = esp_ota_begin(update_partition, OTA_WITH_SEQUENTIAL_WRITES, &ota_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_begin failed: %s", esp_err_to_name(err));
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"ok\":false,\"msg\":\"OTA begin failed\"}", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    char *buf = malloc(4096);
    if (buf == NULL) {
        esp_ota_abort(ota_handle);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
        return ESP_FAIL;
    }

    int remaining = req->content_len;
    bool header_checked = false;

    while (remaining > 0) {
        int recv_len = httpd_req_recv(req, buf, MIN(remaining, 4096));
        if (recv_len <= 0) {
            free(buf);
            esp_ota_abort(ota_handle);
            if (recv_len == HTTPD_SOCK_ERR_TIMEOUT) {
                httpd_resp_send_408(req);
            }
            return ESP_FAIL;
        }

        /* Validate firmware header on first chunk */
        if (!header_checked) {
            if (recv_len < (int)sizeof(esp_image_header_t)) {
                free(buf);
                esp_ota_abort(ota_handle);
                httpd_resp_set_type(req, "application/json");
                httpd_resp_send(req, "{\"ok\":false,\"msg\":\"File too small to be firmware\"}", HTTPD_RESP_USE_STRLEN);
                return ESP_OK;
            }
            esp_image_header_t *hdr = (esp_image_header_t *)buf;
            if (hdr->magic != ESP_IMAGE_HEADER_MAGIC) {
                free(buf);
                esp_ota_abort(ota_handle);
                httpd_resp_set_type(req, "application/json");
                httpd_resp_send(req, "{\"ok\":false,\"msg\":\"Invalid firmware file (bad magic)\"}", HTTPD_RESP_USE_STRLEN);
                return ESP_OK;
            }
            if (hdr->chip_id != CONFIG_IDF_FIRMWARE_CHIP_ID) {
                char msg[128];
                snprintf(msg, sizeof(msg),
                    "{\"ok\":false,\"msg\":\"Wrong chip type (firmware: 0x%04X, this device: 0x%04X)\"}",
                    hdr->chip_id, CONFIG_IDF_FIRMWARE_CHIP_ID);
                free(buf);
                esp_ota_abort(ota_handle);
                httpd_resp_set_type(req, "application/json");
                httpd_resp_send(req, msg, HTTPD_RESP_USE_STRLEN);
                return ESP_OK;
            }
            header_checked = true;
        }

        err = esp_ota_write(ota_handle, buf, recv_len);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "esp_ota_write failed: %s", esp_err_to_name(err));
            free(buf);
            esp_ota_abort(ota_handle);
            httpd_resp_set_type(req, "application/json");
            httpd_resp_send(req, "{\"ok\":false,\"msg\":\"OTA write failed\"}", HTTPD_RESP_USE_STRLEN);
            return ESP_OK;
        }

        remaining -= recv_len;
    }

    free(buf);

    err = esp_ota_end(ota_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_end failed: %s", esp_err_to_name(err));
        char msg[128];
        snprintf(msg, sizeof(msg),
            "{\"ok\":false,\"msg\":\"Firmware validation failed: %s\"}",
            esp_err_to_name(err));
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, msg, HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    err = esp_ota_set_boot_partition(update_partition);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed: %s", esp_err_to_name(err));
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"ok\":false,\"msg\":\"Failed to set boot partition\"}", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    ESP_LOGI(TAG, "OTA update successful, rebooting in 3 seconds...");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, "{\"ok\":true,\"msg\":\"Firmware updated! Rebooting...\"}", HTTPD_RESP_USE_STRLEN);

    esp_timer_start_once(restart_timer, 3000000);
    return ESP_OK;
}

static httpd_uri_t ota_uploadp = {
    .uri       = "/api/ota-upload",
    .method    = HTTP_POST,
    .handler   = ota_upload_handler,
};

esp_err_t http_404_error_handler(httpd_req_t *req, httpd_err_code_t err)
{
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Page not found");
    return ESP_FAIL;
}

char* html_escape(const char* src) {
    //HTML escape for both attribute and element-content contexts.
    //Encodes < > & " ' \ # ; as numeric entities (&#NNN;), so attacker-controlled
    //strings (e.g. scanned SSIDs) cannot inject markup or break out of attributes.
    int len = strlen(src);
    //Every char in the string + a null, plus worst-case 5-char entity per special char
    int esc_len = len + 1;

    for (int i = 0; i < len; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '\\' || c == '\'' || c == '\"' || c == '&' || c == '#' || c == ';' || c == '<' || c == '>') {
            //Entity "&#NNN;" is at most 6 chars, source char is 1 -> +5 worst case
            esc_len += 5;
        }
    }

    char* res = malloc(sizeof(char) * esc_len);
    if (res == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for HTML escaping");
        return NULL;
    }

    int j = 0;
    for (int i = 0; i < len; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '\\' || c == '\'' || c == '\"' || c == '&' || c == '#' || c == ';' || c == '<' || c == '>') {
            char entity[8];
            int elen = snprintf(entity, sizeof(entity), "&#%d;", c);
            memcpy(res + j, entity, elen);
            j += elen;
        } else {
            res[j++] = src[i];
        }
    }
    res[j] = '\0';

    return res;
}

static esp_err_t favicon_get_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "image/png");
    httpd_resp_send(req, (const char*)favicon_png, favicon_png_len);
    return ESP_OK;
}

static const httpd_uri_t favicon_uri = {
    .uri       = "/favicon.png",
    .method    = HTTP_GET,
    .handler   = favicon_get_handler,
    .user_ctx  = NULL
};

/* Index page GET handler - Bridge Status with navigation (no password ops) */
static esp_err_t index_get_handler(httpd_req_t *req)
{
    char param[16];
    char login_message[256] = "";
    bool authenticated;
    bool password_protection_enabled = is_web_password_set();

    /* Parse query string for non-sensitive actions only: logout, auth_required */
    {
        size_t buf_len = httpd_req_get_url_query_len(req) + 1;
        if (buf_len > 1) {
            char* buf = malloc(buf_len);
            if (buf && httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {
                if (httpd_query_key_value(buf, "logout", param, sizeof(param)) == ESP_OK) {
                    clear_session();
                    strcpy(login_message, "Logged out successfully.");
                } else if (httpd_query_key_value(buf, "auth_required", param, sizeof(param)) == ESP_OK) {
                    strcpy(login_message, "Please log in to access that page.");
                }
            }
            free(buf);
        }
    }

    authenticated = is_authenticated(req);
    return stream_index_html(req, authenticated, password_protection_enabled, login_message);
}

/* Index page POST handler - Login and password change (secrets in body, not URL) */
static esp_err_t index_post_handler(httpd_req_t *req)
{
    char login_message[256] = "";
    bool authenticated;
    bool password_protection_enabled = is_web_password_set();

    /* Read POST body */
    size_t content_len = req->content_len;
    if (content_len == 0 || content_len >= 512) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid request");
        return ESP_FAIL;
    }

    char body[512];
    int rcv = httpd_req_recv(req, body, sizeof(body));
    if (rcv <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Failed to read body");
        return ESP_FAIL;
    }
    body[rcv] = '\0';

    char param[256];
    char param2[256];

    /* Handle login */
    if (httpd_query_key_value(body, "login_password", param, sizeof(param)) == ESP_OK) {
        preprocess_string(param);
        if (password_protection_enabled && verify_web_password(param)) {
            create_session(req);
            { char _ip[16]; ESP_LOGI(TAG, "Web UI login successful from %s", get_client_ip(req, _ip, sizeof(_ip))); }
            /* Redirect to reload page with session cookie */
            httpd_resp_set_status(req, "303 See Other");
            httpd_resp_set_hdr(req, "Location", "/");
            httpd_resp_send(req, NULL, 0);
            return ESP_OK;
        } else {
            char _ip[16];
            ESP_LOGW(TAG, "Web UI login failed: incorrect password from %s", get_client_ip(req, _ip, sizeof(_ip)));
            strcpy(login_message, "ERROR: Incorrect password.");
        }

    /* Handle password change */
    } else if (httpd_query_key_value(body, "new_password", param, sizeof(param)) == ESP_OK &&
               httpd_query_key_value(body, "confirm_password", param2, sizeof(param2)) == ESP_OK) {
        preprocess_string(param);
        preprocess_string(param2);

        authenticated = is_authenticated(req);
        if (authenticated || !password_protection_enabled) {
            if (strcmp(param, param2) == 0) {
                esp_err_t err = set_web_password_hashed(param);
                if (err == ESP_OK) {
                    clear_session();
                    /* Redirect to reload page */
                    httpd_resp_set_status(req, "303 See Other");
                    httpd_resp_set_hdr(req, "Location", "/");
                    httpd_resp_send(req, NULL, 0);
                    return ESP_OK;
                } else {
                    strcpy(login_message, "ERROR: Failed to save password.");
                }
            } else {
                strcpy(login_message, "ERROR: Passwords do not match.");
            }
        } else {
            char _ip[16];
            ESP_LOGW(TAG, "Unauthorized attempt to change web password from %s", get_client_ip(req, _ip, sizeof(_ip)));
            strcpy(login_message, "ERROR: Not authorized to change password.");
        }
    }

    authenticated = is_authenticated(req);
    return stream_index_html(req, authenticated, password_protection_enabled, login_message);
}

static httpd_uri_t indexp = {
    .uri       = "/",
    .method    = HTTP_GET,
    .handler   = index_get_handler,
};

static httpd_uri_t index_post = {
    .uri       = "/",
    .method    = HTTP_POST,
    .handler   = index_post_handler,
};

/* Bridge Config page GET handler */
static esp_err_t config_get_handler(httpd_req_t *req)
{
    /* Check authentication if password protection is enabled */
    bool password_protection_enabled = is_web_password_set();

    if (password_protection_enabled && !is_authenticated(req)) {
        { char _ip[16]; ESP_LOGW(TAG, "Unauthenticated access to /config from %s", get_client_ip(req, _ip, sizeof(_ip))); }
        /* Redirect to index page with auth_required flag */
        httpd_resp_set_status(req, "303 See Other");
        httpd_resp_set_hdr(req, "Location", "/?auth_required=1");
        httpd_resp_send(req, NULL, 0);
        return ESP_OK;
    }

    char*  buf;
    size_t buf_len;

    /* Read URL query string length and allocate memory for length + 1 */
    buf_len = httpd_req_get_url_query_len(req) + 1;
    if (buf_len > 1) {
        buf = malloc(buf_len);
        if (buf == NULL) {
            ESP_LOGE(TAG, "Failed to allocate memory for query string");
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
            return ESP_ERR_NO_MEM;
        }
        if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found URL query => %s", buf);
            char param1[64];
            char param2[64];
            char param3[64];
            char param5[64];
            char reset_param[16];

            if (httpd_query_key_value(buf, "reset", reset_param, sizeof(reset_param)) == ESP_OK) {
                esp_timer_start_once(restart_timer, 500000);
            }

            /* Handle disable interface button */
            if (strstr(buf, "disable_interface=") != NULL) {
                ESP_LOGI(TAG, "Disabling web interface");
                if (set_config_param_str("web_disabled", "1") == ESP_OK) {
                    ESP_LOGI(TAG, "Web interface disabled. Use 'web_ui enable' command via serial to re-enable.");
                }
                esp_timer_start_once(restart_timer, 500000);
            }

            /* Handle AP settings */
            if (httpd_query_key_value(buf, "ap_ssid", param1, sizeof(param1)) == ESP_OK) {
                ESP_LOGI(TAG, "Found URL query parameter => ap_ssid=%s", param1);
                preprocess_string(param1);
                if (httpd_query_key_value(buf, "ap_password", param2, sizeof(param2)) == ESP_OK) {
                    preprocess_string(param2);

                    // "Open network" checkbox overrides password to empty
                    {
                        char open_val[4] = "";
                        if (httpd_query_key_value(buf, "ap_open", open_val, sizeof(open_val)) == ESP_OK) {
                            param2[0] = '\0';
                        } else if (strlen(param2) == 0) {
                            // Keep existing password if field was left empty
                            strlcpy(param2, ap_passwd, sizeof(param2));
                        }
                    }

                    // Set SSID and password
                    int argc = 3;
                    char* argv[3];
                    argv[0] = "set_ap";
                    argv[1] = param1;
                    argv[2] = param2;
                    set_ap(argc, argv);

                    // Handle AP hidden SSID setting
                    {
                        int hidden_val = 0;
                        if (httpd_query_key_value(buf, "ap_hidden", param5, sizeof(param5)) == ESP_OK) {
                            hidden_val = 1;
                        }
                        set_config_param_int("ap_hidden", hidden_val);
                        ap_ssid_hidden = (uint8_t)hidden_val;
                    }

                    // Handle AP auth mode setting
                    if (httpd_query_key_value(buf, "ap_auth", param5, sizeof(param5)) == ESP_OK) {
                        int auth_val = atoi(param5);
                        if (auth_val >= 0 && auth_val <= 2) {
                            set_config_param_int("ap_authmode", auth_val);
                            ap_authmode = (uint8_t)auth_val;
                        }
                    }

                    // Handle AP channel setting
                    if (httpd_query_key_value(buf, "ap_channel", param5, sizeof(param5)) == ESP_OK) {
                        int channel_val = atoi(param5);
                        wifi_country_t _ci2;
                        int max_ch = 13;
                        if (esp_wifi_get_country(&_ci2) == ESP_OK) {
                            max_ch = _ci2.schan + _ci2.nchan - 1;
                        }
                        if (channel_val >= 0 && channel_val <= max_ch) {
                            set_config_param_int("ap_channel", channel_val);
                            ap_channel = (uint8_t)channel_val;
                        }
                    }

                    // Handle WiFi country code setting
                    if (httpd_query_key_value(buf, "wifi_cc", param5, sizeof(param5)) == ESP_OK) {
                        if (strlen(param5) == 2) {
                            char upper[3];
                            upper[0] = toupper((unsigned char)param5[0]);
                            upper[1] = toupper((unsigned char)param5[1]);
                            upper[2] = '\0';
                            set_config_param_str("wifi_cc", upper);
                            wifi_country_code[0] = upper[0];
                            wifi_country_code[1] = upper[1];
                            wifi_country_code[2] = '\0';
                            esp_wifi_set_country_code(wifi_country_code, true);
                        }
                    }

                    // Handle AP enabled checkbox (unchecked = absent = disabled)
                    {
                        char ap_en_val[4] = "";
                        int ap_enabled = (httpd_query_key_value(buf, "ap_enable", ap_en_val, sizeof(ap_en_val)) == ESP_OK) ? 1 : 0;
                        ap_disabled = !ap_enabled;
                        set_config_param_int("ap_disabled", ap_disabled ? 1 : 0);
                    }

                    esp_timer_start_once(restart_timer, 500000);
                }
            }

            /* Handle management IP (static IP) settings */
            if (httpd_query_key_value(buf, "staticip", param1, sizeof(param1)) == ESP_OK) {
                ESP_LOGI(TAG, "Found URL query parameter => staticip=%s", param1);
                preprocess_string(param1);
                if (httpd_query_key_value(buf, "subnetmask", param2, sizeof(param2)) == ESP_OK) {
                    preprocess_string(param2);
                    if (httpd_query_key_value(buf, "gateway", param3, sizeof(param3)) == ESP_OK) {
                        preprocess_string(param3);
                        int argc = 4;
                        char* argv[4];
                        argv[0] = "set_mgmt_ip";
                        argv[1] = param1;
                        argv[2] = param2;
                        argv[3] = param3;
                        set_mgmt_ip(argc, argv);
                        esp_timer_start_once(restart_timer, 500000);
                    }
                }
            }

            /* Handle hostname setting */
            if (httpd_query_key_value(buf, "hostname", param1, sizeof(param1)) == ESP_OK) {
                preprocess_string(param1);
                if (strlen(param1) > 0) {
                    set_config_param_str("hostname", param1);
                    free(hostname);
                    hostname = strdup(param1);
                    ESP_LOGI(TAG, "Hostname set to: %s", param1);
                }
                esp_timer_start_once(restart_timer, 500000);
            }

            /* Handle PCAP settings */
            if (httpd_query_key_value(buf, "pcap_save", param1, sizeof(param1)) == ESP_OK) {
                if (httpd_query_key_value(buf, "pcap_enabled", param1, sizeof(param1)) == ESP_OK) {
                    int enabled = atoi(param1);
                    pcap_set_mode(enabled ? PCAP_MODE_PROMISCUOUS : PCAP_MODE_OFF);
                }
                if (httpd_query_key_value(buf, "pcap_snaplen", param1, sizeof(param1)) == ESP_OK) {
                    int snaplen = atoi(param1);
                    if (snaplen >= 64 && snaplen <= 1600) pcap_set_snaplen((uint16_t)snaplen);
                }
                ESP_LOGI(TAG, "PCAP settings saved via web");
                free(buf);
                httpd_resp_set_status(req, "303 See Other");
                httpd_resp_set_hdr(req, "Location", "/config");
                httpd_resp_send(req, NULL, 0);
                return ESP_OK;
            }

            /* Handle Remote Console settings (single form) */
            if (httpd_query_key_value(buf, "rc_save", param1, sizeof(param1)) == ESP_OK) {
                /* Enable/disable */
                if (httpd_query_key_value(buf, "rc_enabled", param1, sizeof(param1)) == ESP_OK) {
                    preprocess_string(param1);
                    if (strcmp(param1, "1") == 0) {
                        remote_console_enable();
                    } else {
                        remote_console_disable();
                    }
                }
                /* Port */
                if (httpd_query_key_value(buf, "rc_port", param1, sizeof(param1)) == ESP_OK) {
                    preprocess_string(param1);
                    int port = atoi(param1);
                    if (port >= 1 && port <= 65535) {
                        remote_console_set_port((uint16_t)port);
                    }
                }
                /* Bind interfaces (checkboxes: absent = unchecked) */
                uint8_t bind = 0;
                if (httpd_query_key_value(buf, "rc_bind_ap", param1, sizeof(param1)) == ESP_OK) bind |= RC_BIND_AP;
                if (httpd_query_key_value(buf, "rc_bind_eth", param1, sizeof(param1)) == ESP_OK) bind |= RC_BIND_ETH;
                if (bind == 0) bind = RC_BIND_AP;
                remote_console_set_bind(bind);
                /* Timeout */
                if (httpd_query_key_value(buf, "rc_timeout", param1, sizeof(param1)) == ESP_OK) {
                    preprocess_string(param1);
                    int timeout = atoi(param1);
                    if (timeout >= 0) {
                        remote_console_set_timeout((uint32_t)timeout);
                    }
                }
                ESP_LOGI(TAG, "Remote console settings saved via web");
                free(buf);
                httpd_resp_set_status(req, "303 See Other");
                httpd_resp_set_hdr(req, "Location", "/config");
                httpd_resp_send(req, NULL, 0);
                return ESP_OK;
            }

            /* Handle Remote Console kick */
            if (httpd_query_key_value(buf, "rc_kick", param1, sizeof(param1)) == ESP_OK) {
                remote_console_kick();
                ESP_LOGI(TAG, "Remote console session kicked via web");
                free(buf);
                httpd_resp_set_status(req, "303 See Other");
                httpd_resp_set_hdr(req, "Location", "/config");
                httpd_resp_send(req, NULL, 0);
                return ESP_OK;
            }

            /* Handle DHCP server settings */
            if (httpd_query_key_value(buf, "dhcps_save", param1, sizeof(param1)) == ESP_OK) {
                if (httpd_query_key_value(buf, "dhcps_enabled", param1, sizeof(param1)) == ESP_OK) {
                    int en = atoi(param1);
                    if (en && !(static_ip && strlen(static_ip) > 0)) {
                        en = 0;
                        ESP_LOGW(TAG, "DHCP server requires static IP; ignoring enable request");
                    }
                    set_config_param_int("dhcps_enabled", en);
                    dhcps_enabled = (en != 0);
                }
                if (httpd_query_key_value(buf, "dhcps_start", param1, sizeof(param1)) == ESP_OK) {
                    preprocess_string(param1);
                    set_config_param_str("dhcps_start_ip", param1);
                    free(dhcps_start_ip);
                    dhcps_start_ip = strdup(param1);
                }
                if (httpd_query_key_value(buf, "dhcps_end", param1, sizeof(param1)) == ESP_OK) {
                    preprocess_string(param1);
                    set_config_param_str("dhcps_end_ip", param1);
                    free(dhcps_end_ip);
                    dhcps_end_ip = strdup(param1);
                }
                if (httpd_query_key_value(buf, "dhcps_lease", param1, sizeof(param1)) == ESP_OK) {
                    int lease = atoi(param1);
                    if (lease >= 1 && lease <= 14400) {
                        set_config_param_int("dhcps_lease", lease);
                        dhcps_lease_min = (uint32_t)lease;
                    }
                }
                if (httpd_query_key_value(buf, "dhcps_dns", param1, sizeof(param1)) == ESP_OK) {
                    preprocess_string(param1);
                    set_config_param_str("dhcps_dns", param1);
                    free(dhcps_dns_ip);
                    dhcps_dns_ip = strdup(param1);
                }
                ESP_LOGI(TAG, "DHCP server settings saved via web");
                esp_timer_start_once(restart_timer, 500000);
                free(buf);
                httpd_resp_set_status(req, "303 See Other");
                httpd_resp_set_hdr(req, "Location", "/config");
                httpd_resp_send(req, NULL, 0);
                return ESP_OK;
            }
        }
        free(buf);
    }

    /* Escape into a stack buffer and release the heap copy immediately.
     * Holding an html_escape() allocation across the chunked render below would
     * leak it whenever a SEND_CHUNK bails out on a dead client. */
    char safe_ap_ssid[200];
    html_escape_to(safe_ap_ssid, sizeof(safe_ap_ssid), ap_ssid);

    // Remote Console state
    remote_console_config_t rc_config;
    remote_console_status_t rc_status;
    remote_console_get_config(&rc_config);
    remote_console_get_status(&rc_status);

    const char* rc_enabled_checked = rc_config.enabled ? "checked" : "";
    const char* rc_disabled_checked = rc_config.enabled ? "" : "checked";

    const char* rc_status_color;
    const char* rc_status_text;
    const char* rc_kick_section = "";
    char rc_kick_buf[200] = "";

    switch (rc_status.state) {
        case RC_STATE_DISABLED:
            rc_status_color = "#888";
            rc_status_text = "Disabled";
            break;
        case RC_STATE_LISTENING:
            rc_status_color = "#4caf50";
            rc_status_text = "Listening";
            break;
        case RC_STATE_AUTH_WAIT:
            rc_status_color = "#ffc107";
            rc_status_text = "Authenticating...";
            break;
        case RC_STATE_ACTIVE:
            rc_status_color = "#ffb300";
            rc_status_text = rc_status.client_ip;
            snprintf(rc_kick_buf, sizeof(rc_kick_buf),
                " <a href='/config?rc_kick=1' style='margin-left: 0.5rem; padding: 0.2rem 0.6rem; background: #f44336; color: #fff; border-radius: 4px; text-decoration: none; font-size: 0.8rem;'>Kick</a>");
            rc_kick_section = rc_kick_buf;
            break;
        default:
            rc_status_color = "#888";
            rc_status_text = "Unknown";
            break;
    }

    const char* rc_ap_chk = (rc_config.bind & RC_BIND_AP) ? "checked" : "";
    const char* rc_eth_chk = (rc_config.bind & RC_BIND_ETH) ? "checked" : "";

    const char* ap_en_checked = !ap_disabled ? "checked" : "";
    const char* ap_open_checked = (strlen(ap_passwd) == 0) ? "checked" : "";
    const char* ap_hidden_checked = ap_ssid_hidden ? "checked" : "";

    /* Reusable buffer for building sections */
    char section[2048];

    /* --- Begin chunked response --- */

    /* Chunk 1: Page header (styles) */
    SEND_CHUNK(req, CONFIG_CHUNK_HEAD, HTTPD_RESP_USE_STRLEN);

    /* Chunk 2: Logout button (if authenticated) */
    if (session_active && password_protection_enabled) {
        SEND_CHUNK(req,
            "<a href='/?logout=1' style='padding: 0.4rem 1rem; background: rgba(255,82,82,0.15); color: #ff5252; border: 1px solid #ff5252; border-radius: 6px; text-decoration: none; font-size: 0.85rem; font-weight: 500;'>Logout</a>",
            HTTPD_RESP_USE_STRLEN);
    }

    /* Chunk 3: JavaScript */
    SEND_CHUNK(req, CONFIG_CHUNK_SCRIPT, HTTPD_RESP_USE_STRLEN);

    /* Chunk 4: AP Settings */
    wifi_country_t _ci;
    int max_channel = 13;
    if (esp_wifi_get_country(&_ci) == ESP_OK) {
        max_channel = _ci.schan + _ci.nchan - 1;
    }
    const char* auth_sel0 = (ap_authmode == 0) ? "selected" : "";
    const char* auth_sel1 = (ap_authmode == 1) ? "selected" : "";
    const char* auth_sel2 = (ap_authmode == 2) ? "selected" : "";
    snprintf(section, sizeof(section), CONFIG_CHUNK_AP,
        safe_ap_ssid, max_channel, (int)ap_channel, wifi_country_code,
        auth_sel0, auth_sel1, auth_sel2,
        ap_en_checked, ap_open_checked, ap_hidden_checked);
    SEND_CHUNK(req, section, HTTPD_RESP_USE_STRLEN);

    /* Chunk 5: Management IP Settings */
    snprintf(section, sizeof(section), CONFIG_CHUNK_MGMT_IP,
        static_ip, subnet_mask, gateway_addr);
    SEND_CHUNK(req, section, HTTPD_RESP_USE_STRLEN);

    /* Chunk 5b: DHCP Server Settings */
    {
        const char *dhcps_en_chk  = dhcps_enabled ? "checked" : "";
        const char *dhcps_dis_chk = dhcps_enabled ? "" : "checked";
        snprintf(section, sizeof(section), CONFIG_CHUNK_DHCPS,
            dhcps_en_chk, dhcps_dis_chk,
            (dhcps_start_ip && dhcps_start_ip[0]) ? dhcps_start_ip : "",
            (dhcps_end_ip   && dhcps_end_ip[0])   ? dhcps_end_ip   : "",
            (unsigned long)dhcps_lease_min,
            (dhcps_dns_ip   && dhcps_dns_ip[0])   ? dhcps_dns_ip   : "");
        SEND_CHUNK(req, section, HTTPD_RESP_USE_STRLEN);
    }

    /* Chunk 6: Hostname */
    snprintf(section, sizeof(section), CONFIG_CHUNK_HOSTNAME,
        hostname, hostname);
    SEND_CHUNK(req, section, HTTPD_RESP_USE_STRLEN);

    /* Chunk 7: Remote Console */
    snprintf(section, sizeof(section), CONFIG_CHUNK_RC,
        rc_enabled_checked, rc_disabled_checked,
        rc_status_color, rc_status_text, rc_kick_section,
        rc_config.port,
        rc_ap_chk, rc_eth_chk,
        (unsigned long)rc_config.idle_timeout_sec);
    SEND_CHUNK(req, section, HTTPD_RESP_USE_STRLEN);

    /* Chunk 7b: PCAP Capture */
    {
        pcap_capture_mode_t pcap_mode = pcap_get_mode();
        const char *pcap_on_chk = (pcap_mode != PCAP_MODE_OFF) ? "checked" : "";
        const char *pcap_off_chk = (pcap_mode == PCAP_MODE_OFF) ? "checked" : "";

        /* Get current bridge IP for the hint text */
        char bridge_ip_str[16] = "bridge-ip";
        if (br_netif) {
            esp_netif_ip_info_t ip_info;
            if (esp_netif_get_ip_info(br_netif, &ip_info) == ESP_OK && ip_info.ip.addr != 0) {
                snprintf(bridge_ip_str, sizeof(bridge_ip_str), IPSTR, IP2STR(&ip_info.ip));
            }
        } else if (my_ip != 0) {
            esp_ip4_addr_t addr;
            addr.addr = my_ip;
            snprintf(bridge_ip_str, sizeof(bridge_ip_str), IPSTR, IP2STR(&addr));
        }

        snprintf(section, sizeof(section), CONFIG_CHUNK_PCAP,
            pcap_on_chk, pcap_off_chk, (int)pcap_get_snaplen(),
            bridge_ip_str);
        SEND_CHUNK(req, section, HTTPD_RESP_USE_STRLEN);
    }

    /* Chunk 8: Device management heading */
    SEND_CHUNK(req, CONFIG_CHUNK_TAIL, HTTPD_RESP_USE_STRLEN);

    /* Chunk 8a: Dynamic OTA info (running partition, version) */
    {
        const esp_partition_t *running = esp_ota_get_running_partition();
        const esp_app_desc_t *app_desc = esp_app_get_description();
        snprintf(section, sizeof(section),
            "<table>"
            "<tr><td>Running</td><td>%s</td></tr>"
            "<tr><td>Version</td><td>%s</td></tr>"
            "<tr><td>Built</td><td>%s %s</td></tr>"
            "</table>",
            running ? running->label : "unknown",
            app_desc ? app_desc->version : "unknown",
            app_desc ? app_desc->date : "", app_desc ? app_desc->time : "");
        SEND_CHUNK(req, section, HTTPD_RESP_USE_STRLEN);
    }

    /* Chunk 8b: OTA upload form, reboot, and footer */
    SEND_CHUNK(req, CONFIG_CHUNK_TAIL2, HTTPD_RESP_USE_STRLEN);

    /* End chunked response */
    SEND_CHUNK(req, NULL, 0);

    /* No cleanup needed: safe_ap_ssid lives in a stack buffer (the heap copy
     * was freed before streaming began). */
    return ESP_OK;
}

static httpd_uri_t configp = {
    .uri       = "/config",
    .method    = HTTP_GET,
    .handler   = config_get_handler,
};

/* Called by httpd for every accepted connection. */
static esp_err_t http_open_fn(httpd_handle_t hd, int sockfd)
{
    /* Enable TCP keepalive on every accepted connection.  A client that leaves
     * WiFi without closing leaves the socket in ESTABLISHED forever; without
     * probes lwIP never notices and the socket (and its few KB of buffers) leaks
     * until the table fills.  With keepalive the dead peer is detected and the
     * socket torn down automatically.  ~30 s idle, then 3 probes 5 s apart. */
    int ka = 1, ka_idle = 30, ka_intvl = 5, ka_cnt = 3;
    setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &ka, sizeof(ka));
    setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &ka_idle, sizeof(ka_idle));
    setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &ka_intvl, sizeof(ka_intvl));
    setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, &ka_cnt, sizeof(ka_cnt));
    return ESP_OK;
}

httpd_handle_t start_webserver(uint16_t port)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = port;
    config.stack_size = 16384;
    config.max_uri_handlers = 5;
    config.max_uri_len = 1024;
    config.open_fn = http_open_fn;
    /* Fail a stalled send/recv fast (default 5s) so an abandoned connection
     * frees its socket and buffers quickly instead of pinning them; paired
     * with the SEND_CHUNK bail-out, a dead client costs ~one timeout total. */
    config.send_wait_timeout = 2;
    config.recv_wait_timeout = 2;
    /* A WiFi client that just walks out of range never sends a TCP FIN, so its
     * connections sit in httpd's socket table forever, each pinning a netconn +
     * PCB + pbufs (the few-KB-per-disconnect leak).  After a few rounds the table
     * fills and accept() fails with ENFILE (errno 23).  lru_purge_enable lets
     * httpd close the least-recently-used connection to admit a new one, so the
     * server always recovers; the keepalive probes set in http_open_fn reap the
     * dead sockets proactively before it ever comes to that. */
    config.lru_purge_enable = true;

    esp_timer_create(&restart_timer_args, &restart_timer);

    // Start the httpd server
    ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK) {
        // Set URI handlers
        ESP_LOGI(TAG, "Registering URI handlers");
        httpd_register_uri_handler(server, &indexp);
        httpd_register_uri_handler(server, &index_post);
        httpd_register_uri_handler(server, &configp);
        httpd_register_uri_handler(server, &favicon_uri);
        httpd_register_uri_handler(server, &ota_uploadp);

        return server;
    }

    ESP_LOGI(TAG, "Error starting server!");
    return NULL;
}

static void stop_webserver(httpd_handle_t server)
{
    // Stop the httpd server
    httpd_stop(server);
}
