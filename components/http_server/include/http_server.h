/* HTTP server public API.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include <esp_http_server.h>

#ifdef __cplusplus
extern "C" {
#endif

httpd_handle_t start_webserver(uint16_t port);

#ifdef __cplusplus
}
#endif
