idf_component_register(SRCS "power_cycle_reset.c" "esp32_nat_router.c"
                            "netif_hooks.c"
                    INCLUDE_DIRS "."
                    PRIV_REQUIRES mbedtls esp_timer pcap_capture esp_wifi esp_netif lwip console nvs_flash driver esp_http_server fatfs cmd_router wpa_supplicant cmd_system remote_console syslog esp_eth http_server app_update mdns_responder eth_w5500)
