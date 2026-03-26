idf_component_register(
    SRCS "http_server.c"
    INCLUDE_DIRS "include"
    PRIV_REQUIRES esp_http_server esp_wifi esp_netif esp_event nvs_flash
                  esp_timer cmd_router
                  remote_console pcap_capture
                  app_update esp_app_format
)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-unused-function)
