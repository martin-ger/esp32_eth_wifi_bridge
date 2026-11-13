// NETWORK DEFAULTS
// See https://github.com/martin-ger/esp32_eth_wifi_bridge#network
//
#define DEFAULT_SSID            "esp32-bridge"
#define DEFAULT_AP_PASSWORD     ""
#define DEFAULT_STATIC_IP       ""
#define DEFAULT_SUBNETMASK      ""         //Cannot be blank if DEFAULT_STATIC_IP is set
#define DEFAULT_GATEWAY         ""         //Cannot be blank if DEFAULT_STATIC_IP is set
#define DEFAULT_COUNTRY         "01"      

#define DEFAULT_DHCPS_ENABLED   0          //0 = disabled, 1 = enabled
#define DEFAULT_DHCPS_START_IP  ""    
#define DEFAULT_DHCPS_END_IP    ""  
#define DEFAULT_DHCPS_LEASE_MIN 120
#define DEFAULT_DHCPS_DNS_IP    ""   

#define DEFAULT_TX_POWER_DBM    0

// WEB SERVER DEFAULTS
// See https://github.com/martin-ger/esp32_eth_wifi_bridge#web-interface-1
//
#define DEFAULT_WEB_DISABLED    "0"
#define DEFAULT_WEB_PORT        80

