# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ESP32 Ethernet-WiFi Bridge — Layer 2 bridge firmware for the WT32-ETH01 board. Transparently bridges Ethernet and WiFi AP at the MAC layer. No NAT, no routing, no separate subnets. Devices on both sides share a single broadcast domain.

**Branch:** `wt32-eth01-bridge` (derived from the `esp32_nat_router` project, stripped of NAT/routing/VPN/ACL/DHCP features)

## Build Commands

```bash
. $IDF_PATH/export.sh
idf.py -B build_eth_sta menuconfig   # Configure build options
idf.py -B build_eth_sta build        # Build the project
idf.py -B build_eth_sta flash        # Flash to device
idf.py -B build_eth_sta monitor      # Watch serial output (115200 bps)
./build_firmware.sh                   # Clean build, copies binaries to firmware/
```

## Architecture

### Source Structure
```
main/
├── esp32_nat_router.c   # Entry point: Ethernet/WiFi/bridge init, event handlers, LED status
└── netif_hooks.c        # ETH interface hooks for byte counting, LED flicker, PCAP capture

include/
├── router_globals.h     # Umbrella header (includes all below)
├── router_config.h      # NVS namespace, byte counters, LED state, uptime, netif hooks
├── client_stats.h       # Per-client TX/RX traffic statistics
├── wifi_config.h        # AP config, NVS helpers, set_mgmt_ip, set_ap, ap_set_enabled
└── web_password.h       # Web password hashing API

components/
├── cmd_router/          # CLI commands: set_ap, set_mgmt_ip, show, web_ui, set_router_password,
│                        #   pcap, bytes, remote_console, syslog, set_led_gpio, set_tx_power, etc.
├── cmd_system/          # System commands: heap, restart, factory_reset, tasks
├── http_server/         # Web UI server (pages: /, /config)
├── pcap_capture/        # PCAP packet capture with TCP streaming to Wireshark
├── remote_console/      # Network-accessible CLI via TCP (password protected)
└── syslog/              # Remote syslog forwarding via UDP
```

### Key Global Variables

**`router_config.h`:**
- `br_netif` - Bridge netif (management IP)
- `sta_bytes_sent`, `sta_bytes_received` - ETH interface byte counters
- `led_gpio` - Status LED GPIO (-1 = disabled)
- `led_lowactive` - LED active-low mode flag
- `led_toggle` - Packet-driven LED flicker state

**`wifi_config.h`:**
- `ap_ssid`, `ap_passwd` - WiFi AP credentials
- `static_ip`, `subnet_mask`, `gateway_addr` - Management IP config
- `my_ip` - Current management IP address
- `ap_connect` - Ethernet link status flag
- `connect_count` - Number of connected WiFi clients
- `ap_disabled` - AP enable/disable flag (persisted in NVS)
- `ap_ssid_hidden`, `ap_authmode`, `ap_channel` - AP settings

### Network Interface Hooks (Byte Counting & PCAP)

The firmware hooks into the lwIP ETH netif to count bytes and capture packets.

**How it works** (`netif_hooks.c`):
- Intercepts ETH port input/output via lwIP function pointer hooks
- Counts bytes in `sta_bytes_sent`/`sta_bytes_received`
- Toggles LED on each packet for traffic activity indication
- Feeds packets to PCAP capture when enabled

**Public API** (`router_config.h`):
- `init_byte_counter()` - Install ETH hooks
- `get_sta_bytes_sent()` / `get_sta_bytes_received()` - Read counters
- `reset_sta_byte_counts()` - Reset counters
- `init_ap_netif_hooks()` - Install AP hooks (for PCAP)

### Remote Console Component
The `components/remote_console/` directory provides network-accessible CLI via TCP.

**Features:**
- TCP server on port 2323 (configurable)
- Password authentication (reuses `web_password` from NVS)
- Single concurrent session with idle timeout
- Output capture via linker wrapping (`--wrap=printf`, `--wrap=puts`, etc.)
- Disabled by default for security

**Interface binding:**
- `RC_BIND_AP` (0x01) - Listen on WiFi AP interface
- `RC_BIND_ETH` (0x02) - Listen on Ethernet interface

**NVS keys:**
- `rc_enabled` (u8) - Service enabled flag
- `rc_port` (u16) - TCP port (default 2323)
- `rc_bind` (u8) - Interface binding bitmask
- `rc_timeout` (u32) - Idle timeout in seconds

### Configuration Storage
All settings persist in NVS (Non-Volatile Storage) under namespace `esp32_nat`:
- AP credentials, management IP settings, AP options (hidden, auth, channel)
- Web interface password (`web_password` key) and disable state
- LED GPIO, TX power, timezone, AP disabled flag
- Remote console and syslog settings
- Survives firmware updates (use `esptool.py erase_flash` or `factory_reset` to clear)

### Critical SDK Configuration
These settings in `sdkconfig.defaults` are required:
```
CONFIG_LWIP_L2_TO_L3_COPY=y       # LWIP layer support
CONFIG_ESP_NETIF_BRIDGE_EN=y       # Bridge netif support
CONFIG_LWIP_NUM_NETIF_CLIENT_DATA=1
CONFIG_ETH_USE_ESP32_EMAC=y        # WT32-ETH01 Ethernet (LAN8720)
```

Note: No `CONFIG_LWIP_IP_FORWARD` or `CONFIG_LWIP_IPV4_NAPT` — this is a Layer 2 bridge, not a router.

## Serial Console Commands

Connect at 115200 bps. Key commands:
```
set_ap <ssid> <passwd>            # Configure WiFi AP
set_mgmt_ip <ip> <subnet> <gw>   # Set management IP
set_mgmt_ip dhcp                  # Revert to DHCP (requires restart)
set_ap_dns <dns>                  # Set DNS for AP clients
set_ap_mac <AA> <BB> <CC> <DD> <EE> <FF>  # Override AP MAC
set_ap_hidden <on|off>            # Hide/show AP SSID
set_ap_auth <wpa2|wpa3|wpa2wpa3>  # Set AP auth mode
set_ap_channel <0-13>             # Set AP channel (0=auto)
ap <enable|disable>               # Enable/disable AP at runtime
set_router_password <password>    # Set web/console password (empty to disable)
web_ui enable                     # Enable web interface (after reboot)
web_ui disable                    # Disable web interface (after reboot)
web_ui port <port>                # Set web server port (after reboot)
set_hostname <name>               # Set DHCP hostname
set_tx_power <dBm>                # Set WiFi TX power (2-20, 0=max)
set_led_gpio <gpio|none>          # Set status LED GPIO
set_led_lowactive <true|false>    # Set LED active-low mode
set_tz <POSIX TZ string>          # Set timezone
pcap start                        # Start promiscuous packet capture
pcap stop                         # Stop capture
pcap snaplen [<bytes>]            # Get/set max capture bytes (64-1600)
pcap status                       # Show capture statistics
bytes                             # Show ETH byte counters
bytes reset                       # Reset byte counters
show status                       # Show bridge status (connection, clients, memory)
show config                       # Show bridge configuration (AP/ETH settings)
show ota                          # Show OTA partition info
scan                              # Scan for WiFi networks
remote_console status             # Show remote console status
remote_console enable             # Enable remote console
remote_console disable            # Disable remote console
remote_console bind <ap,eth>      # Set interface binding
syslog enable <server> [<port>]   # Enable syslog forwarding
syslog disable                    # Disable syslog forwarding
factory_reset                     # Erase all settings and restart
# W5500 build only (CONFIG_ETH_UPLINK_W5500):
set_spi_clock <MHz>              # Set W5500 SPI clock speed (saved to NVS, applied after restart)
w5500 status                     # Show W5500 register diagnostics and SPI error counters
w5500 reset                      # Soft-reset W5500 socket (no lwIP teardown)
```

## Web Interface

Access at `http://<management-ip>` from any device on the bridged network.

**Pages:**
- `/` - Bridge status (ETH link, management IP, WiFi clients, byte counters, uptime), login form
- `/config` - Bridge configuration (AP settings, management IP, hostname, remote console, PCAP, OTA) - protected

**Password Protection:**
- Optional password protects `/config` page
- Login form shown on index page when password is set
- Cookie-based sessions with 30-minute timeout
- Set via web interface or `set_router_password` command
- Empty password disables protection

## LED Status
- Solid on: Ethernet link up (idle)
- Solid off: Ethernet link down
- Flickering: network traffic activity
- GPIO configurable via `set_led_gpio` command (default: none)
