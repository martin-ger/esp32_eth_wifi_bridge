# ESP32 Ethernet-WiFi Bridge

Firmware that creates a plain transparent Layer 2 bridge between an Ethernet port and a WiFi access point. Devices on both sides appear on the same network — no NAT, no routing, no separate subnet.

**Derived from** [esp32_nat_router](https://github.com/martin-ger/esp32_nat_router). The original project is a WiFi NAT router with lot of additional features. This variant operates as a **pure L2 bridge**: the Ethernet port and WiFi AP share a single broadcast domain, and all frames are forwarded transparently at the MAC layer.

<img src="https://github.com/martin-ger/esp32_eth_wifi_bridge/blob/master/topology.png">

All WiFi clients receive their IP addresses from the upstream network's DHCP server and are directly reachable from the wired side. The bridge itself can optionally obtain a management IP (static or DHCP) for web access and remote administration.

All settings are managed through a browser-based web interface or via the serial console at 115200 bps.

---

## Supported Hardware

Two compile-time variants are provided. Both expose the same feature set and CLI.

### WT32-ETH01 (default)

ESP32 module with an integrated LAN8720 Ethernet PHY.

| Parameter | Value |
|-----------|-------|
| SoC | ESP32 (dual-core 240 MHz) |
| Flash | 4 MB |
| Ethernet PHY | LAN8720 (internal EMAC) |
| Ethernet MDC | GPIO 23 |
| Ethernet MDIO | GPIO 18 |
| PHY address | 1 |
| PHY power | GPIO 16 |
| Status LED | GPIO 2 (configurable) |
| Serial | 115200 bps (UART0) |

### ESP32-C3 SuperMini + W5500

ESP32-C3 module with a W5500 SPI Ethernet chip. Default wiring (all pins configurable via `menuconfig`):

| W5500 pin | GPIO |
|-----------|------|
| MISO | 5 |
| MOSI | 6 |
| SCLK | 4 |
| CS | 7 |
| INT | 3 |
| RST | 2 |

| Parameter | Value |
|-----------|-------|
| SoC | ESP32-C3 (single-core 160 MHz) |
| Flash | 4 MB |
| Ethernet | W5500 via SPI (~26.67 MHz) |
| Serial | 115200 bps (USB Serial/JTAG, `/dev/ttyACM0`) |

---

## Use Cases

- **Wireless extension for a wired network** — add WiFi access to a switch or router that has no wireless capability
- **Lab bridge** — give WiFi clients direct L2 access to devices on a wired bench segment
- **Transparent monitoring tap** — capture and inspect all bridged traffic in Wireshark without any client changes
- **Headless IoT bridge** — connect WiFi sensors and devices directly to an existing wired LAN

---

## Features

- Transparent Layer 2 bridging between Ethernet and WiFi AP
- WiFi AP with configurable SSID, password, channel, and authentication (WPA2/WPA3)
- Optional management IP (static or DHCP) for web and remote access
- Packet capture to Wireshark over TCP (PCAP streaming, promiscuous mode)
- Remote console — password-protected TCP CLI on a configurable port
- Syslog forwarding — ship ESP log output to a remote syslog server via UDP
- OTA firmware update through the web interface
- Byte counters for the Ethernet interface
- Configurable WiFi TX power, status LED, and timezone
- AP interface can be enabled/disabled at runtime
- All settings persisted in NVS flash; survive firmware updates

---

## LED Behavior

- Solid on: Ethernet link up (idle)
- Solid off: Ethernet link down
- Flickering: network traffic activity

---

## Web Interface

Access the web interface from any device connected to the WiFi AP or the Ethernet network. The default address is `http://<management-ip>` or if the client supports mDNS `http://esp32-bridge.local` (if you use the default hostname for the device).

### Pages

**/ — Status**

Shows current connection state: Ethernet link status, management IP, connected WiFi clients, byte counters, and uptime. When a web password is set, the login form appears here.

<img src="https://github.com/martin-ger/esp32_eth_wifi_bridge/blob/master/UI_index.png">

**Configuration**

Grouped into sections. Changes trigger a reboot to apply.

- *AP Settings* — SSID, password, channel, authentication mode (WPA2/WPA3), hidden SSID, enable/disable
- *Management IP* — static IP, subnet mask, gateway; leave empty to use DHCP
- *DNS Server* — override DNS for AP clients
- *Remote Console* — enable/disable, port, interface binding (AP/ETH), idle timeout
- *PCAP Packet Capture* — on/off toggle, snaplen
- *Device Management* — OTA firmware upload, factory reset

<img src="https://github.com/martin-ger/esp32_eth_wifi_bridge/blob/master/UI_config.png">

### Password Protection

Set a password with `set_router_password <password>` or through the web interface. When set, the Configuration page requires authentication. Sessions last 30 minutes. Clear the password by setting an empty string.

---

## Packet Capture

Traffic on the bridge can be streamed live to Wireshark over a TCP connection on port 19000. No client software other than netcat and Wireshark is required.

### Usage

```
pcap start
pcap stop
pcap snaplen [<bytes>]
pcap status
```

Connect from a workstation on the network:

```
nc <bridge-ip> 19000 | wireshark -k -i -
```

The connection command is also shown in the PCAP section of the Configuration page. Snaplen limits the captured bytes per packet (64-1600, default 1600).

---

## Remote Console

A TCP server provides a password-authenticated CLI session accessible over the network. It reuses the web interface password. Output from CLI commands is captured and forwarded to the remote session.

```
remote_console enable
remote_console disable
remote_console port <port>
remote_console bind <ap,eth>
remote_console timeout <seconds>
remote_console kick
remote_console status
```

Default port is 2323. Connect with any TCP client:

```
nc <bridge-ip> 2323
```

The service is disabled by default. A web password must be set before enabling it. Idle sessions are disconnected after the configured timeout (default 300 seconds; 0 disables the timeout). Only one session is active at a time.

The `bind` option controls which network interfaces the server listens on (AP = WiFi access point, ETH = Ethernet uplink).

---

## Syslog

ESP log output can be forwarded to a remote syslog server over UDP.

```
syslog enable <server> [<port>]
syslog disable
syslog status
```

The default port is 514. Configuration is persisted in NVS.

---

## CLI Reference

Connect via serial at 115200 bps, or via the remote console.

### Network

| Command | Description |
|---------|-------------|
| `show config` | AP and Ethernet configuration |
| `set_ap <ssid> <password>` | Set WiFi AP credentials |
| `set_ap_dns <dns>` | Set DNS server for AP clients |
| `set_ap_mac <mac>` | Override AP MAC address |
| `set_ap_hidden <on\|off>` | Hide or show AP SSID |
| `set_ap_auth <wpa2\|wpa3\|wpa2wpa3>` | Set AP authentication mode |
| `set_ap_channel <0-13>` | Set AP WiFi channel (0=auto) |
| `ap <enable\|disable>` | Enable or disable AP interface |
| `set_mgmt_ip <ip> <mask> <gw>` | Set static management IP |
| `set_mgmt_ip dhcp` | Revert management IP to DHCP |
| `set_hostname <name>` | Set DHCP hostname |
| `set_tx_power <dBm>` | Set WiFi transmit power (2-20, 0=max) |
| `set_tz <TZ string>` | Set POSIX timezone |
| `bytes` | Show Ethernet byte counters |
| `bytes reset` | Reset byte counters |
| `ping <host> [-c <n>] [-i <ms>] [-W <ms>] [-s <bytes>]` | Send ICMP echo requests |

### Packet Capture

| Command | Description |
|---------|-------------|
| `pcap start` | Start promiscuous capture |
| `pcap stop` | Stop capture |
| `pcap snaplen [<bytes>]` | Get or set max bytes per packet |
| `pcap status` | Show capture statistics |

### Remote Console and Syslog

| Command | Description |
|---------|-------------|
| `remote_console enable` | Enable remote console |
| `remote_console disable` | Disable remote console |
| `remote_console port <port>` | Set TCP port |
| `remote_console bind <ap,eth>` | Set interface binding |
| `remote_console timeout <seconds>` | Set idle timeout |
| `remote_console kick` | Disconnect active session |
| `remote_console status` | Show status |
| `log_level [<level>] [-t <tag>]` | Get/set log level (none/error/warn/info/debug/verbose) |
| `syslog enable <server> [<port>]` | Enable syslog forwarding |
| `syslog disable` | Disable syslog forwarding |
| `syslog status` | Show syslog configuration |

### Web Interface

| Command | Description |
|---------|-------------|
| `web_ui enable` | Enable web server (after reboot) |
| `web_ui disable` | Disable web server (after reboot) |
| `web_ui port <port>` | Set web server port (default 80) |
| `set_router_password <password>` | Set web/console password |

### Status and System

| Command | Description |
|---------|-------------|
| `show status` | Connection state, clients, heap |
| `show ota` | OTA partition info |
| `set_led_gpio <gpio\|none>` | Set status LED GPIO |
| `set_led_lowactive <true\|false>` | Set LED to active-low mode |
| `version` | Show chip and SDK version |
| `restart` | Software reset of the chip |
| `heap` | Show current and minimum free heap |
| `tasks` | List running FreeRTOS tasks |
| `deep_sleep [--time <ms>] [--io <gpio>] [--io_level <0\|1>]` | Enter deep sleep |
| `light_sleep [--time <ms>] [--io <gpio>]...` | Enter light sleep |
| `factory_reset` | Erase all NVS settings and reboot |

### W5500 Build Only (ESP32-C3 + W5500)

| Command | Description |
|---------|-------------|
| `set_spi_clock <MHz>` | Set W5500 SPI clock speed (1–80 MHz). Saved to NVS, applied after restart |
| `w5500 status` | Show W5500 register snapshot and SPI error counters |
| `w5500 reset` | Soft-reset W5500 socket without disturbing lwIP or bridge state |

`show status` also prints the active SPI clock and any SPI error counts when running the W5500 build.

---

## Building

Requires ESP-IDF v5.x. Source the ESP-IDF environment first:

```bash
. $IDF_PATH/export.sh
```

### WT32-ETH01 (default)

```bash
./build_firmware.sh
```

Performs a clean build and copies binaries to `firmware/`:

```
firmware/
├── bootloader.bin
├── partition-table.bin
├── ota_data_initial.bin
└── esp32_eth_wifi_bridge.bin
```

To reconfigure before building:

```bash
idf.py -B build_eth_sta menuconfig
```

### ESP32-C3 + W5500

```bash
./build_firmware_w5500_c3.sh
```

Performs a clean build targeting `esp32c3` and copies binaries to `firmware_w5500_c3/`:

```
firmware_w5500_c3/
├── bootloader.bin
├── partition-table.bin
├── ota_data_initial.bin
└── esp32_eth_wifi_bridge.bin
```

To reconfigure before building:

```bash
idf.py set-target esp32c3 -B build_w5500_c3 \
  -D SDKCONFIG=sdkconfig.w5500_c3 \
  -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.w5500_c3" \
  menuconfig
```

OTA updates are supported through the web interface (Device Management section) with partition rollback on failed updates.

---

## Installation

### WT32-ETH01

```bash
esptool.py --chip esp32 --port /dev/ttyUSB0 --baud 460800 \
  write_flash \
  0x1000  firmware/bootloader.bin \
  0x8000  firmware/partition-table.bin \
  0xf000  firmware/ota_data_initial.bin \
  0x20000 firmware/esp32_eth_wifi_bridge.bin
```

### ESP32-C3 + W5500

```bash
# SuperMini (USB-JTAG port):
esptool.py --chip esp32c3 --port /dev/ttyACM0 --baud 460800 \
  write_flash \
  0x0000  firmware_w5500_c3/bootloader.bin \
  0x8000  firmware_w5500_c3/partition-table.bin \
  0xf000  firmware_w5500_c3/ota_data_initial.bin \
  0x20000 firmware_w5500_c3/esp32_eth_wifi_bridge.bin
```

Note: the ESP32-C3 bootloader flashes to `0x0000` (not `0x1000` as on classic ESP32).

### First-time setup (both variants)

After flashing, connect via serial at 115200 bps and configure the WiFi AP:

```
set_ap MyWiFiSSID MyPassword
restart
```

The bridge will reboot. Connect a WiFi client to the AP — it will receive an IP from the upstream network's DHCP server. You can then access the web interface at `http://esp32-bridge.local` (mDNS) or set a static management IP:

```
set_mgmt_ip 192.168.1.200 255.255.255.0 192.168.1.1
```

To erase all settings and return to defaults:

```
factory_reset
```

or via esptool (full flash wipe):

```bash
# ESP32 (WT32-ETH01)
esptool.py --chip esp32 --port /dev/ttyUSB0 erase_flash

# ESP32-C3 + W5500
esptool.py --chip esp32c3 --port /dev/ttyACM0 erase_flash
```
