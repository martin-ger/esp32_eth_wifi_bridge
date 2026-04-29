#!/bin/bash
# Build ESP32-C3 + W5500 SPI Ethernet bridge firmware and collect binaries into firmware_w5500_c3/
set -e

BUILD_DIR="build_w5500_c3"
OUT_DIR="firmware_w5500_c3"
BIN_NAME="esp32_eth_wifi_bridge"
SDKCONFIG="sdkconfig.w5500_c3"
SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.w5500_c3"

echo "=== W5500 + ESP32-C3 bridge firmware build ==="

if [ -z "$IDF_PATH" ]; then
    echo "ERROR: IDF_PATH is not set. Source your ESP-IDF export script first:"
    echo "  . \$IDF_PATH/export.sh"
    exit 1
fi

echo "IDF_PATH: $IDF_PATH"
echo "Build dir: $BUILD_DIR"
echo "Output dir: $OUT_DIR"
echo ""

echo "--- Cleaning previous build ---"
rm -rf "$BUILD_DIR"
# Remove stale sdkconfig so it is regenerated from SDKCONFIG_DEFAULTS.
# A cached sdkconfig from before the ETH_UPLINK_TYPE choice was added will
# lack CONFIG_ETH_UPLINK_W5500 and silently default to the EMAC branch.
rm -f "$SDKCONFIG"

echo "--- Building ---"
idf.py \
    -B "$BUILD_DIR" \
    -D SDKCONFIG="$SDKCONFIG" \
    -D SDKCONFIG_DEFAULTS="$SDKCONFIG_DEFAULTS" \
    set-target esp32c3
idf.py \
    -B "$BUILD_DIR" \
    -D SDKCONFIG="$SDKCONFIG" \
    -D SDKCONFIG_DEFAULTS="$SDKCONFIG_DEFAULTS" \
    build

echo ""
echo "--- Collecting binaries ---"
mkdir -p "$OUT_DIR"

cp "$BUILD_DIR/bootloader/bootloader.bin"           "$OUT_DIR/bootloader.bin"
cp "$BUILD_DIR/partition_table/partition-table.bin" "$OUT_DIR/partition-table.bin"
cp "$BUILD_DIR/ota_data_initial.bin"                "$OUT_DIR/ota_data_initial.bin"
cp "$BUILD_DIR/${BIN_NAME}.bin"                     "$OUT_DIR/${BIN_NAME}.bin"

echo ""
echo "=== Done ==="
echo ""
echo "Firmware files in $OUT_DIR/:"
ls -lh "$OUT_DIR/"
echo ""
echo "Flash command:"
echo "  esptool.py --chip esp32c3 --port /dev/ttyACM0 --baud 460800 write_flash \\"
echo "    0x0000  $OUT_DIR/bootloader.bin \\"
echo "    0x8000  $OUT_DIR/partition-table.bin \\"
echo "    0xf000  $OUT_DIR/ota_data_initial.bin \\"
echo "    0x20000 $OUT_DIR/${BIN_NAME}.bin"
