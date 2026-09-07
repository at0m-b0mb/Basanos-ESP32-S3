#!/usr/bin/env bash
# Basanos — flash helper.
#
# esptool's automatic reset is unreliable on this board's USB-Serial/JTAG: it
# intermittently reports "Failed to connect: No serial data received" even
# though the chip is up and enumerating as the JTAG/serial debug unit.
#
# Driving the download-mode line sequence ourselves and then connecting with
# --before no_reset is reliable. Run this instead of `idf.py flash`.
#
# Usage: tools/flash.sh [port]
set -euo pipefail

PORT="${1:-/dev/cu.usbmodem2101}"
cd "$(dirname "$0")/.."

if [ ! -f build/basanos.bin ]; then
    echo "build/basanos.bin missing — run idf.py build first" >&2
    exit 1
fi

python3 - "$PORT" <<'PY'
import serial, sys, time
port = sys.argv[1]
s = serial.Serial(port, 115200)
# The sequence esptool uses for USB-Serial/JTAG parts: toggle DTR/RTS through
# (1,1) rather than (0,0) so the transition is seen on every host.
s.setRTS(False); s.setDTR(False); time.sleep(0.1)
s.setDTR(True);  s.setRTS(False); time.sleep(0.1)
s.setRTS(True);  s.setDTR(False); s.setRTS(True); time.sleep(0.1)
s.setDTR(False); s.setRTS(False)
s.close()
print("download mode requested")
PY

sleep 1
python -m esptool --chip esp32s3 -p "$PORT" -b 460800 \
    --before no_reset --after hard_reset \
    write_flash --flash_mode dio --flash_freq 80m --flash_size 16MB \
    0x0     build/bootloader/bootloader.bin \
    0x8000  build/partition_table/partition-table.bin \
    0x10000 build/basanos.bin
