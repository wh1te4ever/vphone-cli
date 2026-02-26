#!/bin/zsh
# ramdisk_send.sh — Send signed ramdisk components to device via irecovery.
#
# Usage: ./ramdisk_send.sh [ramdisk_dir]
#
# Expects device in DFU mode. Loads iBSS/iBEC, then boots with
# SPTM, TXM, trustcache, ramdisk, device tree, SEP, and kernel.
set -euo pipefail

RAMDISK_DIR="${1:-Ramdisk}"

if [ ! -d "$RAMDISK_DIR" ]; then
    echo "[-] Ramdisk directory not found: $RAMDISK_DIR"
    echo "    Run build_ramdisk.py first."
    exit 1
fi

echo "[*] Sending ramdisk from $RAMDISK_DIR ..."

# 1. Load iBSS + iBEC (DFU → recovery)
echo "  [1/8] Loading iBSS..."
irecovery -f "$RAMDISK_DIR/iBSS.vresearch101.RELEASE.img4"

echo "  [2/8] Loading iBEC..."
irecovery -f "$RAMDISK_DIR/iBEC.vresearch101.RELEASE.img4"
irecovery -c go

sleep 1

# 2. Load SPTM
echo "  [3/8] Loading SPTM..."
irecovery -f "$RAMDISK_DIR/sptm.vresearch1.release.img4"
irecovery -c firmware

# 3. Load TXM
echo "  [4/8] Loading TXM..."
irecovery -f "$RAMDISK_DIR/txm.img4"
irecovery -c firmware

# 4. Load trustcache
echo "  [5/8] Loading trustcache..."
irecovery -f "$RAMDISK_DIR/trustcache.img4"
irecovery -c firmware

# 5. Load ramdisk
echo "  [6/8] Loading ramdisk..."
irecovery -f "$RAMDISK_DIR/ramdisk.img4"
sleep 2
irecovery -c ramdisk

# 6. Load device tree
echo "  [7/8] Loading device tree..."
irecovery -f "$RAMDISK_DIR/DeviceTree.vphone600ap.img4"
irecovery -c devicetree

# 7. Load SEP
echo "  [8/8] Loading SEP..."
irecovery -f "$RAMDISK_DIR/sep-firmware.vresearch101.RELEASE.img4"
irecovery -c firmware

# 8. Load kernel and boot
echo "  [*] Booting kernel..."
irecovery -f "$RAMDISK_DIR/krnl.img4"
irecovery -c bootx

echo "[+] Boot sequence complete. Device should be booting into ramdisk."
