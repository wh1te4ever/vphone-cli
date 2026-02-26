#!/bin/zsh

set -euo pipefail
cd "$(dirname "$0")"

IPROXY_PIDS=()

cleanup() {
    for pid in "${IPROXY_PIDS[@]}"; do
        kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null
    done
}
trap cleanup EXIT INT TERM HUP

iproxy 22222:22 &
IPROXY_PIDS+=($!)
iproxy 5901:5901 &
IPROXY_PIDS+=($!)

echo "iproxy started: 22222->22, 5901->5901 (pids: ${IPROXY_PIDS[*]})"

./vphone-cli \
    --rom ./contents/AVPBooter.vresearch1.bin \
    --disk ./contents/Disk.img \
    --nvram ./contents/nvram.bin \
    --cpu 4 \
    --memory 4096 \
    --stop-on-panic \
    --stop-on-fatal-error \
    --sep-rom ./contents/AVPSEPBooter.vresearch1.bin \
    --sep-storage ./contents/SEPStorage \
    --no-graphics

