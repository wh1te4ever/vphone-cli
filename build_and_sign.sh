#!/bin/zsh
# build_and_sign.sh — Build vphone-cli and sign with private entitlements.
#
# Requires: SIP/AMFI disabled (amfi_get_out_of_my_way=1)
#
# Usage:
#   zsh build_and_sign.sh           # build + sign
#   zsh build_and_sign.sh --install # also copy to ../bin/vphone-cli
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="${SCRIPT_DIR}/.build/release/vphone-cli"
ENTITLEMENTS="${SCRIPT_DIR}/vphone.entitlements"

print "=== Building vphone-cli ==="
cd "${SCRIPT_DIR}"
swift build -c release 2>&1 | tail -5

print ""
print "=== Signing with entitlements ==="
print "  entitlements: ${ENTITLEMENTS}"
codesign --force --sign - --entitlements "${ENTITLEMENTS}" "${BINARY}"
print "  signed OK"

# Verify entitlements
print ""
print "=== Entitlement verification ==="
codesign -d --entitlements - "${BINARY}" 2>/dev/null | head -20

print ""
print "=== Binary ==="
ls -lh "${BINARY}"

if [[ "${1:-}" == "--install" ]]; then
  REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
  mkdir -p "${REPO_ROOT}/bin"
  cp -f "${BINARY}" "${REPO_ROOT}/bin/vphone-cli"
  print ""
  print "Installed to ${REPO_ROOT}/bin/vphone-cli"
fi

print ""
print "Done. Run with:"
print "  ${BINARY} --rom <rom> --disk <disk> --serial"
