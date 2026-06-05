#!/usr/bin/env bash
# setup.sh — prepare the SUPPLICANT (client) host:
#   - liboqs + oqs-provider          (shared PQC OpenSSL toolchain)
#   - dependencies for a PQC-capable wpa_supplicant build
#   - activate the oqs-provider for the system OpenSSL (opt-in)
#
# Override from the environment:
#   SRC_DIR                where sources are cloned   (default: $HOME/src)
#   INSTALL_SYSTEM_OPENSSL set to 1 to overwrite the system openssl.cnf with the
#                          provider-activating config (a .bak is kept). Default: off.
set -euo pipefail

SRC_DIR="${SRC_DIR:-$HOME/src}"
INSTALL_SYSTEM_OPENSSL="${INSTALL_SYSTEM_OPENSSL:-0}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HERE="$REPO_ROOT/supplicant"

echo "==> apt dependencies"
sudo apt update
sudo apt install -y git build-essential pkg-config libssl-dev \
    cmake ninja-build gcc \
    libnl-3-dev libnl-genl-3-dev libnl-route-3-dev libdbus-1-dev \
    vim tcpdump

echo "==> PQC OpenSSL toolchain (liboqs + oqs-provider)"
SRC_DIR="$SRC_DIR" "$REPO_ROOT/scripts/build-oqs.sh"

chmod +x "$HERE/algorithm.sh" "$HERE/connect.sh"

echo "==> install commands into /usr/local/bin (run from any directory)"
# Both scripts resolve their own real path, so they find certs/ and wlan.conf
# beside the script even when called via these symlinks from another directory.
sudo ln -sfn "$HERE/algorithm.sh" /usr/local/bin/algorithm
sudo ln -sfn "$HERE/connect.sh"   /usr/local/bin/connect

if [ "$INSTALL_SYSTEM_OPENSSL" = "1" ]; then
    sys_cnf="$(openssl version -d | sed -E 's/^OPENSSLDIR: "(.*)"$/\1/')/openssl.cnf"
    echo "==> activating oqs-provider in system OpenSSL ($sys_cnf)"
    sudo cp -n "$sys_cnf" "$sys_cnf.bak" || true
    sudo cp "$HERE/openssl.conf" "$sys_cnf"
else
    echo "!! Not touching system OpenSSL config (INSTALL_SYSTEM_OPENSSL=1 to opt in)."
    echo "   Otherwise run the supplicant with: OPENSSL_CONF=$HERE/openssl.conf"
fi

cat <<EOF

==> Build complete.
EOF
