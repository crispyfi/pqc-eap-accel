#!/usr/bin/env bash
# setup.sh — prepare the SUPPLICANT (client) host:
#   - liboqs + oqs-provider          (shared PQC OpenSSL toolchain)
#   - wpa_supplicant (patched, source) EAP-TLS 1.3 peer for large PQC chains
#   - install helper commands; activate oqs-provider for system OpenSSL (opt-in)
#
# Override from the environment:
#   SRC_DIR                where sources live         (default: $HOME/src)
#   WPA_VERSION            wpa_supplicant release     (default: 2.11)
#   INSTALL_SYSTEM_OPENSSL set to 1 to overwrite the system openssl.cnf with the
#                          provider-activating config (a .bak is kept). Default: off.
set -euo pipefail

SRC_DIR="${SRC_DIR:-$HOME/src}"
WPA_VERSION="${WPA_VERSION:-2.11}"
INSTALL_SYSTEM_OPENSSL="${INSTALL_SYSTEM_OPENSSL:-0}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HERE="$REPO_ROOT/supplicant"
mkdir -p "$SRC_DIR"

# Apply every *.patch in $1 to the source tree $2 (paths are relative to the
# tree root, so git apply -p1). Loud — but non-fatal — if none are present, so
# an unpatched build still proceeds (it will then fail on large PQC flights).
# git apply works on the tarball-extracted tree even though it isn't a git
# checkout. See the patches section of the repo README for what each one does.
apply_patches() {
    local dir="$1" tree="$2"
    shopt -s nullglob; local patches=("$dir"/*.patch); shopt -u nullglob
    if [ ${#patches[@]} -eq 0 ]; then
        echo "!! WARNING: no patches in $dir" >&2
        echo "   building UNPATCHED — large PQC flights will be rejected." >&2
        return 0
    fi
    # --recount tolerates hunk line drift; --ignore-whitespace lets the patch
    # apply even if an editor altered whitespace in the surrounding context.
    ( cd "$tree" && for p in "${patches[@]}"; do
        echo "   applying $(basename "$p")"
        git apply --recount --ignore-whitespace "$p"; done )
}

echo "==> apt dependencies"
sudo apt update
sudo apt install -y git curl build-essential pkg-config libssl-dev \
    cmake ninja-build gcc \
    libnl-3-dev libnl-genl-3-dev libnl-route-3-dev libdbus-1-dev \
    vim tcpdump

echo "==> PQC OpenSSL toolchain (liboqs + oqs-provider)"
SRC_DIR="$SRC_DIR" "$REPO_ROOT/scripts/build-oqs.sh"

echo "==> wpa_supplicant ($WPA_VERSION, patched for large PQC cert chains)"
WPA_TARBALL="$SRC_DIR/wpa_supplicant-$WPA_VERSION.tar.gz"
WPA_SRC="$SRC_DIR/wpa_supplicant-$WPA_VERSION"
[ -f "$WPA_TARBALL" ] || \
    curl -fsSL "https://w1.fi/releases/wpa_supplicant-$WPA_VERSION.tar.gz" -o "$WPA_TARBALL"
# Re-extract pristine source each run so patches always apply to a clean tree
# (the auth-server build gets the same guarantee via `git stash`).
rm -rf "$WPA_SRC"
tar -xzf "$WPA_TARBALL" -C "$SRC_DIR"
apply_patches "$REPO_ROOT/patches/supplicant" "$WPA_SRC"
# config -> .config: selects EAP-TLS 1.3 + nl80211/wired drivers and links the
# system OpenSSL that carries oqs-provider. wpa_supplicant reads .config from
# its own subdirectory, which is also where make runs.
cp "$HERE/config" "$WPA_SRC/wpa_supplicant/.config"
make -C "$WPA_SRC/wpa_supplicant"
sudo make -C "$WPA_SRC/wpa_supplicant" install   # -> /usr/local/sbin/wpa_supplicant

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
