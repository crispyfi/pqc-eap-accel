#!/usr/bin/env bash
# build-oqs.sh — build + install the post-quantum OpenSSL toolchain
# (liboqs + oqs-provider) that BOTH Linux hosts (auth server, supplicant) need.
#
# Shared by auth-server/setup.sh and supplicant/setup.sh. Safe to run on its own.
# See docs/pqc-toolchain.md for the prose version and provider-activation notes.
#
# Override any of these from the environment:
#   SRC_DIR          where to clone sources   (default: $HOME/src)
#   LIBOQS_TAG       liboqs git tag           (default: 0.14.0)
#   OQSPROVIDER_TAG  oqs-provider git tag     (default: 0.9.0)
set -euo pipefail

SRC_DIR="${SRC_DIR:-$HOME/src}"
LIBOQS_TAG="${LIBOQS_TAG:-0.14.0}"
OQSPROVIDER_TAG="${OQSPROVIDER_TAG:-0.9.0}"

mkdir -p "$SRC_DIR"

echo "==> liboqs $LIBOQS_TAG"
if [ ! -d "$SRC_DIR/liboqs" ]; then
    git clone https://github.com/open-quantum-safe/liboqs.git "$SRC_DIR/liboqs"
fi
cd "$SRC_DIR/liboqs"
git checkout "$LIBOQS_TAG"
cmake -GNinja -S . -B build
ninja -C build
sudo ninja -C build install

echo "==> oqs-provider $OQSPROVIDER_TAG"
if [ ! -d "$SRC_DIR/oqs-provider" ]; then
    git clone https://github.com/open-quantum-safe/oqs-provider.git "$SRC_DIR/oqs-provider"
fi
cd "$SRC_DIR/oqs-provider"
git checkout "$OQSPROVIDER_TAG"
cmake -S . -B _build
cmake --build _build
sudo cmake --install _build

echo "==> OQS toolchain installed."
echo "    Activate the provider via your host's openssl.conf and verify with:"
echo "      OPENSSL_CONF=<openssl.conf> openssl list -providers | grep -i oqs"
