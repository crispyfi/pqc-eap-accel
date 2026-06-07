#!/usr/bin/env bash
# setup.sh — build + install the AUTH-SERVER VM stack:
#   - liboqs + oqs-provider          (shared PQC OpenSSL toolchain)
#   - radsecproxy (patched, source)  (RadSec/TLS server termination)
#   - FreeRADIUS 3.2.8 (patched)     (EAP-TLS state machine + cert validation)
#   - install configs, cert Makefile, and helper scripts into /usr/local/etc/raddb
#   - tune installed radiusd.conf (max_attributes) for reassembled PQC flights
#
# It does NOT generate certs or start daemons — that's the runbook in INSTALL.md.
# Read INSTALL.md alongside this; the patches are explained in the patches section
# of the repo README (../README.md).
#
# Override from the environment if your layout differs:
#   SRC_DIR          where sources are cloned     (default: $HOME/src)
#   RADDB            FreeRADIUS config dir         (default: /usr/local/etc/raddb)
#   FREERADIUS_TAG   FreeRADIUS git tag            (default: release_3_2_8)
#   RADSECPROXY_TAG  radsecproxy git tag/branch    (default: master)
set -euo pipefail

SRC_DIR="${SRC_DIR:-$HOME/src}"
RADDB="${RADDB:-/usr/local/etc/raddb}"
FREERADIUS_TAG="${FREERADIUS_TAG:-release_3_2_8}"
RADSECPROXY_TAG="${RADSECPROXY_TAG:-master}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HERE="$REPO_ROOT/auth-server"
mkdir -p "$SRC_DIR"

# Apply every *.patch in $1 to the source tree $2 (relative paths, via git apply).
# Loud — but non-fatal — if none are present, so a classical-RSA build still works.
apply_patches() {
    local dir="$1" tree="$2"
    shopt -s nullglob; local patches=("$dir"/*.patch); shopt -u nullglob
    if [ ${#patches[@]} -eq 0 ]; then
        echo "!! WARNING: no patches in $dir" >&2
        echo "   building UNPATCHED — large PQC packets will be rejected." >&2
        echo "   See the patches section of $REPO_ROOT/README.md." >&2
        return 0
    fi
    # --recount tolerates hunk line-count drift; --ignore-whitespace lets the
    # patch apply even if an editor altered trailing whitespace in the context
    # (a common way these small patches get mangled in transit).
    ( cd "$tree" && for p in "${patches[@]}"; do
        echo "   applying $(basename "$p")"
        git apply --recount --ignore-whitespace "$p"; done )
}

echo "==> apt dependencies"
sudo apt update
sudo apt install -y git build-essential pkg-config libssl-dev \
    autoconf automake libtool autoconf-archive \
    cmake ninja-build gcc libtalloc-dev libcrypt-dev \
    net-tools tcpdump vim

# Let tcpdump capture without root so Wireshark's sshdump (remote SSH capture
# from the Mac) works as the login user — no sudo, no sudoers edit. Grants the
# raw-socket capabilities directly on the binary.
echo "==> grant tcpdump raw-capture capabilities (for remote sshdump)"
sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v tcpdump)"

echo "==> PQC OpenSSL toolchain (liboqs + oqs-provider)"
SRC_DIR="$SRC_DIR" "$REPO_ROOT/scripts/build-oqs.sh"

echo "==> radsecproxy ($RADSECPROXY_TAG, patched)"
if [ ! -d "$SRC_DIR/radsecproxy" ]; then
    git clone https://github.com/radsecproxy/radsecproxy.git "$SRC_DIR/radsecproxy"
fi
cd "$SRC_DIR/radsecproxy"
git checkout "$RADSECPROXY_TAG"
git stash || true            # drop any prior patch so re-runs start clean
apply_patches "$REPO_ROOT/patches/radsecproxy" "$SRC_DIR/radsecproxy"
./autogen.sh                 # a fresh clone has no ./configure
# radsecproxy master + a recent GCC trips -Werror on warnings older toolchains
# ignored (e.g. discarded-qualifiers in tlscommon.c). -Wno-error keeps a
# third-party warning from failing our build.
./configure CFLAGS="-g -O2 -Wno-error"
make
sudo make install

echo "==> FreeRADIUS ($FREERADIUS_TAG, patched)"
if [ ! -d "$SRC_DIR/freeradius-server" ]; then
    git clone https://github.com/FreeRADIUS/freeradius-server.git "$SRC_DIR/freeradius-server"
fi
cd "$SRC_DIR/freeradius-server"
git checkout "$FREERADIUS_TAG"
git stash || true
apply_patches "$REPO_ROOT/patches/freeradius" "$SRC_DIR/freeradius-server"
./configure
make
sudo make install

echo "==> install configs + helper scripts into $RADDB"
sudo install -d "$RADDB" "$RADDB/certs" "$RADDB/mods-available"
sudo install -m 0644 "$HERE/openssl.conf"      "$RADDB/openssl.conf"
sudo install -m 0644 "$HERE/clients.conf"      "$RADDB/clients.conf"
sudo install -m 0644 "$HERE/eap"               "$RADDB/mods-available/eap"
sudo install -m 0644 "$HERE/Makefile"          "$RADDB/certs/Makefile"
sudo install -m 0755 "$HERE/generate.sh"       "$RADDB/generate.sh"
sudo install -m 0755 "$HERE/algorithm.sh"      "$RADDB/algorithm.sh"
sudo install -m 0755 "$HERE/freeradius-pqc.sh" "$RADDB/freeradius-pqc.sh"
sudo install -m 0755 "$HERE/latency.sh"        "$RADDB/latency.sh"

echo "==> raise RADIUS max_attributes for reassembled PQC EAP-TLS flights"
# A reassembled PQC cert flight arrives as ONE Access-Request carrying >200
# EAP-Message attributes (each <=253 bytes); FreeRADIUS's default
# max_attributes=200 misreads that as a DoS flood ("Too many attributes in
# request") and drops it. radiusd.conf is written by `make install` above and
# is NOT shipped in this repo, so edit the installed copy in place. Idempotent:
# re-running just re-sets whatever value is present to 1024.
sudo sed -i -E 's/^([[:space:]]*max_attributes[[:space:]]*=[[:space:]]*)[0-9]+/\11024/' \
    "$RADDB/radiusd.conf"

echo "==> install radsecproxy.conf"
sudo install -m 0644 "$HERE/radsecproxy.conf"  /usr/local/etc/radsecproxy.conf
sudo install -d /usr/local/etc/radsecproxy/certs

echo "==> install commands into /usr/local/bin (run from any directory)"
# Point the on-PATH commands at the installed copies in $RADDB (those use
# absolute paths, so they work regardless of the caller's directory). latency
# and freeradius-pqc need root; algorithm doesn't, but a single location keeps
# them discoverable and sudo-safe.
sudo ln -sfn "$RADDB/algorithm.sh"      /usr/local/bin/algorithm
sudo ln -sfn "$RADDB/freeradius-pqc.sh" /usr/local/bin/freeradius-pqc
sudo ln -sfn "$RADDB/latency.sh"        /usr/local/bin/latency

cat <<EOF

==> Build complete.
EOF
