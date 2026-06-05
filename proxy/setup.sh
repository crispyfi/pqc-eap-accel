#!/usr/bin/env bash
# setup.sh — build + install the PROXY VM stack:
#   - radsecproxy (patched, source)  (RadSec/TLS client toward the auth server)
#   - a uv-managed Python env        (the eap-accel proxy, this project)
#   - install radsecproxy.conf + the config template
#   - symlink the `eap-accel` and `latency` commands into /usr/local/bin
#
# It does NOT place certs or start daemons — that's the runbook in INSTALL.md.
#
# Override from the environment if your layout differs:
#   SRC_DIR          where sources are cloned     (default: $HOME/src)
#   RADSECPROXY_TAG  radsecproxy git tag/branch    (default: master)
#   AUTH_SERVER_IP   auth-server VM IP; if set, an /etc/hosts entry for
#                    'auth-server' is added (radsecproxy.conf resolves that name)
set -euo pipefail

SRC_DIR="${SRC_DIR:-$HOME/src}"
RADSECPROXY_TAG="${RADSECPROXY_TAG:-master}"
AUTH_SERVER_IP="${AUTH_SERVER_IP:-}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HERE="$REPO_ROOT/proxy"
mkdir -p "$SRC_DIR"

apply_patches() {
    local dir="$1" tree="$2"
    shopt -s nullglob; local patches=("$dir"/*.patch); shopt -u nullglob
    if [ ${#patches[@]} -eq 0 ]; then
        echo "!! WARNING: no patches in $dir" >&2
        echo "   building UNPATCHED — large PQC packets will be rejected." >&2
        echo "   See $REPO_ROOT/patches/README.md to capture them." >&2
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
    python3 python3-venv python3-pip \
    net-tools tcpdump vim

# Let tcpdump capture without root so Wireshark's sshdump (remote SSH capture
# from the Mac) works as the login user — no sudo, no sudoers edit. Grants the
# raw-socket capabilities directly on the binary.
echo "==> grant tcpdump raw-capture capabilities (for remote sshdump)"
sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v tcpdump)"

echo "==> radsecproxy ($RADSECPROXY_TAG, patched)"
if [ ! -d "$SRC_DIR/radsecproxy" ]; then
    git clone https://github.com/radsecproxy/radsecproxy.git "$SRC_DIR/radsecproxy"
fi
cd "$SRC_DIR/radsecproxy"
git checkout "$RADSECPROXY_TAG"
git stash || true
apply_patches "$REPO_ROOT/patches/radsecproxy" "$SRC_DIR/radsecproxy"
./autogen.sh
# radsecproxy master + a recent GCC trips -Werror on warnings older toolchains
# ignored (e.g. discarded-qualifiers in tlscommon.c). -Wno-error keeps a
# third-party warning from failing our build.
./configure CFLAGS="-g -O2 -Wno-error"
make
sudo make install

echo "==> install radsecproxy.conf"
sudo install -m 0644 "$HERE/radsecproxy.conf" /usr/local/etc/radsecproxy.conf
sudo install -d /usr/local/etc/radsecproxy/certs

# radsecproxy.conf connects to the auth server by the name 'auth-server'
# (server auth-server { host auth-server ... }), so that name must resolve here.
if [ -n "$AUTH_SERVER_IP" ]; then
    echo "==> /etc/hosts: auth-server -> $AUTH_SERVER_IP"
    if grep -qE '[[:space:]]auth-server([[:space:]]|$)' /etc/hosts; then
        echo "   entry already present, leaving as-is"
    else
        echo "$AUTH_SERVER_IP auth-server" | sudo tee -a /etc/hosts >/dev/null
    fi
else
    echo "!! AUTH_SERVER_IP not set — add '<auth-server-ip> auth-server' to /etc/hosts yourself"
fi

echo "==> Python environment via uv (creates $REPO_ROOT/.venv)"
if ! command -v uv >/dev/null 2>&1; then
    echo "   installing uv (https://docs.astral.sh/uv/)"
    curl -LsSf https://astral.sh/uv/install.sh | sh
    # The installer drops uv in ~/.local/bin; make it usable for the rest of
    # this script even if that dir isn't on PATH yet.
    export PATH="$HOME/.local/bin:$PATH"
fi
# `uv sync` builds .venv from pyproject.toml and installs THIS project editable,
# so edits to proxy/*.py take effect with no reinstall. Run it from the repo
# root, where pyproject.toml lives.
( cd "$REPO_ROOT" && uv sync )
[ -f "$HERE/config.yaml" ] || cp "$HERE/config.yaml.example" "$HERE/config.yaml"

echo "==> install commands into /usr/local/bin (run from any directory)"
# uv sync wrote a launcher to .venv/bin/eap-accel whose shebang points at the
# venv python (absolute), so the command runs standalone with no uv at runtime.
# eap-accel needs no root (UDP/1812 is unprivileged); latency does (it runs tc).
sudo ln -sfn "$REPO_ROOT/.venv/bin/eap-accel" /usr/local/bin/eap-accel
sudo ln -sfn "$HERE/latency.sh"               /usr/local/bin/latency

cat <<EOF

==> Build complete.
EOF
