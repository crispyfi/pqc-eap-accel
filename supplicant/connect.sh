#!/bin/bash
# connect.sh — bring up wpa_supplicant with the lab EAP-TLS config.
# Runnable from anywhere as `connect` (symlinked onto PATH by setup.sh).
set -euo pipefail

# Resolve our own real location (even via the /usr/local/bin symlink) so
# wlan.conf is loaded from beside this script, not the caller's $PWD.
DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"

# Run from $DIR so the *relative* cert paths inside wlan.conf (certs/ca.pem,
# etc.) resolve beside this script. wpa_supplicant resolves those against its
# working directory, and sudo preserves CWD into the child process.
cd "$DIR"

# IFACE overridable for hosts whose wireless interface isn't wlan0.
IFACE="${IFACE:-wlan0}"

# wpa_supplicant must load the oqs-provider, or it can only parse the algorithms
# the *system* OpenSSL knows natively (ML-DSA on OpenSSL 3.5+). Falcon and
# SPHINCS+ use OQS experimental OIDs and fail with "decode error / ee key too
# small" unless the provider is active. The provider is activated by the lab
# openssl.conf beside this script. Override OPENSSL_CONF if you installed it
# system-wide (setup.sh INSTALL_SYSTEM_OPENSSL=1) and want the system default.
OPENSSL_CONF="${OPENSSL_CONF:-$DIR/openssl.conf}"

# Pass OPENSSL_CONF *through* sudo with `env`: sudo resets the environment, so
# exporting it in this shell alone wouldn't reach the wpa_supplicant process.
sudo env OPENSSL_CONF="$OPENSSL_CONF" \
    /usr/local/sbin/wpa_supplicant -i "$IFACE" -c "$DIR/wlan.conf" -D nl80211 -dd