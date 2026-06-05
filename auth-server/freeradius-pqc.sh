#!/bin/bash
# freeradius-pqc.sh — run FreeRADIUS in the foreground (-X debug) with the
# PQC-enabled OpenSSL config so it can negotiate post-quantum cert chains.
# Runnable from anywhere as `freeradius-pqc` (symlinked onto PATH by setup.sh).
#
# radiusd needs root to read the root-owned server private key, so self-elevate
# if we aren't already root. `sudo freeradius-pqc` still works — the guard sees
# EUID 0 and skips.
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    exec sudo "$0" "$@"
fi
exec env OPENSSL_CONF=/usr/local/etc/raddb/openssl.conf radiusd -X "$@"