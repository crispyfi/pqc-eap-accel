#!/bin/bash
# algorithm.sh — swap the live FreeRADIUS EAP-TLS cert chain to one algorithm.
# Runnable from anywhere as `algorithm <name>` (symlinked onto PATH by setup.sh).
# Paths are absolute, so it's already location-independent.
set -euo pipefail

CERTS=/usr/local/etc/raddb/certs
CERTS_ALL=/usr/local/etc/raddb/certs_all

# Supported algorithms — STATIC list. Keep in sync with docs/pqc-toolchain.md,
# the canonical source (and what generate.sh builds the chains for).
_usage() {
    cat <<'EOF'
usage: algorithm <name>

Swap the live FreeRADIUS EAP-TLS cert chain (server.{pem,key}, ca.pem,
client.{pem,key} in certs/) to <name>'s chain from certs_all/. Run generate.sh
first to build the chains (see auth-server/INSTALL.md).

Available algorithms:
  Pure PQC:
    mldsa44  mldsa65  mldsa87
    falcon512  falcon1024
    sphincssha2128fsimple  sphincssha2192fsimple
    sphincssha2128ssimple
  Hybrid:
    p256_mldsa44  p384_mldsa65  p521_mldsa87
    p256_falcon512  p521_falcon1024
    p256_sphincssha2128fsimple  p384_sphincssha2192fsimple
    p256_sphincssha2128ssimple
  Baseline:
    rsa
EOF
}

case "${1:-}" in
    -h|--help) _usage; exit 0 ;;
esac

algorithm="${1:-}"
if [ -z "$algorithm" ]; then
    echo "usage: algorithm <name>   (try 'algorithm --help' for the full list)" >&2
    exit 1
fi

# The swap reads root-owned private keys from certs_all/ and writes into the live
# raddb cert dir, so it needs root. Self-elevate if not already running as root
# (so plain `algorithm <name>` works without typing sudo).
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    exec sudo "$0" "$@"
fi

# Verify every source exists BEFORE copying anything, so a typo or an
# ungenerated algorithm can't leave the live chain half-swapped.
for f in server_"$algorithm".key server_"$algorithm".pem ca_"$algorithm".pem \
         client_"$algorithm".key client_"$algorithm".pem; do
    if [ ! -f "$CERTS_ALL/$f" ]; then
        echo "error: $CERTS_ALL/$f not found — has '$algorithm' been generated? (run generate.sh)" >&2
        exit 1
    fi
done

cp "$CERTS_ALL/server_$algorithm.key" "$CERTS/server.key"
cp "$CERTS_ALL/server_$algorithm.pem" "$CERTS/server.pem"
cp "$CERTS_ALL/ca_$algorithm.pem"     "$CERTS/ca.pem"
cp "$CERTS_ALL/client_$algorithm.key" "$CERTS/client.key"
cp "$CERTS_ALL/client_$algorithm.pem" "$CERTS/client.pem"

# Print the signature algorithm read straight from the now-active server cert —
# the real proof the PQC algorithm landed (vs trusting the name). openssl needs
# the oqs-provider to parse ML-DSA/Falcon/SLH-DSA, so run it with the lab config.
sig="$(OPENSSL_CONF=/usr/local/etc/raddb/openssl.conf \
       openssl x509 -in "$CERTS/server.pem" -noout -text 2>/dev/null \
       | sed -n 's/.*Signature Algorithm: *//p' | head -1 || true)"
echo "Active Signature Algorithm: ${sig:-<could not read — is the oqs-provider configured?>}"
