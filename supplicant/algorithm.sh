#!/bin/bash
# algorithm.sh — swap the live supplicant EAP-TLS cert chain to one algorithm.
# Runnable from anywhere as `algorithm <name>` (symlinked onto PATH by setup.sh).
set -euo pipefail

# Resolve our own real location even when invoked via the /usr/local/bin
# symlink, so the live certs/ dir is found beside the script, not in $PWD.
DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
CERTS="$DIR/certs"

# The certs_all/ archive (every algorithm's chains, copied over from the auth
# server's generate.sh output) lives in the invoking user's home — NOT beside
# the script. Override with the CERTS_ALL env var if you keep it elsewhere.
CERTS_ALL="${CERTS_ALL:-$HOME/certs_all}"

# Supported algorithms — STATIC list. Keep in sync with docs/pqc-toolchain.md,
# the canonical source (and what the auth server's generate.sh builds chains for).
_usage() {
    cat <<'EOF'
usage: algorithm <name>

Swap the live supplicant EAP-TLS cert chain (ca.pem, client.pem, client.key in
certs/) to <name>'s chain from ~/certs_all/. Generate the chains on the auth
server and copy certs_all/ into your home dir first (see supplicant/INSTALL.md).

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

mkdir -p "$CERTS"

for f in ca_"$algorithm".pem client_"$algorithm".pem client_"$algorithm".key; do
    if [ ! -f "$CERTS_ALL/$f" ]; then
        echo "error: $CERTS_ALL/$f not found — has '$algorithm' been generated?" >&2
        exit 1
    fi
done

cp "$CERTS_ALL/ca_$algorithm.pem"     "$CERTS/ca.pem"
cp "$CERTS_ALL/client_$algorithm.pem" "$CERTS/client.pem"
cp "$CERTS_ALL/client_$algorithm.key" "$CERTS/client.key"

# Print the signature algorithm read straight from the now-active client cert.
# openssl needs the oqs-provider to parse ML-DSA/Falcon/SLH-DSA, so run it with
# the supplicant's OpenSSL config (beside this script).
sig="$(OPENSSL_CONF="$DIR/openssl.conf" \
       openssl x509 -in "$CERTS/client.pem" -noout -text 2>/dev/null \
       | sed -n 's/.*Signature Algorithm: *//p' | head -1 || true)"
echo "Active Signature Algorithm: ${sig:-<could not read — is the oqs-provider configured?>}"
