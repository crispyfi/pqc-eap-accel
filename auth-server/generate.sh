#!/bin/bash
# generate.sh — generate a CA/server/client certificate chain for every
# signature algorithm and archive each set.

CERTS=/usr/local/etc/raddb/certs
CERTS_ALL=/usr/local/etc/raddb/certs_all

mkdir -p "$CERTS_ALL"

for algorithm in \
    rsa \
    mldsa44 mldsa65 mldsa87 \
    falcon512 falcon1024 \
    sphincssha2128fsimple sphincssha2192fsimple \
    sphincssha2128ssimple \
    p256_mldsa44 p384_mldsa65 p521_mldsa87 \
    p256_falcon512 p521_falcon1024 \
    p256_sphincssha2128fsimple p384_sphincssha2192fsimple \
    p256_sphincssha2128ssimple
do
    echo "=== generating certs for $algorithm ==="
    (cd "$CERTS" && make destroycerts)        # clean slate so make regenerates
    (cd "$CERTS" && make name="$algorithm")   # generate this algorithm's chain
    cp "$CERTS"/ca*     "$CERTS_ALL"/         # archive the generated *_$algorithm.* files
    cp "$CERTS"/server* "$CERTS_ALL"/
    cp "$CERTS"/client* "$CERTS_ALL"/
done
