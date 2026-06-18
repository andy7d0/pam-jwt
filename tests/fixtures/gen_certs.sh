#!/usr/bin/env bash
# tests/fixtures/gen_certs.sh
#
# Generate X.509 certificates + matching private keys used as fixtures by
# the pam-jwt unit tests.
#
# Two issuers are produced:
#
#   - rsa_issuer.*  (RSA-2048)        -> signed with RS256
#   - ec_issuer.*   (EC P-256 / prime256v1) -> signed with ES256
#
# For each issuer we also produce a "wrong key" so we can verify that the
# module rejects tokens signed by some unrelated key (e.g. to confirm the
# wrong-key / tampered-signature paths).
#
# All artefacts land in the directory passed as the first argument. The
# script is idempotent: re-running it overwrites everything cleanly.
#
# This file is shell, not C, because openssl's CLI is the most portable way
# to mint test certificates and the test fixtures don't need any C runtime
# to produce. The test suite itself is still pure C.

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <out-dir>" >&2
    exit 2
fi

OUT_DIR="$1"
mkdir -p "$OUT_DIR"

# Common subject fields. CN is purely cosmetic; the module only checks the
# public key, not the certificate's identity.
SUBJ_RSA="/CN=pam-jwt-test-rsa"
SUBJ_EC="/CN=pam-jwt-test-ec"
SUBJ_OTHER="/CN=pam-jwt-test-other"

gen_rsa() {
    local name="$1"
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "${OUT_DIR}/${name}.key" \
        -out "${OUT_DIR}/${name}.pem" -days 3650 \
        -subj "$2" 2>/dev/null
}

gen_ec() {
    local name="$1"
    # Generate the EC parameters once and reuse them; openssl ecparam
    # handles key + csr in a single pipeline.
    openssl ecparam -name prime256v1 -genkey -noout \
        -out "${OUT_DIR}/${name}.key" 2>/dev/null
    openssl req -new -x509 -key "${OUT_DIR}/${name}.key" \
        -out "${OUT_DIR}/${name}.pem" -days 3650 \
        -subj "$2" 2>/dev/null
}

gen_rsa rsa_issuer  "$SUBJ_RSA"
gen_ec  ec_issuer   "$SUBJ_EC"
# A second, unrelated RSA keypair: cert uses its own pubkey but is not
# what rsa_issuer.pem advertises. Useful for the wrong-key test.
gen_rsa other_rsa   "$SUBJ_OTHER"

echo "fixtures written to: $OUT_DIR"
ls -1 "$OUT_DIR"
