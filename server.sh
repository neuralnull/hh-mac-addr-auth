#!/bin/bash
#
# Local token signing server

# Service port
PORT="$1"
[ -z "${PORT}" ] && PORT=8000

# RSA key location
PRIVATE_KEY=private.pem
PUBLIC_KEY=public.pem
# Generate key if it doesn't exist
if ! [ -f "${PRIVATE_KEY}" ]; then
    openssl genrsa -out "${PRIVATE_KEY}" 4096
    openssl rsa -in "${PRIVATE_KEY}" -pubout -out "${PUBLIC_KEY}"
    chmod 0600 "${PRIVATE_KEY}"
fi

python token-signer.py "${PORT}" "${PRIVATE_KEY}"
