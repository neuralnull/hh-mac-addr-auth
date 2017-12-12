#!/bin/bash
#
# MAC-auth server

# Service port
PORT="$1"
[ -z "${PORT}" ] && PORT=8000

# tcpdump packet filter for 'GET /mac-addr-auth.js?token='
TCPDUMP_FILTER="tcp dst port ${PORT} \
                and tcp[32:4]=0x47455420 \
                and tcp[36:4]=0x2f6d6163 \
                and tcp[40:4]=0x2d616464 \
                and tcp[44:4]=0x722d6175 \
                and tcp[48:4]=0x74682e6a \
                and tcp[52:4]=0x733f746f \
                and tcp[56:4]=0x6b656e3d"

# RSA key location
PRIVATE_KEY=private.pem
PUBLIC_KEY=public.pem
# Generate key if it doesn't exist
if ! [ -f "${PRIVATE_KEY}" ]; then
    openssl genrsa -out "${PRIVATE_KEY}" 4096
    openssl rsa -in "${PRIVATE_KEY}" -pubout -out "${PUBLIC_KEY}"
    chmod 0600 "${PRIVATE_KEY}"
fi

sudo tcpdump -elnqtx -s0 "${TCPDUMP_FILTER}" \
    | awk -f tcpdump-parser.awk \
    | python mac-addr-auth.py "${PORT}" "${PRIVATE_KEY}"
