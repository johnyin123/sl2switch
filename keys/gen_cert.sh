#!/bin/bash
set -o nounset -o pipefail
dirname="$(dirname "$(readlink -e "$0")")"
SCRIPTNAME=${0##*/}

if [ "${DEBUG:=false}" = "true" ]; then
    export PS4='[\D{%FT%TZ}] ${BASH_SOURCE}:${LINENO}: ${FUNCNAME[0]:+${FUNCNAME[0]}(): }'
    set -o xtrace
fi

SERVER_KEY=${1:-"server"}
CA_SUBJECT="/C=CN/L=LN/O=VPN/CN=johnyinca"
SRV_SUBJECT="/C=CN/L=LN/O=VPN/CN=${SERVER_KEY}"
KEY_LEN=1024
SRV_KEY_DAYS=1095
if [ ! -e ca-key.pem ]; then
    echo "creating a key for our ca"
    openssl genrsa -des3 -out ca-key.pem ${KEY_LEN}
fi
if [ ! -e ca-cert.pem ]; then
    echo "creating a ca"
    openssl req -new -x509 -days ${SRV_KEY_DAYS} -key ca-key.pem -out ca-cert.pem -utf8 -subj "${CA_SUBJECT}"
fi
if [ ! -e ${SERVER_KEY} ]; then
    echo "create server key"
    openssl genrsa -out ${SERVER_KEY} ${KEY_LEN}
fi
if [ ! -e ${SERVER_KEY}.csr ]; then
    echo "create a certificate signing request (csr)"
    openssl req -new -key ${SERVER_KEY} -out ${SERVER_KEY}.csr -utf8 -subj "${SRV_SUBJECT}"
fi
if [ ! -e ${SERVER_KEY}.pem ]; then
    echo "signing our server certificate with this ca"
    openssl x509 -req -days ${SRV_KEY_DAYS} -in ${SERVER_KEY}.csr -CA ca-cert.pem -CAkey ca-key.pem -set_serial 01 -out ${SERVER_KEY}.pem
fi

# now create a key that doesn't require a passphrase
openssl rsa -in ${SERVER_KEY} -out ${SERVER_KEY}.insecure
rm -f ${SERVER_KEY} ${SERVER_KEY}.csr
mv ${SERVER_KEY}.insecure ${SERVER_KEY}.key
# show the results (no other effect)
openssl rsa -noout -text -in ${SERVER_KEY}.key
openssl rsa -noout -text -in ca-key.pem
# openssl req -noout -text -in server-key.csr
# openssl x509 -noout -text -in server-cert.pem
# openssl x509 -noout -text -in ca-cert.pem

