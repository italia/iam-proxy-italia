#!/bin/sh

set -euo pipefail

openssl_conf=$(mktemp)

# check input parameters

COMMON_NAME=${COMMON_NAME:=""}
if [ "X${COMMON_NAME}" == "X" ]; then
    echo "[E] COMMON_NAME must be set"
    exit 1
fi

LOCALITY_NAME=${LOCALITY_NAME:=""}
if [ "X${LOCALITY_NAME}" == "X" ]; then
    echo "[E] LOCALITY_NAME must be set"
    exit 1
fi

ORGANIZATION_IDENTIFIER=${ORGANIZATION_IDENTIFIER:=""}
if [ "X${ORGANIZATION_IDENTIFIER}" == "X" ]; then
    echo "[E] ORGANIZATION_IDENTIFIER must be set"
    exit 1
fi

if [ $(echo ${ORGANIZATION_IDENTIFIER} | grep -c '^PA:IT-') -ne 1 ]; then
    echo "[E] ORGANIZATION_IDENTIFIER must be in the format of 'PA:IT-<IPA code>'"
    exit 1
fi

ORGANIZATION_NAME=${ORGANIZATION_NAME:=""}
if [ "X${ORGANIZATION_NAME}" == "X" ]; then
    echo "[E] ORGANIZATION_NAME must be set"
    exit 1
fi

SERIAL_NUMBER=${SERIAL_NUMBER:=""}
if [ "X${SERIAL_NUMBER}" == "X" ]; then
    echo "[E] SERIAL_NUMBER must be set"
    exit 1
fi

URI=${URI:=""}
if [ "X${URI}" == "X" ]; then
    echo "[E] URI must be set"
    exit 1
fi

SPID_SECTOR=${SPID_SECTOR:=""}
if [ "X${SPID_SECTOR}" == "X" ]; then
    echo "[E] SPID_SECTOR must be set"
    exit 1
fi

case ${SPID_SECTOR} in
    public)
        POLICY_IDENTIFIER="spid-publicsector-SP"
        ;;
    private)
        POLICY_IDENTIFIER="spid-privatesector-SP"
        ;;
    *)
    echo "[E] SPID_SECTOR must be one of ['public', 'private']"
    exit 1
        ;;
esac

# generate configuration file

cat > ${openssl_conf} <<EOF
oid_section=spid_oids
[ req ]
default_bits=3072
default_md=sha384
distinguished_name=dn
encrypt_key=no
prompt=no
req_extensions=req_ext
[ spid_oids ]
#organizationIdentifier=2.5.4.97
spid-privatesector-SP=1.3.76.16.4.3.1
spid-publicsector-SP=1.3.76.16.4.2.1
uri=2.5.4.83
[ dn ]
commonName=${COMMON_NAME}
countryName=IT
localityName=${LOCALITY_NAME}
organizationIdentifier=${ORGANIZATION_IDENTIFIER}
organizationName=${ORGANIZATION_NAME}
serialNumber=${SERIAL_NUMBER}
uri=${URI}
[ req_ext ]
certificatePolicies=@spid_policies
[ spid_policies ]
policyIdentifier=${POLICY_IDENTIFIER}
EOF

# generate selfsigned certificate

openssl req -new -x509 -config ${openssl_conf} \
    -days ${DAYS:=730} \
    -keyout privkey.pem -out cert.pem \
    -extensions req_ext

# dump (text) the certificate

openssl x509 -noout -text -in cert.pem

# dump (ASN.1) the certificate

openssl asn1parse -inform PEM \
    -oid oids.conf \
    -i -in cert.pem

# cleanup

rm -fr ${openssl_conf}
