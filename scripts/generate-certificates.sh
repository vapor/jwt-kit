# This gets called by the `generateTokens.swift` script. Do not modify!

#!/usr/bin/env bash
set -e -o pipefail

# Configuration variables
COUNTRY="US"
STATE="New York"
CITY="New York"
ORGANIZATION="Vapor"
ORGANIZATIONAL_UNIT="Engineering"
EMAIL="admin@vapor.example.com"

mkdir -p x5c_test_certs
pushd x5c_test_certs

# Function to generate subject string
generate_subject() {
    local prefix="$1"
    echo "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORGANIZATION/OU=$ORGANIZATIONAL_UNIT/CN=$ORGANIZATION $prefix/emailAddress=$EMAIL"
}

# Create Root Certificate
openssl ecparam -name prime256v1 -genkey -noout -out root_key.pem
openssl req -new -x509 -key root_key.pem -out root_cert.pem -days 3650 \
    -subj "$(generate_subject 'Root CA')" \
    -nodes

# Create Intermediate Certificate
openssl ecparam -name prime256v1 -genkey -noout -out intermediate_key.pem
openssl req -new -key intermediate_key.pem -out intermediate_csr.pem \
    -subj "$(generate_subject 'Intermediate CA')" \
    -nodes

echo 'basicConstraints=CA:TRUE' > intermediate_ext.txt
openssl x509 -req \
    -in intermediate_csr.pem \
    -CA root_cert.pem -CAkey root_key.pem \
    -CAcreateserial \
    -out intermediate_cert.pem \
    -days 1825 \
    -extfile intermediate_ext.txt

# Create Valid Leaf Certificate
openssl ecparam -name prime256v1 -genkey -noout -out leaf_key.pem
openssl req -new -key leaf_key.pem -out leaf_csr.pem \
    -subj "$(generate_subject 'Leaf')" \
    -nodes
openssl x509 -req -in leaf_csr.pem \
    -CA intermediate_cert.pem -CAkey intermediate_key.pem \
    -CAcreateserial \
    -out leaf_cert.pem -days 365

# Create Expired Leaf Certificate
openssl ecparam -name prime256v1 -genkey -noout -out expired_leaf_key.pem
openssl req -new -key expired_leaf_key.pem -out expired_leaf_csr.pem \
    -subj "$(generate_subject 'Expired Leaf')" \
    -nodes
openssl x509 -req -in expired_leaf_csr.pem \
    -CA intermediate_cert.pem -CAkey intermediate_key.pem \
    -CAcreateserial \
    -out expired_leaf_cert.pem \
    -not_before 200101010000Z \
    -not_after 200102010000Z

rm -f intermediate_ext.txt
popd
