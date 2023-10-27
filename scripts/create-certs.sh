#!/usr/bin/env bash

set -e -o pipefail

mkdir jwt_x5c_certs
pushd jwt_x5c_certs

# Create a Root Certificate (self-signed):

# Generate a private key for the Root CA
openssl ecparam -name prime256v1 -genkey -noout -out root_key.pem

# Create a self-signed Root certificate
openssl req -new -x509 -key root_key.pem -out root_cert.pem -days 3650

# Create an Intermediate CA Certificate (signed by the Root, and itself a CA):

# Generate a private key for the Intermediate CA
openssl ecparam -name prime256v1 -genkey -noout -out intermediate_key.pem

# Create a certificate signing request for the Intermediate CA
openssl req -new -key intermediate_key.pem -out intermediate_csr.pem

# Sign the Intermediate CA certificate with the Root, specifying the basicConstraints extension
openssl x509 -req \
    -in intermediate_csr.pem \
    -CA root_cert.pem -CAkey root_key.pem \
    -out intermediate_cert.pem \
    -days 1825 \
    -extfile <(echo 'basicConstraints=CA:TRUE')

# Create a Leaf Certificate (signed by the Intermediate):

# Generate a private key for the Leaf certificate
openssl ecparam -name prime256v1 -genkey -noout -out leaf_key.pem

# Create a certificate signing request (CSR) for the Leaf
openssl req -new -key leaf_key.pem -out leaf_csr.pem

# Sign the Leaf certificate with the Intermediate
openssl x509 -req -in leaf_csr.pem -CA intermediate_cert.pem -CAkey intermediate_key.pem -out leaf_cert.pem -days 365

# Create a Leaf Expired Certificate

# Generate a private key for the Leaf certificate
openssl ecparam -name prime256v1 -genkey -noout -out expired_leaf_key.pem

# Create a certificate signing request (CSR) for the Leaf
openssl req -new -key expired_leaf_key.pem -out expired_leaf_csr.pem

# Sign the Leaf certificate with the Intermediate
openssl x509 -req -in expired_leaf_csr.pem -CA intermediate_cert.pem -CAkey intermediate_key.pem -out expired_leaf_cert.pem -days -1

popd
