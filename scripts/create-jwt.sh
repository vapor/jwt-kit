#!/usr/bin/env bash

# Function to convert a string to base64 URL encoding
function b64url() { 
    echo "${1}" | openssl base64 -a -A | tr '+' '-' | tr '/' '_' | tr -d '='
}

# Read and concatenate certificate files, remove PEM header/footer lines and newlines
certs=$(cat root_cert.pem intermediate_cert.pem leaf_cert.pem | 
        sed '/-----/d' | tr -d '\n')

# Base64 URL encode the JWT Header with embedded certificate chain
hdr="$(b64url '{"alg":"ES256","typ":"JWT","x5c":["'"${certs}"'"]}')"

# Base64 URL encode the JWT Payload
pld="$(b64url '{"cool":true}')"

# Concatenate the encoded header and payload
msg="${hdr}.${pld}"

# Sign the message using the private key and Base64 URL encode the signature
# Ensure that the message is hashed if necessary
sig=$(echo -n "${msg}" | openssl dgst -sha256 -sign leaf_key.pem | b64url)

# Concatenate the header, payload, and signature to form the JWT
jwt="${msg}.${sig}"

# Output the JWT
echo "${jwt}"
