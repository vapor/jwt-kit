import jwt
import cryptography

# This script creates a JWT token with an x5c array in the header.
# The certs are loaded from the filesystem using the commands which are in the create-certs.sh file.
# To load different certs into the x5c header, change the x5c array below.

# Load base64-encoded certificates
with open('root_cert.pem', 'r') as f:
    root_cert = f.read().strip()
    root_cert = root_cert.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "")
with open('intermediate_cert.pem', 'r') as f:
    intermediate_cert = f.read().strip()
    intermediate_cert = intermediate_cert.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "")
with open('leaf_cert.pem', 'r') as f:
    leaf_cert = f.read().strip()
    leaf_cert = leaf_cert.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", "")

# Create JWT token with x5c array
payload = {"cool": False}
key = open("leaf_key.pem").read()
x5c = [leaf_cert, intermediate_cert, root_cert]
token = jwt.encode(payload, algorithm="ES256", key=key, headers={"x5c": x5c})

print(token)
