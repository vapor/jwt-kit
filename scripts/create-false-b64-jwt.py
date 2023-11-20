import json
import base64
import hmac
import hashlib

# This script is used to generate a JWT with the b64 header set to false.

def base64url_encode(input):
    return base64.urlsafe_b64encode(input).rstrip(b'=').decode('utf-8')

def generate_jwt_with_b64_false(payload, secret):
    header = {
        "alg": "HS256",
        "typ": "JWT",
        "b64": False
    }
    encoded_header = base64url_encode(json.dumps(header).encode())

    raw_payload = json.dumps(payload)

    signing_input = f"{encoded_header}.{raw_payload}".encode()
    signature = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    encoded_signature = base64url_encode(signature)

    return f"{encoded_header}.{raw_payload}.{encoded_signature}"

payload = {
    "sub": "1234567890", 
    "name": "John Doe", 
    "exp": 2000000000, 
    "admin": False
}
secret = "secret"

jwt_token = generate_jwt_with_b64_false(payload, secret)
print(jwt_token)
