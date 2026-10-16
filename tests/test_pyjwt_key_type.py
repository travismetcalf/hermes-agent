"""Contract for the PyJWT version shipped with Hermes."""

import base64
import hmac

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def test_pem_public_key_cannot_be_used_as_hmac_secret():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # This format remains a valid RSA public key after a config round trip.
    formatted_public_pem = public_pem.replace(b"-----END", b"\t-----END")

    signed = jwt.encode({"sub": "user"}, private_pem, algorithm="RS256")
    assert jwt.decode(signed, formatted_public_pem, algorithms=["RS256"]) == {
        "sub": "user"
    }

    header = b"eyJhbGciOiJIUzI1NiJ9"  # {"alg":"HS256"}
    payload = b"eyJzdWIiOiJ1c2VyIn0"  # {"sub":"user"}
    signing_input = header + b"." + payload
    signature = base64.urlsafe_b64encode(
        hmac.digest(formatted_public_pem, signing_input, "sha256")
    ).rstrip(b"=")
    token = signing_input + b"." + signature

    with pytest.raises(jwt.InvalidKeyError):
        jwt.decode(token, formatted_public_pem, algorithms=["RS256", "HS256"])
