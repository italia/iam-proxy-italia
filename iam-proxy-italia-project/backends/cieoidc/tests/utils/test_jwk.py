from cryptojwt.jwk.rsa import new_rsa_key
from backends.cieoidc.utils.helpers.jwks import (
    create_jwk,
    public_jwk_from_private_jwk,
    private_pem_from_jwk,
    public_pem_from_jwk,
)

def test_us01():
    jwk = create_jwk()
    assert "kid" in jwk
    assert jwk["kty"] == "RSA"

def test_us02():
    jwk = create_jwk()
    pub = public_jwk_from_private_jwk(jwk)
    assert "d" not in pub
    assert pub["kid"] == jwk["kid"]

def test_us03():
    jwk = create_jwk()
    pem = private_pem_from_jwk(jwk)
    assert pem.startswith("-----BEGIN RSA PRIVATE KEY-----")

def test_us04():
    jwk = create_jwk()
    pem = public_pem_from_jwk(jwk)
    assert pem.startswith("-----BEGIN PUBLIC KEY-----")