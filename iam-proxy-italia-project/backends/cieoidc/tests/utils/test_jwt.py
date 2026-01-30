import pytest
from unittest.mock import patch
from backends.cieoidc.utils.helpers.jwt import decrypt_jwe
from cryptojwt.exception import UnsupportedAlgorithm

from backends.cieoidc.utils.helpers.jwt import (
    unpad_jwt_payload,
    create_jws,
    verify_at_hash,
)

def test_us01():
    jwt = (
        "eyJhbGciOiJSUzI1NiJ9."
        "eyJzdWIiOiJ1c2VyMTIzIn0."
        "signature"
    )
    payload = unpad_jwt_payload(jwt)
    assert payload["sub"] == "user123"

def test_us02():
    payload = {"sub": "user123"}
    jwk = {
        "kty": "RSA",
        "kid": "key1",
        "use": "sig",
        "n": "abc",
        "e": "AQAB",
        "d": "def",
    }

    with patch("cryptojwt.jwk.jwk.key_from_jwk_dict"):
        with patch("cryptojwt.jws.jws.JWS.sign_compact", return_value="signed.jwt"):
            jws = create_jws(payload, jwk)
            assert jws == "signed.jwt"

def test_us03():
    id_token = {"at_hash": "dummy"}
    with patch("cryptojwt.jws.utils.left_hash", return_value="dummy"):
        assert verify_at_hash(id_token, "access_token") is True

def test_us04():
    id_token = {"at_hash": "wrong"}
    with patch("cryptojwt.jws.utils.left_hash", return_value="correct"):
        with pytest.raises(Exception):
            verify_at_hash(id_token, "access_token")

