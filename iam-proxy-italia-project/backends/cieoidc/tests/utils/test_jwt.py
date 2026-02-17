import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.jwk.ec import ECKey
from unittest.mock import patch
from cryptojwt.jws.utils import left_hash

from backends.cieoidc.utils.helpers.jwtse import (
    unpad_jwt_head,
    unpad_jwt_payload,
    create_jwe,
    decrypt_jwe,
    create_jws,
    verify_at_hash,
)


@pytest.fixture
def rsa_jwk():
    priv = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    key = RSAKey(priv_key=priv, kid="rsa1")
    return key.serialize(private=True)


@pytest.fixture
def rsa_pub_jwk(rsa_jwk):
    return {k: v for k, v in rsa_jwk.items() if k != "d"}


@pytest.fixture
def ec_jwk():
    priv = ec.generate_private_key(ec.SECP256R1())
    key = ECKey(priv_key=priv, kid="ec1")
    return key.serialize(private=True)


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
        "use": "sig",
        "n": "uXfJA-wTlTCA4FdsoE0qZfmKIgedmarrtWgQbElKbWg9RDR7Z8JVBaRLFqwyfyG1JJFm64G51cBJwLIFwWoF7nxsH9VYLm5ocjAnsR4RhlfVE0y_60wjf8skJgBRpiXQPlwH9jDGaqVE_PEBTObDO5w3XourD1F360-v5cLDLRHdFJIitdEVtqATqY5DglRDaKiBhis7a5_1bk839PDLaQhju4XJk4tvDy5-LVkMy5sP2zU6-1tJdA-VmaBZLXy9n0967FGIWmMzpafrBMOuHFcUOH56o-clDah_CITH1dq2D64K0MYhEpACO2p8AH4K8Q6YuJ1dnkVDDwZp2C84sQ",  # noqa: E501
        "p": "5PA7lJEDd3vrw5hlolFzvjvRriOu1SMHXx9Y52AgpOeQ6MnE1pO8qwn33lwYTSPGYinaq4jS3FKF_U5vOZltJAGBMa4ByEvAROJVCh958rKVRWKIqVXLOi8Gk11kHbVKw6oDXAd8Qt_y_ff8k_K6jW2EbWm1K6kfTvTMzoHkqrU",  # noqa: E501
        "q": "z2QeMH4WtrdiWUET7JgZNX0TbcaVBgd2Gpo8JHnfnGOUsvO_euKGgqpCcxiWVXSlqffQyTgVzl4iMROP8bEaQwvueHurtziMDSy9Suumyktu3PbGgjqu_izRim8Xlg7sz8Hs2quJPII_fQ8BCoaWpg30osFZqCBarQM7CWhxR40",  # noqa: E501
        "d": "n_ePK5DdOxqArf75tDGaViYrXDqRVk8zyl2dfKiiR0dXQJK7tbzJtHoGQeH4E-sw3_-Bc7OKY7DcbBWgHTijMRWj9LkAu9uCvqqGMaAroWH0aBcUmZAsNjcyUIyJ3_JRcNfUDiX3nVg67qe4ZWnMDogowaVZv3aXJiCvKE8aJK4BV_nF3Nt5R6zUYpjZQ8T1GDZCV3vza3qglDrXe8zoc-p8cLs3rJn7tMVSJVznCIqOfeM1VIg0I3n2bubYOx88sckHuDnfXTiTDlyq5IwDyBHmiIe3fpu-c4e1tiBmbOf2IqDCaX8SdpnU2gTj9YlZtRNqmh3NB_rksBKWLz3uIQ",  # noqa: E501
        "e": "AQAB",
        "kid": "YhuIJU6o15EUCyqA0LHEqJd-xVPJgoyW5wZ1o4padWs"
    }

    with patch("cryptojwt.jwk.jwk.key_from_jwk_dict"):
        with patch("cryptojwt.jws.jws.JWS.sign_compact", return_value="signed.jwt"):
            jws = create_jws(payload, jwk)
            assert jws == "signed.jwt"


def test_us03():
    id_token = {"at_hash": "hrOQHuo3oE6FR82RIiX1SA"}
    with patch("cryptojwt.jws.utils.left_hash", return_value="hrOQHuo3oE6FR82RIiX1SA"):
        assert verify_at_hash(id_token, "access_token") is True


def test_us04():
    id_token = {"at_hash": "wrong"}
    with patch("cryptojwt.jws.utils.left_hash", return_value="correct"):
        with pytest.raises(Exception):
            verify_at_hash(id_token, "access_token")


def test_us05():
    header = {"alg": "none"}
    payload = {"a": 1}

    import base64
    import json
    jwt = (
        base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        + "."
        + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        + ".sig"
    )

    assert unpad_jwt_head(jwt) == header
    assert unpad_jwt_payload(jwt) == payload


def test_us06(rsa_jwk):
    jwe = create_jwe(
        {"foo": "bar"},
        rsa_jwk,
        default_jwe_alg="RSA-OAEP",
        default_jwe_enc="A256GCM",
    )
    assert isinstance(jwe, str)


def test_us07(rsa_jwk):
    jwe = create_jwe(
        None,
        rsa_jwk,
        default_jwe_alg="RSA-OAEP",
        default_jwe_enc="A256GCM",
    )
    assert isinstance(jwe, str)


def test_us08(rsa_jwk):
    jwe = create_jwe(
        set([1, 2]),
        rsa_jwk,
        default_jwe_alg="RSA-OAEP",
        default_jwe_enc="A256GCM",
    )
    assert isinstance(jwe, str)


def test_us09(rsa_jwk):
    jwe = create_jwe(
        {"x": 1},
        rsa_jwk,
        "RSA-OAEP",
        "A256GCM",
    )

    out = decrypt_jwe(
        jwe,
        rsa_jwk,
        "RSA-OAEP",
        "A256GCM",
        encryption_alg_values_supported=["RSA-OAEP"],
    )

    assert out == {"x": 1}


def test_us10(rsa_jwk):
    jwe = create_jwe(
        {"x": 1},
        rsa_jwk,
        "RSA-OAEP",
        "A256GCM",
    )

    import pytest
    from cryptojwt.exception import UnsupportedAlgorithm

    with pytest.raises(UnsupportedAlgorithm):
        decrypt_jwe(
            jwe,
            rsa_jwk,
            "RSA-OAEP",
            "A256GCM",
            encryption_alg_values_supported=[],
        )


def test_us11():
    access_token = "access"
    at_hash = left_hash(access_token, "HS256")

    id_token = {"at_hash": at_hash}

    assert verify_at_hash(id_token, access_token) is True


def test_us12():
    import pytest

    with pytest.raises(Exception):
        verify_at_hash({"at_hash": "wrong"}, "access")
