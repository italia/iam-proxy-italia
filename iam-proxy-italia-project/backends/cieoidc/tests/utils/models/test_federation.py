import json
import pytest
from unittest.mock import patch, MagicMock, PropertyMock

from backends.cieoidc.models.federation import FederationEntityConfiguration, is_leaf


@pytest.fixture
def jwk_example():
    return [{
        "kty": "RSA",
        "kid": "key1",
        "n": "modulus",
        "e": "AQAB",
        "d": "private"
    }]


@pytest.fixture
def jwks_example():
    return [{
        "kty": "RSA",
        "kid": "key1",
        "n": "modulus",
        "e": "AQAB",
        "d": "private"
    }]


@pytest.fixture
def metadata_leaf():
    return {"openid_relying_party": {"client_id": "client123"}}


@pytest.fixture
def metadata_non_leaf():
    return {"some_other_type": {"info": "data"}}


@pytest.fixture
def federation_entity(jwk_example, metadata_leaf):
    return FederationEntityConfiguration(
        sub="https://example.org",
        exp=3600,
        default_signature_alg="RS256",
        jwks_core=jwk_example,
        jwks_fed=jwk_example,
        entity_type="openid_relying_party",
        metadata=metadata_leaf,
        authority_hints=["https://trust-anchor.example.org"]
    )


def test_us01(metadata_leaf):
    assert is_leaf(metadata_leaf) is True


def test_us02(metadata_non_leaf):
    assert is_leaf(metadata_non_leaf) is None


@patch("backends.cieoidc.utils.helpers.jwks.serialize_rsa_key")
@patch("cryptojwt.jwk.jwk.key_from_jwk_dict")
def test_us03(mock_key_from_jwk, mock_serialize, federation_entity, jwk_example):
    mock_pub = MagicMock()
    mock_key_from_jwk.return_value.public_key.return_value = mock_pub
    mock_serialize.return_value = {"kty": "RSA"}

    res = federation_entity.public_jwks
    assert res[0]["kty"] == "RSA"
    assert res[0]["kid"] == jwk_example[0]["kid"]


@patch("backends.cieoidc.models.federation.private_pem_from_jwk")
@patch("backends.cieoidc.models.federation.public_pem_from_jwk")
def test_us04(mock_public_pem, mock_private_pem, federation_entity, jwk_example):
    mock_private_pem.return_value = "PRIVATE"
    mock_public_pem.return_value = "PUBLIC"

    res = federation_entity.pems_as_dict

    assert res == {
        "key1": {
            "private": "PRIVATE",
            "public": "PUBLIC",
        }
    }


def test_us05(federation_entity):
    with patch(
        "backends.cieoidc.models.federation.FederationEntityConfiguration.pems_as_dict",
        new_callable=PropertyMock,
            return_value={"k": "v"}):
        res = federation_entity.pems_as_json
        assert json.loads(res) == {"k": "v"}


def test_us06(federation_entity, jwk_example):
    assert federation_entity.kids == [jwk_example[0]["kid"]]


def test_us07(federation_entity, metadata_leaf):
    assert federation_entity.type == list(metadata_leaf.keys())


def test_us08(federation_entity):
    assert federation_entity.is_leaf is True


@patch("backends.cieoidc.models.federation.exp_from_now", return_value=12345)
@patch("backends.cieoidc.models.federation.iat_now", return_value=67890)
def test_us09(mock_iat, mock_exp, federation_entity):
    conf = federation_entity.entity_configuration_as_dict
    assert conf["exp"] == 12345
    assert conf["iat"] == 67890
    assert conf["iss"] == federation_entity.sub
    assert "jwks" in conf
    assert conf["metadata"] == federation_entity.metadata


def test_us10(federation_entity):
    with patch(
        "backends.cieoidc.models.federation.FederationEntityConfiguration.entity_configuration_as_dict",
        new_callable=PropertyMock,
        return_value={"a": 1},
    ):
        res = federation_entity.entity_configuration_as_json
        assert json.loads(res) == {"a": 1}


@patch("backends.cieoidc.models.federation.create_jws")
def test_us11(mock_create_jws, federation_entity):
    mock_create_jws.return_value = "signed.jwt"
    res = federation_entity.entity_configuration_as_jws
    assert res == "signed.jwt"
    mock_create_jws.assert_called_once()


def test_us12(federation_entity):
    federation_entity.metadata["federation_entity"] = {"federation_fetch_endpoint": "https://fetch.example"}
    assert federation_entity.fetch_endpoint == "https://fetch.example"


def test_us13(federation_entity):
    federation_entity.jwks_fed = {"k": "v"}
    federation_entity.jwks_core = {"k": "v"}
    federation_entity.set_jwks_as_array()
    assert isinstance(federation_entity.jwks_fed, list)
    assert isinstance(federation_entity.jwks_core, list)
