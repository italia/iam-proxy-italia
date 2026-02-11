import json
import pytest
from unittest.mock import patch, MagicMock

from backends.cieoidc.utils.validators import (
    validate_public_jwks,
    validate_private_jwks,
    validate_metadata_algs,
    validate_metadata_algs_v1,
    ValidationError,
    SIGNING_ALG_VALUES_SUPPORTED,
    ENCRYPTION_ALG_VALUES_SUPPORTED,
    ENCRYPTION_ENC_SUPPORTED,
)


@patch("backends.cieoidc.utils.validators.key_from_jwk_dict")
def test_validate_public_jwks_success(mock_key_from_jwk):
    key = MagicMock()
    key.private_key.return_value = False
    mock_key_from_jwk.return_value = key
    jwks = [{"kty": "RSA", "kid": "pub"}]
    validate_public_jwks(jwks)


@patch("backends.cieoidc.utils.validators.serialize_rsa_key")
@patch("backends.cieoidc.utils.validators.key_from_jwk_dict")
def test_validate_public_jwks_private_key_rejected(
    mock_key_from_jwk, mock_serialize
):
    key = MagicMock()
    key.private_key.return_value = True
    key.public_key.return_value = "pubkey"
    mock_key_from_jwk.return_value = key
    mock_serialize.return_value = {"kty": "RSA", "kid": "pub"}
    jwks = {"kty": "RSA", "kid": "priv"}
    with pytest.raises(ValidationError):
        validate_public_jwks(jwks)


@patch("backends.cieoidc.utils.validators.key_from_jwk_dict")
def test_validate_public_jwks_invalid_jwk(mock_key_from_jwk):
    mock_key_from_jwk.side_effect = Exception("invalid jwk")
    with pytest.raises(ValidationError):
        validate_public_jwks({"invalid": True})

@patch("backends.cieoidc.utils.validators.key_from_jwk_dict")
def test_validate_private_jwks_success(mock_key_from_jwk):
    key = MagicMock()
    key.private_key.return_value = True
    mock_key_from_jwk.return_value = key
    validate_private_jwks({"kty": "RSA"})


@patch("backends.cieoidc.utils.validators.key_from_jwk_dict")
def test_validate_private_jwks_public_key_rejected(mock_key_from_jwk):
    key = MagicMock()
    key.private_key.return_value = False
    mock_key_from_jwk.return_value = key
    with pytest.raises(ValidationError):
        validate_private_jwks({"kty": "RSA"})


@patch("backends.cieoidc.utils.validators.key_from_jwk_dict")
def test_validate_private_jwks_invalid_jwk(mock_key_from_jwk):
    mock_key_from_jwk.side_effect = Exception("boom")
    with pytest.raises(ValidationError):
        validate_private_jwks({"invalid": True})

def test_validate_metadata_algs_success():
    metadata = {
        "openid_provider": {
            "id_token_signing_alg_values_supported": ["RS256"],
            "userinfo_encryption_alg_values_supported": ["RSA-OAEP"],
            "userinfo_encryption_enc_values_supported": ["A256GCM"],
        }
    }
    validate_metadata_algs(metadata)


def test_validate_metadata_algs_unsupported_signing_alg():
    metadata = {
        "openid_provider": {
            "id_token_signing_alg_values_supported": ["HS256"],
        }
    }
    with pytest.raises(ValidationError):
        validate_metadata_algs(metadata)


def test_validate_metadata_algs_ignored_when_no_openid_provider():
    metadata = {
        "some_other_entity": {
            "id_token_signing_alg_values_supported": ["HS256"]
        }
    }
    validate_metadata_algs(metadata)

def test_validate_metadata_algs_v1_success():
    metadata = {
        "openid_provider": {
            "id_token_signing_alg_values_supported": ["RS256"],
            "userinfo_encryption_alg_values_supported": ["RSA-OAEP"],
            "userinfo_encryption_enc_values_supported": ["A256GCM"],
        }
    }
    validate_metadata_algs_v1(
        signing_alg_values_supported=["RS256"],
        encryption_alg_values_supported=["RSA-OAEP"],
        metadata=metadata,
    )


def test_validate_metadata_algs_v1_unsupported_alg():
    metadata = {
        "openid_provider": {
            "id_token_signing_alg_values_supported": ["HS256"],
        }
    }
    with pytest.raises(ValidationError):
        validate_metadata_algs_v1(
            signing_alg_values_supported=["RS256"],
            encryption_alg_values_supported=["RSA-OAEP"],
            metadata=metadata,
        )


def test_validate_metadata_algs_v1_none_supported_lists():
    metadata = {
        "openid_provider": {}
    }
    validate_metadata_algs_v1(
        signing_alg_values_supported=None,
        encryption_alg_values_supported=None,
        metadata=metadata,
    )