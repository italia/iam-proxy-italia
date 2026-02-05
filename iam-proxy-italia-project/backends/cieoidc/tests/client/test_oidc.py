import json
import pytest
from unittest.mock import patch, MagicMock

from backends.cieoidc.oauth2.oidc_userinfo import OidcUserInfo
from backends.cieoidc.utils.exceptions import UnknownKid
from backends.cieoidc.helpers.configuration_utils import ConfigurationPlugin

@pytest.fixture
def provider_config():
    return {"userinfo_endpoint": "https://op/userinfo"}


@pytest.fixture
def jwks_core():
    return [{"kid": "core-kid", "kty": "RSA"}]


@pytest.fixture
def httpc_params():
    return {"connection": {"ssl": False}, "session": {"timeout": 5}}


@pytest.fixture
def configuration_utils():
    utils = MagicMock(spec=ConfigurationPlugin)
    utils.get_default_jwe_alg = "RSA-OAEP"
    utils.get_default_jwe_enc = "A256GCM"
    utils.get_encryption_alg_values_supported = ["RSA-OAEP"]
    utils.get_signing_alg_values_supported = ["RS256"]
    return utils


@pytest.fixture
def userinfo(provider_config, jwks_core, httpc_params):
    return OidcUserInfo(provider_config, jwks_core, httpc_params)

@patch("backends.cieoidc.oauth2.oidc_userinfo.requests.get")
def test_get_userinfo_plain_json(mock_get, userinfo, configuration_utils):
    response_payload = {"sub": "user123"}
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = response_payload
    mock_response.content = json.dumps(response_payload).encode()
    mock_get.return_value = mock_response

    result = userinfo.get_userinfo(
        state="state123",
        access_token="token123",
        verify=False,
        timeout=5,
        configuration_utils=configuration_utils,
    )

    assert result == response_payload
    mock_get.assert_called_once_with(
        "https://op/userinfo",
        headers={"Authorization": "Bearer token123"},
        verify=False,
        timeout=5,
    )

@patch("backends.cieoidc.oauth2.oidc_userinfo.requests.get")
def test_get_userinfo_http_error(mock_get, userinfo, configuration_utils):
    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_get.return_value = mock_response

    result = userinfo.get_userinfo(
        state="state123",
        access_token="token123",
        verify=True,
        timeout=5,
        configuration_utils=configuration_utils,
    )

    assert result is False

@patch("backends.cieoidc.oauth2.oidc_userinfo.verify_jws")
@patch("backends.cieoidc.oauth2.oidc_userinfo.get_jwks")
@patch("backends.cieoidc.oauth2.oidc_userinfo.decrypt_jwe")
@patch("backends.cieoidc.oauth2.oidc_userinfo.unpad_jwt_head")
@patch("backends.cieoidc.oauth2.oidc_userinfo.requests.get")
def test_get_userinfo_jwe_jws(mock_get, mock_unpad, mock_decrypt, mock_get_jwks, mock_verify, userinfo, configuration_utils):
    # response finta
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = b"fake-jwe"
    mock_response.json.side_effect = Exception("not json")
    mock_get.return_value = mock_response

    # unpad jwt header
    mock_unpad.side_effect = [
        {"kid": "core-kid"},  # header JWE
        {"kid": "idp-kid"}    # header JWS
    ]

    mock_decrypt.return_value = b"fake-jws"
    mock_get_jwks.return_value = [{"kid": "idp-kid"}]
    mock_verify.return_value = {"sub": "user123"}

    result = userinfo.get_userinfo(
        state="state123",
        access_token="token123",
        verify=True,
        timeout=5,
        configuration_utils=configuration_utils,
    )

    assert result == {"sub": "user123"}
    assert mock_decrypt.called
    assert mock_verify.called

@patch("backends.cieoidc.oauth2.oidc_userinfo.requests.get")
def test_get_userinfo_unknown_kid(mock_get, userinfo, configuration_utils):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = b"fake"
    mock_response.json.side_effect = Exception("not json")
    mock_get.return_value = mock_response

    # Sovrascriviamo il metodo privato per forzare UnknownKid
    userinfo._OidcUserInfo__get_jwk = lambda kid, jwks: (_ for _ in ()).throw(UnknownKid())

    result = userinfo.get_userinfo(
        state="state123",
        access_token="token123",
        verify=True,
        timeout=5,
        configuration_utils=configuration_utils,
    )

    assert result is False

@patch("backends.cieoidc.oauth2.oidc_userinfo.requests.get")
@patch("backends.cieoidc.oauth2.oidc_userinfo.unpad_jwt_head")
@patch("backends.cieoidc.oauth2.oidc_userinfo.decrypt_jwe")
def test_get_userinfo_key_error(mock_decrypt, mock_unpad, mock_get, userinfo, configuration_utils):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = b"fake"
    mock_response.json.side_effect = Exception("not json")
    mock_get.return_value = mock_response

    # unpad restituisce header senza 'kid'
    mock_unpad.return_value = {}

    result = userinfo.get_userinfo(
        state="state123",
        access_token="token123",
        verify=True,
        timeout=5,
        configuration_utils=configuration_utils,
    )

    assert result is False
