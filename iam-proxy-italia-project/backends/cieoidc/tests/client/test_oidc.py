import json
import pytest
from unittest.mock import patch, MagicMock

from backends.cieoidc.utils.clients.oidc import OidcUserInfo
from backends.cieoidc.utils.exceptions import UnknownKid
from backends.cieoidc.utils.helpers.configuration_utils import ConfigurationPlugin

@pytest.fixture
def provider_config():
    return {"userinfo_endpoint": "http://cie-provider.example.org:8002/oidc/op/userinfo"}


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
@patch("backends.cieoidc.utils.clients.oidc.requests.get")
def test_us01(mock_get, userinfo, configuration_utils):
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
        "http://cie-provider.example.org:8002/oidc/op/userinfo",
        headers={"Authorization": "Bearer token123"},
        verify=False,
        timeout=5,
    )

@patch("backends.cieoidc.utils.clients.oidc.requests.get")
def test_us02(mock_get, userinfo, configuration_utils):
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

@patch("backends.cieoidc.utils.clients.oidc.requests.get")
@patch("backends.cieoidc.utils.clients.oidc.unpad_jwt_head")
@patch("backends.cieoidc.utils.clients.oidc.decrypt_jwe")
@patch("backends.cieoidc.utils.clients.oidc.get_jwks")
@patch("backends.cieoidc.utils.clients.oidc.verify_jws")
def test_us03(mock_verify, mock_get_jwks, mock_decrypt, mock_unpad, mock_get, userinfo, configuration_utils):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = b"fake-jwe"
    mock_response.json.side_effect = Exception("not json")
    mock_get.return_value = mock_response
    mock_unpad.side_effect = [
        {"kid": "core-kid"},
        {"kid": "idp-kid"}
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

@patch("backends.cieoidc.utils.clients.oidc.requests.get")
def test_us04(mock_get, userinfo, configuration_utils):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = b"fake"
    mock_response.json.side_effect = Exception("not json")
    mock_get.return_value = mock_response
    userinfo._OidcUserInfo__get_jwk = lambda kid, jwks: (_ for _ in ()).throw(UnknownKid())

    result = userinfo.get_userinfo(
        state="state123",
        access_token="token123",
        verify=True,
        timeout=5,
        configuration_utils=configuration_utils,
    )

    assert result is False

@patch("backends.cieoidc.utils.clients.oidc.requests.get")
@patch("backends.cieoidc.utils.clients.oidc.unpad_jwt_head")
@patch("backends.cieoidc.utils.clients.oidc.decrypt_jwe")
def test_us05(mock_decrypt, mock_unpad, mock_get, userinfo, configuration_utils):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = b"fake"
    mock_response.json.side_effect = Exception("not json")
    mock_get.return_value = mock_response
    mock_unpad.return_value = {}

    result = userinfo.get_userinfo(
        state="state123",
        access_token="token123",
        verify=True,
        timeout=5,
        configuration_utils=configuration_utils,
    )

    assert result is False