import json
import pytest
from unittest.mock import patch, MagicMock

from backends.cieoidc.utils.clients.oauth2 import (
    OAuth2AuthorizationCodeGrant
)


@pytest.fixture
def grant():
    return OAuth2AuthorizationCodeGrant(
        grant_type="authorization_code",
        client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        jws_core={"keys": ["dummy"]},
        httpc_params={
            "connection": {"ssl": False},
            "session": {"timeout": 5},
        },
    )


@patch("backends.cieoidc.utils.clients.oauth2.requests.post")
@patch("backends.cieoidc.utils.clients.oauth2.create_jws")
@patch("backends.cieoidc.utils.clients.oauth2.get_key")
@patch("backends.cieoidc.utils.clients.oauth2.iat_now")
@patch("backends.cieoidc.utils.clients.oauth2.exp_from_now")
def test_us01(
    mock_exp,
    mock_iat,
    mock_get_key,
    mock_create_jws,
    mock_post,
    grant,
):
    mock_iat.return_value = 100
    mock_exp.return_value = 200
    mock_get_key.return_value = {"kty": "RSA"}
    mock_create_jws.return_value = "signed-jwt"

    response_payload = {"access_token": "abc123"}
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = json.dumps(response_payload).encode()
    mock_post.return_value = mock_response

    result = grant.access_token_request(
        redirect_uri="https://client/cb",
        state="state123",
        code="authcode",
        client_id="client123",
        token_endpoint_url="http://cie-provider.example.org:8002/oidc/op/token",
        code_verifier="verifier",
    )

    assert result == response_payload

    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    assert args[0] == "http://cie-provider.example.org:8002/oidc/op/token"
    assert kwargs["timeout"] == 5


@patch("backends.cieoidc.utils.clients.oauth2.requests.post")
@patch("backends.cieoidc.utils.clients.oauth2.create_jws")
@patch("backends.cieoidc.utils.clients.oauth2.get_key")
def test_us02(
    mock_get_key,
    mock_create_jws,
    mock_post,
    grant,
):
    mock_get_key.return_value = {"kty": "RSA"}
    mock_create_jws.return_value = "jwt"

    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_response.content = b"error"
    mock_post.return_value = mock_response

    result = grant.access_token_request(
        redirect_uri="cb",
        state="s",
        code="c",
        client_id="client",
        token_endpoint_url="http://cie-provider.example.org:8002/oidc/op/token",
    )

    assert result == mock_response


@patch("backends.cieoidc.utils.clients.oauth2.requests.post")
@patch("backends.cieoidc.utils.clients.oauth2.create_jws")
@patch("backends.cieoidc.utils.clients.oauth2.get_key")
@patch("backends.cieoidc.utils.clients.oauth2.iat_now")
@patch("backends.cieoidc.utils.clients.oauth2.exp_from_now")
def test_us03(
    mock_exp,
    mock_iat,
    mock_get_key,
    mock_create_jws,
    mock_post,
    grant,
):
    mock_iat.return_value = 100
    mock_exp.return_value = 200
    mock_get_key.return_value = {"kty": "RSA"}
    mock_create_jws.return_value = "signed-jwt"

    authorization = {
        "refresh_token": "refresh123",
        "client_id": "client123",
        "provider_configuration": {
            "token_endpoint": "http://cie-provider.example.org:8002/oidc/op/token"
        },
    }
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_post.return_value = mock_response

    result = grant.refresh_token(authorization, "client123")

    assert result == mock_response
    mock_post.assert_called_once()


@patch("backends.cieoidc.utils.clients.oauth2.create_jws")
@patch("backends.cieoidc.utils.clients.oauth2.get_key")
def test_us04(
    mock_get_key,
    mock_create_jws,
    grant,
):
    authorization = {
        "refresh_token": "refresh123",
        "client_id": "client123",
        "provider_configuration": {},
    }

    mock_get_key.return_value = {"kty": "RSA"}
    mock_create_jws.return_value = "jwt"
    result = grant.refresh_token(authorization, "client123")
    assert result is None


def test_us05(grant):
    conf = grant._OAuth2AuthorizationCodeGrant__get_rp_conf("client123")
    assert isinstance(conf, dict)
