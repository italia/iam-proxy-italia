import json
import pytest
from unittest.mock import MagicMock, patch

from datetime import datetime, timezone

from backends.cieoidc.endpoints.authorization_endpoint import AuthorizationHandler



@pytest.fixture
def minimal_config():
    return {
        "entity_type": "openid_relying_party",
        "jwks_core": [{"kty": "RSA", "use": "sig"}],
        "prompt": "login",
        "metadata": {
            "openid_relying_party": {
                "client_id": "client123",
                "redirect_uris": ["https://client/callback"],
                "scope": "openid",
                "claim": {"userinfo": {"email": None}},
                "response_types": ["code"],
                "code_challenge": {
                    "length": 32,
                    "method": "S256"
                }
            }
        },
        "endpoints": {
            "authorization_endpoint": {
                "config": {
                    "metadata": {
                        "openid_relying_party": {
                            "client_id": "client123",
                            "redirect_uris": ["https://client/callback"]
                        }
                    }
                }
            }
        }
    }


@pytest.fixture
def context():
    ctx = MagicMock()
    ctx.internal_data = {"target_entity_id": "https://op.example"}
    return ctx


@pytest.fixture
def trust_chain():
    tc = MagicMock()
    tc.subject = "https://op.example"
    tc.subject_configuration.payload = {
        "metadata": {
            "openid_provider": {
                "authorization_endpoint": "https://op.example/auth"
            }
        }
    }
    return tc


@pytest.fixture
def handler(minimal_config, trust_chain):
    with patch("backends.cieoidc.storage.db_engine.OidcDbEngine") as db_mock:
        db = db_mock.return_value
        db.connect.return_value = None
        db.add_session.return_value = 1

        h = AuthorizationHandler(
            config=minimal_config,
            internal_attributes={},
            base_url="https://proxy",
            name="authz",
            auth_callback_func=MagicMock(),
            converter=MagicMock(),
            trust_chains={"https://op.example": trust_chain}
        )
        return h



def test_validate_configs_ok(handler):
    handler._validate_configs()


def test_validate_configs_missing_field(minimal_config):
    del minimal_config["endpoints"]

    with patch("backends.cieoidc.storage.db_engine.OidcDbEngine"):
        handler = AuthorizationHandler(
            config=minimal_config,
            internal_attributes={},
            base_url="x",
            name="x",
            auth_callback_func=MagicMock(),
            converter=MagicMock(),
            trust_chains={}
        )

    with pytest.raises(ValueError):
        handler._validate_configs()


@patch("backends.cieoidc.utils.utils.helpers.misc.get_pkce")
@patch("backends.cieoidc.utils.utils.helpers.jwtse.create_jws")
@patch("backends.cieoidc.utils.utils.helpers.misc.get_key")
@patch("satosa.response.Redirect")
def test_endpoint_happy_path(
    redirect_mock,
    get_key_mock,
    create_jws_mock,
    get_pkce_mock,
    handler,
    context
):
    get_pkce_mock.return_value = {
        "code_challenge": "abc",
        "code_challenge_method": "S256"
    }
    get_key_mock.return_value = {"kty": "RSA"}
    create_jws_mock.return_value = "signed.jwt"

    response = handler.endpoint(context)

    # Redirect creato
    redirect_mock.assert_called_once()
    assert response == redirect_mock.return_value

    # PKCE generato
    get_pkce_mock.assert_called_once()

    # JWS creato
    create_jws_mock.assert_called_once()


def test_pkce_generation_missing_length(handler):
    handler.config["metadata"]["openid_relying_party"]["code_challenge"]["length"] = None

    with pytest.raises(ValueError):
        handler._AuthorizationHandler__pkce_generation({})


def test_generate_uri():
    authz_data = {
        "client_id": "client123",
        "scope": "openid",
        "response_type": "code",
        "code_challenge": "abc",
        "code_challenge_method": "S256",
        "request": "jwt"
    }

    with patch(
        "backends.cieoidc.utils.utils.helpers.misc.http_dict_to_redirect_uri_path"
    ) as uri_mock:
        uri_mock.return_value = "client_id=client123"

        uri = AuthorizationHandler.generate_uri(authz_data)

        assert uri == "client_id=client123"
        uri_mock.assert_called_once()


@patch("backends.cieoidc.models.oidc_auth.OidcAuthentication")
def test_insert_called(mock_auth, handler):
    handler._db_engine.add_session.return_value = 1

    handler._AuthorizationHandler__insert({
        "client_id": "client123",
        "state": "state",
        "endpoint": "x",
        "provider_id": "y",
        "data": "{}",
        "provider_configuration": {}
    })

    mock_auth.assert_called_once()
