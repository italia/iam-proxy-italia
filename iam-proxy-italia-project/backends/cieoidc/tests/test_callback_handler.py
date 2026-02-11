import pytest
from unittest.mock import MagicMock, patch
from satosa.context import Context
from satosa.response import Response
from backends.cieoidc.endpoints.authorization_callback_endpoint import AuthorizationCallBackHandler
from ..utils.clients.oidc import OidcUserInfo
from satosa.exception import SATOSAAuthenticationError, SATOSABadRequestError


@pytest.fixture(autouse=True)
def mock_db_engine():
    with patch(
        "backends.cieoidc.endpoints.authorization_callback_endpoint.OidcDbEngine"
    ) as mock_engine:
        instance = mock_engine.return_value
        instance.connect.return_value = None
        instance.is_connected.return_value = True
        instance.get_sessions.return_value = [MagicMock(model_dump=lambda mode: {
            "state": "dummy_state",
            "provider_id": "http://cie-provider.example.org:8002/oidc/op",
            "client_id": "client123",
            "data": '{"redirect_uri":"http://satosa-nginx.example.org/cb"}',
            "provider_configuration": {
                "openid_provider": {
                    "token_endpoint": "http:/cie-provider.example.org/op/token"
                }
            }
        })]
        instance.update_session.return_value = True
        yield


@pytest.fixture
def handler():
    config = {
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "grant_type": "authorization_code",
        "jwks_core": {},
        "httpc_params": {"connection": {"ssl": False}, "session": {"timeout": 5}},
        "claims": {},
        "metadata": {"openid_relying_party": {"client_id": "client123"}},
        "db_config": {"mongo_db":{"module":"backends.cieoidc.storage.impl.mongo_storage","class":"MongoStorage","init_params":{"url":"mongodb://localhost:27017"}}}
    }

    auth_callback_func = MagicMock(return_value=Response("OK"))
    converter = MagicMock()
    trust_evaluator = MagicMock()
    internal_attributes = {}

    return AuthorizationCallBackHandler(
        config=config,
        internal_attributes=internal_attributes,
        base_url="http://localhost",
        name="test_handler",
        auth_callback_func=auth_callback_func,
        converter=converter,
        trust_evaluator=trust_evaluator
    )

@pytest.mark.parametrize("qs_params", [
    {"error": "invalid_request"},
    {"state": None},
    {"code": None},
])
def test_us01(handler, qs_params):
    context = Context()
    context.qs_params = qs_params
    with pytest.raises(Exception):
        handler.endpoint(context)


def test_us02(handler):
    context = Context()
    context.qs_params = {"state": "dummy_state", "code": "code123", "iss": "http://other-provider"}
    with pytest.raises(SATOSABadRequestError):
        handler.endpoint(context)


def test_us03(handler):
    context = Context()
    context.state = MagicMock()
    context.qs_params = {"state": "nonexistent_state", "code": "code123", "iss": "http://cie-provider.example.org:8002/oidc/op"}
    with patch.object(handler, "_AuthorizationCallBackHandler__get_authorization", return_value=None):
        with pytest.raises(SATOSAAuthenticationError):
            handler.endpoint(context)

@patch.object(OidcUserInfo, "get_userinfo", return_value={"email": "test@example.com"})
@pytest.mark.parametrize("state, code, iss", [("dummy_state", "dummy_code", "http://cie-provider.example.org:8002/oidc/op")])
def test_us04(handler, state, code, iss):
    context = Context()
    context.qs_params = {"state": state, "code": code, "iss": iss}

    with patch("backends.cieoidc.endpoints.authorization_callback_endpoint.get_jwks", return_value={"keys": []}), \
         patch("backends.cieoidc.endpoints.authorization_callback_endpoint.get_jwk_from_jwt", return_value={"kid": "key1"}), \
         patch("backends.cieoidc.endpoints.authorization_callback_endpoint.verify_jws", return_value=True), \
         patch("backends.cieoidc.endpoints.authorization_callback_endpoint.unpad_jwt_payload",
               return_value={"sub": "user123", "at_hash": "dummy"}), \
         patch("backends.cieoidc.endpoints.authorization_callback_endpoint.verify_at_hash"), \
         patch("backends.cieoidc.endpoints.authorization_callback_endpoint.process_user_attributes",
               return_value={"email": "test@example.com"}), \
         patch.object(handler, "_AuthorizationCallBackHandler__access_token_request", return_value={
             "access_token": "dummy_access_token",
             "id_token": "dummy_id_token",
             "expires_in": 3600,
             "token_type": "Bearer",
             "scope": "openid"
         }):
        response = handler.endpoint(context)
        assert response


def test_us05(handler):
    context = Context()
    context.state = MagicMock()
    context.qs_params = {"state": "dummy_state", "code": "dummy_code",
                         "iss": "http://cie-provider.example.org:8002/oidc/op"}

    with patch("backends.cieoidc.utils.clients.oidc.OidcUserInfo.get_userinfo", return_value=None), \
         patch("backends.cieoidc.utils.clients.oauth2.OAuth2AuthorizationCodeGrant.access_token_request",
               return_value={"access_token": "t", "id_token": "t", "token_type": "Bearer", "expires_in": 1}), \
         patch("backends.cieoidc.endpoints.authorization_callback_endpoint.get_jwks", return_value={"keys": []}), \
         patch("backends.cieoidc.endpoints.authorization_callback_endpoint.get_jwk_from_jwt", return_value={"kid": "k"}), \
         patch("backends.cieoidc.endpoints.authorization_callback_endpoint.verify_jws", return_value=True), \
         patch("backends.cieoidc.endpoints.authorization_callback_endpoint.unpad_jwt_payload",
               return_value={"sub": "user123", "at_hash": "dummy"}):
        with pytest.raises(SATOSAAuthenticationError):
            handler.endpoint(context)



def test_us06(handler):
    user_attrs = {"invalid": "data"}  # non rispetta schema OidcUser
    result = handler._AuthorizationCallBackHandler__add_user(user_attrs)
    assert result is None


def test_us07(handler):
    assert handler._AuthorizationCallBackHandler__check_provider(
        "https://example.org/", "https://example.org"
    )
    assert handler._AuthorizationCallBackHandler__check_provider(
        "https://example.org", "https://example.org/"
    )

def test_us08(handler):
    attributes = {"sub": "user123"}
    internal = handler._translate_response(attributes, "issuer123", "sub123")
    assert internal.subject_id == "sub123"
    assert hasattr(internal, "attributes")

def test_us09(handler):
    plugin = handler.generate_configuration_plugin(handler.config)
    assert plugin is not None


def test_init_generate_configuration_plugin_called():
    config = {
        "default_enc_alg": "RSA-OAEP",
        "default_enc_enc": "A256GCM",
        "supported_sign_alg": ["RS256"],
        "supported_enc_alg": ["RSA-OAEP"],
        "metadata": {"openid_relying_party": {"client_id": "client123"}},
        "db_config": {}
    }
    with patch(
        "backends.cieoidc.endpoints.authorization_callback_endpoint.OidcDbEngine"
    ) as mock_engine:
        mock_engine.return_value.is_connected.return_value = True

        handler = AuthorizationCallBackHandler(
            config=config,
            internal_attributes={},
            base_url="http://localhost",
            name="test",
            auth_callback_func=MagicMock(),
            converter=MagicMock(),
            trust_evaluator=MagicMock()
        )

        assert handler.configuration_plugins is not None


def test_endpoint_error_param(handler):
    context = Context()
    context.state = MagicMock()
    context.qs_params = {
        "error": "access_denied",
        "error_description": "Denied"
    }
    with pytest.raises(SATOSAAuthenticationError):
        handler.endpoint(context)

def test_authorization_empty(handler):
    context = Context()
    context.state = MagicMock()
    context.qs_params = {
        "state": "dummy_state",
        "code": "code",
        "iss": "http://cie-provider.example.org:8002/oidc/op"
    }
    with patch.object(
        handler,
        "_AuthorizationCallBackHandler__get_authorization",
        return_value={}
    ):
        with pytest.raises(SATOSAAuthenticationError):
            handler.endpoint(context)

def test_invalid_client_id(handler):
    context = Context()
    context.state = MagicMock()
    context.qs_params = {
        "state": "dummy_state",
        "code": "code",
        "iss": "http://cie-provider.example.org:8002/oidc/op"
    }
    authorization = {
        "state": "dummy_state",
        "provider_id": "http://cie-provider.example.org:8002/oidc/op",
        "client_id": "WRONG_CLIENT",
        "data": '{"redirect_uri":"http://cb"}',
        "provider_configuration": {"openid_provider": {"token_endpoint": "x"}}
    }
    with patch.object(
        handler,
        "_AuthorizationCallBackHandler__get_authorization",
        return_value=authorization
    ):
        with pytest.raises(SATOSABadRequestError):
            handler.endpoint(context)

def test_empty_token_response(handler):
    context = Context()
    context.state = MagicMock()
    context.qs_params = {
        "state": "dummy_state",
        "code": "code",
        "iss": "http://cie-provider.example.org:8002/oidc/op"
    }
    with patch(
        "backends.cieoidc.utils.clients.oauth2.OAuth2AuthorizationCodeGrant.access_token_request",
        return_value=None
    ):
        with pytest.raises(SATOSAAuthenticationError):
            handler.endpoint(context)

def test_missing_jwk(handler):
    context = Context()
    context.state = MagicMock()
    context.qs_params = {
        "state": "dummy_state",
        "code": "code",
        "iss": "http://cie-provider.example.org:8002/oidc/op"
    }
    with patch(
        "backends.cieoidc.utils.clients.oauth2.OAuth2AuthorizationCodeGrant.access_token_request",
        return_value={"access_token": "a", "id_token": "b", "token_type": "Bearer", "expires_in": 1}
    ), patch(
        "backends.cieoidc.endpoints.authorization_callback_endpoint.get_jwks",
        return_value={"keys": []}
    ), patch(
        "backends.cieoidc.endpoints.authorization_callback_endpoint.get_jwk_from_jwt",
        return_value=None
    ):
        with pytest.raises(SATOSAAuthenticationError):
            handler.endpoint(context)

def test_verify_jws_exception(handler):
    context = Context()
    context.state = MagicMock()
    context.qs_params = {
        "state": "dummy_state",
        "code": "code",
        "iss": "http://cie-provider.example.org:8002/oidc/op"
    }
    with patch(
        "backends.cieoidc.utils.clients.oauth2.OAuth2AuthorizationCodeGrant.access_token_request",
        return_value={
            "access_token": "a",
            "id_token": "b",
            "token_type": "Bearer",
            "expires_in": 1
        }
    ), patch(
        "backends.cieoidc.endpoints.authorization_callback_endpoint.get_jwks",
        return_value={"keys": []}
    ), patch(
        "backends.cieoidc.endpoints.authorization_callback_endpoint.get_jwk_from_jwt",
        return_value={"kid": "k"}
    ), patch(
        "backends.cieoidc.endpoints.authorization_callback_endpoint.verify_jws",
        side_effect=Exception("boom")
    ):
        with pytest.raises(SATOSAAuthenticationError):
            handler.endpoint(context)

def test_verify_at_hash_exception(handler):
    context = Context()
    context.state = MagicMock()
    context.qs_params = {
        "state": "dummy_state",
        "code": "code",
        "iss": "http://cie-provider.example.org:8002/oidc/op"
    }

    with patch(
        "backends.cieoidc.utils.clients.oauth2.OAuth2AuthorizationCodeGrant.access_token_request",
        return_value={
            "access_token": "a",
            "id_token": "b",
            "token_type": "Bearer",
            "expires_in": 1
        }
    ), patch(
        "backends.cieoidc.endpoints.authorization_callback_endpoint.get_jwks",
        return_value={"keys": []}
    ), patch(
        "backends.cieoidc.endpoints.authorization_callback_endpoint.get_jwk_from_jwt",
        return_value={"kid": "k"}
    ), patch(
        "backends.cieoidc.endpoints.authorization_callback_endpoint.verify_jws",
        return_value=True
    ), patch(
        "backends.cieoidc.endpoints.authorization_callback_endpoint.unpad_jwt_payload",
        return_value={"at_hash": "x"}
    ), patch(
        "backends.cieoidc.endpoints.authorization_callback_endpoint.verify_at_hash",
        side_effect=Exception("boom")
    ):
        with pytest.raises(SATOSAAuthenticationError):
            handler.endpoint(context)


def test_empty_user_attributes(handler):
    context = Context()
    context.state = MagicMock()
    context.qs_params = {
        "state": "dummy_state",
        "code": "code",
        "iss": "http://cie-provider.example.org:8002/oidc/op"
    }

    with patch(
        "backends.cieoidc.utils.clients.oauth2.OAuth2AuthorizationCodeGrant.access_token_request",
        return_value={
            "access_token": "a",
            "id_token": "b",
            "token_type": "Bearer",
            "expires_in": 1
        }
    ), patch(
        "backends.cieoidc.endpoints.authorization_callback_endpoint.get_jwks",
        return_value={"keys": []}
    ), patch(
        "backends.cieoidc.endpoints.authorization_callback_endpoint.get_jwk_from_jwt",
        return_value={"kid": "k"}
    ), patch(
        "backends.cieoidc.endpoints.authorization_callback_endpoint.verify_jws",
        return_value=True
    ), patch(
        "backends.cieoidc.endpoints.authorization_callback_endpoint.unpad_jwt_payload",
        return_value={"sub": "user123", "at_hash": "x"}
    ), patch(
        "backends.cieoidc.endpoints.authorization_callback_endpoint.verify_at_hash",
        return_value=True
    ), patch(
        "backends.cieoidc.endpoints.authorization_callback_endpoint.process_user_attributes",
        return_value=None
    ), patch(
        "backends.cieoidc.utils.clients.oidc.OidcUserInfo.get_userinfo",
        return_value={"email": "test@example.com"}
    ):
        with pytest.raises(SATOSAAuthenticationError):
            handler.endpoint(context)



def test_update_authorization_db_failure(handler):
    handler._db_engine.update_session.return_value = False
    auth = {
        "state": "s",
        "provider_id": "i",
        "client_id": "c",
        "data": "{}",
        "provider_configuration": {}
    }
    handler._AuthorizationCallBackHandler__update_authorization(auth)
