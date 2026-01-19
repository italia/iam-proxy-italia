import pytest
from unittest.mock import MagicMock, patch
from backends.cieoidc.endpoints.authorization_callback_endpoint import AuthorizationCallBackHandler
from satosa.context import Context
from satosa.response import Response
from ..utils.clients.oidc import OidcUserInfo




@pytest.fixture
def handler():
    config = {
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "grant_type": "authorization_code",
        "jwks_core": {},
        "httpc_params": {"connection": {"ssl": False}, "session": {"timeout": 5}},
        "claims": {},
        "db_config": {"mongo_db":{"module":"backends.cieoidc.storage.impl.mongo_storage","class":"MongoStorage","init_params":{"url":"mongodb://localhost:27017","conf":{"db_name":"cie_oidc","db_auth_collection":"authentication","db_token_collection":"authentication_token","db_user_collection":"users","data_ttl":63072000},"connection_params":{"username":"satosa","password":"thatpassword"}}}}
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

@patch.object(OidcUserInfo, "get_userinfo", return_value={"email": "test@example.com"})
@pytest.mark.parametrize("state, code, iss", [("dummy_state", "dummy_code", "http:/localhost:8002/oidc/op")])
def test_endpoint_happy_path(handler, state, code, iss):
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

