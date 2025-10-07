import unittest
from unittest.mock import MagicMock, patch
from yourmodule.callback_handler import CallBackHandler
from satosa.context import Context
from satosa.response import Response
from satosa.internal import InternalData


"""
    python -m unittest test_callback_handler.py
    Test for __access_token_request with requests.post failed
    Test for __create_token, __insert_token, __update_authentication_token test coverage
    Test excpetion endopoint
"""
class TestCallBackHandler(unittest.TestCase):

    def setUp(self):
        self.config = {
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "grant_type": "authorization_code",
            "jwks_core": {},
            "httpc_params": {
                "connection": {"ssl": False},
                "session": {"timeout": 5}
            },
            "claims": {}
        }

        self.base_url = "http://localhost"
        self.name = "test_handler"
        self.internal_attributes = {}
        self.auth_callback_func = MagicMock(return_value=Response("OK"))
        self.converter = MagicMock()
        self.trust_evaluator = MagicMock()

        self.handler = CallBackHandler(
            config=self.config,
            internal_attributes=self.internal_attributes,
            base_url=self.base_url,
            name=self.name,
            auth_callback_func=self.auth_callback_func,
            converter=self.converter,
            trust_evaluator=self.trust_evaluator
        )

    def test_check_provider_matching(self):
        self.assertTrue(self.handler._CallBackHandler__check_provider(
            "http://example.org/", "http://example.org"
        ))

    def test_check_provider_not_matching(self):
        self.assertFalse(self.handler._CallBackHandler__check_provider(
            "http://example.org/provider", "http://another.org"
        ))

    def test_get_authorization_returns_mock_data(self):
        state = "dummy_state"
        result = self.handler._CallBackHandler__get_authorization(state)
        self.assertIsInstance(result, dict)
        self.assertIn("client_id", result)

    @patch("yourmodule.callback_handler.get_jwks")
    @patch("yourmodule.callback_handler.get_jwk_from_jwt")
    @patch("yourmodule.callback_handler.verify_jws")
    @patch("yourmodule.callback_handler.unpad_jwt_payload", return_value={"sub": "user123", "at_hash": "dummy"})
    @patch("yourmodule.callback_handler.verify_at_hash")
    @patch("yourmodule.callback_handler.process_user_attributes", return_value={"email": "test@example.com"})
    def test_endpoint_happy_path(
        self, mock_process_attrs, mock_at_hash, mock_unpad, mock_verify, mock_get_jwk, mock_get_jwks
    ):
        context = Context()
        context.qs_params = {
            "state": "kTN6Rb83bJEMjKakV1DTlVh9xpSTyQOm",
            "code": "dummy_code",
            "iss": "http://cie-provider.org:8002/oidc/op"
        }

        mock_get_jwks.return_value = {"keys": []}
        mock_get_jwk.return_value = {"kid": "key1"}
        mock_verify.return_value = True

        with patch.object(self.handler, "get_userinfo", return_value={"email": "test@example.com"}), \
             patch.object(self.handler, "_CallBackHandler__access_token_request", return_value={
                 "access_token": "dummy_access_token",
                 "id_token": "dummy_id_token",
                 "expires_in": 3600,
                 "token_type": "Bearer",
                 "scope": "openid"
             }):
            response = self.handler.endpoint(context)
            self.assertIsInstance(response, Response)
            self.assertEqual(response.message, "OK")
