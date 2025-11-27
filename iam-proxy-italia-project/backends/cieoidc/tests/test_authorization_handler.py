import pytest
from unittest.mock import MagicMock
from satosa.context import Context
from ..endpoints.authorization_endpoint import AuthorizationHandler


@pytest.fixture
def base_config():
    return {
        "entity_type": "test_rp",
        "jwks_core": [{"kty": "RSA", "kid": "1"}],
        "metadata": {
            "openid_relying_party": {
                "client_id": "test-client-id",
                "redirect_uris": ["https://client/callback"]
            }
        },
        "authorization_endpoint": "https://auth.example.com/authorize"
    }


@pytest.fixture
def handler(base_config):
    return AuthorizationHandler(
        config=base_config,
        internal_attributes={},
        base_url="https://base.url",
        name="test",
        auth_callback_func=MagicMock(),
        converter=MagicMock(),
        trust=MagicMock()
    )


def test_require_config_field_valid(handler):
    path = ["metadata", "openid_relying_party", "client_id"]
    assert handler._require_config_field(path, "Client ID") == "test-client-id"


def test_require_config_field_missing(handler):
    path = ["metadata", "invalid"]
    with pytest.raises(ValueError, match="Invalid Field is missing"):
        handler._require_config_field(path, "Invalid Field")


def test_validate_configs_success(handler, base_config):
    # Complete the config structure required by _validate_configs
    base_config["endpoints"] = {
        "authorization_endpoint": {
            "config": {
                "metadata": {
                    "openid_relying_party": {
                        "client_id": "id",
                        "redirect_uris": ["https://callback"]
                    }
                }
            }
        }
    }
    handler.config = base_config
    handler._validate_configs()  # Should not raise


@pytest.mark.parametrize("missing_path", [
    (["endpoints", "authorization_endpoint"]),
    (["endpoints", "authorization_endpoint", "config"]),
    (["endpoints", "authorization_endpoint", "config", "metadata"]),
    (["endpoints", "authorization_endpoint", "config", "metadata", "openid_relying_party"]),
    (["endpoints", "authorization_endpoint", "config", "metadata", "openid_relying_party", "client_id"]),
    (["endpoints", "authorization_endpoint", "config", "metadata", "openid_relying_party", "redirect_uris"]),
])
def test_validate_configs_failure(handler, base_config, missing_path):
    # Remove a key from the config
    pointer = base_config
    for key in missing_path[:-1]:
        pointer = pointer.setdefault(key, {})
    pointer.pop(missing_path[-1], None)

    handler.config = base_config
    with pytest.raises(ValueError):
        handler._validate_configs()


def test_endpoint_returns_redirect(handler, mocker):
    # Mock dependencies
    mocker.patch("yourmodule.authorization_handler.random_string", side_effect=lambda x: "random")
    mocker.patch("yourmodule.authorization_handler.get_pkce", return_value={
        "code_challenge": "abc",
        "code_challenge_method": "S256",
        "code_verifier": "verifier"
    })
    mocker.patch("yourmodule.authorization_handler.get_key", return_value={"k": "key"})
    mocker.patch("yourmodule.authorization_handler.create_jws", return_value="signed-request")
    mocker.patch("yourmodule.authorization_handler.http_dict_to_redirect_uri_path", return_value="client_id=test-client-id")

    context = MagicMock(spec=Context)
    response = handler.endpoint(context)

    assert response.__class__.__name__ == "Redirect"
    assert response.message.startswith("https://auth.example.com/authorize?")
    assert "client_id=test-client-id" in response.message
