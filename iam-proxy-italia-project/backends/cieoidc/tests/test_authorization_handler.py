import json
import pytest
from unittest.mock import MagicMock, patch

from datetime import datetime, timezone

from backends.cieoidc.endpoints.authorization_endpoint import AuthorizationHandler



@pytest.fixture
def minimal_config():
    return {
        "entity_type": "openid_relying_party",
        "jwks_core": [
            {
                "kty": "RSA",
                "use": "sig",
                "n": "uXfJA-wTlTCA4FdsoE0qZfmKIgedmarrtWgQbElKbWg9RDR7Z8JVBaRLFqwyfyG1JJFm64G51cBJwLIFwWoF7nxsH9VYLm5ocjAnsR4RhlfVE0y_60wjf8skJgBRpiXQPlwH9jDGaqVE_PEBTObDO5w3XourD1F360-v5cLDLRHdFJIitdEVtqATqY5DglRDaKiBhis7a5_1bk839PDLaQhju4XJk4tvDy5-LVkMy5sP2zU6-1tJdA-VmaBZLXy9n0967FGIWmMzpafrBMOuHFcUOH56o-clDah_CITH1dq2D64K0MYhEpACO2p8AH4K8Q6YuJ1dnkVDDwZp2C84sQ",
                "p": "5PA7lJEDd3vrw5hlolFzvjvRriOu1SMHXx9Y52AgpOeQ6MnE1pO8qwn33lwYTSPGYinaq4jS3FKF_U5vOZltJAGBMa4ByEvAROJVCh958rKVRWKIqVXLOi8Gk11kHbVKw6oDXAd8Qt_y_ff8k_K6jW2EbWm1K6kfTvTMzoHkqrU",
                "q": "z2QeMH4WtrdiWUET7JgZNX0TbcaVBgd2Gpo8JHnfnGOUsvO_euKGgqpCcxiWVXSlqffQyTgVzl4iMROP8bEaQwvueHurtziMDSy9Suumyktu3PbGgjqu_izRim8Xlg7sz8Hs2quJPII_fQ8BCoaWpg30osFZqCBarQM7CWhxR40",
                "d": "n_ePK5DdOxqArf75tDGaViYrXDqRVk8zyl2dfKiiR0dXQJK7tbzJtHoGQeH4E-sw3_-Bc7OKY7DcbBWgHTijMRWj9LkAu9uCvqqGMaAroWH0aBcUmZAsNjcyUIyJ3_JRcNfUDiX3nVg67qe4ZWnMDogowaVZv3aXJiCvKE8aJK4BV_nF3Nt5R6zUYpjZQ8T1GDZCV3vza3qglDrXe8zoc-p8cLs3rJn7tMVSJVznCIqOfeM1VIg0I3n2bubYOx88sckHuDnfXTiTDlyq5IwDyBHmiIe3fpu-c4e1tiBmbOf2IqDCaX8SdpnU2gTj9YlZtRNqmh3NB_rksBKWLz3uIQ",
                "e": "AQAB",
                "kid": "YhuIJU6o15EUCyqA0LHEqJd-xVPJgoyW5wZ1o4padWs"
            }
        ],
        "prompt": "login",
        "metadata": {
            "openid_relying_party": {
                "client_id": "client123",
                "redirect_uris": ["https://localhost/callback"],
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
                            "redirect_uris": ["https://localhost/callback"]
                        }
                    }
                }
            }
        }
    }


@pytest.fixture
def context():
    ctx = MagicMock()
    ctx.internal_data = {"target_entity_id": "http://trust-anchor.example.org:5002"}
    return ctx


@pytest.fixture
def trust_chain():
    tc = MagicMock()
    tc.subject = "http://trust-anchor.example.org:5002"
    tc.subject_configuration.payload = {
        "metadata": {
            "openid_provider": {
                "authorization_endpoint": "http://trust-anchor.example.org:5002/auth"
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
            base_url="https://satosa-nginx.example.org",
            name="authz",
            auth_callback_func=MagicMock(),
            converter=MagicMock(),
            trust_chains={"http://trust-anchor.example.org:5002": trust_chain}
        )
        return h



def test_us01(handler):
    handler._validate_configs()


def test_us02(minimal_config):
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


@patch("backends.cieoidc.utils.helpers.misc.get_pkce")
@patch("backends.cieoidc.utils.helpers.jwtse.create_jws")
@patch("backends.cieoidc.utils.helpers.misc.get_key")
@patch("satosa.response.Redirect")
def test_us03(
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
    assert response is not None



def test_us04(handler):
    handler.config["metadata"]["openid_relying_party"]["code_challenge"]["length"] = None

    with pytest.raises(ValueError):
        handler._AuthorizationHandler__pkce_generation({})


def test_us05():
    authz_data = {
        "client_id": "client123",
        "scope": "openid",
        "response_type": "code",
        "code_challenge": "abc",
        "code_challenge_method": "S256",
        "request": "jwt"
    }

    with patch(
        "backends.cieoidc.utils.helpers.misc.http_dict_to_redirect_uri_path"
    ) as uri_mock:
        uri_mock.return_value = "client_id=client123&scope=openid&response_type=code&code_challenge=abc&code_challenge_method=S256&request=jwt"
        uri = AuthorizationHandler.generate_uri(authz_data)
        assert uri == "client_id=client123&scope=openid&response_type=code&code_challenge=abc&code_challenge_method=S256&request=jwt"


@patch("backends.cieoidc.models.oidc_auth.OidcAuthentication")
def test_us06(mock_auth, handler):
    handler._db_engine.add_session = MagicMock(return_value=1)

    auth_obj = {
        "client_id": "client123",
        "state": "state",
        "endpoint": "x",
        "provider_id": "y",
        "data": "{}",
        "provider_configuration": {}
    }
    handler._AuthorizationHandler__insert(auth_obj)

    handler._db_engine.add_session.assert_called_once()
