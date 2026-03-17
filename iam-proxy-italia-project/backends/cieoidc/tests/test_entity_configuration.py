import json
import pytest
from unittest.mock import patch, MagicMock

from backends.cieoidc.endpoints.entity_configuration import EntityConfigHandler
from satosa.context import Context


@pytest.fixture
def minimal_config():
    return {
        "entity_type": "openid_relying_party",
        "jwks_core": [
            {
                "kty": "RSA",
                "use": "sig",
                "n": "uXfJA-wTlTCA4FdsoE0qZfmKIgedmarrtWgQbElKbWg9RDR7Z8JVBaRLFqwyfyG1JJFm64G51cBJwLIFwWoF7nxsH9VYLm5ocjAnsR4RhlfVE0y_60wjf8skJgBRpiXQPlwH9jDGaqVE_PEBTObDO5w3XourD1F360-v5cLDLRHdFJIitdEVtqATqY5DglRDaKiBhis7a5_1bk839PDLaQhju4XJk4tvDy5-LVkMy5sP2zU6-1tJdA-VmaBZLXy9n0967FGIWmMzpafrBMOuHFcUOH56o-clDah_CITH1dq2D64K0MYhEpACO2p8AH4K8Q6YuJ1dnkVDDwZp2C84sQ",  # noqa: E501
                "p": "5PA7lJEDd3vrw5hlolFzvjvRriOu1SMHXx9Y52AgpOeQ6MnE1pO8qwn33lwYTSPGYinaq4jS3FKF_U5vOZltJAGBMa4ByEvAROJVCh958rKVRWKIqVXLOi8Gk11kHbVKw6oDXAd8Qt_y_ff8k_K6jW2EbWm1K6kfTvTMzoHkqrU",  # noqa: E501
                "q": "z2QeMH4WtrdiWUET7JgZNX0TbcaVBgd2Gpo8JHnfnGOUsvO_euKGgqpCcxiWVXSlqffQyTgVzl4iMROP8bEaQwvueHurtziMDSy9Suumyktu3PbGgjqu_izRim8Xlg7sz8Hs2quJPII_fQ8BCoaWpg30osFZqCBarQM7CWhxR40",  # noqa: E501
                "d": "n_ePK5DdOxqArf75tDGaViYrXDqRVk8zyl2dfKiiR0dXQJK7tbzJtHoGQeH4E-sw3_-Bc7OKY7DcbBWgHTijMRWj9LkAu9uCvqqGMaAroWH0aBcUmZAsNjcyUIyJ3_JRcNfUDiX3nVg67qe4ZWnMDogowaVZv3aXJiCvKE8aJK4BV_nF3Nt5R6zUYpjZQ8T1GDZCV3vza3qglDrXe8zoc-p8cLs3rJn7tMVSJVznCIqOfeM1VIg0I3n2bubYOx88sckHuDnfXTiTDlyq5IwDyBHmiIe3fpu-c4e1tiBmbOf2IqDCaX8SdpnU2gTj9YlZtRNqmh3NB_rksBKWLz3uIQ",  # noqa: E501
                "e": "AQAB",
                "kid": "YhuIJU6o15EUCyqA0LHEqJd-xVPJgoyW5wZ1o4padWs"
            }
        ],
        "jwks_federation": [{
            "d": "Npw19klvaNLdUWZRwe4MjPIgD8AH5BjfU5_dM05Gb6lBRWQKSWNlqP8bET-oZbWSw3zMaOAy2-k2GnYVXBYKu9WnjFFFPlbH-sVPfdKQLYzEABmxR_aaeSHrnDfKozTtFsYEgtI_WoGEaxPoE0P-Ds11Tp9h9ovZM48sDGnEdyjopnLPEZBR6VinP_yF1kfDg0kcIPmM1ZchIqJrnQpoKWeVTXtFFGrVqOAYmm4xBfP4U8TEimbeJJuYkJ9gLNnRDg_FC-ZPUiBIXigWZsEeJyevymP-NH4lq3osLgFOq0sqPxS3zkDwx9tWfT5UyqrCCortiQd2dxKzxZlEEvlQAQ",  # noqa: E501
            "e": "AQAB",
            "kid": "wL_LmP8UjLVN-sAeoZ7KGEMJfBkFtbNLd24eDD9RGCs",
            "kty": "RSA",
            "n": "6SDksa64IjBk7HNQC7x5C9nMARGaanfaUm3wC2WulwG_8a5aIy4CEwXN2LENkCyypODqWZcTAwCzWsiihVN9kDcEs7UNu-X1WokK252D7_DRY-FXI8AB3P0CxTngs0k-OjcmbxqVW2U8G56rJFp4G_CYA4vzBoAP_5skFBt-4a5lYJlBfJ2gJlE0vh4_46oyNuUT9kmKauR7npVSHjBUSxYyDELzoaPmvR7SkX4sJe0MK39HES6s4no9G7BraLp75eOwEQmHgEhESWscSOf_CmC5ALnzWJ3FcFhxgsuMkdjoU7bH09y8pdKs64kR2znxs-yIWrPFW8hJKnySc2fk8w",  # noqa: E501
            "p": "-1JcdcT2FdwavmPqtfOEKFUGBM9hhvwgX7KyCwl8tmresJQz8pNDkILMeKJf8ZCDVU7v4_i4C_P8oe41f2_SDsv9AIYh09zu_tQsMMdH_lqNx0YP8Yv25N5KOxnSOBO837SieFZ2xkbolXXIV7WIHrdFiyAOMOSWlETEO6JNu_M",  # noqa: E501
            "q": "7XfVt4ArSMLmRvvSl11yDF25t1aR3ylUmwZgLAJTNo76j-zo8Q2Ty7GfCIQmLOhOZTkwqnrbmwEBMEBsomWZFh_j90CLMyn1ccYUjiTI4CHJOTLMA8rYVWeArYkqek1jC4TQ9e1PkRrPcEvq2Tak8GFsBhnhOCzejJrMDgqkcwE"  # noqa: E501
        }],
        "metadata": {"openid_relying_party": {"client_id": "client123"}},
        "default_sig_alg": "RS256",
        "entity_configuration_exp": 3600
    }


@pytest.fixture
def handler(minimal_config):
    with patch("backends.cieoidc.utils.validators.validate_private_jwks") as mock_val_jwks, \
            patch("backends.cieoidc.utils.validators.validate_entity_metadata") as mock_val_meta:
        mock_val_jwks.return_value = None
        mock_val_meta.return_value = None

        h = EntityConfigHandler(
            config=minimal_config,
            internal_attributes={},
            base_url="http://iam-proxy-italia.example.org",
            name="auth",
            auth_callback_func=MagicMock(),
            converter=MagicMock(),
            trust=None
        )
        return h


def test_initialization_calls_validation(minimal_config):
    with patch("backends.cieoidc.utils.validators.validate_private_jwks") as mock_val_jwks, \
            patch("backends.cieoidc.utils.validators.validate_entity_metadata") as mock_val_meta:
        mock_val_jwks.return_value = {"jwks_core": [
            {
                "kty": "RSA",
                "use": "sig",
                "n": "uXfJA-wTlTCA4FdsoE0qZfmKIgedmarrtWgQbElKbWg9RDR7Z8JVBaRLFqwyfyG1JJFm64G51cBJwLIFwWoF7nxsH9VYLm5ocjAnsR4RhlfVE0y_60wjf8skJgBRpiXQPlwH9jDGaqVE_PEBTObDO5w3XourD1F360-v5cLDLRHdFJIitdEVtqATqY5DglRDaKiBhis7a5_1bk839PDLaQhju4XJk4tvDy5-LVkMy5sP2zU6-1tJdA-VmaBZLXy9n0967FGIWmMzpafrBMOuHFcUOH56o-clDah_CITH1dq2D64K0MYhEpACO2p8AH4K8Q6YuJ1dnkVDDwZp2C84sQ",  # noqa: E501
                "p": "5PA7lJEDd3vrw5hlolFzvjvRriOu1SMHXx9Y52AgpOeQ6MnE1pO8qwn33lwYTSPGYinaq4jS3FKF_U5vOZltJAGBMa4ByEvAROJVCh958rKVRWKIqVXLOi8Gk11kHbVKw6oDXAd8Qt_y_ff8k_K6jW2EbWm1K6kfTvTMzoHkqrU",  # noqa: E501
                "q": "z2QeMH4WtrdiWUET7JgZNX0TbcaVBgd2Gpo8JHnfnGOUsvO_euKGgqpCcxiWVXSlqffQyTgVzl4iMROP8bEaQwvueHurtziMDSy9Suumyktu3PbGgjqu_izRim8Xlg7sz8Hs2quJPII_fQ8BCoaWpg30osFZqCBarQM7CWhxR40",  # noqa: E501
                "d": "n_ePK5DdOxqArf75tDGaViYrXDqRVk8zyl2dfKiiR0dXQJK7tbzJtHoGQeH4E-sw3_-Bc7OKY7DcbBWgHTijMRWj9LkAu9uCvqqGMaAroWH0aBcUmZAsNjcyUIyJ3_JRcNfUDiX3nVg67qe4ZWnMDogowaVZv3aXJiCvKE8aJK4BV_nF3Nt5R6zUYpjZQ8T1GDZCV3vza3qglDrXe8zoc-p8cLs3rJn7tMVSJVznCIqOfeM1VIg0I3n2bubYOx88sckHuDnfXTiTDlyq5IwDyBHmiIe3fpu-c4e1tiBmbOf2IqDCaX8SdpnU2gTj9YlZtRNqmh3NB_rksBKWLz3uIQ",  # noqa: E501
                "e": "AQAB",
                "kid": "YhuIJU6o15EUCyqA0LHEqJd-xVPJgoyW5wZ1o4padWs"
            }
        ],
            "jwks_federation": [{
                "d": "Npw19klvaNLdUWZRwe4MjPIgD8AH5BjfU5_dM05Gb6lBRWQKSWNlqP8bET-oZbWSw3zMaOAy2-k2GnYVXBYKu9WnjFFFPlbH-sVPfdKQLYzEABmxR_aaeSHrnDfKozTtFsYEgtI_WoGEaxPoE0P-Ds11Tp9h9ovZM48sDGnEdyjopnLPEZBR6VinP_yF1kfDg0kcIPmM1ZchIqJrnQpoKWeVTXtFFGrVqOAYmm4xBfP4U8TEimbeJJuYkJ9gLNnRDg_FC-ZPUiBIXigWZsEeJyevymP-NH4lq3osLgFOq0sqPxS3zkDwx9tWfT5UyqrCCortiQd2dxKzxZlEEvlQAQ",  # noqa: E501
                "e": "AQAB",
                "kid": "wL_LmP8UjLVN-sAeoZ7KGEMJfBkFtbNLd24eDD9RGCs",
                "kty": "RSA",
                "n": "6SDksa64IjBk7HNQC7x5C9nMARGaanfaUm3wC2WulwG_8a5aIy4CEwXN2LENkCyypODqWZcTAwCzWsiihVN9kDcEs7UNu-X1WokK252D7_DRY-FXI8AB3P0CxTngs0k-OjcmbxqVW2U8G56rJFp4G_CYA4vzBoAP_5skFBt-4a5lYJlBfJ2gJlE0vh4_46oyNuUT9kmKauR7npVSHjBUSxYyDELzoaPmvR7SkX4sJe0MK39HES6s4no9G7BraLp75eOwEQmHgEhESWscSOf_CmC5ALnzWJ3FcFhxgsuMkdjoU7bH09y8pdKs64kR2znxs-yIWrPFW8hJKnySc2fk8w",  # noqa: E501
                "p": "-1JcdcT2FdwavmPqtfOEKFUGBM9hhvwgX7KyCwl8tmresJQz8pNDkILMeKJf8ZCDVU7v4_i4C_P8oe41f2_SDsv9AIYh09zu_tQsMMdH_lqNx0YP8Yv25N5KOxnSOBO837SieFZ2xkbolXXIV7WIHrdFiyAOMOSWlETEO6JNu_M",  # noqa: E501
                "q": "7XfVt4ArSMLmRvvSl11yDF25t1aR3ylUmwZgLAJTNo76j-zo8Q2Ty7GfCIQmLOhOZTkwqnrbmwEBMEBsomWZFh_j90CLMyn1ccYUjiTI4CHJOTLMA8rYVWeArYkqek1jC4TQ9e1PkRrPcEvq2Tak8GFsBhnhOCzejJrMDgqkcwE"  # noqa: E501
            }]}

        mock_val_meta.return_value = None

        handler = EntityConfigHandler(
            config=minimal_config,
            internal_attributes={},
            base_url="http://iam-proxy-italia.example.org/",
            name="auth",
            auth_callback_func=MagicMock(),
            converter=MagicMock(),
            trust=None
        )
        assert handler


def test_metadata_property(handler):
    with patch("backends.cieoidc.utils.helpers.jwks.public_jwk_from_private_jwk") as mock_pub:
        mock_pub.side_effect = lambda x: {"kty": x["kty"], "kid": x["kid"]}
        meta = handler._metadata
        assert "openid_relying_party" in meta
        assert meta["openid_relying_party"]["client_id"] == handler._client_id
        assert meta["openid_relying_party"]["jwks"]["keys"][0]["kid"] == "YhuIJU6o15EUCyqA0LHEqJd-xVPJgoyW5wZ1o4padWs"


@patch("backends.cieoidc.models.federation.FederationEntityConfiguration")
def test_get_entity_configuration_dict(mock_fed_conf, handler):
    res = handler.get_entity_configuration(jws=False)
    assert json.loads(res)
    res_jws = handler.get_entity_configuration(jws=True)
    assert res_jws


@patch("backends.cieoidc.utils.helpers.jwtse.create_jws")
@patch("backends.cieoidc.utils.helpers.jwks.public_jwk_from_private_jwk")
def test_get_openid_jwks(mock_pub, mock_create_jws, handler):
    mock_pub.s_


def test_endpoint_well_known_json(handler):
    context = Context()
    context.target_backend = "/auth"
    context.path = "auth/.well-known/openid-federation"
    context.qs_params = {"format": "json"}
    response = handler.endpoint(context)
    assert response


@patch("backends.cieoidc.endpoints.entity_configuration.EntityConfigHandler.get_entity_configuration")
def test_endpoint_well_known_jws(mock_get_entity, handler):
    mock_get_entity.return_value = "signed-jws"

    context = Context()
    context.target_backend = "/auth"
    context.path = "auth/.well-known/openid-federation"
    context.qs_params = {}
    response = handler.endpoint(context)
    assert response


@patch("backends.cieoidc.endpoints.entity_configuration.EntityConfigHandler.get_openid_jwks")
def test_endpoint_openid_jwks_jose(mock_get_jwks, handler):
    mock_get_jwks.return_value = "jwks-jws"
    context = Context()
    context.target_backend = "/auth"
    context.path = "auth/openid_relying_party/jwks.jose"
    context.qs_params = {}
    response = handler.endpoint(context)
    assert response


@patch("backends.cieoidc.endpoints.entity_configuration.EntityConfigHandler.get_openid_jwks")
def test_endpoint_openid_jwks_json(mock_get_jwks, handler):
    mock_get_jwks.return_value = json.dumps({"keys": []})
    context = Context()
    context.target_backend = "/auth"
    context.path = "auth/openid_relying_party/jwks.json"
    context.qs_params = {}
    response = handler.endpoint(context)
    assert response


@patch("backends.cieoidc.endpoints.entity_configuration.public_jwk_from_private_jwk")
def test_get_openid_jwks_json(mock_pub, handler):
    mock_pub.side_effect = lambda k: {"kid": k["kid"], "kty": k["kty"]}
    result = handler.get_openid_jwks(jws=False)
    data = json.loads(result)
    assert "keys" in data
    assert len(data["keys"]) == 1
    assert data["keys"][0]["kid"] == "YhuIJU6o15EUCyqA0LHEqJd-xVPJgoyW5wZ1o4padWs"
    assert mock_pub.call_count == 1


@patch("backends.cieoidc.endpoints.entity_configuration.create_jws")
@patch("backends.cieoidc.endpoints.entity_configuration.public_jwk_from_private_jwk")
def test_get_openid_jwks_jws(mock_pub, mock_create_jws, handler):
    mock_pub.side_effect = lambda k: {"kid": k["kid"]}
    mock_create_jws.return_value = "signed-jws"
    result = handler.get_openid_jwks(jws=True)
    assert result == "signed-jws"
    mock_create_jws.assert_called_once()
    args, kwargs = mock_create_jws.call_args
    payload, signing_key = args
    assert "keys" in payload
    assert signing_key["kid"] == "wL_LmP8UjLVN-sAeoZ7KGEMJfBkFtbNLd24eDD9RGCs"
