import pytest
from unittest.mock import patch, MagicMock

from backends.cieoidc.utils.helpers.misc import (
    get_http_url,
    dynamic_class_loader,
    cacheable_get_http_url,
    _lru_cached_get_http_url,
    get_jwks,
    get_jwk_from_jwt,
    import_string,
    process_user_attributes,
)


def test_get_http_url_sync():
    mock_resp = MagicMock()
    with patch(
        "backends.cieoidc.utils.helpers.misc.http_get_sync",
        return_value=[mock_resp],
    ) as m:
        resp = get_http_url(
            "http://example.com",
            {"connection": {"ssl": True}},
            http_async=False,
        )
        assert resp == [mock_resp]
        m.assert_called_once()


def test_dynamic_class_loader_not_callable():
    with patch(
        "backends.cieoidc.utils.helpers.misc.get_dynamic_class",
        return_value=123,
    ):
        with pytest.raises(TypeError):
            dynamic_class_loader("x", "y")


def test_cacheable_get_http_url_invalid_params():
    with pytest.raises(ValueError):
        cacheable_get_http_url(
            10,
            "http://example.com",
            httpc_params={"connection": {}},
        )


def test_lru_cached_get_http_url_calls_get_http_url():
    mock_resp = MagicMock()
    with patch(
        "backends.cieoidc.utils.helpers.misc.get_http_url",
        return_value=[mock_resp],
    ):
        resp = _lru_cached_get_http_url(
            1,
            "http://example.com",
            httpc_params_tuple=type(
                "T", (), {"ssl": True, "timeout": 1}
            )(),
            http_async=False,
        )
        assert resp == mock_resp


def test_get_jwks_direct():
    metadata = {
        "jwks": {
            "keys": [{"kid": "1"}]
        }
    }
    result = get_jwks(metadata, httpc_params={})
    assert result == [{"kid": "1"}]


def test_get_jwks_uri_exception():
    metadata = {"jwks_uri": "http://bad"}
    with patch(
        "backends.cieoidc.utils.helpers.misc.get_http_url",
        side_effect=Exception("boom"),
    ):
        result = get_jwks(metadata, httpc_params={})
        assert result == []


def test_get_jwks_signed_uri_exception():
    metadata = {"signed_jwks_uri": "http://bad"}
    with patch(
        "backends.cieoidc.utils.helpers.misc.get_http_url",
        side_effect=Exception("boom"),
    ):
        result = get_jwks(metadata, httpc_params={})
        assert result == []


def test_get_jwk_from_jwt_not_found():
    jwt = "eyJraWQiOiAiYWJjIn0.dummy.dummy"
    provider_jwks = {"keys": [{"kid": "xyz"}]}
    result = get_jwk_from_jwt(jwt, provider_jwks)
    assert result == {}


def test_import_string_invalid_path():
    with pytest.raises(ImportError):
        import_string("invalidpath")


def test_import_string_missing_attr():
    with pytest.raises(ImportError):
        import_string("json.not_existing")


def test_process_user_attributes_string_mapping():
    userinfo = {"email": "a@b.it"}
    user_map = {"mail": ["email"]}
    authz = {}
    result = process_user_attributes(userinfo, user_map, authz)
    assert result["mail"] == "a@b.it"
