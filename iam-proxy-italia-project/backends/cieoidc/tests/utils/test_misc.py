import pytest
from unittest.mock import patch, MagicMock
import datetime
import base64
import json

from backends.cieoidc.utils.helpers.misc import (
    make_timezone_aware,
    random_token,
    get_pkce,
    http_dict_to_redirect_uri_path,
    iat_now,
    exp_from_now,
    datetime_from_timestamp,
    timestamp_from_datetime,
    random_string,
    get_key,
    cacheable_get_http_url,
    _lru_cached_get_http_url,
    get_jwk_from_jwt,
    unpad_jwt_head,
    unpad_jwt_element,
    issuer_prefixed_sub,
    process_user_attributes,
    import_string,
)


def test_make_timezone_aware_naive():
    dt = datetime.datetime.utcnow()
    aware = make_timezone_aware(dt)
    assert aware.tzinfo is not None


def test_make_timezone_aware_already_aware():
    dt = datetime.datetime.now(datetime.timezone.utc)
    with pytest.raises(ValueError):
        make_timezone_aware(dt)

def test_random_token_length_and_type():
    token = random_token(10)
    assert isinstance(token, str)
    assert len(token) == 20

def test_get_pkce_structure():
    pkce = get_pkce()
    assert "code_verifier" in pkce
    assert "code_challenge" in pkce
    assert "code_challenge_method" in pkce
    assert pkce["code_challenge_method"] == "S256"

def test_http_dict_to_redirect_uri_path():
    data = {"a": "1", "b": "2"}
    encoded = http_dict_to_redirect_uri_path(data)
    assert encoded == "a=1&b=2"


def test_iat_now_returns_int():
    ts = iat_now()
    assert isinstance(ts, int)
    assert ts > 0


def test_exp_from_now_greater_than_now():
    ts = exp_from_now(10)
    assert isinstance(ts, int)
    assert ts > iat_now()


def test_datetime_timestamp_roundtrip():
    now = datetime.datetime.now(datetime.timezone.utc)
    ts_from_dt = timestamp_from_datetime(now)
    dt_from_ts = datetime.datetime.utcfromtimestamp(ts_from_dt).replace(tzinfo=datetime.timezone.utc)
    assert dt_from_ts.tzinfo == datetime.timezone.utc
    assert timestamp_from_datetime(dt_from_ts) == ts_from_dt

def test_random_string_length():
    s = random_string(16)
    assert isinstance(s, str)
    assert len(s) == 16

def test_get_key_default_and_specific():
    jwks = [{"use": "enc"}, {"use": "sig"}]
    key = get_key(jwks)
    assert key["use"] == "sig"
    key2 = get_key(jwks, use="enc")
    assert key2["use"] == "enc"

def test_cacheable_get_http_url_200():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch("backends.cieoidc.utils.helpers.misc._lru_cached_get_http_url", return_value=mock_resp):
        resp = cacheable_get_http_url(
            10,
            "http://example.com",
            {"connection": {"ssl": True}, "session": {"timeout": 1}}
        )
        assert resp.status_code == 200


def test_us():
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    with patch("backends.cieoidc.utils.helpers.misc._lru_cached_get_http_url", return_value=mock_resp) as m:
        resp = cacheable_get_http_url(
            10,
            "http://example.com",
            {"connection": {"ssl": True}, "session": {"timeout": 1}}
        )
        assert resp.status_code == 404
        assert m.cache_clear.called

def test_unpad_jwt_element():
    payload = {"kid": "123"}
    jwt_part = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    jwt = f"{jwt_part}.dummy.dummy"
    result = unpad_jwt_head(jwt)
    assert result["kid"] == "123"

def test_get_jwk_from_jwt_matches_kid():
    payload = {"kid": "abc"}
    jwt_part = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    jwt = f"{jwt_part}.dummy.dummy"
    provider_jwks = [{"kid": "abc"}, {"kid": "xyz"}]
    jwk = get_jwk_from_jwt(jwt, provider_jwks)
    assert jwk["kid"] == "abc"

def test_issuer_prefixed_sub_basic():
    data = {"sep": "--"}
    user_info = {"sub": "user1"}
    client_conf = {"provider_id": "prov"}
    result = issuer_prefixed_sub(user_info, client_conf, data)
    assert result == "prov--user1"

def dummy_func(userinfo, authz, kwargs):
    return "ok"

def test_process_user_attributes_with_func(monkeypatch):
    monkeypatch.setattr("backends.cieoidc.utils.helpers.misc.import_string", lambda x: dummy_func)
    userinfo = {"field": "val"}
    user_map = {"new": [{"func": "dummy.path"}]}
    authz = {}
    result = process_user_attributes(userinfo, user_map, authz)
    assert result["new"] == "ok"
