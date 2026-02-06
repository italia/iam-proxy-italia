import pytest
from backends.cieoidc.utils.helpers.misc import (
    make_timezone_aware,
    random_token,
    get_pkce,
    http_dict_to_redirect_uri_path,
)
import datetime

def test_us01():
    dt = datetime.datetime.utcnow()
    aware = make_timezone_aware(dt)
    assert aware.tzinfo is not None

def test_us02():
    dt = datetime.datetime.now(datetime.timezone.utc)
    with pytest.raises(ValueError):
        make_timezone_aware(dt)

def test_us03():
    token = random_token(10)
    assert isinstance(token, str)

def test_us04():
    pkce = get_pkce()
    assert "code_verifier" in pkce
    assert "code_challenge" in pkce

def test_us05():
    data = {"a": "1", "b": "2"}
    encoded = http_dict_to_redirect_uri_path(data)
    assert encoded == "a=1&b=2"