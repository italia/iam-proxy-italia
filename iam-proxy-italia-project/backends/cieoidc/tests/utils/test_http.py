from backends.cieoidc.utils.helpers.misc import cacheable_get_http_url
from backends.cieoidc.utils.exceptions import HttpError
from unittest.mock import patch, MagicMock
import pytest
import requests
import aiohttp

from backends.cieoidc.utils.helpers.http import (
    http_get_sync,
    http_get_async,
    fetch_all,
    fetch,
)

def test_us01():
    resp = MagicMock()
    resp.status_code = 200

    with patch("requests.get", return_value=resp):
        res = http_get_sync(["http://example.com"])
        assert res == [resp]

def test_us02():
    resp = MagicMock()
    resp.status_code = 404
    resp.reason = "Not Found"

    with patch("requests.get", return_value=resp):
        with pytest.raises(HttpError):
            http_get_sync(["http://example.com"])

def test_us03():
    with patch("requests.get", side_effect=requests.exceptions.ConnectionError):
        with pytest.raises(HttpError):
            http_get_sync(["http://example.com"])

@pytest.mark.asyncio
async def test_us04():
    resp = MagicMock()
    resp.status = 200
    resp.status_code = 200

    async def fake_fetch(*args, **kwargs):
        return resp

    with patch("backends.cieoidc.utils.helpers.http.fetch", side_effect=fake_fetch):
        result = await fetch_all(MagicMock(), ["http://example.com"])
        assert result == [resp]

@pytest.mark.asyncio
async def test_us05():
    with patch(
        "backends.cieoidc.utils.helpers.http.asyncio.gather",
        side_effect=OSError("connection failed")
    ):
        with pytest.raises((HttpError,OSError)):
            await fetch_all(MagicMock(), ["http://example.com"])



def test_us06():
    resp = MagicMock()
    resp.status_code = 200

    with patch(
        "backends.cieoidc.utils.helpers.misc._lru_cached_get_http_url",
        return_value=resp
    ):
        r = cacheable_get_http_url(
            cache_ttl=10,
            url="http://example.com",
            httpc_params={"connection": {"ssl": True}, "session": {"timeout": 5}},
            http_async=False,
        )
        assert r.status_code == 200

def test_us07():
    with pytest.raises(ValueError):
        cacheable_get_http_url(
            cache_ttl=10,
            url="http://example.com",
            httpc_params={},
        )


