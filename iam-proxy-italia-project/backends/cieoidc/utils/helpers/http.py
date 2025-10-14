import asyncio

import aiohttp
import requests

from ..exceptions import HttpError

DEFAULT_HTTPC_PARAMS = {
    "connection": {
        "ssl": True
    },
    "session": {
        "timeout": 4
    },
}

def http_get_sync(urls: list[str], httpc_params: dict = DEFAULT_HTTPC_PARAMS) -> list[requests.Response]:
    """
    Perform a GET http call sync.

    :param urls: the url list where fetch the content
    :type urls: list[str]
    :param httpc_params: parameters to perform http requests.
    :type httpc_params: dict

    :raises HttpError: if the response status code is not 200 or a connection error occurs

    :returns: the list of responses
    :rtype: list[requests.Response]
    """
    _conf = {
        "verify": httpc_params["connection"]["ssl"],
        "timeout": httpc_params["session"]["timeout"],
    }
    try:
        res = [requests.get(url, **_conf) for url in urls]  # nosec - B113
    except requests.exceptions.ConnectionError as e:
        raise HttpError(f"Connection error: {e}")

    for r in res:
        if r.status_code != 200:
            raise HttpError(f"HTTP error: {r.status_code} -- {r.reason}")

    return res


async def http_get_async(urls, httpc_params: dict = DEFAULT_HTTPC_PARAMS) -> list[requests.Response]:
    """
    Perform a GET http call async.

    :param session: a dict representing the current session
    :type session: dict
    :param urls: the url list where fetch the content
    :type urls: list[str]
    :param httpc_params: parameters to perform http requests.
    :type httpc_params: dict

    :raises HttpError: if the response status code is not 200 or a connection error occurs

    :returns: the list of responses
    :rtype: list[requests.Response]
    """
    if not isinstance(httpc_params["session"]["timeout"], aiohttp.ClientTimeout):
        httpc_params["session"]["timeout"] = aiohttp.ClientTimeout(
            total=httpc_params["session"]["timeout"]
        )

    async with aiohttp.ClientSession(**httpc_params.get("session", {})) as session:
        text = await fetch_all(session, urls, httpc_params)
        return text
    
async def fetch(
    session: aiohttp.ClientSession, url: str, httpc_params: dict = DEFAULT_HTTPC_PARAMS
) -> aiohttp.ClientResponse:
    """
    Fetches the content of a URL.

    :param session: a dict representing the current session
    :type session: dict
    :param url: the url where fetch the content
    :type url: str
    :param httpc_params: parameters to perform http requests.
    :type httpc_params: dict

    :returns: the client response 
    :rtype: aiohttp.ClientResponse
    """

    async with session.get(url, **httpc_params.get("connection", {})) as response:
        if response.status != 200:  # pragma: no cover
            response.raise_for_status()
        return response


async def fetch_all(
    session: aiohttp.ClientSession, urls: list[str], httpc_params: dict = DEFAULT_HTTPC_PARAMS
) -> list[requests.Response]:
    """
    Fetches the content of a list of URL.

    :param session: a dict representing the current session
    :type session: dict
    :param urls: the url list where fetch the content
    :type urls: list[str]
    :param httpc_params: parameters to perform http requests.
    :type httpc_params: dict

    :raises HttpError: if the response status code is not 200 or a connection error occurs

    :returns: the list of responses in string format
    :rtype: list[str]
    """

    tasks = []
    for url in urls:
        task = asyncio.create_task(fetch(session, url, httpc_params))
        tasks.append(task)

    try:
        results: list[requests.Response] = await asyncio.gather(*tasks)
    except aiohttp.ClientConnectorError as e:
        raise HttpError(f"Connection error: {e}")

    for r in results:
        if r.status_code != 200:
            raise HttpError(f"HTTP error: {r.status_code} -- {r.reason}")

    return results