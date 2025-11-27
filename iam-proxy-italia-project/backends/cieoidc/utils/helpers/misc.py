import asyncio
import datetime
import importlib
import logging
import random
import os
import string
import time
import hashlib
import base64
import secrets
import urllib
import json
import requests

from functools import lru_cache
from secrets import token_hex
from typing import NamedTuple
from typing import Type

from .. import KeyUsage
from ..helpers.http import http_get_async, http_get_sync

logger = logging.getLogger(__name__)


def make_timezone_aware(
    dt: datetime.datetime,
    tz: datetime.timezone | datetime.tzinfo = datetime.timezone.utc,
) -> datetime.datetime:
    """
    Make a datetime timezone aware.

    :param dt: The datetime to make timezone aware
    :type dt: datetime.datetime
    :param tz: The timezone to use
    :type tz: datetime.timezone | datetime.tzinfo

    :returns: The timezone aware datetime
    :rtype: datetime.datetime
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=tz)
    else:
        raise ValueError("datetime is already timezone aware")


def iat_now() -> int:
    """
    Get the current timestamp in seconds.

    :returns: The current timestamp in seconds
    :rtype: int
    """
    return int(datetime.datetime.now(datetime.timezone.utc).timestamp())


def exp_from_now(minutes: int = 33) -> int:
    """
    Get the expiration timestamp in seconds for the given minutes from now.

    :param minutes: The minutes from now
    :type minutes: int

    :returns: The timestamp in seconds for the given minutes from now
    :rtype: int
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    return int((now + datetime.timedelta(minutes=minutes)).timestamp())


def datetime_from_timestamp(timestamp: int | float) -> datetime.datetime:
    """
    Get a datetime from a timestamp.

    :param value: The timestamp
    :type value: int | float

    :returns: The datetime
    :rtype: datetime.datetime
    """

    return make_timezone_aware(datetime.datetime.fromtimestamp(timestamp))

def timestamp_from_datetime(dt: datetime.datetime) -> int:
    """
    Get a timestamp from a datetime.

    :param dt: The datetime
    :type dt: datetime.datetime

    :returns: The timestamp
    :rtype: int
    """
    return int(dt.timestamp())

def get_http_url(
    urls: list[str] | str, httpc_params: dict, http_async: bool = True
) -> list[requests.Response]:
    """
    Perform an HTTP Request returning the payload of the call.

    :param urls: The url or a list of url where perform the GET HTTP calls
    :type urls: list[str] | str
    :param httpc_params: parameters to perform http requests.
    :type httpc_params: dict
    :param http_async: if is set to True the operation will be performed in async (deafault True)
    :type http_async: bool

    :returns: A list of responses.
    :rtype: list[dict]
    """
    urls = urls if isinstance(urls, list) else [urls]

    if http_async:
        responses = asyncio.run(http_get_async(urls, httpc_params))  # pragma: no cover
    else:
        responses = http_get_sync(urls, httpc_params)
    return responses


def random_token(n=254) -> str:
    """
    Generate a random token.

    :param n: The length of the token
    :type n: int

    :returns: The random token
    :rtype: str
    """
    return token_hex(n)


def get_dynamic_class(module_name: str, class_name: str) -> Type:
    """
    Get a class type dynamically.

    :param module_name: The name of the module
    :type module_name: str
    :param class_name: The name of the class
    :type class_name: str

    :returns: The class type
    :rtype: Type
    """

    module = importlib.import_module(module_name)
    instance_class = getattr(module, class_name)
    return instance_class


def dynamic_class_loader(
    module_name: str, class_name: str, init_params: dict = {}
) -> object:
    """
    Load a class dynamically.

    :param module_name: The name of the module
    :type module_name: str
    :param class_name: The name of the class
    :type class_name: str
    :param init_params: The parameters to pass to the class constructor
    :type init_params: dict

    :returns: The class instance
    :rtype: object
    """

    dynamic_class = get_dynamic_class(module_name, class_name)
    if callable(dynamic_class):
        storage_instance = dynamic_class(**init_params)
    else:
        raise TypeError(f"The class '{class_name}' in module '{module_name}' is not callable.")
    return storage_instance


_HttpcParams_T = NamedTuple("_HttpcParams_T", [("ssl", bool), ("timeout", int)])


def cacheable_get_http_url(
    cache_ttl: int, url: str, httpc_params: dict, http_async: bool = True
) -> requests.Response:
    """
    Make a cached http GET request.
    The cache duration is UP TO cache_ttl. The actual duration is always
    below that threshold.
    The cache is realized with an lru_cache, which does not natively support a
    time-based cache. To realize it, we exapand the call with a timestamp
    rounded at the desired time.
    For example, if the cache_ttl is 1 hour, and we make a request at 14:32,
    the recorded timestamp will be 14:00 and the cache will be hit for all
    subsequent requests (with the same parameters) until 14:59.
    At 15:00, we reach a cache miss and a new value will be inserted.

    The minimum supported time to live is 1 second.

    When the response is not 200, the content of the cache is invalidated
    in order to not pollute the cache whit 4xx and 5xx responses.

    IMPORTANT: this function has limited support for httpc_params.
    This is because python does not allow a lru_cache with a dictionary argument.
    Currently, the only supported arguments are:
        httpc_params.connection.ssl: bool
        httpc_params.session.timeout: int
    and they MUST be defined. When this is not the case, ValueError is raised.
    """
    ssl: bool | None = httpc_params.get("connection", {}).get("ssl", None)
    timeout: int | None = httpc_params.get("session", {}).get("timeout", None)
    if (ssl is None) or (timeout is None):
        raise ValueError(
            f"invalid parameter {httpc_params=}: ['connection']['ssl'] and ['session']['timeout'] MUST be defined"
        )
    curr_time_s = time.time_ns() // 1_000_000_000
    if cache_ttl != 0:
        ttl_timestamp = curr_time_s // cache_ttl
    else:
        ttl_timestamp = curr_time_s
    httpc_p_tuple = _HttpcParams_T(ssl, timeout)
    resp = _lru_cached_get_http_url(
        ttl_timestamp, url, httpc_p_tuple, http_async=http_async
    )

    if resp.status_code != 200:
        _lru_cached_get_http_url.cache_clear()
    return resp

def random_string(n=32):
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))  # nosec


def get_pkce(code_challenge_method: str = "S256", code_challenge_length: int = 64):
    hashers = {"S256": hashlib.sha256}

    # https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
    code_verifier_length = secrets.choice(range(43, 128 + 1))
    alpha = string.ascii_letters + string.digits + "-._~"
    code_verifier = "".join([secrets.choice(alpha) for _ in range(code_verifier_length)])

    code_challenge = hashers.get(code_challenge_method)(
        code_verifier.encode("utf-8")
    ).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
    code_challenge = code_challenge.replace("=", "")

    return {
        "code_verifier": code_verifier,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
    }

def get_key(jwks, use=KeyUsage.signature):
   for jwk in jwks:
        if jwk['use'] == use:
            return jwk
   return jwks[0]

def http_dict_to_redirect_uri_path(data):
    return urllib.parse.urlencode(data)

@lru_cache(maxsize=int(os.getenv("PYEUDIW_LRU_CACHE_MAXSIZE", 2048)))
def _lru_cached_get_http_url(
    timestamp: int,
    url: str,
    httpc_params_tuple: _HttpcParams_T,
    http_async: bool = True,
) -> requests.Response:
    """
    Wraps method 'get_http_url' around a ttl cache.
    This is done by including a timestamp in the function argument. For more,
    see the documentation of cacheable_get_http_url.

    Note that dictionary argument cannot be cached due to how lru_cache
    works; hence they are converted to a tuple.

    Moreover, a negative HTTP reponse might be cached. It is caller
    responsability to eventually clear the cache when it happens.
    """
    # explicitly delete dummy argument timestamp since it is only needed for caching lifetime
    del timestamp
    httpc_params = {
        "connection": {
            "ssl": httpc_params_tuple.ssl,
        },
        "session": {"timeout": httpc_params_tuple.timeout},
    }
    resp: list[requests.Response] = get_http_url([url], httpc_params, http_async)
    return resp[0]

def get_jwks(metadata: dict, httpc_params) -> dict:
    """
    This method is ported from spid-cie-oidc-django because we used into callback method
    get jwks or jwks_uri or signed_jwks_uri

    """
    jwks_list = []
    if metadata.get('jwks'):
        jwks_list = metadata["jwks"]["keys"]
    elif metadata.get('jwks_uri'):
        try:
            jwks_uri = metadata["jwks_uri"]
            jwks_list = get_http_url(
                [jwks_uri], httpc_params=httpc_params
            )
            jwks_list = json.loads(jwks_list[0])
        except Exception as e:
            logger.error(f"Failed to download jwks from {jwks_uri}: {e}")
    elif metadata.get('signed_jwks_uri'):
        try:
            signed_jwks_uri = metadata["signed_jwks_uri"]
            jwks_list = get_http_url(
                [signed_jwks_uri], httpc_params=httpc_params
            )[0]
        except Exception as e:
            logger.error(f"Failed to download jwks from {signed_jwks_uri}: {e}")
    return jwks_list

def get_jwk_from_jwt(jwt: str, provider_jwks: dict) -> dict:
    """
        docs here
        This method is ported from spid-cie-oidc-django because we used into callback method
    """
    head = unpad_jwt_head(jwt)
    kid = head["kid"]
    if isinstance(provider_jwks, dict) and provider_jwks.get('keys'):
        provider_jwks = provider_jwks['keys']
    for jwk in provider_jwks:
        if jwk["kid"] == kid:
            return jwk
    return {}

def unpad_jwt_head(jwt: str) -> dict:
    """
        docs here
        see get_jwk_from_jwt
    """
    return unpad_jwt_element(jwt, position=0)

def unpad_jwt_element(jwt: str, position: int) -> dict:
    """
        docs here
        see unpad_jwt_head
    """
    b = jwt.split(".")[position]
    padded = f"{b}{'=' * divmod(len(b), 4)[1]}"
    data = json.loads(base64.urlsafe_b64decode(padded))
    return data

def issuer_prefixed_sub(
    user_info: dict, client_conf: dict, data: dict = None, kwargs: dict = {}
):
    return f"{client_conf['provider_id']}{data.get('sep', '__')}{user_info['sub']}"

def import_string(dotted_path):

    try:
        module_path, attr_name = dotted_path.rsplit('.', 1)
    except ValueError as err:
        raise ImportError(f"{dotted_path} path not found") from err

    module = importlib.import_module(module_path)

    try:
        return getattr(module, attr_name)
    except AttributeError as err:
        raise ImportError(f"Module '{module_path}' dont have the '{attr_name}'.") from err


def process_user_attributes(userinfo: dict, user_map: dict, authz: dict):
    data = dict()
    for k, v in user_map.items():
        for i in v:
            if isinstance(i, str):
                if i in userinfo:
                    data[k] = userinfo[i]
                    break

            elif isinstance(i, dict):
                # Assumiamo che il dizionario contenga almeno "func" e "kwargs"
                func_path = i["func"]
                kwargs = i.get("kwargs", {})  # Safe default in caso manchi

                # Import dinamico della funzione
                func = import_string(func_path)

                # Chiama la funzione passando userinfo, authz e kwargs
                value = func(userinfo, authz, kwargs)

                if value:
                    data[k] = value
                    break
    return data