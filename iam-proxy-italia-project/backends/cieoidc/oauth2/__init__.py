
import logging
import json
import inspect
import uuid
import requests

from ..tools import KeyUsage
from ..tools.utils import (
    get_key,
    iat_now, exp_from_now
)
from ..utils.jwtse import (
    verify_jws,
    unpad_jwt_payload,
    verify_at_hash, create_jws
)


logger = logging.getLogger(__name__)


class OAuth2AuthorizationCodeGrant(object):
    """
    https://tools.ietf.org/html/rfc6749
    """

    def __init__(self,**kwargs):
        self.grant_type = kwargs.get("grant_type")
        self.client_assertion_type = kwargs.get("client_assertion_type")
        self.jws_core = kwargs.get("jws_core")
        self.httpc_params = kwargs.get("httpc_params")



    def access_token_request(
        self,
        redirect_uri: str,
        state: str,
        code: str,
        client_id: str,
        token_endpoint_url: str,
        code_verifier: str = None,
    ):
        """
        Access Token Request
        https://tools.ietf.org/html/rfc6749#section-4.1.3
        """
        logger.debug(f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}."
                     f"Params[redirect_uri: {redirect_uri}, state: {state}, code: {code}, client_id: {client_id}, token_endpoint: {token_endpoint_url}, code_verifier: {code_verifier}]")

        logger.debug(f"self.client_assertion_type {self.client_assertion_type}: self.jws_core: {self.jws_core} ")
        grant_data = dict(
            grant_type=self.grant_type,
            redirect_uri=redirect_uri,
            client_id=client_id,
            state=state,
            code=code,
            code_verifier=code_verifier,
            # here private_key_jwt
            client_assertion_type=self.client_assertion_type,
            client_assertion=create_jws(
                {
                    "iss": client_id,
                    "sub": client_id,
                    "aud": [token_endpoint_url],
                    "iat": iat_now(),
                    "exp": exp_from_now(),
                    "jti": str(uuid.uuid4()),
                },
                jwk_dict=get_key(self.jws_core, KeyUsage.signature),
            ),
        )

        logger.debug(f"Access Token Request for {state}: {grant_data} ")
        token_request = requests.post(
            token_endpoint_url,
            data=grant_data,
            verify=self.httpc_params["connection"].get("ssl"),
            timeout=self.httpc_params["session"].get("timeout"),
        )

        if token_request.status_code != 200: # pragma: no cover
            logger.error(
                f"Something went wrong with {state}: {token_request.status_code}"
            )
        else:
            try:
                token_request = json.loads(token_request.content.decode())
            except Exception as e:  # pragma: no cover
                logger.error(f"Something went wrong with {state}: {e}")
        return token_request
