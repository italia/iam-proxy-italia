import logging
import json
import inspect

from typing import Callable
from satosa.attribute_mapping import AttributeMapper
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Response
from satosa.exception import SATOSAAuthenticationError, SATOSABadRequestError
from backends.cieoidc.utils.clients.oauth2 import OAuth2AuthorizationCodeGrant
from ..utils.handlers.base_endpoint import BaseEndpoint
from ..utils.helpers.jwtse import (
    unpad_jwt_payload
)

from pyeudiw.trust.dynamic import CombinedTrustEvaluator


logger = logging.getLogger(__name__)

class ExtendSessionHandler(BaseEndpoint):

    def __init__(
            self,
            config: dict,
            internal_attributes: dict[str, dict[str, str | list[str]]],
            base_url: str,
            name: str,
            auth_callback_func: Callable[[Context, InternalData], Response],
            converter: AttributeMapper,
            trust_evaluator: CombinedTrustEvaluator
        ) -> None:

        logger.debug(
            f"Initializing: {self.__class__.__name__}."
        )
        super().__init__(config, internal_attributes, base_url, name, auth_callback_func, converter)

        self.httpc_params = config.get("httpc_params", {})

        self.claims = config.get("claims", {})

        self.client_assertion_type = config.get("client_assertion_type")

        self.grant_type = config.get("grant_type")

        self.jws_core = config.get("jwks_core")


    def endpoint(self, context, *args):
        """
        Handles the token endpoint of the op
        :type context: satosa.context.Context
        :type args: Any
        :rtype: satosa.response.Response

        :param context: SATOSA context
        :param args: None
        :return:
        """
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. Params [qs_params {context.qs_params}]"
        )

        authorization_token = self.__get_authorization_token(context.request.get("user"))

        if not authorization_token:
            logger.warning("Token request failer: not found any authentication session")

        try:

            oAuth2_authorization = OAuth2AuthorizationCodeGrant(grant_type=self.grant_type,
                                                                client_assertion_type=self.client_assertion_type,
                                                                jws_core=self.jws_core,
                                                                httpc_params=self.httpc_params)

            token_response = oAuth2_authorization.refresh_token(authorization_token, authorization_token.get("client_id"))

            if token_response.status_code == 400:
                logger.warning("Get 400 from token response service")
                raise SATOSAAuthenticationError(context.state, "Get 400 from token response service")

            refresh_token_response = json.loads(token_response.content.decode())

            # @TODO Verify with Giuseppe
            decoded_access_token = unpad_jwt_payload(refresh_token_response["access_token"])

            # @TODO Verify with Giuseppe
            decoded_refresh_token = unpad_jwt_payload(refresh_token_response["refresh_token"])

            self.__save_refresh_token(authorization_token, refresh_token_response)

            context.http_headers["authorization_token"] = authorization_token

            context.http_headers["refresh_token"] = refresh_token_response["refresh_token"]

        except Exception as exception:  # pragma: no cover
            logger.warning(f"Refresh Token request failed: {exception}")
            raise SATOSAAuthenticationError(context.state, f"Refresh Token request failed: {exception}")



    def __get_authorization_token(self, user: dict) -> dict:
        """
        method __get_authorization_token:
        Get token from user

        :type self: object
        :type user: dict

        :param self: object
        :param user: dict

        """
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. Params [user {user}]"
        )

        # @TODO get form DB layer
        # Replace with repository
        authorization_token = {}

        logger.debug(
            f"authorization_token: {authorization_token}"
        )

        return authorization_token

    def __save_refresh_token(self, authorization_token: dict, refresh_token_response: dict) -> dict:
        """
        method __save_refresh_token:
        Save the refresh token into DB Layer

        :type self: object
        :type authorization_token: dict
        :type refresh_token_response: dict

        :param self: object
        :type authorization_token: dict
        :type refresh_token_response: dict

        """
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. "
            f"Params [authorization_token: {authorization_token}, refresh_token_response: {refresh_token_response}]"
        )

        # @TODO insert into DB layer

        authorization_token["refresh_token"] = refresh_token_response["refresh_token"]

        authorization_token["access_token"] = refresh_token_response["access_token"]


        logger.debug(
            f"authorization_token: {authorization_token}"
        )

        return authorization_token
