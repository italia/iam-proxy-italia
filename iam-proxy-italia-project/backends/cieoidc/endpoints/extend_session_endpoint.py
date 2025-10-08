import logging
import json
import inspect
import uuid
import requests
from typing import Callable
from satosa.attribute_mapping import AttributeMapper
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Response
from ..tools import KeyUsage
from pyeudiw.tools.base_endpoint import BaseEndpoint
from pyeudiw.trust.dynamic import CombinedTrustEvaluator
from ..oauth2 import OAuth2AuthorizationCodeGrant
from ..oidc import OidcUserInfo
from ..tools.utils import (
    get_jwks,
    get_jwk_from_jwt,
    get_key,
    process_user_attributes, iat_now, exp_from_now
)
from ..utils.jwtse import (
    verify_jws,
    unpad_jwt_payload,
    verify_at_hash, create_jws
)


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



        # auth_tokens = OidcAuthenticationToken.objects.filter(
        #     user=request.user
        # ).filter(revoked__isnull=True)
        #
        # if not auth_tokens:
        #     logger.warning(
        #         "Token request failed: not found any authentication session"
        #     )
        #
        # auth_token = auth_tokens.last()
        #
        # try:
        #     token_response = self.get_token_request(auth_token, request, TokenRequestType.refresh)  # "refresh")
        #     if token_response.status_code == 400:
        #         return HttpResponseRedirect(reverse("spid_cie_rp_landing"))
        #
        #     refresh_token_response = json.loads(token_response.content.decode())
        #
        #     auth_token.refresh_token = refresh_token_response["refresh_token"]
        #     auth_token.access_token = refresh_token_response["access_token"]
        #     auth_token.save()
        #
        #     decoded_access_token = unpad_jwt_payload(refresh_token_response["access_token"])
        #     decoded_refresh_token = unpad_jwt_payload(refresh_token_response["refresh_token"])
        #
        #     request.session["rt_expiration"] = decoded_refresh_token['exp'] - iat_now()
        #     request.session["rt_jti"] = decoded_refresh_token['jti']
        #     request.session["oidc_rp_user_attrs"] = request.user.attributes
        #
        #     request.session["at_expiration"] = decoded_access_token['exp'] - iat_now()
        #     request.session["at_jti"] = decoded_access_token['jti']
        #
        #     return HttpResponseRedirect(
        #         getattr(
        #             settings, "LOGIN_REDIRECT_URL", None
        #         ) or reverse("spid_cie_rp_echo_attributes")
        #     )
        # except Exception as e:  # pragma: no cover
        #     logger.warning(f"Refresh Token request failed: {e}")