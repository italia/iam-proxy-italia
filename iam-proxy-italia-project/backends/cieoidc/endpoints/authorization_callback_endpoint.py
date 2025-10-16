import logging
import json
import inspect
from typing import Callable
from satosa.attribute_mapping import AttributeMapper
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Response
from typing import NoReturn
from pydantic import ValidationError
from backends.cieoidc.utils.clients.oauth2 import OAuth2AuthorizationCodeGrant
from backends.cieoidc.utils.clients.oidc import OidcUserInfo
from ..utils.exceptions import UnsupportedStorageEngine, RepositoryNotFound, StorageError
from ..models.oidc_auth import OidcAuthentication
from ..storage import StorageFactory
from ..utils.helpers.misc import (
    get_jwks,
    get_jwk_from_jwt,
    process_user_attributes
)
from ..utils.handlers.base_endpoint import BaseEndpoint
from ..utils.helpers.jwtse import (
    verify_jws,
    unpad_jwt_payload,
    verify_at_hash
)
from pyeudiw.trust.dynamic import CombinedTrustEvaluator


logger = logging.getLogger(__name__)

class AuthorizationCallBackHandler(BaseEndpoint):

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

        self.__init_storage(config.get("db_config", {}))

    def __init_storage(self, config: dict) -> NoReturn:
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. Params [config {config}]"
        )
        if not config:
            raise StorageError
        db_conn = StorageFactory.get_connection_by_config(config)
        if not db_conn:
            raise UnsupportedStorageEngine
        self._repo_auth_callback = StorageFactory.get_repository_by_conn(db_conn, OidcAuthentication)
        if not self._repo_auth_callback:
            raise RepositoryNotFound

    def endpoint(self, context, *args):
        """
        Handles the authentication response from the OP.
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

        if context.qs_params.get("error"):
            logger.debug(
                f"error: {context.qs_params.get('error')} with details: {context.qs_params.get('error_description')}"
            )
            #@TODO Talking with Giuseppe for rendering raise exception?


        state : str = context.qs_params.get("state")

        authorization = self.__get_authorization(state)

        if not authorization:
            logger.debug("Authorization empty")
            #@TODO Talking with Giuseppe for rendering raise exception?

        logger.debug(f"authorization: {authorization}")

        # try:
        #     self.validate_json_schema(
        #         request.GET.dict(),
        #         "authn_response",
        #         "Authn response object validation failed"
        #     )
        # except ValidationException:
        #     return JsonResponse(
        #         {
        #             "error": "invalid_request",
        #             "error_description": "Authn response object validation failed",
        #         },
        #         status=400
        #     )
        #

        code: str = context.qs_params.get("code")

        iss: str = context.qs_params.get("iss")

        if not self.__check_provider(authorization.get("provider_id"), iss):
            logger.debug("Provider ID and iss don't match")
            #@TODO Talking with Giuseppe for rendering raise exception?

        authorization_token =  self.__create_token(authorization, code)

        # @TODO Talking with Giuseppe for this logic
        # self.rp_conf = FederationEntityConfiguration.objects.filter(
        #     sub=authz_token.authz_request.client_id
        # ).first()
        # if not self.rp_conf:
        #     context = {
        #         "error": "invalid request",
        #         "error_description": _("Relying party not found"),
        #     }
        #     return render(request, self.error_template, context, status=400)
        #

        authorization_data = json.loads(authorization.get("data"))

        oAuth2_authorization = OAuth2AuthorizationCodeGrant(grant_type = self.grant_type,
                                                            client_assertion_type = self.client_assertion_type,
                                                            jws_core = self.jws_core,
                                                            httpc_params = self.httpc_params)

        token_response = oAuth2_authorization.access_token_request(redirect_uri=authorization_data["redirect_uri"],
            state=authorization.get("state"),
            code=code,
            client_id=authorization.get("client_id"),
            token_endpoint_url=authorization["provider_configuration"]["openid_provider"].get("token_endpoint"),
            code_verifier=authorization_data.get("code_verifier")
         )

        if not token_response:
            logger.debug("Token response is empty")
            #@TODO Talking with Giuseppe for rendering raise exception?


        # else:
        #     try:
        #         self.validate_json_schema(
        #             token_response,
        #             "token_response",
        #             "Token response object validation failed"
        #         )
        #     except ValidationException:
        #         return JsonResponse(
        #             {
        #                 "error": "invalid_request",
        #                 "error_description": "Token response object validation failed",
        #             },
        #             status=400
        #         )

        jwks = get_jwks(authorization.get("provider_configuration"), self.httpc_params)

        access_token = token_response["access_token"]

        id_token = token_response["id_token"]

        op_ac_jwk = get_jwk_from_jwt(access_token, jwks)

        op_id_jwk = get_jwk_from_jwt(id_token, jwks)

        if not op_ac_jwk or not op_id_jwk:
            logger.debug("AC JWK or ID JWK is empty")
            # @TODO Talking with Giuseppe for rendering raise exception?

        try:
            verify_jws(access_token, op_ac_jwk)
        except Exception as exception:
            logger.error(f"Exception from verify_jws, detail: {exception}")
            # @TODO Talking with Giuseppe for rendering raise exception?

        try:
            verify_jws(id_token, op_id_jwk)
        except Exception as exception:
            logger.error(f"Exception from verify_jws, detail: {exception}")
            # @TODO Talking with Giuseppe for rendering raise exception?

        decoded_id_token = unpad_jwt_payload(id_token)

        logger.debug(f"Token decoded:  {decoded_id_token}")

        try:
            verify_at_hash(decoded_id_token, access_token)
        except Exception as exception:
            logger.error(f"Exception from verify_at_hash, detail: {exception}")
            # @TODO Talking with Giuseppe for rendering raise exception?

        decoded_access_token = unpad_jwt_payload(access_token)
        logger.debug(f"unpad_jwt_payload: {decoded_access_token}")

        self.__update_authentication_token(authorization_token, access_token, id_token, token_response)

        oidc_user = OidcUserInfo(authorization.get("provider_configuration"), self.jwks_core)

        user_info = oidc_user.get_userinfo(
            authorization.get("state"),
            authorization_token.get("access_token"),
            verify=self.httpc_params["connection"].get("ssl"),
            timeout=self.httpc_params["session"].get("timeout")
        )


        if not user_info:
            logger.error(
                "User_info request failed for state: "
                f"{authorization.get("state")} to {authorization.get("provider_id")}"
            )
            # @TODO Talking with Giuseppe for rendering raise exception?

        user_attrs = process_user_attributes(user_info, self.claims, authorization)

        if not user_attrs:
            logger.error(
                "No user attributes have been processed: "
                f"user_info: {user_info} claims: {self.claims} authorization: {authorization}"
            )
            # @TODO Talking with Giuseppe for rendering raise exception?

        user = self.user_reunification(user_attrs)

        if not user:
            logger.error("User is empty")
            # @TODO Talking with Giuseppe for rendering raise exception?

        authorization_token["user"] = user
        # @TODO Update the authorization_token

        #  add header
        # @TODO Talking with Manuel and Giuseppe
        context.http_headers["authorization_token"] = authorization_token
        context.http_headers["refresh_token"] = token_response["refresh_token"]

        # request.session["rt_expiration"] = 0
        #
        # if token_response.get('refresh_token', None):
        #     refresh_token = token_response["refresh_token"]
        #     authz_token.refresh_token = refresh_token
        #     decoded_refresh_token = unpad_jwt_payload(refresh_token)
        #     request.session["rt_expiration"] = decoded_refresh_token['exp'] - iat_now()
        #     request.session["rt_jti"] = decoded_refresh_token['jti']
        #     logger.info(decoded_refresh_token)
        #
        # # authenticate the user
        # login(request, user)
        # request.session["oidc_rp_user_attrs"] = user_attrs
        #
        # request.session["at_expiration"] = decoded_access_token['exp'] - iat_now()
        # request.session["at_jti"] = decoded_access_token['jti']
        #
        # authz_token.user = user
        # authz_token.save()
        # return HttpResponseRedirect(
        #     getattr(
        #         settings, "LOGIN_REDIRECT_URL", None
        #     ) or reverse("spid_cie_rp_echo_attributes")
        # )
        return self.auth_callback_func(context, "")


    def __get_authorization(self, state: str) -> dict:

        """
        method __get_authorization:
        This method get the state from DB.

        :type self: object
        :type state: str

        :param self: object
        :param state: str

        """
        logger.debug(f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. Params [state {state}]")
        try:
            output = self._repo_auth_callback.find_all({"state": state})
            if output:
                return output[0].model_dump(mode="json")
        except ValidationError as e:
            logger.debug(e)
        return {}

    def __create_token(self, authorization_input: dict, code: str) -> dict:

        """
        method __create_token:
        This method create an instance for Authorization Token Object.

        :type self: object
        :type input: dict

        :param self: object
        :param input: dict

        """
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. Params [authorization_input {authorization_input}, code: {code}]"
        )

        # @TODO insert DB layer

        logger.debug(
            f"Registration success for input: {input}"
        )

        return { "authz_request": authorization_input, "code": code}

    def __update_authentication_token(self, authorization: dict, access_token: dict, id_token: dict, token_response: dict):
        """
        method __update_authentication_token:
        This method update the authentication token. Add this properties:
            - access_token
            - id_token
            - scope
            - token_type
            - expiration
        """
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. "
            f"Params [authorization {authorization}, access_token: {access_token}, id_token:{id_token}, token_response:{token_response}]"
        )
        authorization.access_token = access_token

        authorization["id_token"] = id_token

        authorization["scope"] = token_response.get("scope")

        authorization["token_type"] = token_response["token_type"]

        authorization["expires_in"] = token_response["expires_in"]

        authorization["refresh_token"] = token_response["refresh_token"]

        self.__insert_token(authorization)

    def __insert_token(self, authorization_input: dict):

        """
        method __insert_token:
        This method create the instance for authorization input.

        :type self: object
        :type authorization_input: dict

        :param self: object
        :param authorization_input: dict

        """
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. Params [authorization_input {authorization_input}]"
        )

        # @TODO insert DB layer

        logger.debug(
            f"Registration success for input: {input}"
        )

    def __check_provider(self, provider_is: str, iss: str) -> bool:

        """
        method __check_issuer:
        This method check if provider is equal to iss.


        :type self: object
        :type provider_is: dict
        :type iss: dict

        :param self: object
        :param provider_is: dict
        :param iss: dict

        """
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. Params [provider_is {provider_is}, iss: {iss} ]"
        )

        if provider_is.endswith("/") and not iss.endswith("/"):
            iss += "/"
        elif not provider_is.endswith("/") and iss.endswith("/"):
            iss = iss[:-1]

        return provider_is == iss
