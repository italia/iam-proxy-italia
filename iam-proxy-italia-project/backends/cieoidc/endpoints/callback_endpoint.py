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

class CallBackHandler(BaseEndpoint):

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

        self.__create_token(authorization, code)

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

        token_response = self.__access_token_request(
            redirect_uri=authorization_data["redirect_uri"],
            state=authorization.get("state"),
            code=code,
            client_id=authorization.get("client_id"),
            token_endpoint_url=authorization["provider_configuration"]["openid_provider"].get("token_endpoint"),
            code_verifier=authorization_data.get("code_verifier"),
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

        self.__update_authentication_token(authorization, access_token, id_token, token_response)

        user_info = self.get_userinfo(
            authorization.get("state"),
            authorization.get("access_token"),
            authorization.get("provider_configuration"),
            verify=self.httpc_params
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


    def __get_authorization(self, state: str):

        """
        method __get_authorization:
        This method get the state from DB.

        :type self: object
        :type state: str

        :param self: object
        :param state: str

        """

        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. Params [state {state}]"
        )

        output = {'client_id': 'http://relying-party.org:8001', 'state': 'kTN6Rb83bJEMjKakV1DTlVh9xpSTyQOm', 'endpoint': 'http://cie-provider.org:8002/oidc/op/authorization', 'provider_id': 'http://cie-provider.org:8002/oidc/op/', 'data': '{"iss": null, "scope": "openid", "redirect_uri": "http://relying-party.org:8001/oidc/rp/callback", "response_type": "code", "nonce": "XGJNw0R2poSWEC3VAabCJVu6m6mOBhOI", "state": "kTN6Rb83bJEMjKakV1DTlVh9xpSTyQOm", "client_id": null, "endpoint": "http://cie-provider.org:8002/oidc/op/authorization", "acr_values": "https://www.spid.gov.it/SpidL2", "iat": 1759501758, "exp": 1759501818, "jti": "f8b1dee2-b3e4-4e7a-a1f7-9499642164a9", "aud": "http://cie-provider.org:8002/oidc/op/authorization", "claims": {"id_token": {"family_name": {"essential": true}, "given_name": {"essential": true}}, "userinfo": {"given_name": null, "family_name": null, "email": null, "https://attributes.eid.gov.it/fiscal_number": null}}, "prompt": "consent login", "code_verifier": "TD7mCHoId-sCz8eMK.YQtx6Lv~yVqxE6RkI14JPFORWUNBtcQ2hG1ubG-5QgaiOL_Wkxk7WE-a4VrzN9D8V~NgooPGTjwbjmtgM_3H_MyOqVCN1Iqd", "code_challenge": "7w-ZWqS9uuuL5LnRZj26yYJB6EX_E9z8zvKOK_nIZIA", "code_challenge_method": "S256"}', 'provider_configuration': {'federation_entity': {'federation_resolve_endpoint': 'http://cie-provider.org:8002/oidc/op/resolve', 'organization_name': 'CIE OIDC identity provider', 'homepage_uri': 'http://cie-provider.org:8002', 'policy_uri': 'http://cie-provider.org:8002/oidc/op/en/website/legal-information', 'logo_uri': 'http://cie-provider.org:8002/static/svg/logo-cie.svg', 'contacts': ['tech@example.it']}, 'openid_provider': {'authorization_endpoint': 'http://cie-provider.org:8002/oidc/op/authorization', 'revocation_endpoint': 'http://cie-provider.org:8002/oidc/op/revocation', 'id_token_encryption_alg_values_supported': ['RSA-OAEP'], 'id_token_encryption_enc_values_supported': ['A128CBC-HS256'], 'token_endpoint': 'http://cie-provider.org:8002/oidc/op/token', 'userinfo_endpoint': 'http://cie-provider.org:8002/oidc/op/userinfo', 'introspection_endpoint': 'http://cie-provider.org:8002/oidc/op/introspection', 'claims_parameter_supported': True, 'contacts': ['ops@https://idp.it'], 'code_challenge_methods_supported': ['S256'], 'client_registration_types_supported': ['automatic'], 'request_authentication_methods_supported': {'ar': ['request_object']}, 'acr_values_supported': ['https://www.spid.gov.it/SpidL1', 'https://www.spid.gov.it/SpidL2', 'https://www.spid.gov.it/SpidL3'], 'claims_supported': ['given_name', 'family_name', 'birthdate', 'gender', 'phone_number', 'https://attributes.eid.gov.it/fiscal_number', 'phone_number_verified', 'email', 'address', 'document_details', 'https://attributes.eid.gov.it/physical_phone_number'], 'grant_types_supported': ['authorization_code', 'refresh_token'], 'id_token_signing_alg_values_supported': ['RS256', 'ES256'], 'issuer': 'http://cie-provider.org:8002/oidc/op', 'jwks_uri': 'http://cie-provider.org:8002/oidc/op/openid_provider/jwks.json', 'signed_jwks_uri': 'http://cie-provider.org:8002/oidc/op/openid_provider/jwks.jose', 'jwks': {'keys': [{'kty': 'RSA', 'use': 'sig', 'e': 'AQAB', 'n': 'rJoSYv1stwlbM11tR9SYGIJuzqlJe2bv2N35oPRbwV_epjNWvGG2ZqEj53YFMC8AMZNFhuLa_LNwr1kLVE-jXQe8xjiLhe7DgMf1OnSzq9yAEXVo19BPBwkgJe2jp9HIgM_nfbIsUbSSkFAM2CKvGb0Bk2GvvqXZ12P-fpbVyA9hIQr6rNTqnCGx2-v4oViGG4u_3iTw7D1ZvLWmrmZOaKnDAqG3MJSdQ-2ggQ-Aiahg48si9C9D_JgnBV9tJ2eCS58ZC6kVG5sftElQVdH6e26mz464TZj5QgCwZCTsAQfIvBoXSdCKxpnvsFfrajz4q9BiXAryxIOl5fLmCFVNhw', 'kid': 'Pd2N9-TZz_AWS3GFCkoYdRaXXls8YPhx_d_Ez7JwjQI'}]}, 'scopes_supported': ['openid', 'offline_access'], 'logo_uri': 'http://cie-provider.org:8002/static/images/logo-cie.png', 'organization_name': 'SPID OIDC identity provider', 'op_policy_uri': 'http://cie-provider.org:8002/oidc/op/en/website/legal-information', 'request_parameter_supported': True, 'request_uri_parameter_supported': True, 'require_request_uri_registration': True, 'response_types_supported': ['code'], 'response_modes_supported': ['query', 'form_post'], 'subject_types_supported': ['pairwise', 'public'], 'token_endpoint_auth_methods_supported': ['private_key_jwt'], 'token_endpoint_auth_signing_alg_values_supported': ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'], 'userinfo_encryption_alg_values_supported': ['RSA-OAEP', 'RSA-OAEP-256'], 'userinfo_encryption_enc_values_supported': ['A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512', 'A128GCM', 'A192GCM', 'A256GCM'], 'userinfo_signing_alg_values_supported': ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'], 'request_object_encryption_alg_values_supported': ['RSA-OAEP', 'RSA-OAEP-256'], 'request_object_encryption_enc_values_supported': ['A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512', 'A128GCM', 'A192GCM', 'A256GCM'], 'request_object_signing_alg_values_supported': ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512']}}}

        return output

    def __create_token(self, authorization_input: dict, code: str):

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

        authorization.id_token = id_token

        authorization.scope = token_response.get("scope")

        authorization.token_type = token_response["token_type"]

        authorization.expires_in = token_response["expires_in"]

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

    def __access_token_request(
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
