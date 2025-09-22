
import logging


import inspect
from typing import Callable
from satosa.attribute_mapping import AttributeMapper
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Response
from pyeudiw.tools.base_endpoint import BaseEndpoint
from pyeudiw.trust.dynamic import CombinedTrustEvaluator

logger = logging.getLogger(__name__)

class CallBackHandler(BaseEndpoint):

    _SUPPORTED_RESPONSE_METHOD = "post"
    _OIDC_CALLBACK_URL = "callback"

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
            #@TODO Talking with Giuseppe for rendering

        # request_args = {k: v for k, v in request.GET.items()}
        # if "error" in request_args:
        #     return render(
        #         request,
        #         self.error_template,
        #         request_args,
        #         status=401
        #     )

        state : str = context.qs_params.get("state")

        # @TODO Talking with Giuseppe

        # authz = OidcAuthentication.objects.filter(
        #     state=request_args.get("state"),
        # )
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
        # if not authz:
        #     context = {
        #         "error": "unauthorized request",
        #         "error_description": _("Authentication not found"),
        #     }
        #     return render(request, self.error_template, context, status=401)
        # else:
        #     authz = authz.last()

        code: str = context.qs_params.get("state")

        # code = request.GET.get("code")
        # # mixups attacks prevention
        # if request.GET.get('iss', None):
        #     if request.GET['iss'] != authz.provider_id:
        #         context = {
        #             "error": "invalid request",
        #             "error_description": _(
        #                 "authn response validation failed: mixups attack prevention."
        #             ),
        #         }
        #         return render(request, self.error_template, context, status=400)
        #
        # authz_token = OidcAuthenticationToken.objects.create(
        #     authz_request=authz, code=code
        # )
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
        # authz_data = json.loads(authz.data)
        # token_response = self.access_token_request(
        #     redirect_uri=authz_data["redirect_uri"],
        #     state=authz.state,
        #     code=code,
        #     issuer_id=authz.provider_id,
        #     client_conf=self.rp_conf,
        #     token_endpoint_url=authz.provider_configuration["token_endpoint"],
        #     audience=[authz.provider_id],
        #     code_verifier=authz_data.get("code_verifier"),
        # )
        # if not token_response:
        #     context = {
        #         "error": "invalid token response",
        #         "error_description": _("Token response seems not to be valid"),
        #     }
        #     return render(request, self.error_template, context, status=400)
        #
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
        # jwks = get_jwks(authz.provider_configuration)
        # access_token = token_response["access_token"]
        # id_token = token_response["id_token"]
        #
        # op_ac_jwk = get_jwk_from_jwt(access_token, jwks)
        # op_id_jwk = get_jwk_from_jwt(id_token, jwks)
        #
        # if not op_ac_jwk or not op_id_jwk:
        #     logger.warning(
        #         "Token signature validation error, "
        #         f"the tokens were signed with a different kid from: {jwks}."
        #     )
        #     context = {
        #         "error": "invalid_token",
        #         "error_description": _("Authentication token seems not to be valid."),
        #     }
        #     return render(request, self.error_template, context, status=403)
        #
        # try:
        #     verify_jws(access_token, op_ac_jwk)
        # except Exception as e:
        #     logger.warning(
        #         f"Access Token signature validation error: {e} "
        #     )
        #     context = {
        #         "error": "token verification failed",
        #         "error_description": _("Authentication token validation error."),
        #     }
        #     return render(request, self.error_template, context, status=403)
        #
        # try:
        #     verify_jws(id_token, op_id_jwk)
        # except Exception as e:
        #     logger.warning(
        #         f"ID Token signature validation error: {e} "
        #     )
        #     context = {
        #         "error": "token verification failed",
        #         "error_description": _("ID token validation error."),
        #     }
        #     return render(request, self.error_template, context, status=403)
        #
        # decoded_id_token = unpad_jwt_payload(id_token)
        # logger.debug(decoded_id_token)
        #
        # try:
        #     verify_at_hash(decoded_id_token, access_token)
        # except Exception as e:
        #     logger.warning(
        #         f"at_hash validation error: {e} "
        #     )
        #     context = {
        #         "error": "at_hash verification failed",
        #         "error_description": _("at_hash validation error."),
        #     }
        #     return render(request, self.error_template, context, status=403)
        #
        # decoded_access_token = unpad_jwt_payload(access_token)
        # logger.debug(decoded_access_token)
        #
        # authz_token.access_token = access_token
        # authz_token.id_token = id_token
        # authz_token.scope = token_response.get("scope")
        # authz_token.token_type = token_response["token_type"]
        # authz_token.expires_in = token_response["expires_in"]
        # authz_token.save()
        #
        # userinfo = self.get_userinfo(
        #     authz.state,
        #     authz_token.access_token,
        #     authz.provider_configuration,
        #     verify=HTTPC_PARAMS.get("connection", {}).get("ssl", True)
        # )
        # if not userinfo:
        #     logger.warning(
        #         "Userinfo request failed for state: "
        #         f"{authz.state} to {authz.provider_id}"
        #     )
        #     context = {
        #         "error": "invalid userinfo response",
        #         "error_description": _("UserInfo response seems not to be valid"),
        #     }
        #     return render(request, self.error_template, context, status=400)
        #
        # # here django user attr mapping
        # user_attrs = process_user_attributes(userinfo, RP_ATTR_MAP, authz.__dict__)
        # if not user_attrs:
        #     _msg = "No user attributes have been processed"
        #     logger.warning(f"{_msg}: {userinfo}")
        #     # TODO: verify error message and status
        #     context = {
        #         "error": "missing user attributes",
        #         "error_description": _(f"{_msg}: {userinfo}"),
        #     }
        #     return render(request, self.error_template, context, status=403)
        #
        # user = self.user_reunification(user_attrs)
        # if not user:
        #     # TODO: verify error message and status
        #     context = {"error": _("No user found"), "error_description": _("")}
        #     return render(request, self.error_template, context, status=403)
        #
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