import logging
import requests

from backends.cieoidc.utils.exceptions import UnknownKid
from backends.cieoidc.utils.helpers.jwtse import  (
    unpad_jwt_head,
    decrypt_jwe,
    verify_jws
)
from backends.cieoidc.utils.helpers.misc import get_jwks

logger = logging.getLogger(__name__)


class OidcUserInfo(object):
    """
    https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
    """

    def __init__(self,provider_configuration: dict, jwks_core: dict, httpc_params: dict):
        self.provider_configuration = provider_configuration
        self.jwks_core = jwks_core
        self.httpc_params = httpc_params

    def __get_jwk(self, kid, jwks):
        for jwk in jwks:
            if jwk.get("kid", None) and jwk["kid"] == kid:
                return jwk
        raise UnknownKid() # pragma: no cover

    def get_userinfo(
        self, state: str, access_token: str, verify: bool, timeout: int
    ):
        """
        User Info endpoint request with bearer access token
        """
        # userinfo
        headers = {"Authorization": f"Bearer {access_token}"}
        authz_userinfo = requests.get(
            self.provider_configuration["userinfo_endpoint"],
            headers=headers,
            verify=verify,
            timeout=timeout
        )

        if authz_userinfo.status_code != 200: # pragma: no cover
            logger.error(
                f"Something went wrong with {state}: {authz_userinfo.status_code}"
            )
            return False
        else:
            try:
                # if application/json ... let it be
                return authz_userinfo.json()
            except Exception:
                logger.debug("userinfo response is not in plain json")

            try:
                jwe = authz_userinfo.content.decode()

                header = unpad_jwt_head(jwe)
                # header["kid"] kid di rp
                rp_jwk = self.__get_jwk(header["kid"], self.jwks_core)
                jws = decrypt_jwe(jwe, rp_jwk)

                if isinstance(jws, bytes):
                    jws = jws.decode()

                header = unpad_jwt_head(jws)
                idp_jwks = get_jwks(self.provider_configuration,self.httpc_params)
                idp_jwk = self.__get_jwk(header["kid"], idp_jwks)

                decoded_jwt = verify_jws(jws, idp_jwk)
                logger.debug(f"Userinfo endpoint result: {decoded_jwt}")
                return decoded_jwt

            except KeyError as e: # pragma: no cover
                logger.error(f"Userinfo response error {state}: {e}")
                return False
            except UnknownKid as e:
                logger.error(f"Userinfo Unknow KID for session {state}: {e}")
                return False
            except Exception as e:  # pragma: no cover
                logger.error(f"Userinfo response unknown error {state}: {e}")
                return False
