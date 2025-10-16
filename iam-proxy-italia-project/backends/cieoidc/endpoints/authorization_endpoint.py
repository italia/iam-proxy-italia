import logging
import inspect
import json
import uuid
from datetime import datetime, timezone
from pydantic import ValidationError
from typing import Callable, Optional
from copy import deepcopy
from typing import NoReturn
from satosa.attribute_mapping import AttributeMapper
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Response
from satosa.response import Redirect
from ..models.oidc_auth import OidcAuthentication
from ..storage import StorageFactory, IBaseRepository
from ..utils import KeyUsage
from ..utils.exceptions import UnsupportedStorageEngine, RepositoryNotFound, StorageError
from ..utils.handlers.base_endpoint import BaseEndpoint
from ..utils.helpers.jwtse import create_jws
from ..utils.helpers.jwks import  public_jwk_from_private_jwk
from ..utils.helpers.misc import (
    random_string,
    get_pkce,
    get_key,
    http_dict_to_redirect_uri_path
)
from pyeudiw.federation.trust_chain_builder import TrustChainBuilder


logger = logging.getLogger(__name__)


class AuthorizationHandler(BaseEndpoint):

    def __init__(
            self,
            config: dict,
            internal_attributes: dict[str, dict[str, str | list[str]]],
            base_url: str,
            name: str,
            auth_callback_func: Callable[[Context, InternalData], Response],
            converter: AttributeMapper,
            trust_chains
    ) -> None:
        logger.debug(
            f"Initializing: {self.__class__.__name__}."
        )
        super().__init__(config, internal_attributes, base_url, name, auth_callback_func, converter)
        self._entity_type = self.config.get("entity_type")
        self._jwks_core = self.config.get("jwks_core")
        self.trust_chains = trust_chains

        self._repo_auth: Optional[IBaseRepository] = None
        self.__init_storage(config.get("db_config", {}))


    def __init_storage(self, config: dict) -> NoReturn:
        if not config:
            raise StorageError
        db_conn = StorageFactory.get_connection_by_config(config)
        if not db_conn:
            raise UnsupportedStorageEngine
        self._repo_auth = StorageFactory.get_repository_by_conn(db_conn, OidcAuthentication)
        if not self._repo_auth:
            raise RepositoryNotFound

    @property
    def _jwks(self) -> dict:
        _dic_jwks: dict[str, dict] = {self._entity_type: {}}
        _dic_jwks[self._entity_type]["jwks"] = [public_jwk_from_private_jwk(_k) for _k in self._jwks_core]
        return _dic_jwks

    def _require_config_field(self, path, label):
        value = self.config
        try:
            for key in path:
                value = value[key]
        except (KeyError, TypeError):
            raise ValueError(f"{label} is missing in {self.__class__.__name__}")
        if not value:
            raise ValueError(f"{label} is empty in {self.__class__.__name__}")
        return value

    def _validate_configs(self):
        """
        Validates essential configuration fields for the authorization endpoint.
        """
        self._require_config_field(
            ["endpoints", "authorization_endpoint"], "Authorization endpoint")
        self._require_config_field(
            ["endpoints", "authorization_endpoint", "config"], "Authorization endpoint config")
        self._require_config_field(
            ["endpoints", "authorization_endpoint", "config", "metadata"], "Metadata")
        self._require_config_field(
            ["endpoints", "authorization_endpoint", "config", "metadata", "openid_relying_party"],
            "OpenId Relying Party")
        self._require_config_field(
            ["endpoints", "authorization_endpoint", "config", "metadata", "openid_relying_party", "client_id"],
            "Client ID")
        self._require_config_field(
            ["endpoints", "authorization_endpoint", "config", "metadata", "openid_relying_party", "redirect_uris"],
            "Redirect URI")

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
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. Params [context {context}]"
        )

        provider_url = context.internal_data.get("target_entity_id")

        logger.debug(
            f"provider_url: {provider_url}."
        )

        trust_chain = self.__get_trust_chain(provider_url)

        authorization_endpoint = trust_chain.subject_configuration.payload["metadata"]["openid_provider"]["authorization_endpoint"]

        # generate the authorization dict
        authz_data = self.__authorization_data(authorization_endpoint)

        # Add key prompt
        authz_data["prompt"] = self.config["prompt"]

        # generation pkce value
        self.__pkce_generation(authz_data)

        authorization_entity = dict(
            client_id=self.config["metadata"]["openid_relying_party"]["client_id"],
            state=authz_data["state"],
            endpoint=authorization_endpoint,
            provider_id=trust_chain.subject,
            data=json.dumps(authz_data),
            provider_configuration=trust_chain.subject_configuration.payload["metadata"]
        )

        # Add method for DB insert
        # @TODO Insert the DB repository
        self.__insert(authorization_entity)

        self.__create_jws(authz_data)

        uri_path = AuthorizationHandler.generate_uri(authz_data)

        if "?" in authorization_endpoint:
            qstring = "&"
        else:
            qstring = "?"
        url = qstring.join((authorization_endpoint, uri_path))

        resp = Redirect(url)

        return resp

    def __get_trust_chain(self, provider: str) -> TrustChainBuilder:
        """
        Private method __get_trust_chain:
        This method get Trust chain from provider url from Trust Chains dictionary.
        @TODO method for validate trust chain

        :type self: object
        :rtype: TrustChainBuilder

        :param self: object
        :param provider: Trust chain provider
        :return: TrustChainBuilder
        """
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}."
            f"Params[provider: {provider}]"
        )
        return self.trust_chains[provider]


    def __authorization_data(self, provider_authorization_endpoint: str) -> dict:
        """
        method private authorization_data:
        This method generate the authorization data for the authorization endpoint.

        :type self: object
        :rtype: dict

        :param self: object
        :return: dict
        """
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}.]"
        )

        _timestamp_now = int(datetime.now(timezone.utc).timestamp())

        scope = self.config["metadata"]["openid_relying_party"]["scope"]

        claim = self.config["metadata"]["openid_relying_party"]["claim"]

        response_type: str = self.config["metadata"]["openid_relying_party"]["response_types"][0]

        try:
            authz_data = dict(
                iss=self.config["metadata"]["openid_relying_party"]["client_id"],
                scope=scope,
                redirect_uri=self.config["metadata"]["openid_relying_party"]["redirect_uris"][0],
                response_type=response_type,
                nonce=random_string(32),
                state=random_string(32),
                client_id=self.config["metadata"]["openid_relying_party"]["client_id"],
                endpoint=provider_authorization_endpoint,
                acr_values="https://www.spid.gov.it/SpidL2",
                # TODO Ask this to Giuseppe because into Django this variable is empty or not? OIDCFED_ACR_PROFILES = getattr(settings,"OIDCFED_ACR_PROFILES",AcrValues.l2.value)
                iat=_timestamp_now,
                exp=_timestamp_now + 60,
                jti=str(uuid.uuid4()),
                aud=provider_authorization_endpoint,
                claims=claim,
            )
        except Exception as exception:
            logger.error("Exception where generate the authz_data: {}".format(exception))
            raise exception

        return authz_data

    def __pkce_generation(self, authz_data: dict):
        """
        method private pkce_generation:
        Get method and length from configuration and generate, with utils module, the pkce values.
        Add this value into authorization data and return the dictionary updated
        :type self: object
        :type authz_data: dict

        :param self: object
        :param authz_data: dict
        """
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. Params [authz_data {authz_data}]"
        )
        if not self.config["metadata"]["openid_relying_party"]["code_challenge"]["length"]:
            raise ValueError(f"code_challenge length in configuration is empty")

        if not self.config["metadata"]["openid_relying_party"]["code_challenge"]["method"]:
            raise ValueError(f"code_challenge method in configuration is empty")

        code_challenge_length: int = self.config["metadata"]["openid_relying_party"]["code_challenge"]["length"]

        code_challenge_method: str = self.config["metadata"]["openid_relying_party"]["code_challenge"]["method"]

        pkce_values = get_pkce(code_challenge_method, code_challenge_length)

        authz_data.update(pkce_values)

    def __create_jws(self, authz_data: dict):

        """
        method private __create_jws:
        This method get key and generate the JWS.
        Add the object into authorization data and return the dictionary updated

        :type self: object
        :type authz_data: dict

        :param self: object
        :param authz_data: dict
        """
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. Params [authz_data {authz_data}]"
        )

        authz_data_obj = deepcopy(authz_data)

        authz_data_obj["iss"] = self.config["metadata"]["openid_relying_party"]["client_id"]

        jwk_core_sig = get_key(self._jwks_core, KeyUsage.signature)

        request_obj = create_jws(authz_data_obj, jwk_core_sig)

        authz_data["request"] = request_obj

    @staticmethod
    def generate_uri(authz_data: dict) -> str:

        """
        method __generate_uri:
        This method generate the URI from authorization data.

        :type self: object
        :type authz_data: dict
        :rtype: dict

        :param self: object
        :param authz_data: dict
        :return: dict
        """
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. Params [authz_data {authz_data}]"
        )

        uri_path = http_dict_to_redirect_uri_path(
            {
                "client_id": authz_data["client_id"],
                "scope": authz_data["scope"],
                "response_type": authz_data["response_type"],
                "code_challenge": authz_data["code_challenge"],
                "code_challenge_method": authz_data["code_challenge_method"],
                "request": authz_data["request"]
            }
        )

        return uri_path

    def __insert(self, obj: dict):

        """
        method __insert:
        This method insert the input dictionary into DB layer.

        :type self: object
        :type input: dict

        :param self: object
        :param input: dict

        """
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. Params [input {obj}]"
        )

        try:
            auth = OidcAuthentication(**obj)
            if not self._repo_auth.add(auth):
                logger.error("Unable to insert the Authentication object")
        except ValidationError as e:
            logger.debug(e)
        #todo manage result

        logger.debug(
            f"Registration success for input: {obj}"
        )
