import copy
import json
import logging

from typing import Callable

from satosa.attribute_mapping import AttributeMapper
from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Response, Redirect

from ..models.federation import FederationEntityConfiguration
from ..utils.validators import validate_private_jwks, validate_entity_metadata
from ..utils.helpers.jwks import public_jwk_from_private_jwk
from ..utils.handlers.base_endpoint import BaseEndpoint
from ..utils.helpers.jwtse import create_jws

logger = logging.getLogger(__name__)


class EntityConfigHandler(BaseEndpoint):

    OIDCFED_FEDERATION_WELLKNOWN_URL = ".well-known/openid-federation"
    OIDC_JSON_JWS_URL = "openid_relying_party/jwks.json"
    OIDC_JOSE_JWS_URL = "openid_relying_party/jwks.jose"

    def __init__(self, config: dict,
                 internal_attributes: dict[str, dict[str, str | list[str]]],
                 base_url: str,
                 name: str,
                 auth_callback_func: Callable[[Context, InternalData], Response],
                 converter: AttributeMapper,
                 trust) -> None:
        super().__init__(config, internal_attributes, base_url, name, auth_callback_func, converter)
        self._jwks_federation = self.config.get("jwks_federation")
        self._jwks_core = self.config.get("jwks_core")
        self._default_sig_alg = self.config.get("default_sig_alg", "RS256")
        self._auth_hints = self.config.get("authority_hints")
        self._trust_marks = self.config.get("trust_marks")
        self._entity_configuration_exp = self.config.get("entity_configuration_exp")
        self._entity_type = self.config.get("entity_type")
        self._client_id = self.config.get("metadata", {}).get(self._entity_type,{}).get("client_id") or f"{base_url}/{name}"
        self._validate_configs()

    @property
    def _metadata(self) -> dict:
        _meta = copy.deepcopy(self.config.get("metadata", {}))
        _meta[self._entity_type]["client_id"] = self._client_id
        _meta[self._entity_type]["jwks"] = [public_jwk_from_private_jwk(_k) for _k in self._jwks_core]
        return _meta

    def _validate_configs(self):
        validate_private_jwks(self._jwks_core)
        validate_private_jwks(self._jwks_federation)
        validate_entity_metadata(self._metadata)

    def get_entity_configuration(self, jws=False) -> str:
        _entity = FederationEntityConfiguration(self._client_id,
                        self._entity_configuration_exp,
                        self._default_sig_alg,
                        self._jwks_core,
                        self._jwks_federation,
                        self._entity_type,
                        self._metadata,
                        self._auth_hints, self._trust_marks)
        return _entity.entity_configuration_as_jws if jws else json.dumps(_entity.entity_configuration_as_dict)

    def get_openid_jwks(self, jws=False) -> str:
        pub_keys = [public_jwk_from_private_jwk(_k) for _k in self._jwks_core]
        res = dict(keys=pub_keys)
        if not jws:
            return json.dumps(res)
        return create_jws(res, self._jwks_federation[0])


    def endpoint(self, context: Context) -> Redirect | Response:
        """
        Handle the incoming request and return a Response related to metadata.

        Args:
            context (Context): The SATOSA context object containing the request and environment information.
        Returns:
            Redirect | Response: A Response object.
        """

        status_code = "404"
        content_type = "text/plain"
        data = ""

        if context.path == f"{context.target_backend}/{self.OIDCFED_FEDERATION_WELLKNOWN_URL}":
            status_code = "200"

            if context.qs_params.get("format", "") == "json":
                content_type = "application/json"
                data = self.get_entity_configuration()
            else:
                content_type = "application/entity-statement+jwt"
                data = self.get_entity_configuration(jws=True)

        elif context.path == f"{context.target_backend}/{self.OIDC_JOSE_JWS_URL}":
            status_code = "200"
            content_type = "application/entity-statement+jwt"
            data = self.get_openid_jwks(jws=True)
        elif context.path == f"{context.target_backend}/{self.OIDC_JSON_JWS_URL}":
            status_code = "200"
            content_type = "application/json"
            data = self.get_openid_jwks()

        return Response(data, status=status_code, content=content_type)