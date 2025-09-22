import json
import logging

from typing import Union
from cryptojwt.jwk.jwk import key_from_jwk_dict

from ..tools.utils import exp_from_now, iat_now
from ..utils.jwks import serialize_rsa_key, private_pem_from_jwk, public_pem_from_jwk
from ..utils.jwtse import create_jws

logger = logging.getLogger(__name__)


ENTITY_TYPE_LEAFS = [
    "openid_relying_party",
    "openid_provider",
    "openid_credential_issuer",
    "oauth_resource",
    "wallet_provider",
    "wallet_relying_party"
]
def is_leaf(statement_metadata):
    for _typ in ENTITY_TYPE_LEAFS:
        if _typ in statement_metadata:
            return True # pragma: no cover


class FederationEntityConfiguration:
    """
    Federation Authority configuration.
    """

    def __init__(self, sub, exp, default_signature_alg, jwks_core, jwks_fed, entity_type, metadata,
                 authority_hints= None, trust_marks=None, trust_mark_issuers=None, constraints=None):
        self.sub = sub
        self.default_exp: int = exp
        self.default_signature_alg: str = default_signature_alg
        self.jwks_fed: list = jwks_fed
        self.jwks_core = jwks_core
        self.authority_hints = authority_hints
        self.trust_marks = trust_marks
        self.trust_mark_issuers = trust_mark_issuers
        self.entity_type = entity_type
        self.metadata: dict = metadata
        self.constraints = constraints

    @property
    def public_jwks(self):
        res = []
        for i in self.jwks_fed:
            skey = serialize_rsa_key(key_from_jwk_dict(i).public_key())
            skey["kid"] = i["kid"]
            res.append(skey)
        return res

    @property
    def pems_as_dict(self):
        res = {}
        for i in self.jwks_fed:
            res[i["kid"]] = {
                "private": private_pem_from_jwk(i),
                "public": public_pem_from_jwk(i),
            }
        return res

    @property
    def pems_as_json(self):
        return json.dumps(self.pems_as_dict, indent=2)

    @property
    def kids(self) -> list:
        return [i["kid"] for i in self.jwks_fed]

    @property
    def type(self) -> list:
        return [i for i in self.metadata.keys()]

    @property
    def is_leaf(self):
        return is_leaf(self.metadata)

    @property
    def entity_configuration_as_dict(self):
        conf = {
            "exp": exp_from_now(self.default_exp),
            "iat": iat_now(),
            "iss": self.sub,
            "sub": self.sub,
            "jwks": {"keys": self.public_jwks},
            "metadata": self.metadata,
        }

        if self.trust_mark_issuers:
            conf["trust_mark_issuers"] = self.trust_mark_issuers

        if self.trust_marks:
            conf["trust_marks"] = self.trust_marks

        if self.constraints:
            conf["constraints"] = self.constraints

        if self.authority_hints:
            conf["authority_hints"] = self.authority_hints
        elif self.is_leaf: # pragma: no cover
            _msg = f"Entity {self.sub} is a leaf and requires authority_hints valued"
            logger.error(_msg)

        return conf

    @property
    def entity_configuration_as_json(self):
        return json.dumps(self.entity_configuration_as_dict)

    @property
    def entity_configuration_as_jws(self, **kwargs):
        return create_jws(
            self.entity_configuration_as_dict,
            self.jwks_fed[0],
            alg=self.default_signature_alg,
            typ="entity-statement+jwt",
            **kwargs,
        )

    @property
    def fetch_endpoint(self) -> Union[str, None]:
        metadata = self.entity_configuration_as_dict.get('metadata', {})
        if 'federation_entity' in metadata:
            return metadata['federation_entity'].get("federation_fetch_endpoint", None)

    def set_jwks_as_array(self):
        for i in ('jwks_fed','jwks_core'):
            value = getattr(self, i)
            if not isinstance(value, list):
                setattr(self, i, [value])

