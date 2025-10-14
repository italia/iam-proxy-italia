import json

from typing import Union
from cryptojwt.jwk.jwk import key_from_jwk_dict

from .helpers.jwks import serialize_rsa_key

SIGNING_ALG_VALUES_SUPPORTED=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]
ENCRYPTION_ENC_SUPPORTED = [
    "A128CBC-HS256",
    "A192CBC-HS384",
    "A256CBC-HS512",
    "A128GCM",
    "A192GCM",
    "A256GCM",
]
ENTITY_TYPE_LEAFS = [
    "openid_relying_party",
    "openid_provider",
    "openid_credential_issuer",
    "oauth_resource",
    "wallet_provider",
    "wallet_relying_party"
]
ENTITY_TYPES = ["federation_entity"] + ENTITY_TYPE_LEAFS

ENCRYPTION_ALG_VALUES_SUPPORTED=[
        "RSA-OAEP",
        "RSA-OAEP-256",
        "ECDH-ES",
        "ECDH-ES+A128KW",
        "ECDH-ES+A192KW",
        "ECDH-ES+A256KW",
    ]


class ValidationError(Exception):
    pass


def validate_public_jwks(values: Union[dict, list]):
    if isinstance(values, dict):
        values = [values]
    try:
        for jwk_dict in values:
            _k = key_from_jwk_dict(jwk_dict)
            if _k.private_key():
                _pub = serialize_rsa_key(_k.public_key())
                raise ValidationError(
                    f"This JWK is is private {json.dumps(jwk_dict)}. "
                    f"It MUST be public instead, like this: {json.dumps([_pub])}."
                )
    except Exception as e:
        raise ValidationError(f"Not valid: {e}")


def validate_metadata_algs(metadata: dict):
    amap = dict(
        id_token_signing_alg_values_supported = SIGNING_ALG_VALUES_SUPPORTED,
        id_token_encryption_alg_values_supported = ENCRYPTION_ALG_VALUES_SUPPORTED,
        id_token_encryption_enc_values_supported = ENCRYPTION_ENC_SUPPORTED,
        token_endpoint_auth_signing_alg_values_supported = SIGNING_ALG_VALUES_SUPPORTED,
        userinfo_encryption_alg_values_supported = ENCRYPTION_ALG_VALUES_SUPPORTED,
        userinfo_encryption_enc_values_supported = ENCRYPTION_ENC_SUPPORTED,
        userinfo_signing_alg_values_supported = SIGNING_ALG_VALUES_SUPPORTED,
        request_object_encryption_alg_values_supported = ENCRYPTION_ALG_VALUES_SUPPORTED,
        request_object_encryption_enc_values_supported = ENCRYPTION_ENC_SUPPORTED,
        request_object_signing_alg_values_supported = SIGNING_ALG_VALUES_SUPPORTED,
    )
    if metadata.get("openid_provider", None):
        md = metadata["openid_provider"]
        for k, v in amap.items():
            if k in md:
                for alg in md[k]:
                    if alg not in v:
                        raise ValidationError(
                            f"{k} has an unsupported value {alg}. "
                            f"Supported algs are {v}"
                        )


def validate_entity_metadata(value):
    ...
    # status = False
    # for i in ENTITY_TYPES:
    #     if i in value:
    #         status = True
    # if not status:
    #     raise ValidationError(
    #         f'Need to specify one of {", ".join(ENTITY_TYPES)}'
    #     )
    # # todo
    # if "openid_provider" in value:
    #     schema = OIDCFED_PROVIDER_PROFILES[OIDCFED_DEFAULT_PROVIDER_PROFILE]
    #     try:
    #         schema["op_metadata"](**value["openid_provider"])
    #     except Exception as e:
    #         raise ValidationError(
    #             f"OP metadata fail {e}. "
    #         )
    # if "openid_relying_party" in value:
    #     schema = RP_PROVIDER_PROFILES[RP_DEFAULT_PROVIDER_PROFILES]
    #     try:
    #         schema["rp_metadata"](**value["openid_relying_party"])
    #     except Exception as e:
    #         raise ValidationError(
    #             f"RP metadata fail {e}. "
    #         )
    #
    # # TODO - add wallet_provider and wallet_relying_party once standardized


def validate_private_jwks(values: Union[dict, list]):
    if isinstance(values, dict):
        values = [values]
    try:
        for jwk_dict in values:
            _k = key_from_jwk_dict(jwk_dict)
            if not _k.private_key():
                raise ValidationError(f"Can't extract a private JWK from {jwk_dict}")
    except Exception as e:
        raise ValidationError(f"Not valid: {e}")
