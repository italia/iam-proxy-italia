import logging
from typing import Union
from xml.sax.handler import property_encoding

logger = logging.getLogger(__name__)


class ConfigurationPlugin(object):

    DEFAULT_JWE_ALG = "RSA-OAEP"
    DEFAULT_JWE_ENC = "A256CBC-HS512"
    SIGNING_ALG_VALUES_SUPPORTED = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]
    ENCRYPTION_ALG_VALUES_SUPPORTED = [
        "RSA-OAEP",
        "RSA-OAEP-256",
        "ECDH-ES",
        "ECDH-ES+A128KW",
        "ECDH-ES+A192KW",
        "ECDH-ES+A256KW",
    ]


    def __init__(self, default_jwe_alg: str, default_jwe_enc: str, signing_alg_values_supported: Union[list[str],None], encryption_alg_values_supported: Union[list[str],None] ):
        logger.debug(
            f"Initializing: {self.__class__.__name__}. Params [default_jwe_alg: {default_jwe_alg}, default_jwe_enc: {default_jwe_enc}"
            f"encryption_alg_values_supported: {encryption_alg_values_supported}, signing_alg_values_supported: {signing_alg_values_supported}]"
        )
        self.default_jwe_alg = default_jwe_alg
        self.default_jwe_enc = default_jwe_enc
        self.signing_alg_values_supported = signing_alg_values_supported
        self.encryption_alg_values_supported = encryption_alg_values_supported

    @property
    def get_default_jwe_alg(self):
        return self.default_jwe_alg

    @property
    def get_default_jwe_enc(self):
        return self.default_jwe_enc

    @property
    def get_signing_alg_values_supported(self):
        return self.signing_alg_values_supported

    @property
    def get_encryption_alg_values_supported(self):
        return self.encryption_alg_values_supported
