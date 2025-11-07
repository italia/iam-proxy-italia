import base64
import binascii
import json
import logging

import cryptojwt
from cryptojwt.exception import UnsupportedAlgorithm, VerificationError
from cryptojwt.jwe.jwe import factory
from cryptojwt.jwe.jwe_ec import JWE_EC
from cryptojwt.jwe.jwe_rsa import JWE_RSA
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.jws import JWS
from cryptojwt.jws.utils import left_hash
from typing import Union

#todo read from config



logger = logging.getLogger(__name__)


def unpad_jwt_element(jwt: str, position: int) -> dict:
    b = jwt.split(".")[position]
    padded = f"{b}{'=' * divmod(len(b), 4)[1]}"
    data = json.loads(base64.urlsafe_b64decode(padded))
    return data


def unpad_jwt_head(jwt: str) -> dict:
    return unpad_jwt_element(jwt, position=0)


def unpad_jwt_payload(jwt: str) -> dict:
    return unpad_jwt_element(jwt, position=1)


def create_jwe(plain_dict: Union[dict, str, int, None], jwk_dict: dict, default_jwe_alg: str, default_jwe_enc: str,  **kwargs) -> str:
    logger.debug(f"Encrypting dict as JWE: " f"{plain_dict}")
    _key = key_from_jwk_dict(jwk_dict)

    if isinstance(_key, cryptojwt.jwk.rsa.RSAKey):
        JWE_CLASS = JWE_RSA
    elif isinstance(_key, cryptojwt.jwk.ec.ECKey):
        JWE_CLASS = JWE_EC

    if isinstance(plain_dict, dict):
        _payload = json.dumps(plain_dict).encode()
    elif not plain_dict:
        logger.warning("create_jwe with null payload!")
        _payload = ""
    elif isinstance(plain_dict, (str, int)):
        _payload = plain_dict
    else:
        logger.error("create_jwe with unsupported payload type!")
        _payload = ""

    _keyobj = JWE_CLASS(
        _payload,
        alg=default_jwe_alg,
        enc=default_jwe_enc,
        kid=_key.kid,
        **kwargs
    )

    jwe = _keyobj.encrypt(_key.public_key())
    logger.debug(f"Encrypted dict as JWE: {jwe}")
    return jwe


def decrypt_jwe(jwe: str, jwk_dict: dict, default_jwe_alg: str, default_jwe_enc: str, encryption_alg_values_supported: list[str]) -> dict:
    # get header
    try:
        jwe_header = unpad_jwt_head(jwe)
    except (binascii.Error, Exception) as e:  # pragma: no cover
        logger.error(f"Failed to extract JWT header: {e}")
        raise VerificationError("The JWT is not valid")

    _alg = jwe_header.get("alg", default_jwe_alg)
    _enc = jwe_header.get("enc", default_jwe_enc)
    jwe_header.get("kid")

    if _alg not in encryption_alg_values_supported:  # pragma: no cover
        raise UnsupportedAlgorithm(f"{_alg} has beed disabled for security reason")

    _decryptor = factory(jwe, alg=_alg, enc=_enc)

    # _dkey = RSAKey(priv_key=PRIV_KEY)
    _dkey = key_from_jwk_dict(jwk_dict)
    msg = _decryptor.decrypt(jwe, [_dkey])

    try:
        msg_dict = json.loads(msg)
        logger.debug(f"Decrypted JWT as: {json.dumps(msg_dict, indent=2)}")
    except json.decoder.JSONDecodeError:
        msg_dict = msg
        logger.debug(f"Decrypted JWT as: {msg_dict}")
    return msg_dict


def create_jws(payload: dict, jwk_dict: dict, alg: str = "RS256", protected:dict = {}, **kwargs) -> str:
    _key = key_from_jwk_dict(jwk_dict)
    _signer = JWS(payload, alg=alg, **kwargs)

    signature = _signer.sign_compact([_key], protected=protected, **kwargs)
    return signature


def verify_jws(jws: str, pub_jwk: dict, signing_alg_values_supported: list[str],  **kwargs) -> str:
    _key = key_from_jwk_dict(pub_jwk)

    _head = unpad_jwt_head(jws)
    if _head.get("kid") != pub_jwk["kid"]:  # pragma: no cover
        raise Exception(
            f"kid error: {_head.get('kid')} != {pub_jwk['kid']}"
        )

    _alg = _head["alg"]
    if _alg not in signing_alg_values_supported or not _alg:  # pragma: no cover
        raise UnsupportedAlgorithm(f"{_alg} has beed disabled for security reason")

    verifier = JWS(alg=_head["alg"], **kwargs)
    msg = verifier.verify_compact(jws, [_key])
    return msg


def verify_at_hash(id_token, access_token) -> bool:
    id_token_at_hash = id_token['at_hash']
    at_hash = left_hash(access_token, "HS256")
    if at_hash != id_token_at_hash:
        raise Exception(
            f"at_hash error: {at_hash} != {id_token_at_hash}"
        )
    return True
