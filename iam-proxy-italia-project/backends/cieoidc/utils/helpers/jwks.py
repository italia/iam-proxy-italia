from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jwk.rsa import new_rsa_key
from cryptography.hazmat.primitives import serialization
from cryptojwt.jwk.rsa import RSAKey
from cryptography.hazmat.primitives.asymmetric import rsa


def create_jwk(key = None, hash_func="SHA-256"):
    key = key or new_rsa_key()
    thumbprint = key.thumbprint(hash_function=hash_func)
    jwk = key.to_dict()
    jwk["kid"] = thumbprint.decode()
    return jwk


def public_jwk_from_private_jwk(jwk_dict: dict):
    # exports public
    _k = key_from_jwk_dict(jwk_dict)
    jwk = _k.serialize()
    jwk["kid"] = jwk_dict['kid']
    return jwk


def private_pem_from_jwk(jwk_dict: dict):
    # exports private

    _k = key_from_jwk_dict(jwk_dict)
    pk = _k.private_key()
    pem = pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem.decode()


def public_pem_from_jwk(jwk_dict: dict):
    # exports private

    _k = key_from_jwk_dict(jwk_dict)
    pk = _k.public_key()
    cert = pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return cert.decode()


def serialize_rsa_key(rsa_key, kind="public", hash_func="SHA-256"):
    """
    rsa_key can be
         cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey
        or
         cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey
    """
    data = {}
    if isinstance(rsa_key, rsa.RSAPublicKey):
        data = {"pub_key": rsa_key}
    elif isinstance(rsa_key, rsa.RSAPrivateKey):
        data = {"priv_key": rsa_key}
    elif isinstance(rsa_key, (str, bytes)): # pragma: no cover
        if kind == "private":
            data = {
                "priv_key": private_jwk_from_pem(rsa_key)
            }
        else:
            data = {"pub_key": public_jwk_from_pem(rsa_key)}

    jwk_obj = RSAKey(**data)
    thumbprint = jwk_obj.thumbprint(hash_function=hash_func)

    jwk = jwk_obj.to_dict()
    jwk["kid"] = thumbprint.decode()
    return jwk


def private_jwk_from_pem(content:str, password:str = None):
    content = content.encode() if isinstance(content, str) else content
    key = serialization.load_pem_private_key(content, password=password)
    return serialize_rsa_key(key, kind='private')


def public_jwk_from_pem(content:str, password:str = None):
    content = content.encode() if isinstance(content, str) else content
    key = serialization.load_pem_public_key(content)
    return serialize_rsa_key(key, kind='public')

