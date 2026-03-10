#!/usr/bin/env python3
"""
Generate X.509 chain for pyeudiw_backend.yaml with leaf FQDN from SATOSA_HOSTNAME.
Uses same JWK and ChainBuilder pattern as pyeudiw tests (test_vp_mdoc_cbor.py).
Output: PEM blocks for certificate_authorities and leaf_certificate_chains_by_ca.
"""
import base64
import os
import sys

from cryptography.hazmat.primitives.asymmetric import ec

from pyeudiw.x509.chain_builder import ChainBuilder


def base64url_to_int(val: str) -> int:
    return int.from_bytes(base64.urlsafe_b64decode(val + "=="), "big")


# Backend/openid4vp: same JWK as test_vp_mdoc_cbor.py (pyeudiw_backend.yaml metadata_jwks[0])
JWK_BACKEND = {
    "kty": "EC",
    "d": "i0HQiqDPXf-MqC776ztbgOCI9-eARhcUczqJ-7_httc",
    "use": "sig",
    "crv": "P-256",
    "kid": "SQgNjv4yU8sfuafJ2DPWq2tnOlK1JSibd3V5KqYRhOk",
    "x": "Q46FDkhMjewZIP9qP8ZKZIP-ZEemctvjxeP0l3vWHMI",
    "y": "IT7lsGxdJewmonk9l1_TAVYx_nixydTtI1Sbn0LkfEA",
    "alg": "ES256",
}

# Frontend/openid4vci: openid4vci_frontend.yaml metadata_jwks[0] (leaf cert must match this key)
JWK_FRONTEND = {
    "kty": "EC",
    "d": "YbMCJU43_GkbjUlWwTA5LbVvRRmz4788-k4zl2mjwrE",
    "use": "sig",
    "crv": "P-256",
    "kid": "2uhBmKZqkmLaPdJjvQ6ll6dsWXr9FGlouTnhg3mUec0",
    "x": "o8I43oRYmVk5x6Zmq2_Ni--cHD5S81qTD_5cQum2Atk",
    "y": "RrhbyuxVw6ZXEpbb8H_HyvEyL7rX0UeSZqcvulHuyFQ",
    "alg": "ES256",
}

def jwk_to_private_key(jwk):
    _d = base64url_to_int(jwk["d"])
    _x = base64url_to_int(jwk["x"])
    _y = base64url_to_int(jwk["y"])
    return ec.EllipticCurvePrivateNumbers(
        private_value=_d,
        public_numbers=ec.EllipticCurvePublicNumbers(x=_x, y=_y, curve=ec.SECP256R1()),
    ).private_key()


LEAF_FQDN = os.environ.get("SATOSA_HOSTNAME") or "iam-proxy-italia.example.org"

# When run with --frontend, use openid4vci_frontend.yaml metadata_jwks[0] for the leaf key
use_frontend_jwk = "--frontend" in sys.argv
jwk = JWK_FRONTEND if use_frontend_jwk else JWK_BACKEND

private_key = jwk_to_private_key(jwk)

chain = ChainBuilder()
chain.gen_certificate(
    cn="ca.example.com",
    organization_name="Example CA",
    country_name="IT",
    dns="ca.example.com",
    uri="https://ca.example.com",
    crl_distr_point="http://ca.example.com/crl.pem",
    ca=True,
    path_length=1,
    email_address="info@ca.example.com",
)
chain.gen_certificate(
    cn="intermediate.example.com",
    organization_name="Example Intermediate",
    country_name="IT",
    dns="intermediate.example.com",
    uri="https://intermediate.example.com",
    ca=True,
    path_length=0,
    email_address="info@intermediate.example.com",
)
chain.gen_certificate(
    cn=LEAF_FQDN,
    organization_name="IAM Proxy Italia Leaf",
    country_name="IT",
    dns=LEAF_FQDN,
    uri=f"https://{LEAF_FQDN}",
    private_key=private_key,
    ca=False,
    path_length=None,
    email_address=f"info@{LEAF_FQDN}",
)

chain_pem = chain.get_chain("PEM")  # [leaf, intermediate, ca]
ca_pem = chain.get_ca("PEM")

def pem_to_yaml_block(pem: str, indent: str = "             ") -> str:
    return "\n".join(indent + line.decode() for line in pem.strip().splitlines())

if __name__ == "__main__":
    if "--ca-only" in sys.argv:
        print(pem_to_yaml_block(ca_pem))
        sys.exit(0)
    if "--chain" in sys.argv:
        for cert_pem in chain_pem:
            print(pem_to_yaml_block(cert_pem))
            print()
        sys.exit(0)
    # Full YAML-style output
    print("# CA (certificate_authorities ca.example.com):")
    print(pem_to_yaml_block(ca_pem))
    print()
    print("# leaf_certificate_chains_by_ca ca.example.com (leaf, intermediate, ca):")
    for cert_pem in chain_pem:
        print("- |")
        print(pem_to_yaml_block(cert_pem))
        print()
