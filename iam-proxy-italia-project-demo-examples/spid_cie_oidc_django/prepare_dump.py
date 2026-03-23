#!/usr/bin/env python3
"""
Replace placeholder URLs in dump JSON with values from environment.
Must run before loaddata so entity IDs match the runtime Host/URLs.
"""
import os
import sys

def main():
    trust_anchor = os.environ.get("TRUST_ANCHOR_URL", "http://trust-anchor.example.org:5002")
    prov_base = os.environ.get("OPENID_CIE_PROVIDER_URL", "http://cie-provider.example.org:8002/oidc/op")
    prov_base = prov_base.rstrip("/").split("/oidc/op")[0] if "/oidc/op" in prov_base else prov_base.rstrip("/")
    satosa_hostname = os.environ.get("SATOSA_HOSTNAME", "iam-proxy-italia.example.org")
    rp_sub = os.environ.get("RP_URL") or f"https://{satosa_hostname}/CieOidcRp"
    wallet_provider_url = os.environ.get(
        "WALLET_PROVIDER_URL", "http://demo-wi.example.org:8080/provider"
    )
    openid4vp_sub = f"https://{satosa_hostname}/OpenID4VP"
    openid4vci_sub = f"https://{satosa_hostname}/OpenID4VCI"

    dump_path = "dumps/example.json"
    if len(sys.argv) > 1:
        dump_path = sys.argv[1]

    with open(dump_path, "r", encoding="utf-8") as f:
        content = f.read()

    orig = content
    content = content.replace("http://127.0.0.1:5002", trust_anchor)
    content = content.replace("http://127.0.0.1:8002", prov_base)
    content = content.replace("https://satosa.example.org/CieOidcRp", rp_sub)
    content = content.replace(
        "http://wallet-instance.example.org:8080/provider", wallet_provider_url
    )
    content = content.replace("https://satosa.example.org/OpenID4VP", openid4vp_sub)
    content = content.replace("https://satosa.example.org/OpenID4VCI", openid4vci_sub)

    if content == orig:
        print("WARN: No replacements made - check placeholder URLs in dump")
    elif any(
        p in content
        for p in (
            "http://127.0.0.1:5002",
            "http://127.0.0.1:8002",
            "https://satosa.example.org/CieOidcRp",
            "http://wallet-instance.example.org:8080/provider",
            "https://satosa.example.org/OpenID4VP",
            "https://satosa.example.org/OpenID4VCI",
        )
    ):
        print("WARN: Some placeholders may remain after replacement")
    else:
        print(
            f"Prepare: TRUST_ANCHOR_URL={trust_anchor} PROV_BASE={prov_base} RP_SUB={rp_sub} "
            f"WALLET_PROVIDER_URL={wallet_provider_url} OpenID4VP={openid4vp_sub} OpenID4VCI={openid4vci_sub}"
        )

    with open(dump_path, "w", encoding="utf-8") as f:
        f.write(content)

if __name__ == "__main__":
    main()
