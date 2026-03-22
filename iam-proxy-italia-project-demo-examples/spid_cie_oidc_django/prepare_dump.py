#!/usr/bin/env python3
"""
Replace placeholder URLs in dump JSON with values from environment.
Must run before loaddata so entity IDs match the runtime Host/URLs.
"""
import os
import sys

def main():
    trust_anchor = os.environ.get("TRUST_ANCHOR_URL", "http://trust-anchor.example.org:5002")
    prov_base = os.environ.get("OPENID_CIE_PROVIDER_URL", "http://cie-provider.example.org:8002/oidc/op/")
    prov_base = prov_base.rstrip("/").split("/oidc/op")[0] if "/oidc/op" in prov_base else prov_base.rstrip("/")

    dump_path = "dumps/example.json"
    if len(sys.argv) > 1:
        dump_path = sys.argv[1]

    with open(dump_path, "r", encoding="utf-8") as f:
        content = f.read()

    orig = content
    content = content.replace("http://127.0.0.1:5002", trust_anchor)
    content = content.replace("http://127.0.0.1:8002", prov_base)

    if content == orig:
        print("WARN: No replacements made - check placeholder URLs in dump")
    elif "http://127.0.0.1:5002" in content or "http://127.0.0.1:8002" in content:
        print("WARN: Some placeholders may remain after replacement")
    else:
        print(f"Prepare: TRUST_ANCHOR_URL={trust_anchor} PROV_BASE={prov_base}")

    with open(dump_path, "w", encoding="utf-8") as f:
        f.write(content)

if __name__ == "__main__":
    main()
