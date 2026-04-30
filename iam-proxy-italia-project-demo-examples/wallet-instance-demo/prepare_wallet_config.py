#!/usr/bin/env python3
"""
Replace placeholder URLs in wallet config with values from environment.
Ensures trust_root and public_url match the trust anchor and wallet provider URLs.
"""
import os
import sys


def main():
    trust_anchor = os.environ.get("TRUST_ANCHOR_URL", "http://trust-anchor.example.org:5002")
    wallet_provider_url = os.environ.get(
        "WALLET_PROVIDER_URL", "http://demo-wi.example.org:8080/provider"
    )

    config_path = "config/config.json"
    if len(sys.argv) > 1:
        config_path = sys.argv[1]

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"WARN: Wallet config not found at {config_path}, skipping prepare")
        return

    orig = content
    content = content.replace("http://trust-anchor.example.org:5002", trust_anchor)
    content = content.replace(
        "http://wallet-instance.example.org:8080/provider", wallet_provider_url
    )

    if content != orig:
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(
            f"Prepare wallet: TRUST_ANCHOR_URL={trust_anchor} "
            f"WALLET_PROVIDER_URL={wallet_provider_url}"
        )


if __name__ == "__main__":
    main()
