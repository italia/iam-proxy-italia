#!/usr/bin/env python3
"""
Generate wallet config.json from environment variables.
Used when running in Docker to produce config from compose ENV.
"""
import json
import os
import sys


def _getenv(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip() or default


def main():
    config_dir = _getenv("CONFIG_DIR", "config")
    template_path = os.environ.get(
        "WALLET_CONFIG_TEMPLATE",
        os.path.join(os.path.dirname(__file__), "..", "config.json.example"),
    )
    output_path = os.path.join(config_dir, "config.json")

    try:
        with open(template_path, encoding="utf-8") as f:
            config = json.load(f)
    except FileNotFoundError:
        print(f"ERROR: Template not found at {template_path}", file=sys.stderr)
        sys.exit(1)

    # Resolve wallet base URL (where the wallet app is reachable)
    wallet_hostname = _getenv("DEMO_WALLET_INSTANCE_HOSTNAME", "demo-wi.example.org")
    wallet_port = _getenv("WALLET_INSTANCE_PORT", "8080")
    wallet_scheme = _getenv("WALLET_SCHEME", "http")
    wallet_base = f"{wallet_scheme}://{wallet_hostname}:{wallet_port}"

    # Override from ENV
    config["wallet_provider"]["public_url"] = _getenv(
        "WALLET_PROVIDER_URL", f"{wallet_base}/provider"
    )
    redirect_uri = f"{wallet_base}/wallet/cb"
    config["metadata"]["initialize_flow"]["redirect_uri"] = _getenv(
        "WALLET_INITIALIZE_REDIRECT_URI", redirect_uri
    )
    config["metadata"]["credential_flow"]["redirect_uri"] = _getenv(
        "WALLET_CREDENTIAL_REDIRECT_URI", redirect_uri
    )

    trust_root = _getenv("TRUST_ANCHOR_URL", "http://trust-anchor.example.org:5002")
    if "ms_trust_configuration" in config and "IT" in config["ms_trust_configuration"]:
        config["ms_trust_configuration"]["IT"]["trust_root"] = trust_root

    cie2_idphint = _getenv(
        "OPENID_CIE_PROVIDER_ISSUER",
        _getenv("OPENID_CIE_PROVIDER_URL", "http://cie-provider.example.org:8002/oidc/op"),
    )
    config["metadata"]["initialize_flow"]["idphints"]["CIE2"] = cie2_idphint

    port = int(_getenv("FLASK_RUN_PORT", "8080"))
    config["app"]["default_port"] = port

    os.makedirs(config_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    print(f"Generated {output_path} from ENV")


if __name__ == "__main__":
    main()
