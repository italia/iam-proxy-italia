#!/bin/bash
set -e

PROXY_CONF_PATH="iam-proxy-italia-project/proxy_conf.yaml"

if grep -qF "conf/backends/pyeudiw_backend.yaml" "$PROXY_CONF_PATH"; then
  echo "pyeudiw_backend.yaml configured"
  (
    wget -O - https://satosa-nginx/OpenID4VCI/.well-known/openid-federation --no-check-certificate &&
    wget -O - https://satosa-nginx/OpenID4VCI/.well-known/oauth-authorization-server --no-check-certificate &&
    wget -O - https://satosa-nginx/OpenID4VCI/.well-known/openid-credential-issuer --no-check-certificate
  ) || exit 1
fi

if grep -qF "conf/frontends/openid4vci_frontend.yaml" "$PROXY_CONF_PATH"; then
  echo "openid4vci_frontend.yaml configured"
  (
    wget -O - https://satosa-nginx/OpenID4VP/.well-known/jwt-vc-issuer --no-check-certificate &&
    wget -O - https://satosa-nginx/OpenID4VP/.well-known/jar-issuer --no-check-certificate &&
    wget -O - https://satosa-nginx/OpenID4VP/.well-known/openid-federation --no-check-certificate
  ) || exit 1
fi

if grep -qF "conf/frontends/saml2_frontend.yaml" "$PROXY_CONF_PATH"; then
  echo "saml2_frontend.yaml configured"
  wget -O - https://satosa-nginx/Saml2IDP/metadata --no-check-certificate || exit 1
fi
