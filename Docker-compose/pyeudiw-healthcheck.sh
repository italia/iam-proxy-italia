#!/bin/bash
set -e

PROXY_CONF_PATH="proxy_conf.yaml"
WGET_OPTS="--timeout=5 --tries=1 --no-check-certificate --spider --server-response"

function check_url {
  local url=$1
  http_status=$(wget $WGET_OPTS "$url" 2>&1 | awk '/HTTP\// {print $2}' | tail -1)
  if [[ ! $http_status =~ ^[23] ]]; then
    echo "Error: wget failed for $url with status $http_status"
    exit 1
  fi
}

if grep -qF "conf/backends/pyeudiw_backend.yaml" "$PROXY_CONF_PATH"; then
  echo "pyeudiw_backend.yaml configured"
  check_url "https://satosa-nginx/OpenID4VP/.well-known/jwt-vc-issuer"
  check_url "https://satosa-nginx/OpenID4VP/.well-known/jar-issuer"
  check_url "https://satosa-nginx/OpenID4VP/.well-known/openid-federation"
fi

if grep -qF "conf/frontends/openid4vci_frontend.yaml" "$PROXY_CONF_PATH"; then
  echo "openid4vci_frontend.yaml configured"
  check_url "https://satosa-nginx/OpenID4VCI/.well-known/openid-federation"
  check_url "https://satosa-nginx/OpenID4VCI/.well-known/oauth-authorization-server"
  check_url "https://satosa-nginx/OpenID4VCI/.well-known/openid-credential-issuer"
fi

if grep -qF "conf/frontends/saml2_frontend.yaml" "$PROXY_CONF_PATH"; then
  echo "saml2_frontend.yaml configured"
  check_url "https://satosa-nginx/Saml2IDP/metadata"
fi

echo "Health check completed successfully."
