#!/bin/bash
set -e

URL=$1 #url for .well-known req

WGET_OPTS="--timeout=5 --tries=1 --no-check-certificate --spider --server-response"

function check_url {
  local url=$1
  local output http_status
  # wget exits non-zero on non-2xx; capture output anyway so we can enforce status == 200
  output=$(wget $WGET_OPTS "$url" 2>&1) || true
  http_status=$(echo "$output" | awk '/HTTP\// {code=$2} END {print code}')
  http_status=$(echo "$http_status" | tr -d '\r[:space:]')
  if [[ "$http_status" != "200" ]]; then
    echo "Error: expected HTTP 200 from $url, got '${http_status:-empty}'"
    exit 1
  fi
}

check_url "${URL}/.well-known/openid-federation"
echo "Health check completed successfully."
