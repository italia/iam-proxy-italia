#!/bin/bash
set -e

URL=$1 #url for .well-known req

WGET_OPTS="--timeout=5 --tries=1 --no-check-certificate --spider --server-response"

function check_url {
  local url=$1
  http_status=$(wget $WGET_OPTS "$url" 2>&1 | awk '/HTTP\// {print $2}' | tail -1)
  if [[ ! $http_status =~ ^[23] ]]; then
    echo "Error: wget failed for $url with status $http_status"
    exit 1
  fi
}

check_url "${URL}/.well-known/openid-federation"
echo "Health check completed successfully."
