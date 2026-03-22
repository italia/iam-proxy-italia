#!/bin/bash
set -e

URL=$1 #url for .well-known req
URL="${URL%/}"  # strip trailing slash to avoid double slash in path

WGET_OPTS="--timeout=5 --tries=1 --no-check-certificate --spider --server-response"

function check_url {
  local url=$1
  http_status=$(wget $WGET_OPTS "$url" 2>&1 | awk '/HTTP\// {print $2}' | tail -1)
  if [[ ! $http_status =~ ^[23] ]]; then
    echo "Error: wget failed for $url with status $http_status"
    exit 1
  fi
}

# Build URL and collapse any double slashes in path (preserve :// scheme delimiter)
CHECK_URL="${URL}/.well-known/openid-federation"
CHECK_URL=$(echo "$CHECK_URL" | sed 's|://|%%SCHEME%%|g; s|//|/|g; s|%%SCHEME%%|://|g; s|:///|://|g')
check_url "$CHECK_URL"
echo "Health check completed successfully."
