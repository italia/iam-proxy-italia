#!/bin/bash
set -e

URL=$1 #url for .well-known req
URL="${URL%/}"  # strip trailing slash to avoid double slash in path

# Use Python (available in Django base image) instead of wget
function check_url {
  local url=$1
  if ! python3 -c "
import urllib.request
import sys
try:
    r = urllib.request.urlopen(sys.argv[1], timeout=5)
    status = r.getcode()
    sys.exit(0 if 200 <= status < 400 else 1)
except Exception:
    sys.exit(1)
" "$url" 2>/dev/null; then
    echo "Error: health check failed for $url"
    exit 1
  fi
}

# Build URL and collapse any double slashes in path (preserve :// scheme delimiter)
CHECK_URL="${URL}/.well-known/openid-federation"
CHECK_URL=$(echo "$CHECK_URL" | sed 's|://|%%SCHEME%%|g; s|//|/|g; s|%%SCHEME%%|://|g; s|:///|://|g')
check_url "$CHECK_URL"
echo "Health check completed successfully."
