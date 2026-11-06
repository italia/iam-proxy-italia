#!/bin/sh
# Default start runs issuance.
# Presentation runs only when CONFIG_PRESENTATION_AUTHORIZE_URI is set:
# the ini authorize_request_url is a placeholder and has no client_id.
# Any arguments are forwarded to the upstream entrypoint (one wct command).
set -eu

cd /wallet-conformance-test

if [ "$#" -gt 0 ]; then
  exec ./docker-entrypoint.sh "$@"
fi

tests="${WCT_TESTS:-happy}"
ini="${WCT_FILE_INI:-/wct-config/config.ini}"

echo "*************************************************"
echo "          TEST:ISSUANCE"
echo "*************************************************"
set +e
./docker-entrypoint.sh test:issuance --tests "$tests" --file-ini "$ini"
issuance_status=$?
set -e

if [ -z "${CONFIG_PRESENTATION_AUTHORIZE_URI:-}" ]; then
  echo "*************************************************"
  echo "          TEST:PRESENTATION skipped"
  echo "          Set CONFIG_PRESENTATION_AUTHORIZE_URI to run it"
  echo "*************************************************"
  exit "$issuance_status"
fi

echo "*************************************************"
echo "          TEST:PRESENTATION"
echo "*************************************************"
set +e
./docker-entrypoint.sh test:presentation --tests "$tests" --file-ini "$ini"
presentation_status=$?
set -e

if [ "$issuance_status" -ne 0 ]; then
  exit "$issuance_status"
fi
exit "$presentation_status"
