#!/bin/sh
# Default start runs issuance, then presentation.
# Any arguments are forwarded to the upstream entrypoint (one wct command).
set -eu

cd /wallet-conformance-test

if [ "$#" -gt 0 ]; then
  exec ./docker-entrypoint.sh "$@"
fi

tests="${WCT_TESTS:-happy}"
ini="${WCT_FILE_INI:-/wct-config/config.ini}"
issuance_status=0
presentation_status=0

echo "*************************************************"
echo "          TEST:ISSUANCE"
echo "*************************************************"
set +e
./docker-entrypoint.sh test:issuance --tests "$tests" --file-ini "$ini"
issuance_status=$?
set -e

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
