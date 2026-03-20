#!/bin/sh
echo "*********************************************"
echo "          Starting CLI entrypoint"
echo "*********************************************"

cd /wallet-conformance-test/

CONFIG_ARG=""
if [ -n "$CUSTOM_CONFIG_PATH" ] && [ -f "$CUSTOM_CONFIG_PATH" ]; then
    echo "Using custom configuration from: $CUSTOM_CONFIG_PATH"
    cp "$CUSTOM_CONFIG_PATH" /wallet-conformance-test/config.ini
    CONFIG_ARG="--file-ini $CUSTOM_CONFIG_PATH"
else
    if [ -f "/wallet-conformance-test/config.ini" ]; then
      echo "Using default configuration from: /wallet-conformance-test/config.ini"
      CONFIG_ARG="--file-ini /wallet-conformance-test/config.ini"
    fi
fi


echo "*********************************************"
echo "          VERSION                            "
echo "*********************************************"
./bin/wct -V

echo "*************************************************"
echo "          TEST:ISSUANCE                          "
echo "*************************************************"

RESULT=$(./bin/wct test:issuance "$CONFIG_ARG" --credential-issuer-uri https://my-issuer.example.com)

STATUS=$?

echo "*************************************************"
echo "          TEST:RESULT                            "
echo "*************************************************"

if [ $STATUS -eq 0 ]; then
    echo "Test success!"
else
    echo "Test failed! Status: $STATUS"
fi

echo "*************************************************"
echo "          TEST:PRESENTATION                      "
echo "*************************************************"

RESULT=$(./bin/wct test:presentation "$CONFIG_ARG" --credential-issuer-uri https://my-issuer.example.com)

STATUS=$?

echo "*************************************************"
echo "          TEST:RESULT                            "
echo "*************************************************"

if [ $STATUS -eq 0 ]; then
    echo "Test success!"
else
    echo "Test failed! Status: $STATUS"
fi

echo "Finish Testing!"
