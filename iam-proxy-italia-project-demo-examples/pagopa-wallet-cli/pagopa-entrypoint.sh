#!/bin/sh
echo "*********************************************"
echo "          Starting CLI entrypoint"
echo "*********************************************"

cd /wallet-conformance-test/

if [ -n "$CUSTOM_CONFIG_PATH" ] && [ -f "$CUSTOM_CONFIG_PATH" ]; then
    echo "Using custom configuration from: $CUSTOM_CONFIG_PATH"

    DEST_DIR="/wallet-conformance-test"

    DEST_PATH="$DEST_DIR/config.ini"

    find "$DEST_DIR" -type f -name "config.ini" -delete

    if [ "$CUSTOM_CONFIG_PATH" != "$DEST_PATH" ]; then

        cp "$CUSTOM_CONFIG_PATH" "$DEST_PATH"
    fi

    CONFIG_FILE="$DEST_PATH"
else
    CONFIG_FILE="/wallet-conformance-test/config.ini"
fi

echo "Using config: $CONFIG_FILE"

echo "*********************************************"
echo "          VERSION                            "
echo "*********************************************"
./bin/wct -V

echo "*************************************************"
echo "          TEST:ISSUANCE                          "
echo "*************************************************"

RESULT=$(./bin/wct test:issuance --file-ini "$CONFIG_FILE")
STATUS=$?

echo "*************************************************"
echo "          TEST:RESULT                            "
echo "*************************************************"

if [ $STATUS -eq 0 ]; then
    echo "Test success!"
else
    echo "Test failed! Status: $STATUS"
    exit $STATUS
fi

echo "*************************************************"
echo "          TEST:PRESENTATION                      "
echo "*************************************************"

RESULT=$(./bin/wct test:presentation --file-ini "$CONFIG_FILE")
STATUS=$?

echo "*************************************************"
echo "          TEST:RESULT                            "
echo "*************************************************"

if [ $STATUS -eq 0 ]; then
    echo "Test success!"
else
    echo "Test failed! Status: $STATUS"
    exit $STATUS
fi

echo "Finish Testing!"
