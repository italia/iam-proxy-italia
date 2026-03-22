#!/usr/bin/env bash
# Download act to BIN_DIR. Expects ACT_VERSION and BIN_DIR as env or args.
# Run from repository root.

set -e

ACT_VERSION="${ACT_VERSION:-0.2.84}"
BIN_DIR="${1:-.bin}"

U=$(uname -s)
M=$(uname -m)

case "$U" in
  Linux)  OS=Linux ;;
  Darwin) OS=Darwin ;;
  *) echo "Unsupported OS: $U"; exit 1 ;;
esac

case "$M" in
  x86_64)     ARCH=x86_64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  armv6l)     ARCH=armv6 ;;
  armv7l)     ARCH=armv7 ;;
  *) echo "Unsupported arch: $M"; exit 1 ;;
esac

URL="https://github.com/nektos/act/releases/download/v${ACT_VERSION}/act_${OS}_${ARCH}.tar.gz"
echo "Fetching $URL..."
mkdir -p "$BIN_DIR"
curl -sL "$URL" | tar -xz -C "$BIN_DIR" act
chmod +x "$BIN_DIR/act"
echo "Act installed in $BIN_DIR/"
