#!/usr/bin/env bash
# Download official IT-Wallet assets from italia/eid-wallet-it-docs (versione-corrente).
# Run from: iam-proxy-italia-project/static
# See: https://github.com/italia/eid-wallet-it-docs/tree/versione-corrente/official_resources

set -e
BASE_URL="https://raw.githubusercontent.com/italia/eid-wallet-it-docs/versione-corrente/official_resources"
DEST_DIR="wallet-it"
mkdir -p "$DEST_DIR"

echo "Downloading official IT-Wallet assets..."

# Discovery page: white symbol on primary blue button (it_wallet card)
curl -sL -o "$DEST_DIR/wallet_icon.svg" \
  "$BASE_URL/IT-Wallet-Symbol/IT-Wallet-Symbol-Negative-White.svg"
echo "  - wallet_icon.svg (IT-Wallet-Symbol-Negative-White)"

# QR code page and config: blue logo in QR center
curl -sL -o "$DEST_DIR/wallet-icon-blue.svg" \
  "$BASE_URL/IT-Wallet-Logo/IT-Wallet-Logo-Primary-BlueItalia.svg"
echo "  - wallet-icon-blue.svg (IT-Wallet-Logo-Primary-BlueItalia)"

# Optional: keep full set with official names for reference
curl -sL -o "$DEST_DIR/IT-Wallet-Symbol-Negative-White.svg" \
  "$BASE_URL/IT-Wallet-Symbol/IT-Wallet-Symbol-Negative-White.svg"
curl -sL -o "$DEST_DIR/IT-Wallet-Logo-Primary-BlueItalia.svg" \
  "$BASE_URL/IT-Wallet-Logo/IT-Wallet-Logo-Primary-BlueItalia.svg"
echo "  - IT-Wallet-Symbol-Negative-White.svg, IT-Wallet-Logo-Primary-BlueItalia.svg (reference copies)"

echo "IT-Wallet assets updated from eid-wallet-it-docs official_resources."
