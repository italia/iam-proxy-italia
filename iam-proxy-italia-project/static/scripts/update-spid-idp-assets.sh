#!/usr/bin/env bash
# Download official SPID IdP logos from italia/spid-graphics.
# Run from: iam-proxy-italia-project/static
# See: https://github.com/italia/spid-graphics/tree/master/idp-logos

set -e
BASE_URL="https://raw.githubusercontent.com/italia/spid-graphics/master/idp-logos"
DEST_DIR="spid"
mkdir -p "$DEST_DIR"

echo "Downloading SPID IdP logos from italia/spid-graphics..."

for id in arubaid etnaid infocertid intesaid intesigroupspid lepidaid namirialid posteid sielteid spiditalia teamsystemid timid; do
  curl -sL -o "$DEST_DIR/spid-idp-$id.svg" "$BASE_URL/spid-idp-$id.svg" 2>/dev/null && echo "  - spid-idp-$id.svg" || echo "  - spid-idp-$id.svg (skip, not found)"
done

echo "SPID IdP assets updated from italia/spid-graphics."
echo "Note: InfoCamere logo (spid-idp-infocamereid.svg) not yet in official repo; add manually when available."
