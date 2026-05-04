#!/bin/bash
set -e

MODULE_NAME=$1 #folder name for spid_cie_oidc_django module (provider or federation_authority)

DUMP_FILE="./dumps/example.json"
if [ ! -f "$DUMP_FILE" ]; then
  echo "ERROR: dump not found at $DUMP_FILE (cwd=$(pwd))"
  exit 1
fi

# remove dev db
rm -f "./${MODULE_NAME}/db.sqlite3" ./db.sqlite3 2>/dev/null || true

# Replace placeholders using Python (reliable across environments)
python3 /prepare_dump.py "$DUMP_FILE"
