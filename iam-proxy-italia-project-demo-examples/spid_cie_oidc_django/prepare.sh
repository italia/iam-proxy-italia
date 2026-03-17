#!/bin/bash

MODULE_NAME=$1 #folder name for spid_cie_oidc_django module (provider or federation_authority)

# Configure the rewrite rules:
SUB_AT="s,http://127.0.0.1:8000,${TRUST_ANCHOR_URL},g"
SUB_RP="s,http://127.0.0.1:8001,${RP_URL},g"
SUB_OP="s,http://127.0.0.1:8002,${PROVIDER_URL},g"

# remove dev db
rm -f "./${MODULE_NAME}/db.sqlite3"

# Apply the rewrite rules:
sed -e $SUB_AT -e $SUB_RP -e $SUB_OP "./examples/dump.json" > ./dumps/example.json
sed -e $SUB_AT -e $SUB_RP -e $SUB_OP "./examples/settingslocal.py" > "./${MODULE_NAME}/settingslocal.py"
