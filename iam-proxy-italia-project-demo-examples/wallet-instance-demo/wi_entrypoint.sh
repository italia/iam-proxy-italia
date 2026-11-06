#!/bin/sh
set -e
# The wallet app loads YAML from CONFIG_DIR. Compose mounts that directory, which
# hides the config shipped in the image. Seed it once when the mount is empty.
# Deployment values come from !ENV in those files, not from a generated JSON file.
# generate_wallet_config.py, prepare_wallet_config.py and config.example.json
# are gone. They wrote config.json at startup. The wallet instance now loads
# YAML (!INCLUDE) and takes deployment values from environment variables (!ENV).
export CONFIG_DIR="${CONFIG_DIR:-/wallet-instance-demo/config}"
cd /wallet-instance-demo
if [ ! -f "${CONFIG_DIR}/app_config.yaml" ]; then
  mkdir -p "${CONFIG_DIR}"
  cp -a /wallet-instance-demo/config.default/. "${CONFIG_DIR}/"
fi
exec python run.py
