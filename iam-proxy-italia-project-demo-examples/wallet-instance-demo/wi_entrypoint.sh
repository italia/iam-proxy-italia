#!/bin/sh
set -e
# The wallet app loads YAML from CONFIG_DIR. Compose mounts that directory, which
# hides the config shipped in the image. Seed it once when the mount is empty.
# Deployment values come from !ENV in those files, not from a generated JSON file.
export CONFIG_DIR="${CONFIG_DIR:-/wallet-instance-demo/config}"
cd /wallet-instance-demo
if [ ! -f "${CONFIG_DIR}/app_config.yaml" ]; then
  mkdir -p "${CONFIG_DIR}"
  cp -a /wallet-instance-demo/config.default/. "${CONFIG_DIR}/"
fi
exec python run.py
