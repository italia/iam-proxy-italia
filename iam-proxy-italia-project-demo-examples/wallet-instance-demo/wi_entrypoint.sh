#!/bin/sh
set -e
# Generate config.json from ENV before starting the app (no pip install - done at build)
export CONFIG_DIR="${CONFIG_DIR:-/wallet-instance-demo/config}"
cd /wallet-instance-demo
python scripts/generate_wallet_config.py
exec python run.py
