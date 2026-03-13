#!/usr/bin/env bash
#
# Sync Docker-compose/nginx/html to iam-proxy-italia-project/static
#
# Use when developing in Docker-compose/nginx/html and you need to align the
# project's static folder so changes are preserved in the repo.
#
# Run from repo root, e.g.:
#   ./scripts/sync-nginx-static-to-project.sh
#
# Options:
#   --dry-run    Show what would be synced without making changes
#   -n           Same as --dry-run
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC="${REPO_ROOT}/Docker-compose/nginx/html"
DEST="${REPO_ROOT}/iam-proxy-italia-project/static"

DRY_RUN=""
for arg in "$@"; do
  case "$arg" in
    --dry-run|-n) DRY_RUN="--dry-run --verbose" ; break ;;
  esac
done

if [[ ! -d "$SRC" ]]; then
  echo "Error: Source not found: $SRC"
  exit 1
fi

# Sync nginx/html/static -> iam-proxy-italia-project/static
# Exclude node_modules to avoid copying heavy dependencies
if [[ -d "$SRC/static" ]]; then
  echo "Syncing: nginx/html/static → iam-proxy-italia-project/static"
  rsync -a --delete \
    --exclude='node_modules' \
    $DRY_RUN \
    "$SRC/static/" "$DEST/"
  echo "Done."
else
  echo "Warning: $SRC/static not found. Nothing to sync."
  exit 1
fi
