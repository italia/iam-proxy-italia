#!/usr/bin/env bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SOURCE_DIR="$PROJECT_ROOT/iam-proxy-italia-project"
TARGET_DIR="$SCRIPT_DIR/config-files"

EXCLUDE_DIRS=("logs" "static" "pki" "uwsgi_setup" "entrypoint.sh")

if [ ! -d "$SOURCE_DIR" ]; then
    echo "Error: Source directory not found: $SOURCE_DIR"
    exit 1
fi

echo "Syncing config files..."
echo "Source: $SOURCE_DIR"
echo "Target: $TARGET_DIR"
echo "Excluding: ${EXCLUDE_DIRS[*]}"

mkdir -p "$TARGET_DIR"

# Clean target directory
find "$TARGET_DIR" -mindepth 1 -not -name '.gitkeep' -delete

# Build rsync exclude arguments
EXCLUDE_ARGS=()
for dir in "${EXCLUDE_DIRS[@]}"; do
    EXCLUDE_ARGS+=(--exclude="$dir/")
done

# Copy all files except excluded directories
rsync -av "${EXCLUDE_ARGS[@]}" "$SOURCE_DIR/" "$TARGET_DIR/"

FILE_COUNT=$(find "$TARGET_DIR" -type f | wc -l)
echo "✅ Synced $FILE_COUNT files"
