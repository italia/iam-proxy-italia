#!/usr/bin/env bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SOURCE_DIR="$PROJECT_ROOT/iam-proxy-italia-project"
TARGET_DIR="$SCRIPT_DIR/config-files"

INCLUDE_DIRS=("attributes-map" "backends" "conf" "metadata" "templates")

if [ ! -d "$SOURCE_DIR" ]; then
    echo "Error: Source directory not found: $SOURCE_DIR"
    exit 1
fi

echo "Syncing config files..."
echo "Source: $SOURCE_DIR"
echo "Target: $TARGET_DIR"
echo "Including: ${INCLUDE_DIRS[*]}"

mkdir -p "$TARGET_DIR"

# Clean target directory
find "$TARGET_DIR" -mindepth 1 -not -name '.gitkeep' -delete

# Copy only specified directories
for dir in "${INCLUDE_DIRS[@]}"; do
    if [ -d "$SOURCE_DIR/$dir" ]; then
        echo "Copying $dir..."
        rsync -av "$SOURCE_DIR/$dir/" "$TARGET_DIR/$dir/"
    else
        echo "Warning: Directory not found: $SOURCE_DIR/$dir"
    fi
done

FILE_COUNT=$(find "$TARGET_DIR" -type f | wc -l)
echo "✅ Synced $FILE_COUNT files"
