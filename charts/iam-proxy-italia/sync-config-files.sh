#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SOURCE_DIR="$PROJECT_ROOT/iam-proxy-italia-project"
TARGET_DIR="$SCRIPT_DIR/config-files"

INCLUDE_DIRS=("attributes-map" "backends" "conf" "metadata" "templates")

# Use the same release as the image, even when the chart branch has older sources.
# Pass --working-tree to include local application changes during development.
SOURCE_REF="${1:-$(awk '$1 == "appVersion:" {gsub(/"/, "", $2); print $2}' "$SCRIPT_DIR/Chart.yaml")}"
if [ "$SOURCE_REF" != "--working-tree" ]; then
    git -C "$PROJECT_ROOT" rev-parse --verify "${SOURCE_REF}^{commit}" > /dev/null
    SOURCE_CHECKOUT="$(mktemp -d)"
    trap 'rm -rf "$SOURCE_CHECKOUT"' EXIT
    SOURCE_PATHS=()
    for dir in "${INCLUDE_DIRS[@]}"; do
        SOURCE_PATHS+=("iam-proxy-italia-project/$dir")
    done
    git -C "$PROJECT_ROOT" archive "$SOURCE_REF" -- "${SOURCE_PATHS[@]}" |
        tar -xf - -C "$SOURCE_CHECKOUT"
    SOURCE_DIR="$SOURCE_CHECKOUT/iam-proxy-italia-project"
fi

if [ ! -d "$SOURCE_DIR" ]; then
    echo "Error: Source directory not found: $SOURCE_DIR"
    exit 1
fi

echo "Syncing config files..."
echo "Reference: $SOURCE_REF"
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
