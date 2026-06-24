#!/usr/bin/env bash
# Sync iam-proxy-italia static assets into nginx/html/static (served at /static/).
# Run manually from Docker-compose/ or Docker-compose/nginx/:
#   ./nginx/sync-static-assets.sh
#   ./nginx/sync-static-assets.sh --build-config
#   ./nginx/sync-static-assets.sh --dry-run
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

SOURCE_DIR="${STATIC_SOURCE:-${COMPOSE_DIR}/../iam-proxy-italia-project/static}"
DEST_DIR="${STATIC_DEST:-${SCRIPT_DIR}/html/static}"
BUILD_CONFIG=false
DRY_RUN=false

usage() {
  cat <<'EOF'
Usage: sync-static-assets.sh [OPTIONS]

Copy static assets from iam-proxy-italia-project/static to nginx/html/static.

Options:
  --build-config   Run "npm run build:config" in the source static tree before sync
  --dry-run        Print actions without writing files
  -h, --help       Show this help

Environment overrides:
  STATIC_SOURCE    Source directory (default: ../iam-proxy-italia-project/static)
  STATIC_DEST      Destination directory (default: nginx/html/static)
  SYNC_USE_SUDO    If "true", run rsync/cp via sudo when destination is not writable
EOF
}

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

die() {
  log "ERROR: $*"
  exit 1
}

RSYNC_EXCLUDES=(
  --exclude=node_modules/
  --exclude=test-results/
  --exclude=.git/
  --exclude=.playwright/
)

can_write_dest() {
  [[ -d "${DEST_DIR}" && -w "${DEST_DIR}" ]]
}

ensure_dest_writable() {
  if can_write_dest; then
    return 0
  fi
  if [[ "${SYNC_USE_SUDO:-}" == "true" ]]; then
    if ! command -v sudo >/dev/null 2>&1; then
      die "SYNC_USE_SUDO=true but sudo is not available"
    fi
    log "permissions: destination not writable, using sudo"
    return 0
  fi
  die "Destination not writable: ${DEST_DIR}. Fix ownership (e.g. sudo chown -R \"\$(whoami)\" \"${DEST_DIR}\") or run with SYNC_USE_SUDO=true"
}

run_privileged() {
  if [[ "${SYNC_USE_SUDO:-}" == "true" ]]; then
    sudo "$@"
  else
    "$@"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-config) BUILD_CONFIG=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1 (use --help)" ;;
  esac
done

SOURCE_DIR="$(cd "${SOURCE_DIR}" 2>/dev/null && pwd || true)"
if [[ -z "${SOURCE_DIR}" || ! -d "${SOURCE_DIR}" ]]; then
  die "Source directory not found: ${STATIC_SOURCE:-${COMPOSE_DIR}/../iam-proxy-italia-project/static}"
fi

log "sync-static-assets: starting"
log "  source:      ${SOURCE_DIR}"
log "  destination: ${DEST_DIR}"
log "  dry-run:     ${DRY_RUN}"

if [[ "${BUILD_CONFIG}" == true ]]; then
  if [[ ! -f "${SOURCE_DIR}/package.json" ]]; then
    die "--build-config requested but package.json not found in ${SOURCE_DIR}"
  fi
  if ! command -v npm >/dev/null 2>&1; then
    die "--build-config requested but npm is not available in PATH"
  fi
  log "build-config: running npm run build:config in ${SOURCE_DIR}"
  if [[ "${DRY_RUN}" == true ]]; then
    log "build-config: [dry-run] would run: (cd ${SOURCE_DIR} && npm run build:config)"
  else
    (cd "${SOURCE_DIR}" && npm run build:config)
    log "build-config: completed"
  fi
fi

if [[ "${DRY_RUN}" == false ]]; then
  run_privileged mkdir -p "${DEST_DIR}"
  ensure_dest_writable
fi

sync_with_rsync() {
  local rsync_opts=(-a --human-readable --itemize-changes --out-format='%i %n%L')
  rsync_opts+=("${RSYNC_EXCLUDES[@]}")
  if [[ "${DRY_RUN}" == true ]]; then
    rsync_opts+=(--dry-run)
  else
    rsync_opts+=(--delete)
  fi
  log "sync: using rsync (excludes: node_modules, test-results, .git)"
  run_privileged rsync "${rsync_opts[@]}" "${SOURCE_DIR}/" "${DEST_DIR}/"
}

sync_with_cp() {
  log "sync: rsync not found, using cp -a"
  if [[ "${DRY_RUN}" == true ]]; then
    find "${SOURCE_DIR}" -type f | sort | while IFS= read -r file; do
      rel="${file#${SOURCE_DIR}/}"
      log "  would copy: ${rel}"
    done
    return 0
  fi

  if [[ -d "${DEST_DIR}" ]] && [[ -n "$(ls -A "${DEST_DIR}" 2>/dev/null || true)" ]]; then
    log "sync: clearing destination ${DEST_DIR}"
    run_privileged rm -rf "${DEST_DIR:?}"/*
  fi

  local count=0
  while IFS= read -r file; do
    case "${file}" in
      *"/node_modules/"*|*"/test-results/"*|*"/.git/"*) continue ;;
    esac
    rel="${file#${SOURCE_DIR}/}"
    dest_file="${DEST_DIR}/${rel}"
    run_privileged mkdir -p "$(dirname "${dest_file}")"
    run_privileged cp -a "${file}" "${dest_file}"
    log "  copied: ${rel}"
    count=$((count + 1))
  done < <(find "${SOURCE_DIR}" -type f | sort)

  log "sync: ${count} file(s) copied with cp"
}

if command -v rsync >/dev/null 2>&1; then
  sync_with_rsync
else
  sync_with_cp
fi

if [[ "${DRY_RUN}" == false ]]; then
  file_count="$(find "${DEST_DIR}" -type f 2>/dev/null | wc -l | tr -d ' ')"
  dest_size="$(du -sh "${DEST_DIR}" 2>/dev/null | awk '{print $1}')"
  log "sync-static-assets: completed (${file_count} files, ${dest_size} total)"
else
  log "sync-static-assets: dry-run completed (no files written)"
fi
