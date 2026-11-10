#!/bin/bash

# Ensure we are in the script's directory
cd "$(dirname "$0")"

# ==========================================================
# 0. LOAD ENVIRONMENT FILE (.env)
# ==========================================================
# Run from script directory so paths and .env resolve correctly
if [ -f .env ]; then
  echo "Loading variables from .env file..."
  set -o allexport
  source .env
  set +o allexport
else
  echo "Warning: .env file not found, using defaults only."
fi

# ==========================================================
# 1. DEFAULT SERVICES ENV VALUES (Fallback)
# ==========================================================

# --- SATOSA (iam-proxy-italia) --- [Defaults] ---
DEFAULT_SATOSA_HOSTNAME="iam-proxy-italia.example.org"

# --- Federation Authority (trust-anchor) --- [Defaults] ---
DEFAULT_TRUST_ANCHOR_PROTO="http"
DEFAULT_TRUST_ANCHOR_HOSTNAME="trust-anchor.example.org"
DEFAULT_TRUST_ANCHOR_PORT=5002

# --- Cie Provider (cie-provider) --- [Defaults] ---
DEFAULT_OPENID_CIE_PROVIDER_PROTO="http"
DEFAULT_OPENID_CIE_PROVIDER_HOST="cie-provider.example.org"
DEFAULT_OPENID_CIE_PROVIDER_PORT=8002
DEFAULT_OPENID_CIE_PROVIDER_USR="user"
DEFAULT_OPENID_CIE_PROVIDER_PWD="oidcuser"
DEFAULT_OPENID_CIE_PROVIDER_ADMIN_USR="admin"
DEFAULT_OPENID_CIE_PROVIDER_ADMIN_PWD="oidcadmin"

# --- Wallet Instance Demo (wallet-instance-demo) ---
DEFAULT_DEMO_WALLET_INSTANCE_PROTO="https"
DEFAULT_DEMO_WALLET_INSTANCE_PORT=8080
DEFAULT_DEMO_WALLET_INSTANCE_HOSTNAME="demo-wi.example.org"
DEFAULT_WALLET_INSTANCE_PASSWORD="wallet"

# ==========================================================
# 2. EXPORT SERVICES ENV VALUES (Overrides)
# This logic applies the User-defined value OR the Default
# ==========================================================
# --- Cie Provider (cie-provider) ---
export OPENID_CIE_PROVIDER_PROTO="${OPENID_CIE_PROVIDER_PROTO:-$DEFAULT_OPENID_CIE_PROVIDER_PROTO}"
export OPENID_CIE_PROVIDER_HOST="${OPENID_CIE_PROVIDER_HOST:-$DEFAULT_OPENID_CIE_PROVIDER_HOST}"
export OPENID_CIE_PROVIDER_PORT="${OPENID_CIE_PROVIDER_PORT:-$DEFAULT_OPENID_CIE_PROVIDER_PORT}"
export OPENID_CIE_PROVIDER_URL="${OPENID_CIE_PROVIDER_URL:-${OPENID_CIE_PROVIDER_PROTO}://${OPENID_CIE_PROVIDER_HOST}:${OPENID_CIE_PROVIDER_PORT}/oidc/op/}"
export OPENID_CIE_PROVIDER_USR="${OPENID_CIE_PROVIDER_USR:-$DEFAULT_OPENID_CIE_PROVIDER_USR}"
export OPENID_CIE_PROVIDER_PWD="${OPENID_CIE_PROVIDER_PWD:-$DEFAULT_OPENID_CIE_PROVIDER_PWD}"
export OPENID_CIE_PROVIDER_ADMIN_USR="${OPENID_CIE_PROVIDER_ADMIN_USR:-$DEFAULT_OPENID_CIE_PROVIDER_ADMIN_USR}"
export OPENID_CIE_PROVIDER_ADMIN_PWD="${OPENID_CIE_PROVIDER_ADMIN_PWD:-$DEFAULT_OPENID_CIE_PROVIDER_ADMIN_PWD}"

# --- Federation Authority (trust-anchor) ---
export TRUST_ANCHOR_PROTO="${TRUST_ANCHOR_PROTO:-$DEFAULT_TRUST_ANCHOR_PROTO}"
export TRUST_ANCHOR_HOSTNAME="${TRUST_ANCHOR_HOSTNAME:-$DEFAULT_TRUST_ANCHOR_HOSTNAME}"
export TRUST_ANCHOR_PORT="${TRUST_ANCHOR_PORT:-$DEFAULT_TRUST_ANCHOR_PORT}"
export TRUST_ANCHOR_URL="${TRUST_ANCHOR_URL:-${TRUST_ANCHOR_PROTO}://${TRUST_ANCHOR_HOSTNAME}:${TRUST_ANCHOR_PORT}}"

# --- SATOSA (iam-proxy-italia) ---
export SATOSA_HOSTNAME="${SATOSA_HOSTNAME:-$DEFAULT_SATOSA_HOSTNAME}"

# --- Wallet Instance Demo (wallet-instance-demo) ---
export DEMO_WALLET_INSTANCE_PROTO="${DEMO_WALLET_INSTANCE_PROTO:-$DEFAULT_DEMO_WALLET_INSTANCE_PROTO}"
export DEMO_WALLET_INSTANCE_HOSTNAME="${DEMO_WALLET_INSTANCE_HOSTNAME:-$DEFAULT_DEMO_WALLET_INSTANCE_HOSTNAME}"
export DEMO_WALLET_INSTANCE_PORT="${DEMO_WALLET_INSTANCE_PORT:-$DEFAULT_DEMO_WALLET_INSTANCE_PORT}"
export WALLET_INSTANCE_PASSWORD="${WALLET_INSTANCE_PASSWORD:-$DEFAULT_WALLET_INSTANCE_PASSWORD}"
export WALLET_PROVIDER_URL="${WALLET_PROVIDER_URL:-${DEMO_WALLET_INSTANCE_PROTO}://${DEMO_WALLET_INSTANCE_HOSTNAME}:${DEMO_WALLET_INSTANCE_PORT}/provider}"

# --- pagopa wallet-conformance-test (pagopa-wallet-cli) ---
export PAGOPA_CLI_SERVICE_NAME="${PAGOPA_CLI_SERVICE_NAME:-pagopa-wallet-cli}"

# --- Script/Docker-Compose Execution Variables (Internal) ---
if [ -z "${COMPOSE_PROFILES+x}" ]; then
  COMPOSE_PROFILES=demo
fi
export COMPOSE_PROFILES
export SATOSA_CLEAN_DATA="${SATOSA_CLEAN_DATA:-false}"
export SKIP_UPDATE="${SKIP_UPDATE:-}"
export RUN_SPID_TEST="${RUN_SPID_TEST:-}"
#export SATOSA_FORCE_ENV="true"


# ==========================================================
# 3. FUNCTIONS
# ==========================================================

function clean_data {
  if [ "${SATOSA_CLEAN_DATA}" = "true" ]; then
    rm -Rf ./mongo/db/*
    rm -Rf ./iam-proxy-italia-project/*
    rm -Rf ./djangosaml2_sp/*
    rm -Rf ./nginx/html/static
    rm -Rf ./spid_cie_oidc_django/*

#    rm -Rf ./certbot/live/localhost/*
#    rm -Rf ./certbot/live/${SATOSA_HOSTNAME}/*
    find ./certbot/live/* -maxdepth 1 -type d -not -path '.' -exec rm -rf {} +

    if [ "$SATOSA_FORCE_ENV" == "true" ]; then rm .env; fi
  else
    if [ "$SATOSA_FORCE_ENV" == "true" ]; then echo "'-e' options is skipped. To perform this option is required '-f' too "; fi
  fi
}

function init_files () {
  if [ -f "$1" ]; then echo "$2 file is already initialized" ; else $3 ; fi
}

function add_wallet_cert () {
  mkdir -p ./wallet-instance-demo/certs
  openssl req -x509 -out ./wallet-instance-demo/certs/demo-wi.crt -keyout ./wallet-instance-demo/certs/demo-wi.key \
  -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=${DEMO_WALLET_INSTANCE_HOSTNAME}" -extensions EXT -config <( \
   printf "[dn]\nCN=%s\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:%s\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth" "${DEMO_WALLET_INSTANCE_HOSTNAME}" "${DEMO_WALLET_INSTANCE_HOSTNAME}")
}

function add_satosa_cert () {
  openssl req -x509 -out ./certbot/live/${SATOSA_HOSTNAME}/fullchain.pem -keyout ./certbot/live/${SATOSA_HOSTNAME}/privkey.pem \
  -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=${SATOSA_HOSTNAME}" -extensions EXT -config <( \
   printf "[dn]\nCN=%s\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:%s\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth" "${SATOSA_HOSTNAME}" "${SATOSA_HOSTNAME}")
}

function add_iam_cert () {
  cd ./iam-proxy-italia-project/pki
  bash build_spid_certs.sh
  cd ../..
}

# Ensure hostname resolves to 127.0.0.1. Warn if it resolves elsewhere; try to add to /etc/hosts if missing.
function ensure_host_resolvable {
  local hostname="$1"
  local ip
  ip=$(getent hosts "${hostname}" 2>/dev/null | awk '{print $1; exit}')

  # Resolves to loopback — OK
  [[ "$ip" == "127.0.0.1" ]] || [[ "$ip" == "::1" ]] && return 0

  # Resolves to something else — warn only
  if [[ -n "$ip" ]]; then
    echo ""
    echo "WARNING: ${hostname} resolves to ${ip}. For local demo add to /etc/hosts:  127.0.0.1 ${hostname}"
    echo ""
    return 0
  fi

  # Does not resolve — try to add
  grep -q "${hostname}" /etc/hosts 2>/dev/null && return 0
  echo ""
  echo "Adding 127.0.0.1 ${hostname} to /etc/hosts (may prompt for sudo)."
  if echo "127.0.0.1 ${hostname}" | sudo tee -a /etc/hosts >/dev/null 2>&1; then
    return 0
  fi
  echo "Could not write. Add manually:  127.0.0.1 ${hostname}"
  read -r -p "Continue anyway? [y/N] " reply
  [[ "${reply}" =~ ^[yY]$ ]] || exit 1
}

function ensure_satosa_hostname_resolvable {
  ensure_host_resolvable "${SATOSA_HOSTNAME}"
  ensure_host_resolvable "${OPENID_CIE_PROVIDER_HOST}"
  ensure_host_resolvable "${TRUST_ANCHOR_HOSTNAME}"
  ensure_host_resolvable "${DEMO_WALLET_INSTANCE_HOSTNAME}"
  # Hostnames published by the PagoPA conformance tool (profile wct).
  ensure_host_resolvable "trust-anchor.wct.example.org"
  ensure_host_resolvable "wallet-provider.wct.example.org"
  ensure_host_resolvable "credential-issuer.wct.example.org"
}

function initialize_satosa {
  echo "WARNING: creating directories with read/write/execute permissions to anybody"

  mkdir -p ./iam-proxy-italia-project
  mkdir -p ./djangosaml2_sp
  mkdir -p ./mongo/db
  mkdir -p ./nginx/html/static
  mkdir -p ./certbot/live/${SATOSA_HOSTNAME}
  mkdir -p ./spid_cie_oidc_django
  mkdir -p ./wallet-instance-demo/config
  mkdir -p ./wallet-instance-demo/certs
  mkdir -p ./pagopa-wallet-cli/data
  chmod 777 ./pagopa-wallet-cli/data || true

  if [ -f ./.env ] && [ "$SATOSA_FORCE_ENV" != "true" ]; then echo ".env file is already initialized" ; else cp env.example .env ; fi
  init_files ./iam-proxy-italia-project/proxy_conf.yaml "iam-proxy-italia" "cp -R ../iam-proxy-italia-project ./"
  init_files ./djangosaml2_sp/run.sh "djangosaml2_sp" "cp -R ../iam-proxy-italia-project-demo-examples/djangosaml2_sp ./"
  init_files ./nginx/html/static/disco.html "static pages" "cp -R ../iam-proxy-italia-project/static ./nginx/html"
  init_files ./certbot/live/${SATOSA_HOSTNAME}/privkey.pem "SATOSA host cert" "add_satosa_cert"
  init_files ./wallet-instance-demo/certs/demo-wi.crt "Wallet demo cert" "add_wallet_cert"
  # OpenSSL writes the key as 0600. The wallet image runs as wiwuser and must read it.
  chmod a+r ./wallet-instance-demo/certs/demo-wi.key
  init_files ./iam-proxy-italia-project/pki/privkey.pem "IAM Proxy cert" "add_iam_cert"
  init_files ./spid_cie_oidc_django/healthcheck.sh "Federation authorities" "cp -R ../iam-proxy-italia-project-demo-examples/spid_cie_oidc_django/* ./spid_cie_oidc_django/"
  init_files ./wallet-instance-demo/config/app_config.yaml "wallet instance demo config" "cp -a ../iam-proxy-italia-project-demo-examples/iam-proxy-italia-wallet-instance-demo/. ./wallet-instance-demo/config/"
  chmod 777 ./wallet-instance-demo/config || true

  rm -Rf ./iam-proxy-italia-project/static

  chmod -R 777 ./iam-proxy-italia-project
  chmod -R 777 ./spid_cie_oidc_django
  chmod -R 777 ./djangosaml2_sp

  echo "WARNING: iam-proxy-italia-project permission folder set recursively to 777"
}

function update {
  if [[ -z "${SKIP_UPDATE}" ]]; then
    echo -e "Rimuovo le immagini della composizione, così vengono riscaricate o ricostruite. \n"
    ./remove-docker-images.sh
    echo -e "\n"
    echo -e "Provo a scaricare le nuove versioni. Le immagini che hanno un Dockerfile si costruiscono in locale se il tag non è nel registry. \n"
    docker compose -f docker-compose.yml pull --ignore-buildable
    echo -e "\n"
    echo -e "Provo a fare il down della composizione. \n"
    docker compose -f docker-compose.yml down -v
    echo -e "\n"
    echo -e "Tiro su la composizione, in caso, con le nuove versioni delle immagini. \n"
    # docker compose -f docker-compose.yml build django_sp
  fi
}

function build_selected_images {
  if [ -z "${SATOSA_BUILD}" ]; then
    return 0
  fi
  local services=(iam-proxy-italia)
  local profiles=",${COMPOSE_PROFILES},"
  case "${profiles}" in
    *,demo,*|*,dev,*|*,saml2,*)
      services+=(django_sp)
      ;;
  esac
  echo -e "Ricostruisco: ${services[*]} \n"
  docker compose -f docker-compose.yml build --no-cache "${services[@]}"
}

function start {
  # Ensure external network exists (avoids host interface teardown on compose down)
  docker network create iam-proxy-italia 2>/dev/null || true

  if ! build_selected_images; then
    exit 1
  fi

  # NEW BUSINESS

  DOCKER_UP_ARGS=(-f docker-compose.yml)
  if [ -n "${COMPOSE_EXTRA_FILE:-}" ]; then
    DOCKER_UP_ARGS+=(-f "${COMPOSE_EXTRA_FILE}")
  fi
  DOCKER_UP_ARGS+=(
  up
  --wait
  --wait-timeout 60
  --remove-orphans
  )
  if [ -n "${SATOSA_BUILD}" ]; then
    DOCKER_UP_ARGS+=(--no-build)
  fi
  echo -e "Starting compose with args: ${DOCKER_UP_ARGS[*]} \n"
  docker compose "${DOCKER_UP_ARGS[@]}"
  EXIT_CODE=$?
  echo -e "\n Compose finished with exit code: $EXIT_CODE\n"
  if [[ "${EXIT_CODE}" -ne 0 ]]; then
    exit "${EXIT_CODE}"
  fi

  # END NEW BUSINESS

  echo -e "\n"
  echo -e "Completato. Per visionare i logs: 'docker compose -f docker-compose.yml logs -f'"
  echo -e "\n"
  echo -e "=== Demo RP/SP — start the flow at ==="
  local profiles=",${COMPOSE_PROFILES},"
  if [[ "${profiles}" == *",demo,"* || "${profiles}" == *",dev,"* || "${profiles}" == *",saml2,"* ]]; then
    echo -e "  SAML SP (djangosaml2_sp):  http://localhost:8000"
  fi
  if [[ "${profiles}" == *",demo,"* || "${profiles}" == *",storage_mongo,"* || "${profiles}" == *",oidc,"* || "${profiles}" == *",wallet,"* || "${profiles}" == *",wallet_instance_demo,"* ]]; then
    echo -e "  OIDC RP demo:              http://localhost:8090"
    echo -e "  Wallet instance demo:      https://${DEMO_WALLET_INSTANCE_HOSTNAME}:${WALLET_INSTANCE_PORT:-8080}"
    echo -e "  Wallet instance password:  ${WALLET_INSTANCE_PASSWORD}"
  fi
  if [[ "${profiles}" != *",demo,"* && "${profiles}" != *",dev,"* && "${profiles}" != *",saml2,"* && "${profiles}" != *",storage_mongo,"* && "${profiles}" != *",oidc,"* && "${profiles}" != *",wallet,"* && "${profiles}" != *",wallet_instance_demo,"* ]]; then
    echo -e "  (No demo RP/SP in current profile; use default profile for SAML SP and OIDC RP)"
  fi

  # cie-provider (spid-cie-oidc-django sample dump): same profiles as in docker-compose.yml for that service
  case "${profiles}" in
    *,demo,*|*,storage_mongo,*|*,oidc,*)
      echo -e "=== (OIDC CIE Provider) — credentials from sample dump (see spid-cie-oidc-django README) ==="
      echo -e "  Base  URL:           ${OPENID_CIE_PROVIDER_PROTO}://${OPENID_CIE_PROVIDER_HOST}:${OPENID_CIE_PROVIDER_PORT}"
      echo -e "  Admin OIDC login:    username: ${OPENID_CIE_PROVIDER_ADMIN_USR} password: ${OPENID_CIE_PROVIDER_ADMIN_PWD}"
      echo -e "  User  OIDC login:    username: ${OPENID_CIE_PROVIDER_USR}       password: ${OPENID_CIE_PROVIDER_PWD}"
      echo -e ""
      ;;
  esac

  if [[ -n "${RUN_SPID_TEST}" ]]; then
    echo -e "\n"
    echo -e "spid-sp-test SPID metadata, requests and responses. \n"
    spid_sp_test --idp-metadata > ./iam-proxy-italia-project/metadata/idp/spid-sp-test.xml
    spid_sp_test --metadata-url https://${SATOSA_HOSTNAME}/spidSaml2/metadata --authn-url "http://localhost:8000/saml2/login/?idp=https://${SATOSA_HOSTNAME}/Saml2IDP/metadata&next=/saml2/echo_attributes&idphint=https%3A%2F%2F${SATOSA_HOSTNAME}%3A8443" -ap spid_sp_test.plugins.authn_request.SatosaSaml2Spid --extra --debug ERROR -tr

    echo -e "\n"
    echo -e "spid-sp-test CIE id metadata. \n"
    spid_sp_test --profile cie-sp-public --metadata-url https://${SATOSA_HOSTNAME}/cieSaml2/metadata

    echo -e "\n"
    echo -e "spid-sp-test SPID metadata, requests and responses. \n"
    spid_sp_test --profile ficep-eidas-sp --metadata-url https://${SATOSA_HOSTNAME}/spidSaml2/metadata
  fi

  exit 0
}

function announce {
  echo ""
  echo "=== run-docker-compose.sh ==="
  echo ""
  echo "Flag:"
  echo "  -f  cancella e reinizializza i dati locali (Mongo, configurazione Satosa, djangosaml2_sp, static, certificati)"
  echo "  -e  ricrea .env da env.example; ha effetto solo insieme a -f"
  echo "  -b  ricostruisce senza cache iam-proxy-italia e, se il profilo lo avvia, django-sp"
  echo "  -s  lascia container e immagini: niente rimozione, pull o down -v"
  echo "  -t  dopo l'avvio esegue spid-sp-test"
  echo "  COMPOSE_PROFILES seleziona i profili del compose. Se la variabile non è impostata, il profilo è demo."
  echo "  COMPOSE_PROFILES vuota avvia solo satosa e nginx."
  echo ""
  if [ -z "${COMPOSE_PROFILES}" ]; then
    echo "Profilo di questa esecuzione: nessuno (satosa e nginx)."
  else
    echo "Profilo di questa esecuzione: ${COMPOSE_PROFILES}."
  fi
  echo ""
  echo "Sta per succedere:"
  if [ "${SATOSA_CLEAN_DATA}" = "true" ]; then
    echo "- I dati locali vengono cancellati e reinizializzati."
    if [ "${SATOSA_FORCE_ENV}" = "true" ]; then
      echo "- .env viene ricreato da env.example."
    fi
  else
    echo "- I dati locali restano. -f li cancellerebbe."
    if [ "${SATOSA_FORCE_ENV}" = "true" ]; then
      echo "- -e è ignorato: serve anche -f."
    fi
  fi
  if [ -z "${SKIP_UPDATE}" ]; then
    echo "- I container vengono fermati e le immagini della composizione rimosse."
    echo "- I tag pubblici vengono riscaricati. Le immagini con un Dockerfile si ricostruiscono all'avvio."
    echo "- down -v elimina anche i volumi nominati. -s salta questi tre passi."
  else
    echo "- -s: niente rimozione delle immagini, niente pull e niente down -v."
  fi
  echo "- Poi docker compose up --wait."
  if [ -n "${RUN_SPID_TEST}" ]; then
    echo "- A composizione avviata partono i test spid-sp-test."
  fi
  if [ -n "${SATOSA_BUILD}" ]; then
    echo "- -b ricostruisce iam-proxy-italia con --no-cache prima di up."
    echo "- Se il profilo avvia django-sp, la ricostruisce nello stesso build --no-cache."
    echo "- up usa --no-build, così iam-proxy-italia non viene costruita una seconda volta."
  fi
  echo ""
}

function help {
  echo ""
  echo "### run-docker-compose.sh"
  echo ""
  echo "initialize check update and start iam-proxy-italia compose structure"
  echo ""
  echo "#### common Options"
  echo "-b Rebuild iam-proxy-italia without cache. Also rebuild django-sp when the selected profile starts it"
  echo "-e Force update for .env file. A new .env file is generated from env.example file. Require '-f' option otherwise is skipped"
  echo "-f Force clean and reinitialize data for Satosa, MongoDB and Djangosaml2_SP"
  echo "-h Print this help"
  echo ""
  echo "-s Skip docker image removal and update"
  echo "-t Run spid_sp_test tests after startup"
  echo ""
  echo "Profiles come from COMPOSE_PROFILES, as in docker compose."
  echo "When COMPOSE_PROFILES is unset, the script uses demo."
  echo "When COMPOSE_PROFILES is empty, only satosa and nginx start."
  echo "demo starts satosa, nginx, storage_mongo, mongo-express, django-sp, spid-saml-check and the OIDC demo."
  echo ""
  echo "#### SATOSA_HOSTNAME"
  echo "Hostname for the proxy (default when void: $DEFAULT_SATOSA_HOSTNAME). If it does not resolve,"
  echo "the script will try to add it to /etc/hosts as 127.0.0.1, or prompt you to add it manually."
  echo "Use stop-docker-compose.sh to remove those /etc/hosts entries when stopping."
  echo ""
}


# ==========================================================
# 4. ARGUMENT PARSING (While loop)
# ==========================================================
while getopts ":febish" opt; do
  case ${opt} in
   f)
     SATOSA_CLEAN_DATA="true"
     ;;
   e)
     SATOSA_FORCE_ENV="true"
     ;;
   b)
     SATOSA_BUILD="true"
     ;;
   s)
     SKIP_UPDATE=true
     ;;
   t)
     RUN_SPID_TEST=true
      ;;
   h)
     help
     exit 0
     ;;
   ?)
     echo "Invalid option: -${OPTARG}."
     echo ""
     help
     exit 1
     ;;
  esac
done


# ==========================================================
# 5. EXECUTION
# ==========================================================
announce
clean_data         # clean docker compose directories if $SATOSA_CLEAN_DATA == "true"
ensure_satosa_hostname_resolvable
initialize_satosa  # check and initialize docker compose directories
update             # try to update the images unless $SKIP_UPDATE is present
start              # run docker compose
