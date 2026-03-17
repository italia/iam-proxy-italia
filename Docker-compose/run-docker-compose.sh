#!/bin/bash
# Run from script directory so paths and .env resolve correctly
cd "$(dirname "$0")"

# Default when SATOSA_HOSTNAME is unset or empty (single place for the value)
DEFAULT_SATOSA_HOSTNAME="iam-proxy-italia.example.org"
export SATOSA_HOSTNAME="${SATOSA_HOSTNAME:-$DEFAULT_SATOSA_HOSTNAME}"
export COMPOSE_PROFILES="${COMPOSE_PROFILES:-demo}"
export SATOSA_CLEAN_DATA="${SATOSA_CLEAN_DATA:-false}"
export SKIP_UPDATE="${SKIP_UPDATE:-}"
export RUN_SPID_TEST="${RUN_SPID_TEST:-}"

#export SATOSA_FORCE_ENV="true"

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

# Ensure a hostname resolves to 127.0.0.1; if not, add to /etc/hosts or prompt the user.
# Usage: ensure_host_resolvable "hostname"
function ensure_host_resolvable {
  local hostname="$1"
  if getent hosts "${hostname}" >/dev/null 2>&1; then
    return 0
  fi
  echo ""
  echo "Hostname '${hostname}' does not resolve. It must point to 127.0.0.1 for local access (e.g. HTTPS)."
  if grep -q "${hostname}" /etc/hosts 2>/dev/null; then
    echo "An entry for ${hostname} already exists in /etc/hosts."
    return 0
  fi
  echo "Adding '127.0.0.1 ${hostname}' to /etc/hosts (may prompt for sudo)."
  if (echo "127.0.0.1 ${hostname}" | sudo tee -a /etc/hosts >/dev/null 2>&1); then
    echo "Added. ${hostname} now resolves to 127.0.0.1."
    return 0
  fi
  echo ""
  echo "Could not write to /etc/hosts. Add this line manually (e.g. with sudo):"
  echo "  127.0.0.1 ${hostname}"
  echo ""
  read -r -p "Continue anyway? [y/N] " reply
  if [[ ! "${reply}" =~ ^[yY]$ ]]; then
    exit 1
  fi
}

function ensure_satosa_hostname_resolvable {
  ensure_host_resolvable "${SATOSA_HOSTNAME}"
  ensure_host_resolvable "cie-provider.example.org"
  ensure_host_resolvable "trust-anchor.example.org"
}

function initialize_satosa {
  echo "WARNING: creating directories with read/write/execute permissions to anybody"
  
  mkdir -p ./iam-proxy-italia-project
  mkdir -p ./djangosaml2_sp
  mkdir -p ./mongo/db
  mkdir -p ./nginx/html/static
  mkdir -p ./certbot/live/${SATOSA_HOSTNAME}
  mkdir -p ./spid_cie_oidc_django

  if [ -f ./.env ] && [ "$SATOSA_FORCE_ENV" != "true" ]; then echo ".env file is already initialized" ; else cp env.example .env ; fi
  init_files ./iam-proxy-italia-project/proxy_conf.yaml "iam-proxy-italia" "cp -R ../iam-proxy-italia-project ./"
  init_files ./djangosaml2_sp/run.sh "djangosaml2_sp" "cp -R ../iam-proxy-italia-project-demo-examples/djangosaml2_sp ./"
  init_files ./nginx/html/static/disco.html "static pages" "cp -R ../iam-proxy-italia-project/static ./nginx/html"
  init_files ./certbot/live/${SATOSA_HOSTNAME}/privkey.pem "SATOSA host cert" "add_satosa_cert"
  init_files ./iam-proxy-italia-project/pki/privkey.pem "IAM Proxy cert" "add_iam_cert"
  init_files ./spid_cie_oidc_django/healthcheck.sh "Federation authorities" "cp -R ../iam-proxy-italia-project-demo-examples/spid_cie_oidc_django/* ./spid_cie_oidc_django/"

  rm -Rf ./iam-proxy-italia-project/static

  chmod -R 777 ./iam-proxy-italia-project
  chmod -R 777 ./spid_cie_oidc_django
  chmod -R 777 ./djangosaml2_sp

  echo "WARNING: iam-proxy-italia-project permission folder set recursively to 777"
}

function update {
  if [[ -z "${SKIP_UPDATE}" ]]; then
    echo -e "Provo a scaricare le nuove versioni. \n"
    docker compose -f docker-compose.yml pull
    echo -e "\n"
    echo -e "Provo a fare il down della composizione. \n"
    docker compose -f docker-compose.yml down -v
    echo -e "\n"
    echo -e "Tiro su la composizione, in caso, con le nuove versioni delle immagini. \n"
    # docker compose -f docker-compose.yml build django_sp
  fi
}

function start {
  # Ensure external network exists (avoids host interface teardown on compose down)
  docker network create iam-proxy-italia 2>/dev/null || true
  if [ "$SATOSA_BUILD" == "true" ]; then
    docker compose -f docker-compose.yml up --wait --wait-timeout 60 --remove-orphans --build
  else
    docker compose -f docker-compose.yml up --wait --wait-timeout 60 --remove-orphans
  fi
  echo -e "\n"
  echo -e "Completato. Per visionare i logs: 'docker compose -f docker-compose.yml logs -f'"
  echo -e "\n"
  echo -e "=== Demo RP/SP — start the flow at ==="
  case "${COMPOSE_PROFILES}" in
    demo|*demo*)
      echo -e "  SAML SP (djangosaml2_sp):  http://localhost:8000"
      echo -e "  OIDC RP demo:              http://localhost:8090"
      ;;
    dev|*saml2*)
      echo -e "  SAML SP (djangosaml2_sp):  http://localhost:8000"
      ;;
    storage_mongo|*oidc*)
      echo -e "  OIDC RP demo:              http://localhost:8090"
      ;;
    *)
      echo -e "  (No demo RP/SP in current profile; use default profile for SAML SP and OIDC RP)"
      ;;
  esac
  echo -e ""

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

function help {
  echo ""
  echo "### run-docker-compose.sh"
  echo ""
  echo "initialize check update and start iam-proxy-italia compose structure"
  echo ""
  echo "#### common Options"
  echo "-b Build for iam-proxy-italia image and build django-sp image if required"
  echo "-e Force update for .env file. A new .env file is generated from env.example file. Require '-f' option otherwise is skipped"
  echo "-f Force clean and reinitialize data for Satosa, MongoDB and Djangosaml2_SP"
  echo "-h Print this help"
  echo ""
  echo "#### profile options"
  echo "-m Set 'storage_mongo' compose profile. Run: satosa, nginx, mongo (storage for OIDC/Wallet)"
  echo "-M Set 'mongoexpress' compose profile. Run: satosa, nginx, mongo, mongo-express"
  echo "-p unset compose profile. Run: satosa and nginx. Usefull for production"
  echo "-s Skip docker image update"
  echo "-d Set 'dev' compose profile. Run: satosa, nginx, django-sp, spid-saml-check (SAML2)"
  echo "-t Run spid_sp_test tests after startup"
  echo ""
  echo "if isn't set any options of -p, -m, -M, -d, is used 'demo' compose profile"
  echo "demo compose profile start: satosa, nginx, storage_mongo, mongo-express, django-sp, spid-saml-check, OIDC demo"
  echo ""
  echo "#### SATOSA_HOSTNAME"
  echo "Hostname for the proxy (default when void: $DEFAULT_SATOSA_HOSTNAME). If it does not resolve,"
  echo "the script will try to add it to /etc/hosts as 127.0.0.1, or prompt you to add it manually."
  echo "Use stop-docker-compose.sh to remove those /etc/hosts entries when stopping."
  echo ""
}

while getopts ":fepbimMdsh" opt; do
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
   p)
     unset COMPOSE_PROFILES
     ;;
   m)
     COMPOSE_PROFILES="storage_mongo"
     ;;
   M)
     COMPOSE_PROFILES="mongoexpress"
     ;;
   d)
     COMPOSE_PROFILES="dev"
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
clean_data         # clean docker compose directories if $SATOSA_CLEAN_DATA == "true"
ensure_satosa_hostname_resolvable
initialize_satosa  # check and initialize docker compose directories
update             # try to update the images unless $SKIP_UPDATE is present
start              # run docker compose
