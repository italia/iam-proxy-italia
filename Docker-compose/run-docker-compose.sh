#!/bin/bash
export COMPOSE_PROFILES=demo
export SATOSA_CLEAN_DATA="false"
export SKIP_UPDATE=
export RUN_SPID_TEST=

function clean_data {
  if [ $SATOSA_CLEAN_DATA == "true" ]; then
    rm -Rf ./mongo/db/*
    rm -Rf ./iam-proxy-italia-project/*
    rm -Rf ./djangosaml2_sp/*
    rm -Rf ./nginx/html/static
    rm -Rf ./certbot/live/localhost/*
    rm -Rf ./spid_cie_oidc_django/wallet_trust_anchor/*
    if [ "$SATOSA_FORCE_ENV" == "true" ]; then rm .env; fi
  else
    if [ "$SATOSA_FORCE_ENV" == "true" ]; then echo "'-e' options is skipped. To perform this option is required '-f' too "; fi
  fi
}

function init_files () {
  if [ -f $1 ]; then echo "$2 file is already initialized" ; else $3 ; fi
}

function add_localhost_cert () {
  openssl req -x509 -out ./certbot/live/localhost/fullchain.pem -keyout certbot/live/localhost/privkey.pem \
  -newkey rsa:2048 -nodes -sha256 \
  -subj '/CN=localhost' -extensions EXT -config <( \
   printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")
}

function add_iam_cert () {
  cd ./iam-proxy-italia-project/pki
  bash build_spid_certs.sh
  cd ../..
}

function initialize_satosa {
  echo "WARNING: creating directories with read/write/execute permissions to anybody"
  
  mkdir -p ./iam-proxy-italia-project
  mkdir -p ./djangosaml2_sp
  mkdir -p ./mongo/db
  mkdir -p ./nginx/html/static
  mkdir -p ./certbot/live/localhost
  mkdir -p ./spid_cie_oidc_django/wallet_trust_anchor

  init_files ./.env ".env" "cp env.example .env"
  init_files ./iam-proxy-italia-project/proxy_conf.yaml "iam-proxy-italia" "cp -R ../iam-proxy-italia-project ./"
  init_files ./djangosaml2_sp/run.sh "djangosaml2_sp" "cp -R ../iam-proxy-italia-project-demo-examples/djangosaml2_sp ./"
  init_files ./nginx/html/static/disco.html "static pages" "cp -R ../iam-proxy-italia-project/static ./nginx/html"
  init_files ./certbot/live/localhost/privkey.pem "Locahost cert" "add_localhost_cert"
  init_files ./iam-proxy-italia-project/pki/privkey.pem "IAM Proxy cert" "add_iam_cert"
  init_files ./spid_cie_oidc_django/wallet_trust_anchor/manage.py "Wallet Trust Anchor" "cp -R ../iam-proxy-italia-project-demo-examples/spid_cie_oidc_django/wallet_trust_anchor ./spid_cie_oidc_django/"

  rm -Rf ./iam-proxy-italia-project/static

  chmod -R 777 ./iam-proxy-italia-project
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
  if [ "$SATOSA_BUILD" == "true" ]; then
    docker compose -f docker-compose.yml up --wait --wait-timeout 60 --remove-orphans --build
  else
    docker compose -f docker-compose.yml up --wait --wait-timeout 60 --remove-orphans
  fi
  echo -e "\n"
  echo -e "Completato. Per visionare i logs: 'docker-compose -f docker-compose.yml logs -f'"

  if [[ -n "${RUN_SPID_TEST}" ]]; then
    echo -e "\n"
    echo -e "spid-sp-test SPID metadata, requests and responses. \n"
    spid_sp_test --idp-metadata > ./iam-proxy-italia-project/metadata/idp/spid-sp-test.xml
    spid_sp_test --metadata-url https://localhost/spidSaml2/metadata --authn-url "http://localhost:8000/saml2/login/?idp=https://localhost/Saml2IDP/metadata&next=/saml2/echo_attributes&idphint=https%253A%252F%252Flocalhost%253A8443" -ap spid_sp_test.plugins.authn_request.SatosaSaml2Spid --extra --debug ERROR -tr

    echo -e "\n"
    echo -e "spid-sp-test CIE id metadata. \n"
    spid_sp_test --profile cie-sp-public --metadata-url https://localhost/cieSaml2/metadata

    echo -e "\n"
    echo -e "spid-sp-test SPID metadata, requests and responses. \n"
    spid_sp_test --profile ficep-eidas-sp --metadata-url https://localhost/spidSaml2/metadata
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
  echo "-m Set 'mongo' compose profile. Run: satosa, nginx, mongo"
  echo "-M Set 'mongoexpress' compose profile. Run: satosa, nginx, mongo, mongo-express"
  echo "-p unset compose profile. Run: satosa and nginx. Usefull for production"
  echo "-s Skip docker image update"
  echo "-d Set 'dev' compose profile. Run: satosa, nginx, django-sp, spid-saml-check"
  echo "-t Run spid_sp_test tests after startup"
  echo ""
  echo "if isn't set any options of -p, -m, -M, -d, is used 'demo' compose profile"
  echo "demo compose profile start: satosa, nginx, mongo, mongo-express, django-sp, spid-saml-check"
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
     COMPOSE_PROFILES="mongo"
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
initialize_satosa  # check and initialize docker compose directories
update             # try to update the images unless $SKIP_UPDATE is present
start              # run docker compose
