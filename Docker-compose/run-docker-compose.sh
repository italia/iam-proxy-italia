#!/bin/bash
export COMPOSE_PROFILES=demo
export SKIP_UPDATE=
export RUN_SPID_TEST=

function clean_data {
  rm -Rf ./mongo/db/*
  rm -Rf ./iam-proxy-italia-project/*
  rm -Rf ./djangosaml2_sp/*
  rm -Rf ./nginx/html/static
  rm -Rf ./nginx/conf.d/sites-enabled/*
  rm -Rf ./wwwallet/*
}

function initialize_satosa {
  cp env.example .env

  echo "WARNING: creating directories with read/write/execute permissions to anybody"
  
  mkdir -p ./iam-proxy-italia-project
  mkdir -p ./djangosaml2_sp
  mkdir -p ./mongo/db
  mkdir -p ./nginx/html/static
  mkdir -p ./wwwallet

  if [ ! -f ./iam-proxy-italia-project/proxy_conf.yaml ]; then cp -R ../iam-proxy-italia-project/* ./iam-proxy-italia-project/ && rm -R ./satosa/static/ ; else echo 'iam-proxy-italia-project directory is already initialized' ; fi
  if [ ! -f ./djangosaml2_sp/run.sh ]; then cp -R ../iam-proxy-italia-project_sp/djangosaml2_sp/* ./djangosaml2_sp ; else echo 'djangosaml2_sp directory is already initialided' ; fi
  if [ ! -f ./nginx/html/static/disco.html ]; then cp -R ../iam-proxy-italia-project/static/* ./nginx/html/static ; else echo 'nginx directory is already initialized' ; fi
  if [ "$COMPOSE_PROFILES" == *"wwwallet"* ]; then
      if [ ! -f ./nginx/conf.d/sites-enabled/wwwallet.conf ]; then cp -R ../iam-proxy-italia-project/wwwallet/configs/wwwallet.conf ./nginx/conf.d/sites-enabled/ ; else echo 'nginx wwwallet configuration is already initialized' ; fi
      if [ ! -f ./wwwallet/wallet-frontend/package.json ]; then cp -R ../iam-proxy-italia-project/wwwallet/wallet-frontend ./wwwallet/wallet-frontend ; else echo 'wwwallet-frontend directory is already initialized' ; fi
      if [ ! -f ./wwwallet/wallet-backend-server/package.json ]; then cp -R ../iam-proxy-italia-project/wwwallet/wallet-backend-server ./wwwallet/wallet-backend-server ; else echo 'wwwallet-backend-server directory is already initialized' ; fi
      if [ ! -f ./wwwallet/wallet-frontend/.env.prod ]; then cp -R ../iam-proxy-italia-project/wwwallet/configs/.env.prod ./wwwallet/wallet-frontend/.env.prod ; else echo 'wwwallet-frontend .env.prod file is already initialized' ; fi
      if [ ! -f ./wwwallet/wallet-frontend/lib/wallet-common/package.json ]; then mkdir -p ./wwwallet/wallet-frontend/lib/wallet-common && cp -R ../iam-proxy-italia-project/wwwallet/wallet-common ./wwwallet/wallet-frontend/lib/wallet-common ; else echo 'wwwallet-frontend wallet-common directory is already initialized' ; fi
      cp -R ../iam-proxy-italia-project/wwwallet/configs/config.template.ts ./wwwallet/wallet-backend-server/config/config.template.ts
      cp -R ../iam-proxy-italia-project/wwwallet/configs/vite.config.ts ./wwwallet/wallet-frontend/vite.config.ts
      cp -R ../iam-proxy-italia-project/wwwallet/configs/proxy.router.ts ./wwwallet/wallet-backend-server/src/routers/proxy.router.ts
  fi

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
    docker compose -f docker-compose.yml build django_sp
  fi
}

function start {
  docker compose -f docker-compose.yml up --wait --wait-timeout 60 --remove-orphans
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
  echo "### run-docker-compose.sh ###"
  echo ""
  echo "initialize check update and start iam-proxy-italia compose structure"
  echo ""
  echo "Options"
  echo "-f Force clean and reinitialize data for Satosa, MongoDB and Djangosaml2_SP"
  echo "-h Print this help"
  echo "-s Skip docker image update"
  echo "-p unset compose profile. Run: satosa and nginx. Usefull for production"
  echo "-m Set 'mongo' compose profile. Run: satosa, nginx, mongo"
  echo "-M Set 'mongoexpress' compose profile. Run: satosa, nginx, mongo, mongo-express"
  echo "-d Set 'dev' compose profile. Run: satosa, nginx, django-sp, spid-saml-check"
  echo "-t Run spid_sp_test tests after startup"
  echo "   if isn't set any of -p, -m, -M, -d, is used 'demo' compose profile"
  echo "   demo compose profile start: satosa, nginx, mongo, mongo-express, django-sp, spid-saml-check"
}

while getopts ":fpmMdsth" opt; do
  case ${opt} in
   f)
     clean_data
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
initialize_satosa
update
start
