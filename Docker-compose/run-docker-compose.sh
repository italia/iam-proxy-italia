#!/bin/bash
export COMPOSE_PROFILES=demo
export SKIP_UPDATE=

function clean_data {
  rm -Rf ./mongo/db/*
  rm -Rf ./iam-proxy-italia-project/*
  rm -Rf ./djangosaml2_sp/*
  rm -Rf ./nginx/html/static
}

function init_files () {
  if [ -f $1 ]; then echo "$2 file is already initialized" ; else $3 ; fi
}

function initialize_satosa {
  echo "WARNING: creating directories with read/write/execute permissions to anybody"
  
  mkdir -p ./iam-proxy-italia-project
  mkdir -p ./djangosaml2_sp
  mkdir -p ./mongo/db
  mkdir -p ./nginx/html/static

  if [ "$SATOSA_FORCE_ENV" == "true" ]; then rm .env; fi
  init_files ./.env ".env" "cp env.example .env"
  init_files ./iam-proxy-italia-project/proxy_conf.yaml "iam-proxy-italia" "cp -R ../iam-proxy-italia-project ./"
  init_files ./djangosaml2_sp/run.sh "djangosaml2_sp" "cp -R ../iam-proxy-italia-project_sp/djangosaml2_sp ./"
  init_files ./nginx/html/static/disco.html "static pages" "cp -R ../iam-proxy-italia-project/static ./nginx/html"
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
  echo "-e Force update for .env file. A new .env file is generated from env.example file"
  echo "-f Force clean and reinitialize data for Satosa, MongoDB and Djangosaml2_SP"
  echo "-h Print this help"
  echo ""
  echo "#### profile options"
  echo "-m Set 'mongo' compose profile. Run: satosa, nginx, mongo"
  echo "-M Set 'mongoexpress' compose profile. Run: satosa, nginx, mongo, mongo-express"
  echo "-p unset compose profile. Run: satosa and nginx. Usefull for production"
  echo "-s Skip docker image update"
  echo "-d Set 'dev' compose profile. Run: satosa, nginx, django-sp, spid-saml-check"
  echo ""
  echo "if isn't set any options of -p, -m, -M, -d, is used 'demo' compose profile"
  echo "demo compose profile start: satosa, nginx, mongo, mongo-express, django-sp, spid-saml-check"
  echo ""
}

while getopts ":fepbimMdsh" opt; do
  case ${opt} in
   f)
     clean_data
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
