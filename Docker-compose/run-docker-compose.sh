#!/bin/bash
export COMPOSE_PROFILES=demo
export SKIP_UPDATE=

function clean_data {
  rm -Rf ./mongo/db/*
  rm -Rf ./satosa-project/*
  rm -Rf ./djangosaml2_sp/*
  rm -Rf ./nginx/html/static
}

function initialize_satosa {
  cp env.example .env

  echo "WARNING: creating directories with read/write/execute permissions to anybody"
  
  mkdir -p ./satosa-project
  mkdir -p ./djangosaml2_sp
  mkdir -p ./mongo/db
  mkdir -p ./nginx/html/static

  if [ ! -f ./satosa-project/proxy_conf.yaml ]; then cp -R ../iam-proxy-italia-project/* ./satosa-project/ ;  rm -R ./satosa/static/ ; else echo 'satosa-project directory is already initialized' ; fi
  if [ ! -f ./djangosaml2_sp/run.sh ]; then cp -R ../example_sp/djangosaml2_sp/* ./djangosaml2_sp ; else echo 'djangosaml2_sp directory is already initialided' ; fi
  if [ ! -f ./nginx/html/static/disco.html ]; then cp -R ../iam-proxy-italia-project/static/* ./nginx/html/static ; else echo 'nginx directory is already initialized' ; fi

  chmod -R 777 ./satosa-project
  echo "WARNING: satosa-project permission folder set recursively to 777"
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
  echo "   if isn't set any of -p, -m, -M, -d, is used 'demo' compose profile"
  echo "   demo compose profile start: satosa, nginx, mongo, mongo-express, django-sp, spid-saml-check"
}

while getopts ":fpimMdsh" opt; do
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
