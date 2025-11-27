#!/bin/bash
function help {
  echo ""
  echo "### stop-docker-compose.sh"
  echo ""
  echo "Down iamthe -proxy-italia docker compose"
  echo ""
  echo "#### Options"
  echo "-a remove all builded after down, like -i, -d"
  echo "-d remove django-so image after down"
  echo "-i remove iam-proxy-italia image after down"
  echo "-h print this help"
  echo ""
}

function remove_image () {
  if [ "$1" == "true" ]; then
    echo -e "Remove $2 docker image"
    docker image rm $2
  fi
}

while getopts ":adhi" opt; do
  case ${opt} in
    a)
      DJANGO_SP="true"
      IAM_PROXY_ITALIA="true"
      ;;
    d)
      DJANGO_SP="true"
      ;;
    h)
      help
      exit 0
      ;;
    i)
      IAM_PROXY_ITALIA="true"
      ;;
    ?)
      echo "Invalid option: -${OPTARG}."
      echo ""
      help
      exit 1
      ;;
  esac
done


echo -e "\n"
echo -e "Eseguo il down della composizione. \n"
docker compose -f docker-compose.yml --profile "*" down -v --remove-orphans
remove_image "$DJANGO_SP" "docker-compose-django_sp"
remove_image "$IAM_PROXY_ITALIA" "iam-proxy-italia"

exit 0
