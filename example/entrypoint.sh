#!/bin/bash
. /.venv/bin/activate

MAX_RETRY=10
REMOTE_DATA_LOCATION="https://registry.spid.gov.it/entities-idp -O ./spid-entities-idps.xml"

# get IDEM MDQ key
if [[ $GET_IDEM_MDQ_KEY == true ]]; then
  wget https://mdx.idem.garr.it/idem-mdx-service-crt.pem -O $SATOSA_KEYS_FOLDER/idem-mdx-service-crt.pem

  wget $REMOTE_DATA_LOCATION
  status=$?
  while [[ $status != 0 && $MAX_RETRY -gt 0 ]]; do
    echo "Retrying download from registry.spid.gov.it ..."
    wget $REMOTE_DATA_LOCATION
    status=$?
    MAX_RETRY=$((MAX_RETRY-1))
  done

  if [ $MAX_RETRY == 0 ]; then
    echo "Cannot fetch identity providers data from remote registry, aborting..."
    exit 1
  fi

  echo "Downloaded IDEM MDQ key"
fi

poetry show

wsgi_file=/.venv/lib/$(python -c 'import sys; print(f"python{sys.version_info.major}.{sys.version_info.minor}")')/site-packages/satosa/wsgi.py
wsgi_cmd="uwsgi --ini /satosa_proxy/uwsgi_setup/uwsgi/uwsgi.ini.docker --wsgi-file $wsgi_file"
if [[ $SATOSA_DEBUG == true ]]; then
  $wsgi_cmd --honour-stdin
else
  $wsgi_cmd
fi
