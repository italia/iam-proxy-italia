#!/bin/bash
. /.venv/bin/activate

REMOTE_DATA_LOCATION="https://registry.spid.gov.it/entities-idp -O ./spid-entities-idps.xml"

# update federation key and metadata
if [[ $GET_METADATA_AND_KEY == true ]]; then
  TMP = `mktemp`
  wget https://mdx.idem.garr.it/idem-mdx-service-crt.pem -nv -t3 -O $TMP && cp $TMP $SATOSA_KEYS_FOLDER/idem-mdx-service-crt.pem
  wget https://registry.spid.gov.it/entities-idp -nv -t3 -O $TMP && cp $TMP ./metadata/idp/spid-entities-idps.xml 
  wget https://sp-proxy.eid.gov.it/metadata -nv -t3 -O $TMP && cp $TMP ./metadata/idp/ficep.xml
  wget https://idserver.servizicie.interno.gov.it/idp/shibboleth?Metadata -nv -t3 -O $TMP && cp $TMP ./metadata/idp/cie-production.xml
fi

poetry show

wsgi_file=/.venv/lib/$(python -c 'import sys; print(f"python{sys.version_info.major}.{sys.version_info.minor}")')/site-packages/satosa/wsgi.py
wsgi_cmd="uwsgi --ini /satosa_proxy/uwsgi_setup/uwsgi/uwsgi.ini.docker --wsgi-file $wsgi_file"
if [[ $SATOSA_DEBUG == true ]]; then
  $wsgi_cmd --honour-stdin
else
  $wsgi_cmd
fi
