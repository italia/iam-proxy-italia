#!/bin/bash
. /.venv/bin/activate

###  function get_data ###
# try 3 time to get remote http/https data and copy to destination if third param is set "true"
# each try have 2 second of timeout, on error the destination file it is not written. Require wget. 
#
# get_data origin destination param_to_test
function get_data {
  if [[ $3 == 'true' ]]; then
    TMP=`mktemp`
    wget $1 -nv -t3 -T2 -O $TMP && cp $TMP $2
    rm $TMP
    unset $tmp
    chmod +r $2
  fi
}

### Update metadata and keys
get_data https://mdx.idem.garr.it/idem-mdx-service-crt.pem $SATOSA_KEYS_FOLDER/idem-mdx-service-crt.pem $SATOSA_GET_IDEM_MDQ_KEY
get_data https://registry.spid.gov.it/entities-idp ./metadata/idp/spid-entities-idps.xml $SATOSA_GET_SPID_IDP_METADATA
get_data https://sp-proxy.eid.gov.it/metadata ./metadata/idp/ficep.xml $SATOSA_GET_FICEP_IDP_METADATA
get_data https://idserver.servizicie.interno.gov.it/idp/shibboleth?Metadata ./metadata/idp/cie-production.xml $SATOSA_GET_CIE_IDP_METADATA

wsgi_file=/.venv/lib/$(python -c 'import sys; print(f"python{sys.version_info.major}.{sys.version_info.minor}")')/site-packages/satosa/wsgi.py
wsgi_cmd=""
if [[ $SATOSA_DEBUG == "true" ]]; then
  uwsgi --ini /satosa_proxy/uwsgi_setup/uwsgi/uwsgi.ini.debug --wsgi-file $wsgi_file
else
  uwsgi --ini /satosa_proxy/uwsgi_setup/uwsgi/uwsgi.ini.docker --wsgi-file $wsgi_file
fi
