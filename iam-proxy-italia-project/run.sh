#!/bin/bash

bash apply_conf.sh

# Dev execution
export SATOSA_APP=$VIRTUAL_ENV/lib/$(python -c 'import sys; print(f"python{sys.version_info.major}.{sys.version_info.minor}")')/site-packages/satosa
uwsgi --uid 1000 --https 0.0.0.0:9999,pki/cert.pem,pki/privkey.pem --check-static-docroot --check-static static/ --static-index disco.html &
P1=$!
uwsgi --uid 1000 --wsgi-file $SATOSA_APP/wsgi.py  --https 0.0.0.0:10000,pki/cert.pem,pki/privkey.pem --callable app -b 32648
P2=$!
wait $P1 $P2
