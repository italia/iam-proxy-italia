#!/bin/bash

bash apply_conf.sh

# Dev execution
uwsgi --uid 1000 --https 0.0.0.0:9999,pki/cert.pem,pki/privkey.pem --check-static-docroot --check-static static/ --static-index disco.html &
P1=$!
uwsgi --uid 1000 --wsgi-file wsgi.py  --https 0.0.0.0:10000,pki/cert.pem,pki/privkey.pem --callable app -b 32648
P2=$!
wait $P1 $P2
