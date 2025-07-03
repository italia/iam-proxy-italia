#!/bin/bash

SATOSA_APP=../env/lib/python3.10/site-packages/satosa
BASEDIR=./
uwsgi --uid 1000 --https 0.0.0.0:9999,$BASEDIR/pki/cert.pem,$BASEDIR/pki/privkey.pem --check-static-docroot --check-static $BASEDIR/static/ --static-index disco.html &
P1=$!
uwsgi --uid 1000 --wsgi-file $SATOSA_APP/wsgi.py  --https 0.0.0.0:10000,$BASEDIR/pki/cert.pem,$BASEDIR/pki/privkey.pem --callable app -b 32648 --thunder-lock
P2=$!
wait $P1 $P2
