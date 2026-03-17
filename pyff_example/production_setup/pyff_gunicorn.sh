# apt install redis
# pip3 install gunicorn

BASEDIR="/opt"
APPNAME="pyff"
APPDIR="$BASEDIR/$APPNAME"
PYFF_PIPELINE=$APPDIR/pipelines/md.fd
PYFF_UPDATE_FREQUENCY=300

gunicorn --preload --bind 0.0.0.0:8080 -t 600 -e PYFF_PIPELINE=$PYFF_PIPELINE -e PYFF_STORE_CLASS=pyff.store:RedisWhooshStore -e PYFF_UPDATE_FREQUENCY=$PYFF_UPDATE_FREQUENCY --threads 4 --worker-tmp-dir=/dev/shm --worker-class=gthread pyff.wsgi:app
