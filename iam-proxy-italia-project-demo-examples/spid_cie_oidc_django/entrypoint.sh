#!/bin/bash

MODULE_NAME=''

cd /django-project

if [ -f "/prepare.sh" ]; then
    /bin/bash /prepare.sh $MODULE_NAME
    echo "Database initialized with sample data"
    rm -rf /prepare.sh
else
    echo "Database already initialized"
fi

python3 manage.py migrate
python3 manage.py loaddata dumps/example.json
# Port is overridden at Docker build (5002 for TA, 8002 for provider)
exec python3 manage.py runserver 0.0.0.0:5002