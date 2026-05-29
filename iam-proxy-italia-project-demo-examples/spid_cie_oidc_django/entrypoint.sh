#!/bin/bash

# MODULE_NAME and RUNNING_PORT can be set via env (e.g. from docker-compose)
MODULE_NAME="${MODULE_NAME:-}"
RUNNING_PORT="${RUNNING_PORT:-5002}"

cd /django-project

if [ -f "/prepare.sh" ]; then
    /bin/bash /prepare.sh "$MODULE_NAME"
    echo "Database initialized with sample data"
    rm -rf /prepare.sh
else
    echo "Database already initialized"
fi

python3 manage.py migrate
python3 manage.py loaddata dumps/example.json
exec python3 manage.py runserver "0.0.0.0:${RUNNING_PORT}"