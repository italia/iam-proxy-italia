#!/bin/bash

cd /rp-demo-project

echo "Starting FastAPI on port ${RUNNING_PORT} with HOST ${HOST}"

exec uvicorn main:app \
    --reload \
    --host ${HOST:-0.0.0.0} \
    --port ${RUNNING_PORT:-8090}
