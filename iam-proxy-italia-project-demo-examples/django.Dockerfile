FROM alpine:3.19.1
 
RUN apk update
# Keep tzdata: Python zoneinfo (3.9+) needs /usr/share/zoneinfo or the tzdata package.
# Removing it (apk del tzdata) breaks Django timezone handling in slim/minimal images.
RUN apk add --update --no-cache tzdata
RUN cp /usr/share/zoneinfo/Europe/Rome /etc/localtime
RUN echo "Europe/Rome" > /etc/timezone

COPY iam-proxy-italia-project-demo-examples/djangosaml2_sp/requirements.txt /
COPY iam-proxy-italia-project-demo-examples/entrypoint.sh /

WORKDIR /djangosaml2_sp

RUN apk add --update xmlsec-dev libffi-dev openssl-dev python3 py3-pip python3-dev procps git openssl build-base gcc wget bash jq yq 

RUN python3 -m venv .venv && . .venv/bin/activate && pip3 install --upgrade pip setuptools \ 
    && pip3 install -r ../requirements.txt --ignore-installed --root-user-action=ignore
