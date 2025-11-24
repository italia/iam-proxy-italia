FROM ghcr.io/italia/spid-cie-oidc-django:latest

ARG RUNNING_PORT
ARG MODULE_NAME

RUN apt update
RUN apt install -y wget

COPY iam-proxy-italia-project-demo-examples/spid_cie_oidc_django/prepare.sh /
COPY iam-proxy-italia-project-demo-examples/spid_cie_oidc_django/healthcheck.sh /
COPY iam-proxy-italia-project-demo-examples/spid_cie_oidc_django/entrypoint.sh /

#prepare entrypoint script for specified MODULE_NAME (provider or federation_authority)
RUN sed -i "s/\(0\.0\.0\.0:\).*$/\1${RUNNING_PORT}/" /entrypoint.sh
RUN sed -i "s/\(MODULE_NAME=\).*$/\1'${MODULE_NAME}'/" /entrypoint.sh
