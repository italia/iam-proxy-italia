FROM alpine:3.22

RUN apk add --no-cache \
    python3 py3-pip build-base gcc libffi-dev openssl-dev bash

RUN python3 -m venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /rp-demo-project

COPY iam-proxy-italia-project-demo-examples/oidc_rp/requirements.txt .
COPY iam-proxy-italia-project-demo-examples/oidc_rp/main.py .
COPY iam-proxy-italia-project-demo-examples/oidc_rp/init_oidcop_mongo.py .
COPY iam-proxy-italia-project-demo-examples/oidc_rp/env.example .env
COPY iam-proxy-italia-project-demo-examples/oidc_rp/templates ./templates
COPY iam-proxy-italia-project-demo-examples/oidc_rp/static ./static
# Bootstrap Italia assets (svg sprites, fonts) — shared with djangosaml2_sp
COPY iam-proxy-italia-project-demo-examples/djangosaml2_sp/static/bootstrap-italia/svg/sprites.svg ./static/svg/
COPY iam-proxy-italia-project-demo-examples/djangosaml2_sp/static/bootstrap-italia/fonts ./static/bootstrap-italia/fonts
COPY iam-proxy-italia-project-demo-examples/oidc_rp/settings.py .
COPY iam-proxy-italia-project-demo-examples/oidc_rp/i18n ./i18n

RUN pip install --upgrade pip setuptools \
    && pip install --no-cache-dir -r requirements.txt

COPY iam-proxy-italia-project-demo-examples/oidc_rp/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN adduser -D appuser
USER appuser

ENTRYPOINT ["/entrypoint.sh"]
