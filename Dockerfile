FROM alpine:3.21.2

# Metadata params
ARG BUILD_DATE
ARG VERSION
ARG VCS_URL="https://github.com/italia/iam-proxy-italia.git"
ARG VCS_REF
ARG AUTHORS
ARG VENDOR

# Metadata : https://github.com/opencontainers/image-spec/blob/main/annotations.md
LABEL org.opencontainers.image.authors=$AUTHORS \
      org.opencontainers.image.vendor=$VENDOR \
      org.opencontainers.image.title="iam-proxy-italia" \
      org.opencontainers.image.created=$BUILD_DATE \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.source=$VCS_URL \
      org.opencontainers.image.revision=$VCS_REF \
      org.opencontainers.image.description="Docker Image di iam-proxy-italia."

ENV BASEDIR="/satosa_proxy"
RUN mkdir $BASEDIR

RUN addgroup -S satosa && adduser -S satosa -G satosa && chown satosa:satosa $BASEDIR

# "tzdata"  package is required to set timezone with TZ environment
# "mailcap" package is required to add mimetype support
RUN apk add --update --no-cache tzdata mailcap xmlsec libffi-dev openssl-dev python3-dev py3-pip openssl build-base gcc wget bash pcre-dev

# COPY poetry.lock /
COPY pyproject.toml /

RUN python3 -m venv .venv && . .venv/bin/activate
RUN pip3 install --upgrade pip --break-system-packages
RUN pip3 install flake8 pipx poetry --break-system-packages

RUN poetry self update
RUN poetry config virtualenvs.in-project true
RUN poetry install
RUN poetry add setuptools
RUN poetry add pdbpp

WORKDIR $BASEDIR/
