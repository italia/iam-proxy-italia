FROM alpine:3.20

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

COPY requirements.txt /

ENV BASEDIR="/satosa_proxy"

# "tzdata"  package is required to set timezone with TZ environment
# "mailcap" package is required to add mimetype support
RUN apk add --update --no-cache tzdata mailcap xmlsec libffi-dev openssl-dev python3 py3-pip python3-dev procps git openssl build-base gcc wget bash jq yq-go pcre-dev

RUN python3 -m venv .venv && . .venv/bin/activate && pip3 install --upgrade pip setuptools \
      && pip3 install -r requirements.txt --ignore-installed --root-user-action=ignore && mkdir $BASEDIR \
      && addgroup -S satosa && adduser -S satosa -G satosa \
      && chown satosa:satosa $BASEDIR

RUN pip list

WORKDIR $BASEDIR/
