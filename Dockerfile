FROM python:3.12-slim

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
RUN addgroup --system satosa && \
    adduser --system --ingroup satosa satosa && \
    chown -R satosa:satosa $BASEDIR

# Install system packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    build-essential \
    libffi-dev \
    libpcre2-dev \
    libssl-dev \
    mailcap \
    python3-dev \
    tzdata \
    wget \
    xmlsec1 \
    && rm -rf /var/lib/apt/lists/*

# Set up Python virtual environment
ENV VIRTUAL_ENV=/.venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN pip install --upgrade pip setuptools wheel --break-system-packages
RUN pip install flake8 pipx poetry --break-system-packages

# COPY poetry.lock /
COPY pyproject.toml /

RUN poetry self update && \
    poetry config virtualenvs.in-project true && \
    poetry install --no-interaction --no-ansi && \
    poetry add setuptools pdbpp

WORKDIR $BASEDIR/